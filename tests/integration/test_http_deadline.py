#!/usr/bin/env python3
"""Real ESP-IDF HTTP deadline tests in esp-emu; no broker, tokens or firmware keys.

Build tests/integration/http_deadline with ESP-IDF 6.1 into build-http-deadline.
Requires tools/setup-tap.sh and exclusive use of nm-esp-tap. This runner never
changes firewall rules; allow only that TAP to the four fixture ports if needed.
"""
import pathlib
import ssl
import contextlib
import socketserver
import subprocess
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        # Host wall time can advance faster than emulated time under CPU load.
        # The firmware's 1200 ms deadline, not this safety bound, is under test.
        self.request.settimeout(120)
        try:
            request = b""
            while b"\r\n\r\n" not in request and len(request) < 8192:
                part = self.request.recv(1024)
                if not part:
                    return
                request += part
            path = request.split(b" ")[1].decode("ascii")
            send = self.request.sendall
            if path in ("/to-tls", "/to-http"):
                target = "https://deadline.test:18443/ok" if path == "/to-tls" else "http://192.168.4.1:18080/ok"
                send(f"HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            elif path == "/stall":
                time.sleep(3)
            elif path == "/headers":
                for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok":
                    send(bytes([byte]))
                    time.sleep(0.1)
            elif path == "/drip":
                send(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                for _ in range(100):
                    send(b"x")
                    time.sleep(0.1)
            elif path == "/chunked":
                send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                for _ in range(100):
                    send(b"1\r\nx\r\n")
                    time.sleep(0.1)
            elif path.startswith("/redirect/"):
                time.sleep(0.45)
                hop = int(path.rsplit("/", 1)[1]) + 1
                send(f"HTTP/1.1 302 Found\r\nLocation: /redirect/{hop}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            else:
                send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except (OSError, ValueError, IndexError):
            pass  # A timed-out client is expected to close its connection.


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TLSHandler(Handler):
    def handle(self):
        started = time.monotonic()
        try:
            self.request.settimeout(120)
            with self.server.tls.wrap_socket(self.request, server_side=True) as secure:
                self.request = secure
                super().handle()
        except TimeoutError:
            print(f"TLS fixture wall-clock timeout after {time.monotonic() - started:.1f}s", flush=True)
        except (OSError, ssl.SSLError):
            pass


class HandshakeStall(socketserver.BaseRequestHandler):
    def handle(self):
        time.sleep(3)


def main():
    image = ROOT / "build-http-deadline/merged-binary.bin"
    log = ROOT / "build-http-deadline/integration.log"
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ROOT / "build-http-deadline/test-cert.pem", ROOT / "build-http-deadline/test-key.pem")
    untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    untrusted.load_cert_chain(ROOT / "build-http-deadline/untrusted-cert.pem", ROOT / "build-http-deadline/untrusted-key.pem")
    near = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    near.load_cert_chain(ROOT / "build-http-deadline/near-cert.pem", ROOT / "build-http-deadline/near-key.pem")
    names = []
    tls.set_servername_callback(lambda sock, name, context: names.append(name))
    with contextlib.ExitStack() as stack:
        servers = [stack.enter_context(Server(("192.168.4.1", port), handler)) for port, handler in
                   ((18080, Handler), (18443, TLSHandler), (18444, HandshakeStall), (18445, TLSHandler), (18446, TLSHandler))]
        servers[1].tls = tls
        servers[3].tls = untrusted
        servers[4].tls = near
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with log.open("wb") as output_file:
                with subprocess.Popen([
                    str(pathlib.Path.home() / ".local/bin/esp-emu"),
                    "--chip", "esp32s3", "--firmware", str(image),
                    "--net", "tap,ifname=nm-esp-tap", "--psram-size", "8M", "--timeout", "600s",
                    "--wifi-ssid", "test", "--wifi-password", "test-password",
                    "--exit-on", "HTTP_DEADLINE_INTEGRATION_PASS",
                ], stdout=output_file, stderr=subprocess.STDOUT) as process:
                    deadline = time.monotonic() + 660
                    try:
                        while process.poll() is None:
                            output = log.read_text(errors="replace")
                            if any(marker in output for marker in
                                   ("assert failed:", "Guru Meditation", "abort() was called")):
                                process.terminate()
                                break
                            if time.monotonic() >= deadline:
                                process.terminate()
                                break
                            time.sleep(0.25)
                        returncode = process.wait(timeout=10)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
        finally:
            for server in servers:
                server.shutdown()
    output = log.read_text(errors="replace")
    for line in output.splitlines():
        if any(word in line for word in ("CASE ", "HEAP ", "PROBE_MEMORY", "assert", "PASS", "panic")):
            print(line)
    assert returncode == 0 and "HTTP_DEADLINE_INTEGRATION_PASS" in output, str(log)
    assert "HTTPS_EXPIRY_POLICY_PASS" in output, str(log)
    assert "PROBE_MEMORY_INTEGRATION_PASS" in output, str(log)
    assert "deadline.test" in names and "wrong.test" in names, names


if __name__ == "__main__":
    main()
