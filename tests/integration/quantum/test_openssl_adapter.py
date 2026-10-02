"""Real production OpenSSL CLI adapter against disposable local OpenSSL servers.

No broker, Wi-Fi, board, private service keys or database access. No emulator is
needed for these provider-level tests. Firmware/SDK integration is separate.
"""
import contextlib
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import threading


def main():
    probe = pathlib.Path(sys.argv[1]).resolve()
    count = 0
    with tempfile.TemporaryDirectory(prefix="nm-openssl-adapter-") as directory:
        root = pathlib.Path(directory)

        def certificate(name, algorithm="rsa:2048"):
            key, cert = root / f"{name}.key", root / f"{name}.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", algorithm, "-noenc",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext",
                            "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"],
                           check=True, capture_output=True, timeout=30)
            return key, cert

        pair = certificate("server")
        other = certificate("unrelated")
        pq_pair = certificate("pq", "ML-DSA-65")
        # Explicit curve selection avoids depending on OpenSSL's EC defaults.
        ecc_key, ecc_cert = root / "ecc.key", root / "ecc.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-noenc", "-keyout", str(ecc_key),
                        "-out", str(ecc_cert), "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True, timeout=30)
        ecc_pair = ecc_key, ecc_cert

        @contextlib.contextmanager
        def server(pair=pair, *options):
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            process = subprocess.Popen(
                ["openssl", "s_server", "-accept", str(port), "-cert", str(pair[1]),
                 "-key", str(pair[0]), "-groups", "X25519MLKEM768:X25519",
                 "-quiet", *options], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("OpenSSL fixture exited")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise RuntimeError("OpenSSL fixture not ready")
                yield port
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        def check(command, expected=0, contains=(), excludes=(), trust=pair[1]):
            nonlocal count
            result = subprocess.run([str(probe), str(trust), command], capture_output=True,
                                    text=True, timeout=15)
            assert result.returncode == expected, (command, result.stdout, result.stderr)
            for text in contains:
                assert text in result.stdout, (command, result.stdout)
            for text in excludes:
                assert text not in result.stdout, (command, result.stdout)
            assert "AddressSanitizer" not in result.stderr and "runtime error:" not in result.stderr
            count += 1
            print(f"PASS {command}", flush=True)
            return result.stdout

        def openssl_oracle(arguments, trust, suite, protocol):
            # .NET forwards argv to this binary without a shell. Run the same
            # diagnostic switches, with a test-only public CAfile for the oracle.
            result = subprocess.run(["openssl", "s_client", *arguments, "-brief",
                                     "-verify_return_error", "-CAfile", str(trust)],
                                    input="", text=True, capture_output=True, timeout=15)
            assert result.returncode == 0, result.stderr
            assert suite in result.stderr and protocol in result.stderr, result.stderr

        for command in ("version -a", "help", "list -tls-groups", "ciphers -s -tls1_3"):
            check(command)
        with server() as port:
            base = f"s_client -connect 127.0.0.1:{port} -servername localhost"
            check(base, contains=("Protocol: TLSv1.3", "Certificate trust: trusted"))
            check(base + " -verify_return_error", contains=("SigAlg=", "Certificate trust: trusted"))
            check(base + " -verify_hostname wrong.example", expected=1,
                  contains=("TLS connection failed",))
            check(base + " -verify_ip 127.0.0.1")
            check(base + " -verify_ip 127.0.0.2", expected=1)
            check(base + " -verify_return_error", expected=1, trust=other[1])
            check(base, trust=other[1], contains=("Certificate trust: not trusted",))
            check(base + " -4 -brief", contains=("ALPN protocol: none",), excludes=("SigAlg=",))
            check(base + " -6", expected=1)
            check(base + " -groups X25519", contains=("Negotiated TLS group: X25519",))
            check(base + " -groups MLKEM768:unknown", expected=1)
            pem = check(base + " -showcerts -verify_return_error", contains=("BEGIN CERTIFICATE",))
            extracted = pem[pem.index("-----BEGIN CERTIFICATE-----"):]
            parsed = subprocess.run(["openssl", "x509", "-noout", "-subject"], input=extracted,
                                    text=True, capture_output=True, timeout=10)
            assert parsed.returncode == 0 and "localhost" in parsed.stdout, (parsed.stderr, repr(extracted))
            check(f"s_client -connect localhost:{port} -noservername -verify_return_error")
            check(f"s_client -host 127.0.0.1 -port {port} -servername localhost")
            check(base + " -min_protocol TLSv1.3 -max_protocol TLSv1.3")
            check(base + " -tls1_1", expected=2)
            check(base + " -tls1_2 -verify_return_error",
                  contains=("Protocol: TLSv1.2",))
            check(base + " -ciphersuites ALL", expected=2)
        for suite in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"):
            with server(pair, "-tls1_3", "-ciphersuites", suite, "-alpn", "h2,http/1.1") as port:
                base = f"s_client -connect 127.0.0.1:{port} -servername localhost"
                check(base + f" -ciphersuites {suite} -alpn h2,http/1.1",
                      contains=(suite, "ALPN protocol: h2"))
                openssl_oracle(["-connect", f"127.0.0.1:{port}", "-tls1_3",
                                "-ciphersuites", suite, "-alpn", "h2,http/1.1"],
                               pair[1], suite, "TLSv1.3")
                wrong = "TLS_AES_256_GCM_SHA384" if "128" in suite else "TLS_AES_128_GCM_SHA256"
                check(base + f" -ciphersuites {wrong}", expected=1)
                check(base + " -alpn unsupported", expected=1)
        with server(pq_pair) as port:
            check(f"s_client -connect 127.0.0.1:{port} -showcerts",
                  contains=("SigAlg=ML-DSA-65", "KeyAlg=ML-DSA-65", "BEGIN CERTIFICATE"),
                  trust=pq_pair[1])
        for suite in ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"):
            with server(pair, "-tls1_2", "-cipher", suite) as port:
                check(f"s_client -connect 127.0.0.1:{port} -tls1_2 -cipher {suite} "
                      "-verify_return_error -showcerts",
                      contains=("Protocol: TLSv1.2", suite, "BEGIN CERTIFICATE"))
                openssl_oracle(["-connect", f"127.0.0.1:{port}", "-tls1_2", "-cipher", suite],
                               pair[1], suite, "TLSv1.2")
        for suite in ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"):
            with server(ecc_pair, "-tls1_2", "-cipher", suite) as port:
                check(f"s_client -connect 127.0.0.1:{port} -tls1_2 -cipher {suite} "
                      "-verify_return_error", trust=ecc_pair[1],
                      contains=("Protocol: TLSv1.2", suite))
                openssl_oracle(["-connect", f"127.0.0.1:{port}", "-tls1_2", "-cipher", suite],
                               ecc_pair[1], suite, "TLSv1.2")
        for group in ("secp256r1", "secp384r1", "secp521r1"):
            with server(pair, "-tls1_3", "-groups", group) as port:
                check(f"s_client -connect 127.0.0.1:{port} -groups {group} -verify_return_error")

        @contextlib.contextmanager
        def python_peer(ip="127.0.0.1", stalled=False, require_sni=False):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(str(pair[1]), str(pair[0]))
            if require_sni:
                def sni(_ssl, name, _context):
                    if name != "localhost":
                        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
                context.set_servername_callback(sni)
            listener = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET)
            listener.bind((ip, 0))
            listener.listen()
            listener.settimeout(.1)
            stop = threading.Event()
            def run():
                while not stop.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    with connection:
                        connection.settimeout(3)
                        if stalled:
                            stop.wait(3)
                        else:
                            try:
                                with context.wrap_socket(connection, server_side=True):
                                    pass
                            except (ssl.SSLError, OSError):
                                pass
            worker = threading.Thread(target=run)
            worker.start()
            try:
                yield listener.getsockname()[1]
            finally:
                stop.set()
                listener.close()
                worker.join(timeout=5)
                assert not worker.is_alive()

        with python_peer(require_sni=True) as port:
            base = f"s_client -connect 127.0.0.1:{port}"
            check(base + " -servername localhost -verify_return_error")
            check(base + " -noservername", expected=1)
            check(base + " -servername wrong.example", expected=1)
            # Verification identity is independent of the sent SNI name.
            check(base + " -servername localhost -verify_ip 127.0.0.1")
        ipv6_available = True
        with socket.socket(socket.AF_INET6) as ipv6:
            try:
                ipv6.bind(("::1", 0))
            except OSError:
                ipv6_available = False
        if ipv6_available:
            with python_peer(ip="::1") as port:
                check(f"s_client -connect [::1]:{port} -6 -verify_ip ::1")
        else:
            print("SKIP IPv6 transport: host has no ::1 address (IPv6 parsing/filter tests still run)")
        with python_peer(stalled=True) as port:
            start = time.monotonic()
            check(f"s_client -connect 127.0.0.1:{port}", expected=1,
                  contains=("timed out",))
            assert time.monotonic() - start < 4

        # A signed leaf plus the sent root exercises concatenated chain PEM.
        csr, leaf = root / "leaf.csr", root / "leaf.pem"
        subprocess.run(["openssl", "req", "-new", "-key", str(other[0]), "-out", str(csr),
                        "-subj", "/CN=localhost"], check=True, capture_output=True, timeout=30)
        ext = root / "leaf.ext"
        ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(pair[1]),
                        "-CAkey", str(pair[0]), "-set_serial", "99", "-days", "1",
                        "-extfile", str(ext), "-out", str(leaf)],
                       check=True, capture_output=True, timeout=30)
        with server((other[0], leaf), "-cert_chain", str(pair[1])) as port:
            output = check(f"s_client -connect 127.0.0.1:{port} -showcerts -verify_return_error")
            assert output.count("-----BEGIN CERTIFICATE-----") == 2
            pem = output[output.index("-----BEGIN CERTIFICATE-----"):]
            checked = subprocess.run(["openssl", "crl2pkcs7", "-nocrl", "-certfile", "/dev/stdin"],
                                     input=pem, text=True, capture_output=True, timeout=10)
            assert checked.returncode == 0, checked.stderr
        print(f"OPENSSL_ADAPTER_RESULT passed={count} total={count}")


if __name__ == "__main__":
    main()
