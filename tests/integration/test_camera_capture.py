#!/usr/bin/env python3
"""Credential-free ONVIF/HTTP camera fixture against production ESP-IDF code.
Uses esp-emu user networking; no board, broker or network configuration changes.
"""
import base64
import contextlib
import hashlib
import http.server
import pathlib
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
ROOT = pathlib.Path(__file__).resolve().parents[2]
JPEG = base64.b64decode('/9j/4AAQSkZJRgABAgAAAQABAAD//gAQTGF2YzYxLjE5LjEwMQD/2wBDAAgEBAQEBAUFBQUFBQYGBgYGBgYGBgYGBgYHBwcICAgHBwcGBgcHCAgICAkJCQgICAgJCQoKCgwMCwsODg4RERT/xABNAAEBAAAAAAAAAAAAAAAAAAAABgEBAQEAAAAAAAAAAAAAAAAAAAUGEAEAAAAAAAAAAAAAAAAAAAAAEQEAAAAAAAAAAAAAAAAAAAAA/8AAEQgAMABAAwEiAAIRAAMRAP/aAAwDAQACEQMRAD8AgAF9nAAAAAAAAAAAAAAAAAAAAAAH/9k=')
USER, PASSWORD = "test", "test-password"
NONCE, REALM = "camera-test-nonce", "camera-test"

def field(xml, name):
    return next(e.text for e in xml.iter() if e.tag.split("}")[-1] == name)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def send(self, data, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)
    def authorised(self, digest):
        header = self.headers.get("Authorization", "")
        if not digest:
            good = header == "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        else:
            parts = {}
            for match in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', header):
                parts[match[1]] = match[2] if match[2] is not None else match[3]
            md5 = lambda s: hashlib.md5(s.encode()).hexdigest()
            ha1, ha2 = md5(f"{USER}:{REALM}:{PASSWORD}"), md5(f"GET:{self.path}")
            if parts.get("qop"):
                expected = md5(f"{ha1}:{NONCE}:{parts.get('nc')}:{parts.get('cnonce')}:auth:{ha2}")
            else:
                expected = md5(f"{ha1}:{NONCE}:{ha2}")
            good = parts.get("response") == expected and parts.get("username") == USER
        if not good:
            challenge = f'Digest realm="{REALM}", nonce="{NONCE}", algorithm=MD5, qop="auth"' if digest else f'Basic realm="{REALM}"'
            self.send(b"challenge body must be discarded", 401, {"WWW-Authenticate": challenge})
        return good
    def do_GET(self):
        try:
            if self.path == "/stall":
                time.sleep(10)
                return
            if self.path == "/redirect.jpg":
                self.send(b"", 302, {"Location": "http://other.invalid/leak"})
                return
            if self.path.startswith("/basic") and not self.authorised(False): return
            if self.path.startswith("/digest") and not self.authorised(True): return
            if self.path.startswith("/image") and not self.authorised(True): return
            if self.path == "/oversized.jpg":
                self.send(JPEG + b"x" * 65536)
            elif self.path == "/truncated.jpg":
                self.send_response(200)
                self.send_header("Content-Length", str(len(JPEG)+100))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(JPEG)
                self.close_connection = True
            elif self.path == "/chunked.jpg":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                for i in range(0,len(JPEG),17):
                    part=JPEG[i:i+17]
                    self.wfile.write(f"{len(part):x}\r\n".encode()+part+b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send(JPEG, headers={"Content-Type": "image/jpeg"})
        except (BrokenPipeError, ConnectionResetError):
            pass
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        xml = ET.fromstring(raw)
        try:
            nonce = base64.b64decode(field(xml,"Nonce"))
            created = field(xml,"Created")
            expected = base64.b64encode(hashlib.sha1(nonce+created.encode()+PASSWORD.encode()).digest()).decode()
            assert field(xml,"Username") == USER and field(xml,"Password") == expected
            self.server.wsse += 1
        except (StopIteration, AssertionError):
            self.send(b"NotAuthorized",403)
            return
        if "GetProfiles" in raw.decode():
            data = '<m:GetProfilesResponse xmlns:m="http://www.onvif.org/ver10/media/wsdl"><m:Profiles token="actual-profile"/></m:GetProfilesResponse>'
        elif "GetSnapshotUri" in raw.decode():
            if field(xml,"ProfileToken") != "actual-profile":
                self.send(b"bad profile",400)
                return
            data = '<m:GetSnapshotUriResponse xmlns:m="http://www.onvif.org/ver10/media/wsdl"><m:MediaUri><m:Uri>/image.jpg?test=1&amp;key=2</m:Uri></m:MediaUri></m:GetSnapshotUriResponse>'
        else:
            self.send(b"not found",404)
            return
        self.send(('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'+data+'</s:Body></s:Envelope>').encode())

class RtspHandler(__import__('socketserver').StreamRequestHandler):
    def handle(self):
        try:
            while True:
                first = self.rfile.readline().decode().strip()
                if not first: return
                method, uri, _ = first.split()
                headers = {}
                while True:
                    line = self.rfile.readline().decode().strip()
                    if not line: break
                    k, v = line.split(":", 1)
                    headers[k.lower()] = v.strip()
                cseq = headers['cseq']
                authorization = headers.get('authorization', '')
                if not authorization:
                    self.wfile.write((f'RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n'
                        'WWW-Authenticate: Digest realm="camera", nonce="test-nonce", qop="auth"\r\n\r\n').encode())
                    continue
                import re
                params = dict((k, v or w) for k,v,w in re.findall(r'(\w+)=(?:"([^"]*)"|([^, ]+))', authorization))
                a1 = hashlib.md5(f'{USER}:camera:{PASSWORD}'.encode()).hexdigest()
                a2 = hashlib.md5(f'{method}:{uri}'.encode()).hexdigest()
                expected = hashlib.md5(f'{a1}:test-nonce:{params["nc"]}:{params["cnonce"]}:auth:{a2}'.encode()).hexdigest()
                assert params['response'] == expected
                extra, body = '', b''
                if method == 'DESCRIBE':
                    body = b'v=0\r\nm=video 0 RTP/AVP 26\r\na=control:track1\r\n'
                elif method == 'SETUP':
                    extra = 'Session: test-session;timeout=30\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n'
                elif method != 'PLAY': return
                self.wfile.write((f'RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{extra}Content-Length: {len(body)}\r\n\r\n').encode()+body)
                if method == 'PLAY':
                    # Synthetic entropy exercises framing and reconstruction; the real
                    # camera image is independently decoded outside this fixture.
                    rtp = bytes([128,154,0,1,0,0,0,1,0,0,0,2,0,0,0,0,0,90,80,45])+b'fixture-entropy'
                    self.wfile.write(b'$\x00'+len(rtp).to_bytes(2,'big')+rtp)
                    return
        except (BrokenPipeError, ConnectionResetError):
            pass

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    wsse = 0

def main():
    build = ROOT / "firmware/build-camera-capture"
    log = build / "integration.log"
    with contextlib.ExitStack() as stack:
        import socketserver
        rtsp = stack.enter_context(socketserver.ThreadingTCPServer(("0.0.0.0",18554), RtspHandler))
        threading.Thread(target=rtsp.serve_forever, daemon=True).start()
        stack.callback(rtsp.shutdown)
        server = stack.enter_context(Server(("0.0.0.0",18081), Handler))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with log.open("wb") as output:
                process = subprocess.Popen(["esp-emu","--chip","esp32s3","--firmware",str(build/"merged-binary.bin"),
                    "--net","user","--psram-size","8M","--wifi-ssid","test","--wifi-password","test-password",
                    "--timeout","180s","--exit-on","CAMERA_CAPTURE_INTEGRATION_PASS"],stdout=output,stderr=subprocess.STDOUT)
                try:
                    end=time.monotonic()+200
                    while process.poll() is None:
                        text=log.read_text(errors="replace")
                        if any(m in text for m in ("assert failed:","Guru Meditation","abort() was called")) or time.monotonic()>end:
                            process.terminate()
                            break
                        time.sleep(.25)
                    code=process.wait(timeout=10)
                finally:
                    if process.poll() is None: process.kill(); process.wait()
        finally:
            server.shutdown()
    text=log.read_text(errors="replace")
    for line in text.splitlines():
        if any(m in line for m in ("CAMERA_","assert failed", "Guru Meditation")): print(line)
    assert code == 0 and "CAMERA_CAPTURE_INTEGRATION_PASS" in text, str(log)
    assert server.wsse >= 3

if __name__ == "__main__": main()
