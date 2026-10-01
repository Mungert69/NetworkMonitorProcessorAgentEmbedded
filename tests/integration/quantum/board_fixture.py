"""Serve disposable TLS fixtures for the attached board; secrets stay in runtime.

Usage: python3 .../board_fixture.py --connect-host LAN_IP --ssid SSID
    --password-file /private/wifi_password.txt --output-dir /private/quantum/fixtures
Generated firmware contains test Wi-Fi credentials. Never publish it as OTA.
"""
import argparse
import json
import os
import pathlib
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connect-host", required=True)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--password-file", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = pathlib.Path(__file__).resolve().parents[3]
    directory = args.output_dir.resolve()
    if directory == root or root in directory.parents:
        raise ValueError("Private fixture output must be outside the repository")
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    password = args.password_file.read_text().rstrip("\r\n")
    if not 8 <= len(password.encode()) <= 63 or not 1 <= len(args.ssid.encode()) <= 32:
        raise ValueError("Invalid Wi-Fi credentials")
    servers = []
    logs = []
    try:
        pairs = {}
        for algorithm in ("rsa:2048", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
            name = algorithm.replace(":", "-")
            key, cert = directory / (name + ".key"), directory / (name + ".pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", algorithm, "-noenc",
                "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj",
                "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                check=True, capture_output=True, timeout=30)
            pairs[algorithm] = key, cert
        # Public, disposable trust anchors; not production trust.
        (directory / "ca.pem").write_bytes(b"".join(cert.read_bytes() for _, cert in pairs.values()))
        cases = [("rsa:2048", group, "quantum", 0) for group in
            ("MLKEM512", "MLKEM768", "MLKEM1024", "X25519MLKEM768",
             "SecP256r1MLKEM768", "SecP384r1MLKEM1024")]
        cases += [("rsa:2048", "X25519", "quantum", 2),
                  ("rsa:2048", "X25519MLKEM768", "quantumcert", 1),
                  ("rsa:2048", "X25519", "quantumcert", 1)]
        cases += [(algorithm, group, "quantumcert", 0)
            for algorithm in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
            for group in ("X25519MLKEM768", "X25519")]
        header = ["/* PRIVATE GENERATED TEST CONFIG: never distribute this build. */",
                  "#define BOARD_CONNECT_HOST " + json.dumps(args.connect_host),
                  "#define BOARD_WIFI_SSID " + json.dumps(args.ssid),
                  "#define BOARD_WIFI_PASSWORD " + json.dumps(password),
                  "static const struct { const char *mode, *port; int expected; } board_cases[] = {"]
        for index, (algorithm, group, mode, expected) in enumerate(cases):
            port = 19443 + index
            key, cert = pairs[algorithm]
            log = (directory / f"server-{index}.log").open("wb")
            logs.append(log)
            servers.append(subprocess.Popen(["openssl", "s_server", "-accept", str(port),
                "-cert", str(cert), "-key", str(key), "-tls1_3", "-groups", group,
                "-quiet"], stdout=log, stderr=log))
            header.append(f'    {{"{mode}", "{port}", {expected}}},')
        header.append("};")
        (directory / "board_config.h").write_text("\n".join(header) + "\n")
        time.sleep(0.5)
        if any(server.poll() is not None for server in servers):
            raise RuntimeError("Fixture server failed; inspect the private output directory logs")
        print(f"QUANTUM_FIXTURES_READY cases={len(cases)} ports=19443-{19443+len(cases)-1}", flush=True)
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        while all(server.poll() is None for server in servers):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.terminate()
        for server in servers:
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
