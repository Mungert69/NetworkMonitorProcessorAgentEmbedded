"""Local OpenSSL 3.5+ interoperability fixtures; no broker/device credentials."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import threading


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=30)


def main():
    probe = pathlib.Path(sys.argv[1]).resolve()
    cases = 0
    with tempfile.TemporaryDirectory(prefix="nm-quantum-fixtures-") as temp:
        directory = pathlib.Path(temp)

        def certificate(name, algorithm, days=1, san="DNS:localhost"):
            key, cert = directory / (name + ".key"), directory / (name + ".pem")
            command("openssl", "req", "-x509", "-newkey", algorithm, "-noenc",
                    "-keyout", str(key), "-out", str(cert), "-days", str(days),
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=" + san)
            return key, cert

        classical = certificate("classical", "rsa:2048")
        unrelated = certificate("unrelated", "rsa:2048")
        allocation_result = command(str(probe.with_name("quantum-allocation-checks")), str(classical[1]))
        print(allocation_result.stdout.decode(), flush=True)

        def check(pair, group, mode, expected, trust=None, hostname="localhost", concurrent=False,
                  trusted=None):
            nonlocal cases
            key, cert = pair[:2]
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            log = directory / "server.log"
            with log.open("wb") as output:
                chain_args = ["-cert_chain", str(pair[2])] if len(pair) == 3 else []
                server = subprocess.Popen(["openssl", "s_server", "-accept", str(port),
                    "-cert", str(cert), "-key", str(key), "-tls1_3", "-groups", group,
                    "-quiet", *chain_args], stdout=output, stderr=output)
                try:
                    for _ in range(100):
                        if server.poll() is not None:
                            raise RuntimeError(log.read_text())
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.02)
                    args = ([str(probe.with_name("quantum-provider-checks")), mode,
                        hostname, str(port), str(trust or cert), "8", "4"] if concurrent else
                        [str(probe), mode, hostname, str(port), str(trust or cert), "127.0.0.1"])
                    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    if result.returncode != expected:
                        raise AssertionError(f"{mode} {group}: expected {expected}, got "
                            f"{result.returncode}\n{result.stdout}\n{result.stderr}\n{log.read_text()}")
                    if expected in (0, 1) and not concurrent:
                        if f"group={group} " not in result.stdout:
                            raise AssertionError(f"Wrong negotiated group: {result.stdout}")
                    if trusted is not None:
                        noted_untrusted = "Certificate trust: not trusted" in result.stdout
                        if noted_untrusted == trusted:
                            raise AssertionError(f"Wrong trust diagnostic: {result.stdout}")
                    cases += 1
                    print(f"PASS {mode} group={group} expected={expected}\n{result.stdout}", flush=True)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()

        for group in ("MLKEM512", "MLKEM768", "MLKEM1024", "X25519MLKEM768",
                      "SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
            check(classical, group, "quantum", 0)
        check(classical, "X25519", "quantum", 2)  # no shared PQ group
        check(classical, "X25519MLKEM768", "quantumcert", 1)
        check(classical, "X25519", "quantumcert", 1, trusted=True)
        check(classical, "X25519", "quantumcert", 1, unrelated[1], trusted=False)
        check(classical, "X25519", "quantumcert", 1, hostname="wrong.example")
        check(classical, "X25519MLKEM768", "quantum", 2, unrelated[1])
        check(classical, "X25519MLKEM768", "quantum", 2, hostname="wrong.example")
        check(classical, "X25519MLKEM768", "quantum", 2, hostname="127.0.0.1")
        ip_cert = certificate("ip-san", "rsa:2048", san="IP:127.0.0.1,IP:::1")
        check(ip_cert, "X25519MLKEM768", "quantum", 0, hostname="127.0.0.1")
        check(ip_cert, "X25519MLKEM768", "quantum", 0, hostname="::1")
        check(ip_cert, "X25519MLKEM768", "quantum", 2, hostname="127.0.0.2")
        check(classical, "X25519MLKEM768", "quantum", 0, concurrent=True)
        for algorithm in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
            pair = certificate(algorithm, algorithm)
            check(pair, "X25519MLKEM768", "quantumcert", 0)
            check(pair, "X25519", "quantumcert", 0)
            check(pair, "X25519", "quantumcert", 0, unrelated[1], hostname="wrong.example",
                  trusted=False)
            check(pair, "X25519MLKEM768", "quantumcert", 0, concurrent=True)
        def issued(name, algorithm, signer, ca=False, days=1, sha3=False):
            key = directory / f"{name}.key"
            cert = directory / f"{name}.pem"
            csr = directory / f"{name}.csr"
            extensions = directory / f"{name}.ext"
            extensions.write_text("basicConstraints=critical,CA:" + ("TRUE" if ca else "FALSE") +
                "\nkeyUsage=critical," + ("keyCertSign,cRLSign" if ca else "digitalSignature") +
                "\nsubjectAltName=DNS:localhost\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
            command("openssl", "req", "-new", "-newkey", algorithm, "-noenc", "-keyout", str(key),
                "-out", str(csr), "-subj", "/CN=localhost")
            command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(signer[1]),
                "-CAkey", str(signer[0]), "-set_serial", "101",
                *(["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"]
                  if days < 0 else ["-days", str(days)]),
                "-extfile", str(extensions), "-out", str(cert), *(["-sha3-256"] if sha3 else []))
            return key, cert
        intermediate = issued("intermediate", "rsa:2048", classical, ca=True)
        leaf = issued("leaf", "rsa:2048", intermediate)
        check((*leaf, intermediate[1]), "X25519MLKEM768", "quantum", 0, classical[1])
        check((*leaf, intermediate[1]), "X25519MLKEM768", "quantum", 2, unrelated[1])
        check((*leaf, intermediate[1]), "X25519MLKEM768", "quantumcert", 1, classical[1],
              trusted=True)
        check((*leaf, intermediate[1]), "X25519MLKEM768", "quantumcert", 1, unrelated[1],
              trusted=False)
        # OR parity: PQ public key with classical signature, then classical key
        # with PQ signature. Neither should require both fields to be PQ.
        pq_key_leaf = issued("pq-key-leaf", "ML-DSA-65", intermediate)
        check((*pq_key_leaf, intermediate[1]), "X25519MLKEM768", "quantumcert", 0, classical[1])
        pq_signer = certificate("pq-signer", "ML-DSA-65")
        check(pq_signer, "X25519MLKEM768", "policy", 0, unrelated[1], concurrent=True)
        check((*pq_key_leaf, intermediate[1]), "X25519MLKEM768", "policy", 0, unrelated[1],
              concurrent=True)
        classical_key_leaf = issued("pq-signature-leaf", "rsa:2048", pq_signer)
        check(classical_key_leaf, "X25519", "quantumcert", 0, pq_signer[1])
        expired_leaf = issued("expired", "rsa:2048", classical, days=-1)
        check(expired_leaf, "X25519MLKEM768", "quantumcert", 1, classical[1], trusted=False)
        future_leaf = certificate("generalized-date", "ML-DSA-65", days=10000)
        check(future_leaf, "X25519MLKEM768", "quantumcert", 0)
        sha3_leaf = issued("classical-sha3", "rsa:2048", classical, sha3=True)
        check(sha3_leaf, "X25519MLKEM768", "quantumcert", 1, classical[1])
        # Real peer that accepts TCP but never answers TLS: shared budget expires.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            peers = []
            def accept_stalled():
                for _ in range(8):
                    peer, _ = listener.accept()
                    peers.append(peer)
            thread = threading.Thread(target=accept_stalled)
            thread.start()
            try:
                result = subprocess.run([str(probe.with_name("quantum-provider-checks")),
                    "timeout", "localhost", str(listener.getsockname()[1]), str(classical[1]),
                    "8", "1"], capture_output=True, text=True, timeout=10)
                if result.returncode:
                    raise AssertionError(result.stdout + result.stderr)
                thread.join(timeout=2)
                if thread.is_alive(): raise AssertionError("Stalled peer accept did not finish")
                print(result.stdout, flush=True)
                cases += 1
            finally:
                for peer in peers: peer.close()
        print(f"PASS {cases} wolfSSL/OpenSSL interoperability cases")


if __name__ == "__main__":
    main()
