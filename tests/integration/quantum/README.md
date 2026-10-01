# wolfSSL quantum-provider experiment

Branch: `feature/wolfssl-quantum-endpoints`. Both endpoints are now integrated
into the processor on this experimental branch, not a published release.
Production MQTT, HTTP, command verification, Brotli, OTA, partitions and release
version are unchanged. New registrations advertise the two added endpoints;
existing registered processors need re-registration to refresh capabilities.
Do not distribute the diagnostic firmware: its generated hardware
configuration contains private Wi-Fi credentials.

The pinned wolfSSL submodule is v5.9.2-stable, commit
`ac01707f552c611fbd135cc723b2682b3e7f80f2`. It is GPLv3/commercial licensed;
the project's GPL-3.0-only license does not relicense wolfSSL or waive its
copyright notices. Follow the [firmware release licensing checklist](../../../docs/licensing.md)
before distributing a combined image.

## Reference behaviour and scope

The references are `NetworkMonitorLib/Objects/Connection/QuantumConnect.cs`,
`QuantumCertConnect.cs`, `QuantumCertificateProbe.cs` and
`QuantumCertificateAnalyzer.cs` in the sibling .NET checkout.

- `quantum`: success reports `Using quantum safe handshake` and the negotiated
  group. The experiment offers ML-KEM-512/768/1024, X25519MLKEM768,
  SecP256r1MLKEM768 and SecP384r1MLKEM1024. No classical fallback qualifies.
- `quantumcert`: success reports `Quantum-safe certificate detected` if the
  leaf signature **or** public-key OID is ML-DSA-44/65/87. It permits classical
  key exchange, since PQ certificates and PQ key exchange are independent.
  Classical certificates report `Certificate not quantum-safe`. Like .NET's
  OpenSSL `-showcerts` inspection, classification does not require CA trust,
  valid dates or a matching hostname. The per-session observational mode is
  restricted to this monitor; it is never used for MQTT, enrollment, HTTP or OTA.
  Results report `SigAlg` and `KeyAlg`, not the key-exchange group as though it
  were a certificate algorithm. The full summary follows .NET's field labels.
  Chain/date verification failures append `Certificate trust: not trusted` to
  the full MonitorPingInfo summary, without changing the PQ classification.
  This is a trust-store observation, not a revocation or hostname audit.
- Certificate classification compares exact wolfSSL OID constants. Do not copy
  the .NET classifier's broad NIST prefix: that namespace also contains
  classical SHA-3 signature algorithms.
- Unlike .NET's ServerHello-only `quantum` check, the `quantum` endpoint requires a
  completed TLS 1.3 handshake with certificate and hostname verification. There
  is no unverified fallback for `quantum`. This also rejects HRR-only exchanges.
- This is not all OpenSSL/OQS coverage. Legacy Kyber/Frodo/etc., experimental
  groups, SLH-DSA and other certificate algorithms are not enabled here.
- The CLI has a 15-second nonblocking connect/TLS deadline. Host libc DNS is
  not cancellable and is not deadline-bounded. Hardware fixtures connect to a
  numeric LAN address while retaining `localhost` for SNI/name verification.
  The production adapter uses the existing bounded ESP resolver and configured
  monitor timeout, including initialization/DNS/TCP/TLS in its budget.
- `quantum_tls.c` is shared by the CLI, physical diagnostic and complete firmware.
  Library initialization is process-lifetime; no per-probe global cleanup.
  Quantum workers share a trust context initialized under a mutex. Certificate
  probes create a private context from the provider's retained public roots,
  so accepting a private intermediate cannot contaminate another probe's trust
  cache or make subsequent observations appear trusted. Each probe owns its
  SSL session/socket. Allocation/socket exhaustion is local
  and inconclusive, not packet loss. Large allocations use explicit PSRAM.
- Certificate diagnostics include signature/public-key names and wolfSSL codes,
  expiry, subject, issuer and transmitted chain length. Subject formatting is
  wolfSSL's distinguished-name form rather than .NET's DNS-friendly label.
- Alternate-chain verification supports servers sending cross-signed roots;
  certificate/hostname verification remains mandatory for `quantum`. Roots come from the
  IDF installation's public Mozilla PEM set, not developer machine credentials.
  MQTT/HTTP/OTA retain their separate IDF certificate bundle.
- IP SAN support is explicitly enabled, so numeric hosts are verified against
  their certificate's IP addresses. IPv4/IPv6 positive and mismatch fixtures
  exercise this setting. Negotiated group diagnostics use OpenSSL's standard
  names; a group observed before a certificate failure is diagnostic evidence
  only, never a successful quantum observation. Transport/verification failures
  report `Exception` with the socket or TLS error description, rather than
  claiming the certificate was examined and found classical.
- End-to-end backend delivery and HTTPS OTA of this feature branch still need
  verification. `IsQuantumCapable` remains false (command signature policy).

## Reproduce the native interoperability tests

Requires CMake, a C compiler, Python 3 and OpenSSL 3.5+ with ML-KEM/ML-DSA.
Tests use disposable local certificates, not service credentials.

```sh
git submodule update --init third_party/wolfssl
cmake -S tests/integration/quantum -B build-quantum-host \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DCMAKE_C_FLAGS='-ffunction-sections -fdata-sections'
cmake --build build-quantum-host -j4
python3 tests/integration/quantum/test_probe.py build-quantum-host/quantum-probe
```

Exit codes: 0 = endpoint observation passed; 1 = completed handshake but
classical certificate/group; 2 = setup, negotiation, timeout or verification
failure. These CLI codes are not the production inconclusive/down enum.

## Reproduce the physical-board trial

Use only a disposable 16 MiB/8 MiB ESP32-S3. Follow the repository's local
ESP-IDF 6.1 installation guide first. Stop other serial monitors. No broker,
OAuth, private signing key or backend is needed for these direct TLS tests.

Start the fixture servers in one terminal, replacing the LAN address and
credential path. The password is read from the file and is not printed:

```sh
python3 tests/integration/quantum/board_fixture.py \
  --connect-host YOUR_COMPUTER_LAN_IP --ssid YOUR_SSID \
  --password-file /private/wifi_password.txt \
  --output-dir /private/quantum/fixtures
```

Keep that process running. Permit TCP 19443–19457 from the board's LAN only
if a firewall blocks them. Remove any temporary firewall rule after testing.
Generated keys, trust anchors, configuration and logs stay in
the external private fixture directory. Never use the checkout as the output
directory. Configuration changes require rebuilding this test image.

In a second terminal:

```sh
cd tests/integration/quantum/idf
../../../../tools/idf-local.sh idf.py -B /private/quantum/build \
  -D NM_QUANTUM_TRIAL_DIR=/private/quantum/fixtures \
  -D SDKCONFIG=/private/quantum/sdkconfig build
# Destructive: only on the disposable board; erases credentials and state.
../../../../tools/idf-local.sh python -m esptool \
  --chip esp32s3 --port YOUR_PORT erase-flash
../../../../tools/idf-local.sh idf.py -B /private/quantum/build -p YOUR_PORT flash
cd ../../../..
./tools/idf-local.sh python tests/integration/quantum/capture_board.py \
  --port YOUR_PORT --output /private/quantum/board.log
```

The capture command resets the board and requires `QUANTUM_BOARD_RESULT
passed=15 total=15`; it closes the serial port after success/failure/timeout.
Flashing uses the generated DIO image header, QIO second-stage setup, 80 MHz
flash and 40 MHz octal PSRAM. It never burns eFuses. The diagnostic bootloader
does not enforce production app signatures; restore the signed production
bootloader/app before returning the board to normal processor use.

wolfSSL application allocations use explicit PSRAM without internal fallback.
Its small-stack mode moves large temporary crypto buffers to that allocator.
The test worker has a 32 KiB PSRAM stack on CPU1 at idle priority; SDK/RTOS
allocations keep their normal placement. Session caching is disabled: retaining
PQ chains in the global session cache otherwise reserved 2,440,372 bytes of
internal BSS in the first build. Upstream's Xtensa advisory is retained as a
warning; the safer small Curve25519 selection is not bypassed.

## Recorded evidence (2026-10-01)

### Certificate-observation parity and trust diagnostics

- 42 real OpenSSL/wolfSSL cases pass under ASan/UBSan, including all six groups,
  matching/mismatched IPv4/IPv6 SANs, trusted/private/expired certificate
  classification, private-intermediate isolation and concurrent sessions.
- Allocation failures cover all 22 provider, 83 quantum-session setup and 104
  certificate-session setup allocation calls. This does not inject failures at
  every handshake or summary allocation.
- All 26 processor host targets and nine .NET certificate-analyzer tests pass.
- The public `quantum.readyforquantum.com:4433` probe reports `ML-DSA-65` for
  signature and key, with `Certificate trust: not trusted` for its private
  `oqstest CA`. MLKEM768 is its separate negotiated key-exchange group.
- The signed production application remains 1,970,176 bytes. These results
  supersede the earlier certificate-trust requirement described historically
  below; quantum-handshake authentication remains required.

### Production-provider integration

- All 26 processor ASan/UBSan CTest targets pass, including a production adapter
  test for .NET status strings, deadline accounting, default port, DNS failures,
  local-resource classification and transfer/release of certificate diagnostics.
- All 30 native real-TLS interoperability cases pass under ASan/UBSan. They cover eight simultaneous sessions sharing one
  provider, repeated handshakes, stalled peers, wrong hostname/IP SAN, invalid
  roots/chains, expired certificates, GeneralizedTime expiry, classical SHA-3
  rejection as PQ, and signature-only/key-only PQ classification. The allocation
  test fails each of 21 provider and 83 probe-setup allocation calls in turn.
  It does not inject failures at every handshake or certificate-summary allocation.
- The physical board reran the production TLS module: 15/15 cases passed with
  the normal 16 KiB PSRAM worker stack; minimum unused stack 13,284 bytes.
  PSRAM free after every case 8,369,236 bytes; minimum 8,097,552 bytes.
  Internal free 291,171–291,203 bytes, minimum 223,372 bytes.
  These are isolated sequential diagnostics, not the complete agent's budget
  or an eight-worker physical stress pass.
- Complete signed processor build: 1,970,176 bytes (about 1.88 MiB), including
  the additional public roots and wolfSSL. No image was published or OTA-staged.
- Backend delivery and physical concurrency/soak testing remain separate checks.

### Initial standalone feasibility measurement (historical)

- 16/16 native OpenSSL interoperability cases passed, including an untrusted
  certificate rejection; 15/15 physical-board cases passed (same positive and
  classical-negative matrix, without the separate untrusted-root case).
- Standard groups: all three standalone ML-KEM sizes and all three hybrids.
  Certificates: all three ML-DSA sizes, over both hybrid and classical exchange.
- Complete board handshakes took roughly 0.85–3.07 seconds in this fixture run;
  these include Wi-Fi, certificate verification and all handshake work, not
  isolated KEM timings. This does not characterize internet latency.
- PSRAM free after each case: 8,352,852 bytes. Minimum: 8,232,556 bytes
  (120,296-byte transient difference). Internal free after cases approximately
  291,095 bytes; all-time minimum 223,376 bytes includes boot/Wi-Fi setup.
- Worker stack minimum free: 30,004 of 32,768 bytes. No crash or accumulating
  PSRAM loss observed in this short matrix; not a soak/concurrency test.
- Diagnostic app: 942,784 bytes. Linked wolfSSL contribution: 158,973 bytes
  flash code + 14,994 bytes constants + 86 bytes static RAM. This is about
  170 KiB of flash for TLS plus ML-KEM/ML-DSA, not the final processor increase.
  Production roots, adapters, certificate summaries and signed-image padding
  still need measurement. Do not compare the diagnostic app's total size with
  the complete MQTT/BLE processor: they contain different functionality.

Read the `.map` with ESP-IDF 6.1 `esp_idf_size --format json2 --archives` for
the retained component contribution, rather than using archive/download size.
