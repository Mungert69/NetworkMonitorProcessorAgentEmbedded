# Embedded OpenSSL → wolfSSL compatibility report

The registered processor remains `Openssl`. This is a bounded diagnostic adapter,
not the OpenSSL executable, a shell or a binary-compatible OpenSSL library.
Existing command routes, signatures, pagination, correlation and cancellation
are unchanged; no backend/database changes are required.

The reference is the sibling
`NetworkMonitorLib/Objects/Connection/CommandProcessors/OpensslCmdProcessor.cs`.
.NET launches OpenSSL with argv and **without a shell**. Although its help
mentions pipes, the actual wrapper does not implement shell pipelines.

## Supported commands

| Command/switch | Behaviour |
|---|---|
| Optional leading `openssl` | Accepted, never executed as a shell command. |
| `help`, `-help`, `s_client -help` | Embedded usage and limitations. |
| `version [-a]` | Identifies the adapter/wolfSSL provider, not a fictitious OpenSSL version. `-a` does not reproduce desktop build metadata. |
| `list -tls-groups [-tls1_2\|-tls1_3]` | Lists the exposed compiled groups. Either option order is accepted; TLS 1.2 excludes PQ groups. |
| `ciphers [-s] [-tls1_2\|-tls1_3]` | Lists the adapter's exact supported suite names, not OpenSSL cipher expressions. |
| `s_client -connect host[:port]` | DNS, IPv4 or bracketed IPv6; optional port defaults to OpenSSL's **4433**, not HTTPS 443. Explicit target required: no implicit localhost connection. |
| `s_client host[:port]` | Equivalent positional target. |
| `-host host -port port` | Separate destination/port, in either order. Mixing this port setting with `-connect` is rejected. |
| `-servername name` | SNI independent of TCP/DNS destination; explicit numeric SNI is supported. |
| `-noservername` | Actually omits SNI; mutually exclusive with `-servername`. |
| `-tls1_3`, `-tls1_2` | TLS 1.3 default, or explicit TLS 1.2 diagnostic connection. |
| `-no_tls1_2`, `-no_tls1_3` | Select TLS 1.3 or TLS 1.2 respectively; conflicting selections fail. |
| `-min_protocol TLSv1.3`, `-max_protocol TLSv1.3` | Fixed TLS 1.3 profile. Other ranges rejected; use `-tls1_2` for TLS 1.2. |
| `-groups`, `-curves` | Ordered colon-separated list, up to 16 entries/511 bytes. Unsupported/draft names reject the entire list. |
| `-ciphersuites` | Exact supported TLS 1.3 AES-GCM names; unknown entries reject the entire list. |
| `-cipher` | Exact supported TLS 1.2 ECDHE/AES-GCM names; requires explicit TLS 1.2. No `ALL`, exclusions or security-level expressions. |
| `-alpn h2,http/1.1` | Actual ALPN offer/selection. Reports selected protocol or `none`; server rejection fails the handshake. No HTTP request follows. |
| `-4`, `-6` | Restricts connection attempts to that address family; the network must support it. |
| `-verify_return_error` | Requires CA/date **and hostname/IP** verification. Defaults to `-servername` identity if supplied, otherwise destination. Stronger than bare OpenSSL's chain-only flag. |
| `-verify_hostname`, `-verify_ip` | Explicit identity independent of SNI; also requires trusted chain. Invalid IP rejected. |
| `-showcerts` | Actual presented PEM leaf/chain plus diagnostics, including with strict verification. Not a reconstructed verified chain. |
| `-brief` | Suppresses extended certificate summary, retains protocol/cipher/group/ALPN/trust. Explicit `-showcerts` still exports PEM. |
| `-no-interactive`, `-nocommands` | Accepted: there is already no interactive stdin session. |

All other options/subcommands fail explicitly. CLI switches are case-sensitive;
group names additionally accept case/punctuation normalization and aliases below.

### Cryptographic choices

TLS 1.3 suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`.

TLS 1.2 suites (also the restricted default list):

- `ECDHE-RSA-AES128-GCM-SHA256`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-AES128-GCM-SHA256`
- `ECDHE-ECDSA-AES256-GCM-SHA384`

wolfSSL's TLS 1.2 IANA result names are translated to those OpenSSL names.

Groups:

- `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`
- `MLKEM512`, `MLKEM768`, `MLKEM1024`
- `X25519`, `secp256r1`, `secp384r1`, `secp521r1`

Aliases: `prime256v1`/`P-256`, `P-384`, `P-521`. PQ groups are TLS 1.3-only;
requesting them with TLS 1.2 fails. Default TLS 1.3 offers the established six
PQ groups plus X25519/secp256r1. Explicit P-384/P-521 support does not change
normal quantum endpoint default group order. ML-DSA-44/65/87 certificate
classification remains available, not all OpenSSL/OQS algorithms.

## Unsupported functionality

These are deliberate scope/build boundaries, not claims that wolfSSL could
never provide them:

- `x509`, `verify`, `req`, `genpkey`, `dgst`, `enc`, `pkcs12`, `s_server`, `speed`
  and other OpenSSL subcommands. Some could be implemented later independently;
  this command processor currently focuses on remote TLS diagnostics.
- CA/certificate/key files, file output, stdin, pipes, redirection, provider
  loading and filesystem trust directories.
- Automatic TLS 1.3→1.2 fallback; select TLS 1.2 explicitly.
- SSLv2/3, TLS 1.0/1.1, DTLS, QUIC.
- CBC/RC4/3DES/ChaCha20 suites, arbitrary cipher expressions, signature-algorithm
  overrides, draft Kyber/Frodo/experimental groups and SLH-DSA.
- Client keys/certificates (mTLS), PSK/SRP, STARTTLS and HTTP CONNECT proxies.
- OCSP/CRL retrieval, revocation auditing, DANE, certificate transparency,
  arbitrary verification times, custom verification depths/policies.
- Session import/export/resumption, reconnect experiments, early data, key
  logging, packet traces, application-data transfer and benchmarks.
- Scoped IPv6 addresses containing `%interface`.
- Byte-identical OpenSSL stdout/stderr, desktop metadata and exit-code semantics.
  .NET's current wrapper marks process completion successful without checking
  its exit code; the embedded adapter marks diagnostic failures unsuccessful.

## Trust, resources and ownership

Default `s_client` is observational: an untrusted/expired chain can complete
and be described, like the existing .NET certificate diagnostics. CA/date
errors are noted; hostname identity is not certified in observational mode.
Verification switches require authenticated TLS. **No unverified fallback**
follows verification failure. This exception is session-local, not used for
MQTT, HTTP, enrollment or OTA. Existing public Mozilla roots are used; trust
messages are not a revocation audit.

Quantum endpoints still select TLS 1.3-specific methods and their existing
verification/group policy. TLS 1.2 uses private diagnostic contexts. Command
options never mutate the shared TLS 1.3 context. Sessions/sockets and their
SNI/ALPN/cipher policy remain per-call, safe for concurrent endpoint probes.

One monotonic budget covers initialization, production bounded DNS, TCP/TLS
and cancellation checks. Crypto is not forcibly preempted. Output/PEM uses
owned PSRAM, with cleanup of partial allocation/session/context/socket state.
No monitoring/config/NVS writes are added.

Input ≤4096 bytes, token ≤511 bytes, hostname ≤253 bytes. Chain export has a
24 KiB conservative allocation bound, ≤16 certificates and ≤16 KiB DER each.
Complete output ≤32 KiB/256 lines; non-PEM reports reserve 8 KiB. Overflow fails,
never a successful truncated chain. Normal .NET-compatible response pagination
still applies: request `LineLimit=-2`/all output or fetch every page for a long
PEM chain. Pagination is distinct from the export bound.

## Layers and API audit

| Layer | Responsibility |
|---|---|
| `openssl_arguments.c` | Bounded argv parsing/conflicts, typed request; no networking. |
| `openssl_cmd_processor.c` | Command policy/formatting/owned report; no provider handles. |
| `openssl_runner.*` | OpenSSL names, strict supported lists, typed inspection requests. |
| `tls_inspection.*` | Shared provider, bounded DNS, total deadline, optional diagnostic controls. |
| `quantum_tls.*` | wolfSSL sessions/contexts, TCP/TLS, certificate inspection and owned PEM. |

The pinned `third_party/wolfssl/wolfssl/ssl.h` and implementations were checked,
not merely functions with similarly spelled names:

| Intent | wolfSSL API |
|---|---|
| Protocol selection | `wolfTLSv1_2_client_method`, `wolfTLSv1_3_client_method` |
| Suite restriction | Per-session `wolfSSL_set_cipher_list`, after strict list validation |
| Groups | `wolfSSL_set_groups`, compiled IDs |
| SNI | `wolfSSL_UseSNI`, actual omission when disabled |
| ALPN | `wolfSSL_UseALPN`, `wolfSSL_ALPN_GetProtocol` |
| Identity | `wolfSSL_check_domain_name`, `wolfSSL_check_ip_address` |
| Observation | Session-local verification callback and private context |
| PEM | `wolfSSL_get_peer_chain`, count/length getters, `wolfSSL_get_chain_cert_pem` |
| Metadata | Existing X509 getters/typed summary |

Our settings enable `HAVE_ALPN` and `WOLFSSL_DER_TO_PEM`. The latter uses the
proper conversion implementation; the pinned fallback omits the newline after
the PEM header. Tests require OpenSSL to parse the returned PEM, not just find
a BEGIN marker. No vendor source or stripped Brotli profile was patched.

References: [OpenSSL s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/),
[wolfSSL setup APIs](https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html).
Checked-out source is authoritative for the compiled API.

## Reproduce validation

```sh
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-tests -j4
ctest --test-dir build-tests --output-on-failure
cmake -S tests/integration/quantum -B build-quantum-host \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -ffunction-sections -fdata-sections'
cmake --build build-quantum-host -j4
python3 tests/integration/quantum/test_openssl_adapter.py build-quantum-host/openssl-adapter-probe
python3 tests/integration/quantum/test_probe.py build-quantum-host/quantum-probe
./tools/build-firmware.sh
```

Native tests run production parser/policy/runner, including rejection, conflict,
oversize, cancellation and option forwarding. Production private-export tests
use API stand-ins to check count/size bounds, allocation/second-certificate
failures, invalid returned lengths and cleanup. Inspection tests cover actual
forwarding and the original shared deadline.

Real interoperability runs the production CLI parser/runner/formatter and
wolfSSL provider against disposable OpenSSL/Python peers: both protocols, six
suites, ALPN, actual SNI omission/rejection, identity/CA failures, observation,
curves, RSA/ML-DSA PEM, a two-certificate chain and stalled-peer deadlines. Six
suite/protocol cases also run equivalent OpenSSL client arguments as the .NET
wrapper would. Fixture keys live only in external temporary directories.

This harness replaces ESP resolution/provider bootstrapping with host libc DNS
and disposable trust. It is **not** a firmware emulator or board test. IPv6
transport is explicitly skipped without host `::1`; parsing/family filtering
still run. The firmware uses its unchanged bounded resolver. Host passes do not
prove Wi-Fi, MQTT command delivery, memory under load or OTA of this image.

### Recorded validation (2026-10-02)

- Native ASan/UBSan suite: 32/32 passed.
- Real OpenSSL adapter interoperability: 42/42 passed; IPv6 transport separately
  skipped because the test host has no `::1` address.
- Existing quantum interoperability regression suite: 54/54 passed.
- Production ESP-IDF firmware build passed. Signed application size:
  2,232,320 bytes, an increase of 65,536 bytes over the preceding build.

The build retains version 0.3.0. No backend or .NET processor changes were
required. It has not been staged as an OTA release.

The adapter was also flashed to the test ESP32-S3 and exercised through the
frontend and MQTT: catalog/version, TLS 1.2/1.3, hybrid ML-KEM, standalone
ML-KEM, ALPN, IP verification, ML-DSA certificate inspection, paginated PEM
output, and strict rejection of an untrusted certificate. Serial observation
showed continued monitoring, snapshot saves and backend acknowledgements,
with no disconnects, allocation failures or dropped commands. Post-test PSRAM
returned to approximately 7.14 MiB free; the recorded low-water mark was
approximately 6.39 MiB. This short run is not a long-duration leak test.

The subsequent duplicate-trust-line formatting fix has regression coverage for
full, brief and failed reports. The final native and TLS suites were rerun
successfully before the updated production build was deployed.
