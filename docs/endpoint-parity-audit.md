# Supported endpoint audit: .NET and ESP32 (2026-10-05)

This audit covers all 11 types advertised by `firmware/main/endpoints.c`, using
current sibling checkouts of NetworkMonitorLib and NetworkMonitorProcessorAgent.
It checks dispatch/configuration, deadlines, success/failure statuses, recorded
samples, BLE reading selection, and the sequential/concurrent path to model and
MQTT publication. It is a source audit plus deterministic contract tests, not a
claim that the two network stacks give identical results for every remote host.
The generated fixture's `SourceHashes` identifies the .NET working-tree sources.

## Supported types

| Type | .NET reference | C implementation | Measurement / timeout extension | Outcome contract and differences |
|---|---|---|---|---|
| `icmp` | `ICMPConnect` | `endpoint_icmp.c` | Reply RTT in ms, scale 1; no extension | `Success` on reply; failed network replies use `Exception`. C tries supported resolved addresses within one total deadline, including DNS; SDK ping error details differ. |
| `dns` | `DNSConnect` | `endpoint_dns.c` | Lookup duration in ms, scale 1; no extension | `Found IP Addresses`; empty/error/timeout use `Exception`. Address ordering and bounded diagnostic length can differ. |
| `rawconnect` | `SocketConnect` | `endpoint_tcp.c` | TCP duration excluding DNS, ms, scale 1; no extension | Default port 443; `Connected`, `Connection timed out.`, `Unable to resolve domain.`, `Exception`. C tries multiple address families and includes DNS in the total budget; .NET uses the first address and an IPv4 socket, with a separate TCP timeout. |
| `http` | `HTTPConnect`, `ConnectFactory`, `AddressFilter` | `endpoint_http.c`, `http_deadline.*` | GET including body, ms, scale 1; no extension | Completed HTTP responses, including 4xx/5xx, are reachable. Enum-name statuses match .NET 10; timeout/request errors retain their categories. URL, TLS, redirects and headers have the differences below. |
| `httphtml` | Same, HTML mode | Same, with content-length diagnostic | HTML GET including body, ms, scale 1; no extension | Same status handling as HTTP; actual content length/text may differ with headers/content negotiation. |
| `https` | Same, certificate-check client | Same, verified TLS | GET including body, ms, scale 1; no extension | Fixed timing/status contract matches. Seven-day expiry policy matches; schemeless routing remains a gap below. |
| `quantum` | `QuantumConnect` | `endpoint_quantum.c`, `tls_inspection.*`, `quantum_tls.*` | Operation duration, ms, scale 1; no extension | `Using quantum safe handshake`, `Could not negotiate quantum safe handshake`, `Timeout`, `Exception`. C requires authenticated TLS 1.3 completion and supports its documented six groups; .NET can accept ServerHello alone and broader configured OQS algorithms. |
| `quantumcert` | `QuantumCertConnect`, `QuantumCertificateProbe` | Same, isolated certificate-observation mode | Operation duration, ms, scale 1; no extension | `Quantum-safe certificate detected`, `Certificate not quantum-safe`, `Timeout`, `Exception`. C classifies ML-DSA signature or public key independently of certificate trust; algorithm coverage and certificate display labels differ. |
| `nmap` | `NmapCmdConnect("-sV")` | `endpoint_nmap.c`, `nmap_runner_embedded.c` | Duration in ms, scale 10; timeout ×10 | `Port/s open`, `Port/s closed`, `Host status unknown`; runner failures use `Exception`. C scans the configured port or 22 common ports with bounded service hints, not full Nmap service/version/discovery parity. TCP refusal still proves host reachability. |
| `blebroadcastlisten` | `BleBroadcastListenConnect`, listen command processor | `endpoint_ble.c`, shared scanner/decoders | Capture duration in ms, scale 10; timeout ×10 | `BLE listen complete`, including zero captures. Raw and selected/decrypted captures plus decode errors are diagnostics. Output is bounded and formatted differently. |
| `blebroadcast` | `BleBroadcastConnect`, targeted command processor and decoder registry | `endpoint_ble.c`, shared scanner/decoders | Explicit readings use the same v2 unit/scale/offset catalogue; timeout ×10 | `BLE v2:<format>:<metric>`; unavailable/missing/out-of-range selections fail with `BLE Metric Error`. No metric preserves legacy implicit solar PV / raw receipt behavior. Sensor samples are separate from elapsed time. |

ICMP, DNS, TCP and the three HTTP modes retain their .NET timing thresholds in
the shared backend catalogue. Quantum operations, Nmap, BLE discovery and BLE
sensor readings have no timing ratings. Unit/scale/offset, descriptions and LLM
guidance are resolved by Data/API from the same built-in .NET definitions used
for .NET processors; there is no second prompt/description table in the firmware.
ESP32 does not support .NET dynamic compiled connects/catalogue publication.

## Changes made by this audit

- Added `endpoint_measurement.h` as the small C counterpart of built-in
  measurement scale and timeout policy. Nmap and BLE listen record
  `floor(elapsed_ms / 10)`. Ordinary durations retain direct ushort conversion,
  without clamping. A successful Nmap/listen operation taking 70009 ms records
  7000 and reconstructs to 70000 ms (less than 10 ms quantization loss).
- Applied BLE targeted/listen ×10 timeout extension in endpoint dispatch.
  Nmap already extended inside its legacy runner, but imposed a 120-second cap.
  The extension now belongs to endpoint dispatch, and the runner receives the
  exact budget: no hidden second multiplication or runner ceiling. Standalone
  command requests still use their independently supplied exact budgets.
- Added `sample` / `has_sample` to the internal `nm_esp_result`, preserving
  actual elapsed time separately. Both state execution paths use
  `nm_esp_result_sample`. Decoder samples bypass duration conversion; failed
  observations still record 65535. Wire fields and stored schemas are unchanged.
- Removed legacy text parsing/clamping for implicit PV power. Typed readings
  now drive it; unavailable data fails instead of becoming a receipt duration.
- Fixed whitespace-only Args falling back to Username, case-insensitive option
  names, quoted equals values and repeated metric rejection. Command options
  take their last value like the .NET command parser; repeated `--metric` fails
  like `BleBroadcastConnect`. Unknown long options and mode-inappropriate
  flags fail instead of silently recording a different measurement.
- Generic AES-GCM/AES-CTR listen now decrypts the selected payload. It previously
  only printed raw advertisements. Authentication errors remain visible beside
  raw data and do not turn discovery into a failed probe.

The effective default base timeout is 59000 ms, inherited by the model from
PingParams. Extended operations receive 590000 ms. Nmap/listen scale 10 covers
655340 ms before the failure marker. Custom timeout settings must fit their
encoding; neither processor introduces automatic sample saturation. Targeted
raw BLE receipt fallback remains an unclassified legacy ushort duration with
scale 1, despite its extended scan deadline; use explicit numeric metrics for
sensor monitoring. This existing mixed fallback is not a physical sensor value.

## Deliberate adaptations and remaining behavior gaps

These differences are visible to users; do not describe the processors as
unconditionally interchangeable.

- **HTTP routing:** the actual .NET processor calls `AddressFilter` before
  `HTTPConnect`. For schemeless `http` / `httphtml`, it adds HTTPS. For `https`,
  it removes a supplied scheme, after which `HTTPConnect` can add HTTP. C
  defaults schemeless `http` / `httphtml` to HTTP and `https` to HTTPS, retaining
  explicit schemes. The latter avoids reproducing .NET's HTTPS downgrade.
  Choose explicit URLs when comparing `http` / `httphtml`; `https` needs a
  coordinated normalization fix in .NET before exact integrated URL parity.
- **Seven-day certificate expiry:** Both HTTPS endpoints reject a leaf certificate
  expiring before midnight seven calendar days ahead as `HttpRequestException`.
  C delegates to the existing ESP-IDF bundle verifier, then adds a leaf-only
  verification failure; trust, signature, hostname and validity checks remain.
  Exactly midnight on the seventh day is accepted. ESP32 uses UTC midnight;
  .NET uses its host's local midnight, so non-UTC hosts can differ at the boundary.
  This applies only to `https`, including its HTTPS redirects; ordinary `http`
  and `httphtml`, quantum endpoints, enrollment, MQTT and OTA are unaffected.
  The adapter uses IDF 6.1's exported `esp_crt_verify_callback` symbol (not in
  the public bundle header); verify firmware linking and the real TLS suite
  when upgrading IDF. Native tests cover the strict boundary and preserved
  verification flags/errors. The integration workload uses trusted 30-day and
  two-day certificates, with hostname and untrusted-certificate rejection.
- **Other HTTP behavior:** C always verifies TLS (including `http` when pointed
  at HTTPS); .NET's general HTTP client accepts invalid certificates. .NET has
  shared cookies, randomized user agents, browser-style Accept headers and its
  default redirect limit; C lacks that shared cookie/header behavior and allows
  five redirects. Responses/content negotiation and duration can differ. C
  rejects credentials/non-ASCII/ambiguous URLs instead of reproducing all Uri
  normalization. These existing platform adaptations are retained.
- **Base timeout policy:** .NET clamps a newly created connector's monitor
  timeout to PingParams.Timeout, but `UpdateNetConnectionInfo` does not apply
  that clamp on later updates. C inherits zero monitor timeout from PingParams,
  uses an execution fallback of 10000 ms for an actual zero, and caps base
  timeout at 600000 ms before extension. Normal inherited 59000-ms settings
  align; arbitrary overlong/zero settings do not have identical handling.
- **BLE subset (updated for continuous capture):** Both implementations use
  shared history and cycle snapshots, average selected physical values, and
  default to a 70s BLE window. The ordinary timeout clamp above no longer applies
  to BLE. C supports long options, bounded tokens/255-byte legacy advertisements,
  passive scanning only, and no standalone BLE command processors. Raw listen
  has no capture cap and does not decrypt. Manual metric scale/offset overrides
  remain .NET-only. Hexadecimal manufacturer IDs are an additional C syntax;
  embedded NUL text renders as `\\0`. Failed live decodes are skipped while
  considering the remaining snapshot, while bad raw overrides fail explicitly.
  See [continuous capture policy](monitoring-parity.md).
- **Embedded resource handling:** DNS/ICMP late operations keep their bounded
  lifetime slot; local allocation/socket/scanner admission failures are
  inconclusive and retried on a later cycle. They do not create host-down pings
  as a general .NET exception could. See monitoring parity for ownership,
  snapshot, scheduler and acknowledgement adaptations.

Unsupported types remain disabled: `httpfull`, `sitehash`, `configintegrity`,
`smtp`, `nmapvuln`, `crawlsite`, `dailycrawl`, `dailyhugkeepalive`, `hugwake`, plus
dynamic extensions. No capability was advertised without its implementation.

## Reproduce and check future changes

Read AGENTS.md, developer-reference.md and monitoring-parity.md first. Compare
current sibling sources, not just this report. The .NET endpoint/factory classes
are under `NetworkMonitorLib/Objects/Connection` and `Objects/Factory`;
monitor initialization, aggregation and publication are under
`NetworkMonitorProcessorAgent/Services`. C dispatch/probes live in
`firmware/main/endpoint*.c`; `state.c` records/publishes results, while
`monitor_model.c` and `monitor_schedule.c` own model/scheduler policy.

```sh
# Requires the sibling .NET library and its locally cached dependencies.
bash tests/dotnet/generate-endpoints.sh --check
# Existing package-free wire/model oracle.
bash tests/dotnet/generate.sh --check
python3 tools/update-ble-metrics.py --check
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-tests -j 6
ctest --test-dir build-tests --output-on-failure
./tools/build-firmware.sh
```

`EndpointParity` references and executes the real full .NET library. Its pinned
fixture covers all 11 built-in metadata/timeout policies, duration casts and
900 HTTP status names, plus real decoder readings/errors and encoded samples
for Victron, Ruuvi and BTHome. It does not execute real .NET network probes.
The fixture records source hashes; a source change must be reviewed before
regenerating with the same script without `--check`. Do not alter expected
samples to conceal C/.NET disagreement. Native `test_endpoint_contracts` consumes
those fixtures through production C policy/decoder/status functions.

`test_endpoint_execution` exercises production dispatch, Nmap exact-budget and
BLE timeout forwarding with platform adapters. `test_ble_endpoint` exercises
production selection, implicit/unavailable readings, parsing, listening,
decryption and sensor/duration separation. `test_state_adapter` checks actual
sequential/concurrent model statistics, failure samples and decoded MQTT
publication. Capability tooling compares every advertised type to the oracle
and checks the BLE numeric snapshot against the sibling library. Existing
native suites provide broader schema, ownership, resource-failure, timing,
scheduling and acknowledgement coverage.

All 33 CTest targets passed with ASan/UBSan during this audit, including tooling.
The original model oracle passed 113 assertions and matched its eight files.
The signed firmware build succeeded and fit the existing 6 MiB slot; existing
ESP-IDF component include-directory warnings remain. No board flash, live
backend/RF comparison, emulator networking or physical stress test was performed.
Existing runtime data/configuration was preserved. Repeat the authorized
hardware procedures in guide.md and ble-decoders.md before claiming deployment
or physical equivalence.

### HTTPS expiry update and 0.4.1 validation

The signed 0.4.1 firmware and all 33 ASan/UBSan CTest targets built/passed.
The real-IDF emulator passed the six added expiry checks (including the
production `HttpRequestException` endpoint result) and all 44 original HTTP/TLS
deadline cases. The subsequent eight-worker pool/NVS stress workload failed
on an HTTPS request exceeding its 5,000 ms budget in two runs. Therefore the
combined integration suite did **not** pass; investigate the concurrent emulator
stress timing separately. No timeout expectation or production deadline was
relaxed to obtain a pass. This limits the concurrency validation for this build.
