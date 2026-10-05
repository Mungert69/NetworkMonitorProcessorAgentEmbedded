# Monitoring parity with the .NET processor

The authoritative behavioural reference is the original C#/.NET processor at
`~/code/NetworkMonitorProcessorAgent`. Shared models, wire contracts and
message-security policy are in `~/code/NetworkMonitorLib`.
From this repository root, these are the sibling checkouts
`../NetworkMonitorProcessorAgent` and `../NetworkMonitorLib`.
Locate their equivalents if working outside the usual `~/code` layout.
An older C port is not the behavioural reference.

Host tests compile the same `monitor_model.c`, `monitor_record.c`,
`monitor_snapshot.c`, `monitor_schedule.c`, JSON helpers
and status mappings used by firmware. ESP-IDF adapters remain separate.

The dispatcher adapter test compiles production `processor_commands.c` and
records calls to its dependencies. It covers all 11 supported commands, route
isolation, signature-verification gating, AuthKey checks, interval validation,
malformed JSON and failed state/OTA confirmation. Its crypto adapter is a test
double; actual cross-language signature verification remains covered by
`tests/integration/test-command-signatures.sh`.

Endpoint lifetime tests include the individual production endpoint modules
with SDK test doubles, including late DNS/ICMP completion. Firmware builds
compile those modules separately. Serial emulator tests exercise the production
configuration/reset modules, including interrupted factory setup. These checks
do not replace physical-board testing.

The [2026-10-05 endpoint audit](endpoint-parity-audit.md) checks all supported
endpoint types against the current .NET sources, documents remaining HTTP
routing differences and the matched HTTPS advance-expiry policy, and provides a real-library measurement/decoder
oracle. Successful Nmap and BLE-listen durations now use scale 10; BLE sensor
samples retain their protocol catalogue encoding.

## Contracts and reference code

| Contract | .NET reference | Native coverage |
|---|---|---|
| Exact unsigned 64-bit ping/ack IDs | `NetworkMonitorLib/Objects/PingInfo.cs`, `RemovePingInfo.cs` | Source-linked JSON oracle, values through `ulong.MaxValue`, adjacent IDs above 2^53 |
| Unsigned 32-bit `PiIDKey` | `Objects/ServiceMessage/ProcessorDataObj.cs`, `MonitorPingProcessor.Connect` | Sequence rollover and persisted reload |
| Signed 32-bit monitor IDs and counters | `MonitorIP.cs`, `MonitorPingInfo.cs`, `StatusObj.cs` | Invalid ranges/types rejected; defined unchecked counter arithmetic |
| Acknowledgements | `MonitorPingProcessor.ProcessesMonitorReturnData`, `MonitorPingCollection.RemovePingInfosFromPingInfos` | Exact ping ID matching; removal IDs; swap comparer ID-only semantics |
| Configuration and dataset reset | `MonitorPingCollection.FillPingInfo`, `Zero`; `MonitorPingProcessor.Init` | CLR defaults rather than patch semantics, reset ordering, preserved status/metadata |
| Alert transitions | `Merge`, `UpdateAlertFlag`, `UpdateAlertSent`, `ResetAlerts` | Success/failure/dirty-downcount transitions and persisted flags |
| Scheduling | `ConfigurableEndpointFilterStrategy`, `NetConnectCollection.GetFilteredNetConnects` | Skip overrides, counter modes, probability boundaries, daily gates, persistence |
| Endpoint status | `HTTPConnect`, `ICMPConnect`, `DNSConnect`, `SocketConnect`, `NetConnect.ProcessStatus` | HTTP enum names, failure statuses, ushort RTT conversion |
| HTTP total timeout | `NetConnect` cancellation budget and `HTTPConnect` timed request | Production deadline transport unit tests, 44 real ESP-IDF HTTP/TLS fault-injection cases |
| Quantum endpoints | `QuantumConnect`, `QuantumCertConnect`, `QuantumCertificateAnalyzer` | Exact status strings, signature-or-key classification, verified TLS 1.3, bounded DNS adapter; native interoperability/concurrency/allocation tests |
| Nmap service endpoint | `NmapCmdConnect` with `-sV` | Endpoint constructs a bounded argv and invokes a process-like embedded runner; configured port or small common-port list, bounded report and local-resource failure semantics. It is an embedded adaptation, not full Nmap output/service fingerprint parity; `nmapvuln` remains unsupported. |
| Command processors | `QuantumCert`, `QuantumConnect`, `QuantumPortScanner`, `QuantumInfo`, `Openssl`, `Nmap` | Typed command policies and shared process-like runners; .NET naming/metadata drift checks, sanitizer-enabled worker/parser/codec tests, real TLS interoperability and signed MQTT board tests. See [scope and adaptations](command-processor-port-notes.md); arbitrary OpenSSL/Nmap CLI parity is not claimed. |
| BLE broadcast/listen | `BleBroadcastConnect`, `BleBroadcastListenConnect`, shared `Objects/Connection/Ble` decoders | Shared passive scanner, bounded per-worker waiters, source-vector AD filter and production endpoint/AES tests, signed ESP-IDF build; physical RF/coexistence validation still required |

The BLE endpoints share one NimBLE observer instead of starting a platform scan
for each .NET connect. A fresh waiter is registered for each probe, so a stale
advertisement cannot satisfy a later check. Protocol waiters use the shared immutable decoder registry. Victron admits
all 13 supported record types for company `0x02E1`, matching the key-check byte
when a key is supplied. Ruuvi RAWv2 and BTHome v2 select company `0x0499` and
service data `0xFCD2` respectively. The shared
scanner does no decryption or model mutation in its callback. Listen completion
uses the .NET success-on-zero-captures rule; the bounded device message reports the count, while an owned PSRAM diagnostic
contains complete raw captures, decoded readings/errors and the end reason. Service UUID selection and raw-payload
overrides are supported, while scan-response-only fields are unavailable in
passive mode. The bounded listen message is an embedded adaptation rather than
byte-for-byte .NET output parity. See [decoder port and reproduction](ble-decoders.md)
for supported layouts, key policies, vectors and remaining hardware checks.

Explicit BLE metrics use fixed `BLE v2:<format>:<metric>` status labels across
Victron, Ruuvi and BTHome. The typed selected reading is encoded in
`PingInfo.RoundTripTime` using the shared versioned catalogue's scale/offset;
65535 remains reserved for failure. Unit/scale/offset are resolved by Data/API
from the configured protocol/metric. Readable measurements remain in diagnostics.
Without explicit `--metric`, implicit solar/receipt behavior remains. Historical
encoding conversion is deliberately omitted. Never append changing measurements
to `PingInfo.Status`: the backend interns distinct statuses using 16-bit IDs.

The oracle in `tests/dotnet` compiles linked original model files and produces
committed fixtures with source hashes. It does not recreate model declarations.
State-machine expectations are traced to the methods above; they are not all
generated by executing the complete .NET processor. See its README for scope.

```sh
git submodule update --init --recursive
cmake -S . -B build-parity -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-parity
ctest --test-dir build-parity --output-on-failure
bash tests/dotnet/generate.sh --check
```

## Storage and bounded delivery

- Typed C records own monitoring fields, with exact integer widths and separate
  present/null masks. Bounded pointer arrays own references to monitor, status,
  ping, removal and swap records. Candidate snapshots share unchanged records;
  mutation copies only the affected record/status. Validate and replace active
  RAM state without writing flash; failed mutations leave live state unchanged.
- Monitoring persistence follows the .NET in-memory collection / cycle-publication
  model (`MonitorPingCollection.Merge`, `MonitorPingProcessor.Connect` and
  `PublishRepo.MonitorPingInfos`). ESP32 attempts one complete NVS snapshot per
  cycle after all accepted probe jobs drain and publication is attempted, including
  empty, paused and failed probe cycles. There is no dirty-state save gating.
  Like the .NET publisher, ESP32 attempts delivery before saving.
  No per-probe, scheduling, acknowledgement, monitor-update or alert-command
  saves occur. Boot imports state in RAM; legacy migration is first saved at the
  next cycle. Credential/configuration and OTA security persistence are separate.
- A failed snapshot save is logged and the cycle reports failure, but RAM data
  is retained. Publication has already been attempted; publication failure never
  skips the save. Retry occurs at the next cycle.
  Power loss may lose new results/configuration changes since the last snapshot
  or replay previously acknowledged ping IDs. This is an accepted trade-off;
  there is no journal or extra acknowledgement checkpoint mechanism.
- Scheduler counters, per-host skip counters and daily slots are typed arrays.
  Endpoint execution receives a typed monitor; the per-cycle plan is an array
  of monitor IDs rather than another copy of all monitor objects.
- JSON decoding/encoding is restricted to configuration, messaging and storage
  boundaries. Extended/unknown metadata is kept as immutable encoded data and
  restored on output, not discarded or used as the mutable runtime model.
- Preserve complete monitor objects, including unknown/extended metadata and
  supplied swap-in statistics. Disabled monitors retain their aggregate info.
- Persist removals/swaps until their backend return-data acknowledgement.
- Retain pending pings until exact `removePingInfos` IDs arrive. MQTT PUBACK does
  not mutate the pending array. An application acknowledgement that an entire
  removed dataset was deleted also retires its residual events, but only if its
  host is no longer active. Acknowledgements update RAM only; publication-time
  acknowledgements handled before the save reach NVS in that same cycle.
- Publication packs multiple monitor records into each data message, with at
  most 64 pending pings per monitor chunk. It splits at a 128 KiB encoded wire
  limit; incoming commands retain a separate 384 KiB wire bound (256 KiB signed
  payload). Brotli quality
  stays zero and no fields are truncated to fit. ESP-MQTT streams outgoing
  messages larger than its receive/output buffer rather than requiring a
  128 KiB MQTT buffer. The native test covers multi-message size splits.
  An isolated 50-host emulator run delivered one message containing all 50
  MonitorPingInfos and 100 pending PingInfos to Data, with a backend
  removePingInfos reply. Those host IDs were synthetic and did not test
  database persistence for real assigned monitors. Its monitoring snapshot
  encoded 155,655 JSON bytes as a 10,055-byte NVS blob; internal-RAM and
  PSRAM low-water marks were 84,300 and 6,162,240 bytes free respectively.
  In that older run, duplicate wake-up commands filled the then eight-slot
  command queue. It now has 64 slots for a 50-host addition burst plus
  control/ack commands; live burst delivery still needs testing. Bodies are
  separately owned and bounded to 384 KiB each, so this is not a byte budget.
  Periodic resource logs report current and peak command-queue depth plus
  cumulative queue-drop and command-body allocation-failure counts. These are
  diagnostics only and do not change acknowledgement or retry behaviour.
  The runtime MQTT receive buffer is 384 KiB plus header headroom; ESP-MQTT
  allocates it with `malloc`, which the configured ESP-IDF allocator routes to
  PSRAM for allocations above 16 KiB. The command copy and decoded signed
  payload use the explicit PSRAM bulk allocator. MQTT's output buffer is kept
  above 16 KiB and sized for the MQTT CONNECT credentials (20 KiB minimum, so
  malloc prefers PSRAM); enrollment retains its separate 64 KiB receive limit.
- Alert publication failure does not suppress data publication. Retries also run
  when the active monitor list is empty or the pending limit is reached.
- `max_monitors` and `max_pending_ping_infos` remain configuration limits. The
  monitoring JSON is serialized unchanged, then stored as a versioned Brotli
  quality-zero NVS blob. The uncompressed JSON is capped at 1 MiB and the stored
  blob at 512 KiB; an oversized snapshot fails to save without replacing durable
  state, while the RAM model remains intact. Boot still reads legacy raw JSON
  snapshots and the next successful cycle save migrates them to the compressed
  format. Other NVS keys retain their existing format.
  A count limit is not a promise that arbitrary-sized
  metadata will fit in flash.
- Retained monitor records consume the monitor limit until they drain; removal
  IDs are deduplicated and reconciliation lists share that count bound. This
  prevents repeated add/delete commands during an outage from growing metadata
  beyond the configured monitor budget.
- Commands are serviced between probes and between each publication message.
  Publication owns a copy-on-write snapshot so live acknowledgements cannot
  invalidate its records. Reset/configuration epochs cancel obsolete publication;
  snapshots are never committed back over newly acknowledged live state.
  This reduces queue starvation, but is not an unlimited/durable MQTT inbox.
  Burst overflow and hardware-network failure injection still need testing.
- Endpoint probes may run concurrently through a bounded injected executor
  (`nm_probe_pool.*`). The processor task remains the single writer of the
  model: it evaluates scheduling, dispatches probe jobs, and commits each
  finished result; worker tasks perform only the blocking endpoint I/O on a
  private copy of the monitor. This mirrors the concurrent connectors of .NET's
  `NetConnectCollection`. The executor is optional; with none injected the cycle
  is the original sequential per-monitor path that the host parity tests
  exercise. Concurrent mode commits results as they complete. Commands are also
  serviced during worker waits. Configuration/reset epochs reject stale replies;
  a cycle drains every accepted job before returning, including on local failure
  or disconnect. Endpoint monotonic deadlines bound I/O; there is no independent
  wall-clock cycle cutoff that can leave jobs in the next cycle. A per-cycle
  `resources` log line reports internal-heap free and all-time minimum, largest
  internal free block, PSRAM free, and the processor/worker stack high-water
  marks, so the concurrent build's RAM and stack margins can be checked on real
  hardware.

`MaxTaskQueueSize` controls the pool capacity for all supported endpoint types
(ICMP, DNS, rawconnect, HTTP, HTTPS and httphtml), not just HTTP/TCP. It matches
the concurrency meaning of .NET's `NetConnectCollection` semaphore.
ESP32 defaults to 4, not .NET's 100,
and validates a range of 1–8. Each worker reserves a 16 KiB PSRAM stack; the
embedded network/SDK resource limits still apply. One uses a single worker,
not parallel probes. Missing settings
use four workers; explicit existing values are preserved. The setting is read during config bind
for every enrollment/setup state and takes effect at processor startup. Pool
allocation failure is logged and falls back to the sequential path. The upper
bound is an implementation limit, not a promise that eight HTTPS probes are safe
under every workload; endpoint resource limits and pending-data limits still apply.
`MaxOutstandingEndpointOperations` is a separate ESP32 setting, default 4,
valid range 1–8. It bounds outstanding DNS helper operations and ICMP sessions
**combined across the device**, including operations whose callers timed out.
There are no longer independent hard-coded limits of two per type. Four means
four DNS operations, four ICMP sessions, or a mixture totalling four—not four
per worker or per endpoint type. HTTP/TCP hostname resolution uses this same
budget; their connection/TLS work continues in the main probe workers and does
not hold a helper slot after resolution completes. MQTT/SDK-internal DNS is not
managed by this application helper budget.

The shared counter is atomic. Startup configures its limit before starting probe
workers; configuration never resets outstanding accounting. Completion or failed
startup releases a slot exactly once; a caller timeout does not release it.
DNS slots are released only after the completed task is reaped, which can be
slightly later than delivery of its result. A following ICMP operation waits
within its original deadline if that cleanup has not yet returned a slot.
Re-registration preserves the setting; factory reset restores 4. Old saved
configs without it use 4 on the next boot. Neither this count nor worker count
is a byte budget: worker/helper stacks and SDK contexts still add to RAM usage.

Contending probes wait for admission within
their original monotonic timeout instead of failing immediately. The wait consumes
the existing timeout; it never grants a fresh I/O timeout or creates extra late
workers. If no slot becomes available, the result remains inconclusive rather
than a host-down observation. Native tests cover combined DNS/ICMP exhaustion
at 1, 4 and 8, HTTP/TCP resolver contention, late cross-type slot release,
startup failures, reset defaults and simultaneous atomic admission by 16 threads.

### Runtime timing and callback responsibilities

In `firmware/main/processor.c`, the next monitoring cycle is scheduled
`poll_seconds` after the previous cycle returns, not at a fixed start-to-start
interval. `processorConnect` can change the interval. Monitoring is gated on
broker connection and pauses during OTA installation/pending confirmation.
The firmware-status retry check runs at ten-second intervals only while OTA
confirmation is pending or status has not been sent, and only when connected
and not installing. It is not an unconditional ten-second health heartbeat.

In `firmware/main/processor_mqtt.c`, incoming command data is copied and queued
for processor-task dispatch. Connection/subscription callbacks also update
connection state, subscribe, and publish ready/firmware status after subscriptions
complete. They do not run probes or mutate the monitoring model. Thus "MQTT
callbacks only enqueue" is not an accurate description of the whole callback.

### Concurrent-probe regression evidence

The shared-operation-budget change passed all 24 host CTest targets with
ASan/UBSan and the quality-zero Brotli profile, plus all 33 tooling tests.
The signed ESP-IDF firmware build passed. This validates host lifetime/admission
behaviour and firmware compilation; this change has not yet been deployed or
repeated in the 50-host emulator workload. It does not resolve the separate
long-run stress limitation below.

Before the shared helper budget was introduced (with separate two-operation
DNS/ICMP limits), the eight-worker/50-host emulator regression completed one full
cycle: 50 probe observations, no admission failures or TLS allocation errors,
and no command-queue overflow. It handled 48 `removePingInfos` commands during
publication. Internal free heap reached a 35,728-byte minimum. Of the observations,
32 succeeded and 18 failed (external TLS/ICMP errors); MQTT also disconnected and
reconnected. This synthetic host workload is not proof of database persistence for
every host or a long-run stability pass. The original enrolled flash was preserved;
the isolated test instance saved its own state and stopped after the cycle.

## Memory placement and inconclusive probes

### Cycle snapshot validation

The cycle/PSRAM changes passed all 25 ASan/UBSan CTest targets
and the signed ESP-IDF build. State-adapter tests assert one save attempt for
each cycle, no saves during probe execution or while executor replies remain
outstanding, and publish-before-save ordering. Coverage includes 1/4/8-worker
execution, ten 50-host cycles with eight workers, pending-limit pauses, no hosts,
command handling, failed saves retaining RAM results, and reboot before/after
acknowledgement persistence. These are native adapter tests, not a new live or
physical-device stress run.

The .NET oracle passed 113 assertions; all generated data fixtures and source
hashes matched. Its strict manifest check reported only the sibling library's
Git revision changing from `3a78edf` to `6bd88c3`; fixtures were not rewritten.

### Allocation policy

- mbedTLS allocates its contexts and record buffers in PSRAM. Dynamic TLS buffers
  remain disabled so that allocation placement can be measured independently.
  Do not shrink the TLS receive-record limit to obtain misleading savings.
- `nm_memory.h` allocates typed records, collections and snapshot/publication
  buffers in byte-addressable PSRAM; `nm_json.h` supplies the same allocator to
  yyjson at JSON boundaries. Ownership/freeing and the stored/wire schema do not
  change. Host builds use libc so sanitizer and allocation-failure tests still
  exercise the production code. PSRAM exhaustion fails without falling back into
  the internal heap.
- Probe-worker stacks (16 KiB each), DNS helper stacks (4 KiB each), copied job
  strings, queue payloads, pool/state contexts, DNS/ICMP contexts and HTTP deadline
  state are PSRAM-backed. Worker replies and temporary request buffers live on
  the worker's PSRAM stack. Sequential fallback instead uses the internal
  processor stack. Task control blocks, queue/semaphore control objects and
  processor/config/OTA flash-writer stacks stay internal.
- Probe workers are pinned to CPU1 at idle priority. ESP-IDF time slices them
  with IDLE1 so long TLS elliptic-curve computations cannot starve the idle
  task's watchdog; higher-priority processor/MQTT/Wi-Fi work remains eligible.
  This setting must be checked in real full-cycle load tests, because slower
  probe completion can consume the configured endpoint deadline.
- Completed pool workers are deleted by the owner. DNS uses a permanent 3 KiB
  internal-stack reaper; its fixed queue covers the maximum helper budget.
  Reaping allocates nothing and releases the operation slot only after deleting
  the helper. Caller timeout never waits for that cleanup or cancels the helper.
  Do not use IDF WithCaps self-deletion: it allocates a temporary cleanup task
  and can abort if that allocation fails.
- ESP-IDF's ping API does not expose stack-allocation capabilities. Its session
  task, packet/session storage, HTTP client buffers and lwIP allocations remain
  SDK-managed. This is not an assertion that every networking byte is in PSRAM.
  No global malloc policy change or vendor source patch is used.
- The firmware reserves 64 lwIP socket slots instead of the SDK default ten.
  Eight workers plus late ICMP sessions and MQTT/system sockets need separate
  headroom; moving memory to PSRAM does not remove this independent limit.
  `FD_SETSIZE=80` reserves another 16 descriptor numbers for console/VFS use;
  raising socket slots without this accompanying setting fails the ESP-IDF build.
  Socket exhaustion remains an inconclusive local-resource result.
  A compile-time guard rejects older generated configurations with insufficient
  sockets; increasing probe/helper maxima also requires reviewing this ceiling.
  The 150-host/eight-worker stress run exhausted sockets with 32 slots and
  motivated this increase. A 50-host full processor cycle completed with 64
  slots and no local socket-allocation failure; repeated long-duration runs
  remain unverified.
- Flash-writing tasks remain internal because IDF's cache-disable path requires
  an internal stack. Other tasks can be parked by IDF's cross-core flash/cache
  coordination; late DNS/ICMP helpers need not be awaited before a cycle snapshot.
  This depends on normal task-context access, not PSRAM access from cache-off
  ISRs. The Brotli encoder/decoder and snapshot buffers explicitly allocate
  from PSRAM, and compression/decompression finishes outside the NVS write.
  NVS is called from the processor's internal-stack task after accepted probes
  drain. ESP-IDF's default flash operation temporarily disables PSRAM access
  but coordinates normal task execution; passing a PSRAM-backed blob to NVS
  worked in both the raw-snapshot and compressed-snapshot emulator runs.
  Physical hardware remains unverified. See Espressif's
  [ESP32-S3 flash concurrency guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/peripherals/spi_flash/spi_flash_concurrency.html).
  Hardware validation is still required.
- Local allocation/socket-resource failures and busy bounded DNS/ICMP workers
  are **inconclusive**, not host-down observations. They produce a diagnostic,
  pause further dispatch and drain accepted probes. No ping, loss/down counter,
  or alert transition is created for the inconclusive result. The normal next
  scheduled cycle retries eligible monitors; there is no tight retry loop.
  Genuine network failures and timeouts retain the established status mapping.
  This is an intentional embedded adaptation to .NET's general exception path.
- External PSRAM contains TLS material. This development profile does not enable
  flash/PSRAM encryption; physical extraction remains a deployment concern, as
  it already is for unencrypted stored credentials. TLS peer verification and
  command/image signature verification are unchanged.
- `native-probe_pool` runs production pool code on pthread-backed RTOS adapters;
  `native-state_adapter` covers stale replies, wait-time commands, local failures
  and recovery. `native-memory` verifies capability flags, no internal fallback,
  allocation ownership and exact JSON. These do not replace ESP-IDF/emulator and
  physical-board tests.

### PSRAM probe / flash-overlap verification (2026-09-27)

The standalone ESP-IDF emulator test passed all 44 HTTP/TLS deadline cases,
four deliberately late DNS helpers, bounded admission/recovery, and three
50-probe mixed HTTP/HTTPS/DNS/ICMP cycles with eight workers. The cycles overlapped
420, 421 and 420 NVS commits respectively; normal firmware still saves only
once per cycle. Actual pointer checks verified worker/DNS stacks and owned probe
inputs in PSRAM, and the NVS writer's stack in internal RAM. Heap-integrity checks
and pool teardown passed.

Creating the eight-worker pool reduced free internal heap by only 3,048 bytes
(258,827 to 255,779), with 128 KiB of worker stacks in PSRAM. During this isolated
workload, the internal low-water mark was 108,784 bytes; each cycle finished
with 8,251,748 bytes of PSRAM free and at least 9,584 bytes unused on each worker
stack. These are standalone test measurements, not a live MQTT-agent budget.
The signed production image at that time was 1,183,744 bytes. All 25 ASan/UBSan CTest
targets pass, including allocation/startup failure and post-reaping slot release.

The first run exposed the default ten-socket ceiling; 32 slots eliminated that
allocation failure for the 50-host standalone test, but not the later 150-host
full processor test. The host TLS fixture also needed a longer wall-clock safety
timeout under emulation. Firmware deadlines and success assertions were not
relaxed. The runner now terminates on a panic and requires both PASS markers.
This does not validate physical hardware, OTA flash writes, live MQTT delivery,
or resolve the earlier full-model stress failure described below.

### Earlier full-model stress-test limitation (historical)

The 50-host emulator run with this memory placement eliminated the observed
TLS allocation failures and retained over 130 KiB at the internal-heap low-water
mark. However, the extended run hit a `LoadStoreError` in ROM `__memcpy_aux`
while encoding a state snapshot. Later completed 50-host cycles did not
reproduce it, but the original cause is not established and long-duration
physical-device testing remains necessary. The credential-free
[PSRAM/model/NVS diagnostic](../tests/integration/psram_memory/README.md) now
exercises 250 production Brotli-compressed snapshot saves/loads while a second
core reads PSRAM. Neither an emulator defect nor a firmware defect should
be assumed without further evidence.

## Deliberate adaptations, not claims of bit-for-bit equivalence

Endpoint execution boundaries preserve these adaptations. Both quantum endpoint
modes call `tls_inspection.*` for bounded DNS, provider setup and the shared
deadline; `quantum_tls.c` alone implements wolfSSL session/certificate operations.
`endpoint_quantum.c` maps the typed observation into existing .NET-derived
statuses and transfers owned certificate diagnostics. No OpenSSL output parsing,
new tasks, weaker trust policy or messaging changes are introduced.

- The firmware offers six standardized ML-KEM/hybrid groups and
  recognizes ML-DSA-44/65/87 leaf signatures or public keys. It does not claim
  complete OQS/legacy algorithm coverage. Unlike the .NET ServerHello-only
  quantum probe, `quantum` requires a completed authenticated TLS 1.3 handshake.
  `quantumcert` follows .NET's presented-certificate classification independently
  of CA trust, dates and hostname, using an isolated observational session. Its
  result reports signature/public-key algorithms and the .NET summary labels.
  Chain/date verification failures append `Certificate trust: not trusted`
  without changing the algorithm result; contexts are private to each
  certificate observation to isolate accepted untrusted intermediate caches.
  This policy is never used for authenticated application traffic. It
  avoids .NET's broad NIST OID prefix that can label classical SHA-3 signatures
  as PQ. Certificate diagnostics retain subject, issuer, expiry and transmitted
  chain count; display names need not match .NET platform friendly names.
  Roots come from the build's IDF Mozilla PEM set, cached in PSRAM. One monotonic
  budget includes provider setup, bounded DNS, TCP and TLS; cryptographic calls
  are not preempted at the deadline. Local resource failures are inconclusive.
  `IsQuantumCapable` now selects ML-DSA-65 command verification when true and
  ES256 envelope verification when false. The quantum branch defaults to true.
  This setting selects backend command signatures; it does not describe whether
  a particular monitored server is quantum safe.
- .NET uses a randomized per-process string hash for daily slots. The device
  uses a stable FNV-1a hash of the decimal monitor ID. Slot distribution and
  once-per-day gating are equivalent; a particular host's slot need not match.
  Endpoint strategy matching supports the ASCII names used by the endpoint
  catalog. Blank strategy names/non-ASCII patterns fail instead of inventing
  a different Unicode/GUID matching policy.
- `uint` sequence rollover is retained. If a wrapped ID is still pending, pause
  rather than silently overwriting/dropping a sample as a failed .NET `TryAdd`
  could do. Total reset resets the live sequence as well as stored state.
- Retain removed-host aggregates while their pending pings or reconciliation
  records need sending; prune after they drain. .NET can orphan these events and
  suppress publication when no hosts remain. Ownership changes can still make
  old events unacknowledgeable; the bounded pending limit pauses probes rather
  than discarding them silently.
- Legacy saved pings whose aggregate was lost can be rebuilt from saved host
  configuration. If both are absent, startup fails with an explicit orphan-state
  diagnostic and preserves storage rather than silently dropping events. USB
  re-registration/reset remains available if deliberate state removal is needed.
- Store the complete JSON state in a versioned Brotli quality-zero NVS blob,
  not in filesystem files. Legacy raw NVS JSON is accepted at boot; compression
  changes only the storage encoding, never fields or MQTT payloads.
  Configuration, statistics and IDs retain their wire types. Application code
  has one JSON implementation; unused JSON-Patch/incremental/nonstandard features
  are disabled. In the earlier ESP-IDF 5.5.5 build, the firmware ELF was
  checked: yyjson was linked, with no cJSON symbols. IDF still listed its JSON
  archive as an available input;
  that does not mean its code was included in the executable.
- Keep certificate verification even where a .NET endpoint permits an invalid
  certificate. Do not weaken TLS merely to match a platform-specific outcome.
- HTTP monitoring uses a request-owned deadline transport (`http_deadline.*`).
  DNS, incremental TCP/TLS connection setup, headers, body reads and redirects
  share one monotonic deadline. The calling task owns cleanup; no timer task
  frees a client or kills a worker. A timed-out DNS worker keeps only its own
  bounded context until completion. TLS keeps the original host for SNI and
  certificate verification even though connections use resolved IP addresses.
  This is a practical request deadline, not a hard real-time preemption of TLS
  cryptographic work or OS scheduling. See the standalone tests under
  `tests/integration/http_deadline/`; hardware timing remains to be measured.
- Per-probe RAM transitions allow command handling between slow probes. One
  snapshot save per cycle reduces flash writes, but flash wear, write latency
  and PSRAM high-water usage still need physical-device measurement.

Passing host and source-linked contract tests does not demonstrate successful
ESP-IDF linking, emulator networking, OTA rollback or physical Wi-Fi/flash
behaviour. Build and integration-test the complete firmware before deployment.

## Verification of the typed model and module cleanup (2026-09-27)

- All 18 CTest targets passed with address/undefined-behaviour sanitizers,
  including the production command-dispatch adapter tests.
- The same 22 .NET-derived core tests and 95 scheduler inclusion fixtures run
  against both the typed implementation and pre-refactor host-only reference.
  JSON fixture views are refreshed after mutations, never retained as dangling
  pointers. State/endpoint adapter tests invoke the typed firmware paths.
- Direct ownership tests verify copy-on-write sharing, independent status
  mutation and bounds. Each of 231 allocation calls is failed in turn across
  import, cloning, probing, updates and encoding; cleanup leaves live state and
  reference counts unchanged. Reference counts are processor-task-local, not a
  thread-safe ownership API. Incoming MQTT commands are queued for processor-task
  dispatch; connection/subscription callbacks also handle broker lifecycle and
  readiness/status publication, without mutating the monitoring model.
- The source-linked .NET oracle regenerated eight matching fixture files and
  passed 113 deserialization assertions.
- Command-signature integration passed 20 .NET tests and verified all 17
  generated operation fixtures with the C verifier, including rejection tests.
- Historical verification before the IDF 6.1 migration: the actual ESP32-S3
  build succeeded using ESP-IDF 5.5.5, with a signed application size of
  1,904,640 bytes (0x1d1000) and 70% of each 6 MiB OTA slot free.
  This is 65,536 bytes smaller than the preceding JSON-tree build.
  Splitting the platform/runtime modules did not change the signed image size.
- The standalone ESP-IDF HTTP/TLS integration passed all 44 cases again after
  the cleanup, including shared timeouts, redirects and certificate rejection.
- Emulator serial re-registration and factory-reset tests passed, including
  cancellation, interrupted/resumed Wi-Fi setup and preservation of OTA metadata.
  They use synthetic credentials, not a live enrolled identity.

- The running dev emulator was upgraded by replacing its app/boot image while
  preserving NVS (not by HTTPS OTA). It loaded the pre-refactor snapshot and
  enrolled credentials without reauthorization, ran HTTP and ICMP probes over
  TAP, and accepted backend `removePingInfos` acknowledgements back to
  zero pending samples. Data logs and database counters confirmed persistence.

The typed refactor keeps the stored/wire schema. Broader live fault injection,
HTTPS OTA/rollback of this build and hardware memory/flash-wear measurements
remain separate checks; passing this suite is not a claim that every possible
failure on physical hardware was exercised.
# Production daily-hash coverage

The typed scheduler tests exercise `nm_schedule_daily_hash`, the same function
used by the firmware state loop. Golden vectors cover signed int32 boundaries.
For IDs 1–24000, the 24 hourly buckets contain 968–1031 hosts each. Three
50-host sequential samples (starting at 1, 1000, and INT32_MAX-49) occupy
23–24 buckets, with no bucket containing more than four hosts.
Tests also follow 50 hosts through every hourly slot, state serialization/reload,
same-day duplicate suppression, and next-day eligibility using production hashes.

These are distribution regression tests, not a promise of balanced buckets for
every possible ID selection. Like .NET, daily scheduling distributes hosts into
UTC time slots, not evenly spaced instants within each slot. The stable FNV hash
does not reproduce .NET's process-seeded hash or its exact assigned slots.
