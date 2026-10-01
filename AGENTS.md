# Instructions for coding agents

These instructions apply to this repository. Read this file before changing code.
The goal is a maintainable, bounded ESP32-S3 processor with the established .NET
behaviour and backend contracts—not a second, simplified monitoring protocol.

## Before editing

1. Read [the developer reference](docs/developer-reference.md) for the layout,
   build entry points and test commands.
2. Read [monitoring parity](docs/monitoring-parity.md) before changing monitoring,
   scheduling, serialization or acknowledgements.
3. Read the relevant module header, implementation and tests. Inspect callers
   before changing an API or ownership contract.
4. Check `git status --short`. Preserve unrelated user changes.
5. Identify the smallest responsible module and how the change will be tested.
   If a requested behaviour conflicts with a documented contract, explain the
   conflict rather than silently changing the protocol.

Use [docs/guide.md](docs/guide.md) for provisioning, dev/live configuration,
emulation, physical flashing and OTA. Do not infer the current machine, running
process, credentials or backend from an earlier conversation.

## Authoritative .NET references

- `~/code/NetworkMonitorProcessorAgent`: original C#/.NET processor; the
  authoritative behavioural reference for monitoring, scheduling, endpoint
  execution, state transitions and command handling.
- `~/code/NetworkMonitorLib`: shared .NET models, wire contracts, numeric types,
  broker topology and message-security policy.

These are sibling checkouts (`../NetworkMonitorProcessorAgent` and
`../NetworkMonitorLib` from this repository root). On another machine, locate
the equivalent checkouts before investigating parity; do not assume they exist.
Read the relevant original methods and tests rather than inferring behaviour
from an older C port. Preserve the deliberate ESP32 adaptations documented in
[monitoring parity](docs/monitoring-parity.md); not every platform detail is
intended to be identical.

## Repository and module map

There is exactly one production implementation here: `firmware/main/`.

| Path | Purpose |
|---|---|
| `firmware/` | ESP-IDF project, partition layout, version and public config templates |
| `firmware/main/` | Production C modules and their headers |
| `tools/` | Build, provisioning, flashing, emulator and OTA staging utilities |
| `tests/native/` | Host tests exercising actual firmware code with platform adapters |
| `tests/stubs/`, `tests/native/endpoint_stubs/` | Test-only platform stand-ins |
| `tests/dotnet/`, `tests/fixtures/` | Source-linked .NET contract oracle and generated examples |
| `tests/reference/` | Host-only regression reference; never link into firmware |
| `tests/tooling/` | Offline tests for scripts, config generation and layout |
| `tests/integration/` | Explicit signature, serial/emulator and HTTP/TLS tests |
| `third_party/yyjson/` | Pinned application JSON library; Git submodule |
| `third_party/wolfssl/` | Pinned quantum TLS library; Git submodule with its own GPLv3 license |
| `runtime/` | Ignored private enrollment/config/emulator state, not release artifacts |

Within `firmware/main/`, put work in the following places:

| Module | Responsibility—not a place for unrelated helpers |
|---|---|
| `main.c` | Boot sequence |
| `config.c`, `config_reset.c` | Config loading/saving/binding; durable reset markers |
| `network.c` | Wi-Fi and clock synchronization |
| `serial_console.c`, `wifi_setup.c` | Serial commands and Wi-Fi setup |
| `enrollment.c` | Coordinate enrollment stages |
| `enrollment_oauth.c`, `enrollment_http.c` | Device authorization/identity; bounded HTTPS transport |
| `enrollment_registration.c` | Authenticated MQTT registration and signed AuthKey response |
| `processor.c` | Runtime loop and scheduling orchestration |
| `processor_mqtt.c` | MQTT events, subscriptions and command-buffer enqueueing |
| `processor_commands.c` | Route checking, signature/AuthKey gates and command delegation |
| `nm_probe_pool.c`, `nm_probe_pool.h` | Bounded concurrent endpoint-probe executor; endpoint I/O only, never touches the model |
| `processor_messages.c`, `message_publish.c` | Ready/status payloads; shared event encoding/publication |
| `processor_ota.c`, `ota.c` | OTA command/job coordination; installation and health/rollback lifecycle |
| `command_security.c`, `command_mldsa.c` | Signature policy, ES256 envelopes and byte-preserving ML-DSA-65 object verification |
| `state.c` | Transactional model updates, probe cycles and delivery orchestration |
| `monitor_model.c` | Monitoring/reconciliation/status transitions on typed records |
| `monitor_record.c`, `monitor_snapshot.c` | Record ownership/JSON codec; snapshot encoding/loading/cloning |
| `monitor_schedule.c` | Typed strategy state and skip/counter/random/daily decisions |
| `monitor_numbers.c` | Contract-aware numeric conversions |
| `nm_memory.h`, `nm_json.h` | Bulk PSRAM allocation and JSON allocator/ownership boundary; host libc adapters |
| `storage.c` | Bounded NVS storage adapter |
| `endpoints.c` | Supported endpoint selection and dispatch |
| `endpoint_dns.c`, `endpoint_icmp.c`, `endpoint_tcp.c`, `endpoint_http.c` | Individual probe implementations |
| `ble_scanner.c`, `ble_filter.h`, `endpoint_ble.c` | Shared passive BLE scan, bounded AD filtering, BLE endpoint probe/decoding; no model mutations in callbacks |
| `endpoint_common.c`, `http_deadline.c` | Shared endpoint helpers; request deadline/transport lifetime |
| `endpoint_dns_task.c` | PSRAM DNS-task creation and internal-stack completion reaper |
| `endpoint_quantum.c`, `quantum_tls.*` | Quantum endpoint mapping/bounded resolution; reusable wolfSSL TLS provider, no model mutations |

`nm_capabilities.h` and its defaults describe supported capabilities.
`endpoint_status.h` contains endpoint status/URL policy.
USB recovery of a device whose application will not boot uses
`tools/recover_serial.py` in ESP ROM download mode, not a firmware command; the
bootloader still verifies the app signature.
`nm_json.h` provides the existing JSON helpers.
The pinned quality-zero Brotli build is described in
[docs/brotli-quality-zero.md](docs/brotli-quality-zero.md). Keep its public-API
buffer handling and source-hash guard; do not restore higher-quality encoder
objects or edit the managed dependency in place. Use `NM_TEST_BROTLI_Q0=ON` to
exercise the firmware's encoder in host publication/parity tests.
`*_internal.h` headers expose only the contracts needed between related modules.

## Apply SOLID in C, without building an object framework

### Single responsibility

- Keep policy, orchestration and platform I/O separate. A probe does not save NVS,
  a JSON codec does not publish MQTT, and an MQTT callback does not edit monitors.
- Extract a named helper when a function contains distinct stages such as
  validate, prepare, execute and commit. Name helpers after their purpose.
- Do not grow `main.c`, `processor.c`, `nm_esp.h` or a generic `utils.c` into
  catch-all modules. Do not split every small function into its own file either.

### Open/closed

- Extend the responsible implementation behind the existing narrow contract.
  For a new endpoint, add its implementation, dispatch/capability entries and
  tests—not another copy of the processor loop.
- Reuse shared record schemas, status mapping, numeric and publication helpers.
  Fix shared behaviour centrally instead of adding caller-specific patches.
- New operations can require deliberate changes to dispatch/security policy.
  “Open/closed” does not mean inventing a plugin system or avoiding necessary edits.

### Liskov substitution

- Every implementation or test adapter must honour the same success/failure,
  timeout, ownership and side-effect contract.
- A resolver reporting success transfers a valid address list. A failed storage
  operation must not be reported as a durable snapshot. Publishing to MQTT
  must not masquerade as a backend application acknowledgement.
- Do not substitute a fake successful ping or a weaker signature verifier to
  make an integration test pass.

### Interface segregation

- Keep module APIs small. Keep implementation helpers `static`; prefix exported
  functions consistently with the existing `nm_*` conventions.
- Prefer opaque handles for resources with private lifecycle, as in
  `http_deadline.h`. Do not expose SDK handles or mutable internals unnecessarily.
- Put related cross-module details in a private header, not the global API.
  Production files must not include other `.c` files. Some native lifetime tests
  intentionally do so to inspect private paths; that is test-only.

### Dependency inversion

- Keep model/scheduler policy independent of MQTT, Wi-Fi and NVS implementations.
  Use the existing adapter functions at those boundaries.
- Inject small dependencies where needed for determinism: the HTTP resolver,
  scheduler random source and between-probe yield callback are examples.
- Test production functions with boundary adapters, not a rewritten algorithm
  that happens to pass the same assertions.
- Do not add vtables, registries, generic containers or new libraries without a
  concrete need. Straightforward functions and structs are preferred.

## Non-negotiable behaviour and resource contracts

- Preserve .NET field names, numeric widths, null-versus-missing semantics,
  initialization/reset order, status transitions and acknowledgement matching.
  Consult the source-linked oracle and original .NET code when uncertain.
- Ping/ack IDs are `uint64_t`; `PiIDKey` is `uint32_t`; monitor IDs and many
  counters are `int32_t`. Follow the schema for other fields. Never route IDs
  through `double`, assume `long` has the same width on host and Xtensa, or use
  saturation/truncation to conceal a mismatched type.
- Preserve unknown/extended object fields through the existing immutable
  extension mechanism. Do not drop fields to save RAM or shrink payloads.
- Use typed records/arrays for monitoring work. JSON belongs at command,
  persistence and publication boundaries. Do not reintroduce per-probe JSON
  clone/parse/serialize cycles. Use yyjson; do not add a second application JSON
  library. Firmware uses ESP-IDF/mbedTLS, with wolfSSL for quantum endpoints on
  the quantum feature branch, not host curl/OpenSSL. Do not replace MQTT/HTTP/OTA
  TLS incidentally. This project's own code is GPL-3.0-only; wolfSSL and other
  dependencies retain their own licenses. Follow `docs/licensing.md` before
  publishing a combined image.
- Work on a candidate model using copy-on-write APIs. Follow `state.c`:
  validate/mutate candidate, then replace active RAM state. A failed mutation
  releases the candidate and leaves live state unchanged. Do not save per probe
  or command: attempt one monitoring snapshot save per cycle after all accepted
  probe jobs drain and publication is attempted, even for empty/paused cycles.
  Neither publication failure nor save failure suppresses the other attempt.
  No dirty-state save gating.
  Failed saves leave RAM intact and the previous durable snapshot unchanged;
  log the failure and retry at the next cycle. Power-loss
  loss of changes since the last snapshot is an accepted device trade-off.
- MQTT publish acceptance/PUBACK is NOT the acknowledgement for pending pings.
  Apply backend `removePingInfos` semantics, including reconciliation records,
  in RAM; include the resulting state in the next cycle snapshot. Do not discard
  pending data on reconnect or restore a publication snapshot over live state.
- Respect configured monitor/pending limits and independent byte/storage limits.
  At capacity, preserve pending data and use the existing retry/pause behaviour;
  do not grow buffers or silently drop samples. Brotli quality remains zero.
- Preserve scheduler ordering and persisted skip/counter/daily history.
  Disabled hosts can still affect strategy counters. The stable daily hash is
  a documented adaptation, not .NET's exact per-process string hash.
- Target hardware is ESP32-S3, 8 MiB PSRAM and 16 MiB flash. PSRAM is not
  unlimited internal heap or stack. Current OTA slots are 6 MiB each.
  Do not change partitions, state formats or release versions incidentally.

## Memory ownership, concurrency and safe failure

- State in the header whether parameters/results are borrowed, owned or
  transferred, and whether transfer happens only on success.
- Check allocations, JSON construction, queue sends, task creation and storage
  results. Cover partial initialization and every error exit. A single cleanup
  label is appropriate when it makes resource release clear.
- Use `nm_bulk_*` for bulk model data and `nm_json_new/read/clone/write` for JSON
  boundaries. Do not move task stacks, DMA buffers or SDK control objects to PSRAM
  indiscriminately. The audited probe-worker/DNS stacks use IDF WithCaps APIs;
  their application inputs, contexts and queue payloads also use PSRAM. Keep
  task/queue/semaphore control blocks and flash-writing tasks internal. Probe
  workers must not write NVS/config/OTA. Delete WithCaps tasks from their owner
  or the permanent DNS reaper, never by allocating a self-deletion cleanup task.
  DNS retains its operation slot until the reaper has freed its stack/TCB.
  SDK ping-session tasks and HTTP/lwIP internals remain SDK-managed; don't
  globally change SDK allocators to move those incidentally.
  Local probe resource failures are inconclusive, never host-down
  observations. Keep generation checks and drain every accepted worker job.
- Check size arithmetic before allocation, lengths before copies, and
  `snprintf` results before using output. Reject oversized inputs rather than
  silently truncating identities, URLs, signed data or fields.
- Never retain pointers into freed JSON documents, transient command buffers or
  a caller's stack. Copy fields needed by an asynchronous task.
- Use `nm_records_edit`/record APIs before mutating shared records. Model
  reference counts are processor-task-local, not a cross-thread ownership API.
- The MQTT callback owns an incoming buffer until successful queue transfer;
  the processor task then owns and frees it. On queue failure, the callback frees
  it. Do not perform probes or mutate monitoring state in that callback.
- Runtime cross-task flags use atomics. `volatile` is not synchronization.
  Compound shared state requires an explicit ownership/locking design.
- DNS and ICMP workers can finish after the waiter times out. Preserve their
  shared device-wide `MaxOutstandingEndpointOperations` budget (default 4),
  separate from `MaxTaskQueueSize`, and independently owned/refcounted contexts.
  Caller timeout must not release a slot; actual completion or failed startup
  does. Do not restore per-type counters or reset live accounting. Do not
  forcibly delete a task or free callback state while callbacks can still run.
- HTTP uses one monotonic budget across DNS/connect/TLS/redirect/body work.
  Do not restart the full timeout at every stage. Keep original hostname
  certificate/SNI verification when connecting to a resolved numeric address.
  Clean up the HTTP client before its borrowed deadline transport.

For example, `nm_records_append` transfers ownership only on success:

```c
nm_record *record = nm_record_new(NM_PING);
if (!record)
    return false;
if (!nm_records_append(records, record)) {
    nm_record_release(record);
    return false;
}
/* records now owns record; do not release it here. */
```

## Security, configuration and deployment boundaries

- Keep existing command signature/AuthKey gates and TLS hostname/certificate
  verification. Never add an unsigned fallback or insecure “test mode” to
  production code. Do not silently broaden the signature policy either.
  `quantumcert` is the deliberate .NET-compatible certificate observation
  exception: it classifies the presented leaf independently of CA trust, dates
  and hostname. Its per-session policy must never be reused for application
  traffic or for the verified `quantum` endpoint.
- Registration uses OAuth-authenticated MQTT and a verified AuthKey reply.
  Do not restore shared `usersetup` bootstrap credentials or add an HTTP
  registration endpoint as a convenience.
- Dev/live selection belongs to the public appsettings templates and private
  provisioned configuration. The signed application is environment-independent.
  Do not hard-code a developer's AppID, owner, broker or token.
- Never print, commit or package passwords, tokens, AuthKeys, private signing
  keys or provisioned flash. Compiled public verification keys are intentional.
  Do not rotate or generate replacement device trust keys to unblock a build.
- Build/test does not mean deploy. Do not erase, re-register, factory-reset or
  overwrite an enrolled instance unless required and authorized by the task.
  Use separate synthetic test instances; preserve existing private state.
- Read the integration instructions before using TAP: it must have one active
  emulator owner. Default emulator user networking can fake ICMP success;
  use TAP for real probe evidence. Remove temporary test firewall rules afterward.
- Rebuilding firmware does not update a running emulator. Use the documented
  procedure and distinguish development flash rebasing from an actual OTA test.

## Validation and completion

For C changes, run sanitizer-enabled host tests from the repository root:

```sh
git submodule update --init --recursive
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-tests
ctest --test-dir build-tests --output-on-failure
```

Select additional checks according to the change:

| Change | Additional verification |
|---|---|
| Fields, IDs, serialization, model or scheduling | `bash tests/dotnet/generate.sh --check`; extend parity/ownership/failure tests |
| Production C, headers, dependencies or firmware source layout | `./tools/build-firmware.sh`; check signed size and warnings |
| Signature policy/verification | `./tests/integration/test-command-signatures.sh` |
| USB recovery (ROM download mode) | Exercise `tools/recover_serial.py` only on a recoverable board |
| Reset, serial setup, config persistence | `python3 tests/integration/test_serial_emulator.py` and the same command with `--factory-reset` |
| HTTP transport/deadlines | Follow `tests/integration/http_deadline/README.md`; native mocks alone are insufficient |
| Tool/config/path changes | `python3 -m unittest discover -s tests/tooling`; update affected path assertions |
| Messaging, state or runtime integration | When authorized/configured, verify probes, backend saves and application acknowledgements |

- Tests must exercise the production paths and .NET-derived expectations.
  Do not change expected fixtures merely to match new C behaviour. Explain any
  intentional divergence and update its contract tests/documentation together.
- Cover malformed input, numeric boundaries, absent/null fields, allocation and
  storage failure, reconnect/retry, and late callbacks where applicable.
- Add new production source files to `firmware/main/CMakeLists.txt` and relevant
  host targets in root `CMakeLists.txt`. Keep reference/stub code out of firmware.
- Follow `.clang-format` (clang-format 19). Keep FreeRTOS include ordering.
  Format touched code, not unrelated files.
- Documentation-only changes need path/content review and `git diff --check`,
  not a firmware rebuild or disruption of a running processor.
- Update the module map and relevant documentation when responsibilities move.
  Report what changed, which tests actually ran, and any untested layer.
  Host passes do not prove firmware linking, hardware operation or OTA rollback.
- Before a requested commit, inspect the complete diff and untracked files.
  `./commit "message"` stages everything, commits and pushes: use it only when
  the task authorizes that workflow and unrelated files/secrets are excluded.

Final review: one clear responsibility per module; explicit ownership; bounded
resources; preserved contracts; no security bypass; failure paths tested; no
secrets; build sources and docs aligned. Do not claim completion if a required
check failed or was not run—state the remaining limitation.
