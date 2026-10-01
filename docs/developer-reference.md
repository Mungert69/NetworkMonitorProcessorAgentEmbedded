# NetworkMonitor ESP32-S3 processor

Coding agents: read [AGENTS.md](../AGENTS.md) before making changes. It documents
module responsibilities, C/SOLID design rules, ownership and required validation.

See [the ESP32 guide](guide.md) for explicit dev/live configuration,
firmware builds, physical flashing, isolated emulator instances, and OTA releases.
For a new physical board, follow the [first-board procedure](first-physical-board.md).

There is only one processor implementation here: `firmware/main/`.
Broker permissions and backend signing setup are documented in
[backend integration](backend-integration.md).

```text
firmware/           ESP-IDF project, native code and public config templates
tools/              Build, flash, provisioning, emulator and OTA utilities
tests/native/       Host tests of actual firmware headers/functions
tests/tooling/      Offline Python and script regression tests
tests/integration/  Explicit emulator and backend signature tests
tests/dotnet/       Source-linked .NET contract oracle and fixture generator
tests/fixtures/     Generated .NET JSON examples and boundary cases
tests/reference/    Pre-refactor algorithms for host regression comparison only
third_party/yyjson/ Pinned single application JSON library (Git submodule)
third_party/wolfssl/ Pinned quantum TLS library (Git submodule, GPLv3)
docs/               Setup guide and broker configuration examples
runtime/            Ignored private emulator/config state (created as needed)
```

## Tests

Host tests require a C compiler, CMake and Python 3. State-adapter tests additionally
use Brotli and OpenSSL development libraries (OpenSSL is only a host test adapter
for Base64). The firmware uses yyjson and mbedTLS, not cJSON or OpenSSL.
Tests do not require curl, libmosquitto or the removed Linux processor.

```sh
git submodule update --init --recursive
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug
cmake --build build-tests
ctest --test-dir build-tests --output-on-failure
python3 -m unittest discover -s tests/tooling
# Optional: regenerate/verify fixtures using real sibling .NET model sources.
bash tests/dotnet/generate.sh --check
```

Integration tests are opt-in: `tests/integration/test-command-signatures.sh`
requires the .NET backend checkout, local ESP-IDF 6.1 and esp-emu;
`tests/integration/test_serial_emulator.py` requires built firmware (including
its matching ELF for BLE interception), local ESP-IDF 6.1 through EIM and esp-emu. Host
test results are not firmware/emulator test results.
The standalone [HTTP deadline tests](../tests/integration/http_deadline/README.md)
exercise the real ESP-IDF HTTP/TLS stack against local fault-injection servers,
without processor credentials or a broker.
See [monitoring parity](monitoring-parity.md) for the reference contracts,
failure tests and deliberate embedded adaptations.
`quantum` and `quantumcert` use the
[wolfSSL provider](../tests/integration/quantum/README.md), which is part of the
released firmware. Its native and physical-board tests compile the production
TLS module. MQTT/HTTP/OTA continue to use ESP-IDF's mbedTLS integration. See the
licensing and algorithm-coverage notes before distributing firmware; the
[licensing checklist](licensing.md) covers matching source and notices.

Monitoring uses typed C records and bounded collections (`monitor_model.h`),
not a mutable JSON document. Candidate snapshots share records until changed;
only changed records are copied. JSON is decoded/encoded at command, storage
and publication boundaries. Probe results and monitoring commands update RAM;
one NVS snapshot is attempted per cycle after all accepted probe jobs finish
and publication has been attempted. Publication failure does not skip saving;
save failure does not discard RAM state or prevent later cycles.
No per-probe or acknowledgement saves, or dirty-state save gating, are used.
Power-loss loss of changes since the last snapshot is accepted. The old algorithms under `tests/reference/` are not
compiled into firmware; they let the same .NET-derived assertions test both
implementations. See the parity document for ownership and allocation-failure
coverage.

Bulk typed/JSON data, application-owned probe data, probe-worker/DNS stacks and
mbedTLS allocations use PSRAM. RTOS control blocks, flash-writing tasks and
SDK-managed networking/ping-session allocations keep their SDK placement.
Local probe resource exhaustion is logged as
inconclusive and retried on a later scheduled cycle, not recorded as host failure.
See [memory placement](monitoring-parity.md#memory-placement-and-inconclusive-probes).

Set root-level `"MaxTaskQueueSize": 4` in the selected appsettings JSON to limit
simultaneous probes, using the same setting name as .NET. It does not size the
64-slot incoming MQTT command queue. ESP32 accepts integers
1–8 and defaults to 4 when omitted; invalid values reject configuration. Provision
the changed configuration and restart to apply it (editing a template alone does
not update an existing device's NVS). Re-registration preserves this setting;
factory reset restores 4. Startup logs report requested and effective concurrency;
worker allocation failure falls back to sequential probing with a warning.

Set root-level `"MaxOutstandingEndpointOperations": 4` to bound the additional
DNS helpers and ICMP sessions **combined**, independently of probe-worker count.
It defaults to 4 and accepts integers 1–8. This is one device-wide budget, not
four of each type. HTTP/TCP resolution shares it too. Timed-out operations keep
their slots until actual completion; waiting uses the probe's existing timeout
and slot exhaustion is inconclusive, not host-down. Both settings take effect
at startup; re-registration preserves them and factory reset restores 4 each.
See [the detailed limits](monitoring-parity.md#storage-and-bounded-delivery).

Outbound monitoring, ready and firmware-status messages share `message_publish.*`.
Monitoring data packs multiple hosts into one Brotli quality-zero MQTT message
when it fits, splitting at a 128 KiB encoded-wire limit. Incoming commands
retain a separate 384 KiB wire limit (256 KiB signed payload); enrollment
commands remain capped at 64 KiB. A completed isolated 50-host emulator cycle reached
Data as one message. See [monitoring parity](monitoring-parity.md) for the
size-split tests and the synthetic-host caveat.
The firmware builds the existing Brotli encoder for quality zero only; see
[the build profile and compatibility tests](brotli-quality-zero.md).
That module owns event envelopes, Brotli/base64 encoding, message-size checks
and temporary publication buffers. Named encoding modes distinguish plain JSON,
compressed strings and compressed `(payload, AppID)` tuples. State reconciliation
and processor command handling no longer duplicate this transport formatting.

HTTP endpoint result handling lives in `endpoint_http.c`; `http_deadline.*` owns
the request's shared time budget and TCP/TLS transport lifetime. The HTTP client
borrows that transport, and the same task cleans up both. DNS resolution is
injected through a small interface, allowing deterministic deadline tests.

### Firmware responsibilities

All production C modules live under `firmware/main/`; there is no second
processor implementation in this repository.

| Modules | Responsibility |
|---|---|
| `config.c`, `config_reset.c`, `network.c` | Config persistence/binding, durable serial resets, Wi-Fi/time |
| `enrollment.c`, `enrollment_oauth.c`, `enrollment_http.c`, `enrollment_registration.c` | Enrollment sequence, device OAuth/identity, bounded HTTPS, signed broker registration |
| `processor.c`, `processor_mqtt.c`, `processor_commands.c` | Runtime loop, MQTT callback/queue ownership, validated command dispatch |
| `processor_messages.c`, `message_publish.c`, `processor_ota.c`, `ota.c` | Ready/status payloads, shared encoding, OTA command/job coordination, image installation |
| `command_security.c`, `command_mldsa.c` | ES256 envelopes or .NET ML-DSA-65 objects, selected strictly by configured capability |
| `monitor_record.c`, `monitor_snapshot.c`, `monitor_model.c` | Record ownership/JSON codec, snapshot persistence format, monitoring transitions |
| `monitor_schedule.c` | Typed scheduling, with separate skip/counter/daily evaluation helpers |
| `endpoints.c`, `endpoint_{dns,icmp,tcp,http}.c`, `endpoint_common.c` | Endpoint dispatch, individual probes and shared deadline/result helpers |
| `endpoint_quantum.c`, `quantum_tls.*` | Quantum result mapping/bounded DNS; reusable verified TLS 1.3 provider and certificate diagnostics |

Private `*_internal.h` headers describe module boundaries and ownership.
The processor task owns monitoring state. MQTT transfers queued message buffers
to that task; OTA owns copies of its command fields. Cross-task runtime flags
are atomic. No new JSON library, message format, configuration field or topic
is introduced by this separation.

The old `esp32/` paths have moved; use the commands below. Existing private
runtime directories are not moved or overwritten: pass their paths explicitly.
Rebuild firmware after relocating the project; old CMake caches contain absolute paths.

## Workflow

1. Select `firmware/config/appsettings-dev.json` or `appsettings-live.json`.
2. Generate private Wi-Fi configuration with `tools/prepare_config.py --config … --output …`.
3. Compile the environment-independent signed application with `tools/build-firmware.sh`.
4. For emulation, provision a **new** directory with `tools/provision-emulator.sh --config … --instance …`, then pass that directory to `tools/run-emulator.sh`.
5. For hardware, use `tools/device.sh flash --port … --config …`.
6. Verify the signed app and stage application-only OTA releases with `tools/stage_firmware.py` into the chosen dev/live firmware directory.

All command examples and prerequisites are in the [ESP32 guide](guide.md).
The same signed application serves dev and live; private configuration selects the
backend. Build, flash and provisioning use the local EIM-managed ESP-IDF
environment; the emulator is a host process.
Existing runtime flash is not replaced by a rebuild. Updates use OTA, while a
fresh-boot test needs a new instance directory. Scripts do not install the emulator
or restore the private OTA signing key for you.

Preserve the existing private OTA signing key. Configuration and enrolled runtime
flash are private; never commit them or distribute them as OTA artifacts. Keep
all `.bin` firmware images, factory/OTA images, merged flash images, NVS images,
and raw device flash dumps outside the Git working tree. Build output belongs in
the ignored `firmware/build/` directory; stage deployment files under the
external `~/code/securefiles/{dev,live}/firmware/` directories. Public firmware
downloads are GitHub Release assets only when intentionally published, never
files committed to the source repository. The `.gitignore` blocks common binary
image extensions as an additional safeguard.
The build reads `../securefiles/private-ota-signing-key.pem` by default; override
with `NM_OTA_SIGNING_KEY=/absolute/path/to/key.pem`. The build script exposes it
to ESP-IDF through a temporary permission-restricted symlink; no key is copied
into source control.

## Capability reporting

The firmware supports `icmp`, `dns`, `rawconnect`, `http`, `httphtml`,
`https`, `blebroadcast`, `blebroadcastlisten`, `quantum`, and `quantumcert`
(standardized ML-KEM/ML-DSA only for the quantum endpoints).
Both BLE endpoints share one
passive NimBLE scanner; they do not create a scanner per monitor. See the
[BLE support notes](guide.md#ble-broadcast-monitoring) for packet filtering,
supported options, and the bounded listen-output adaptation. BLE command
processors remain unsupported.
Dev/live appsettings templates list unsupported endpoints in
`DisabledEndpointTypes` and all current built-in commands in `DisabledCommands`.
Registration sends the existing .NET wire fields `DisabledEndPointTypes` and
`DisabledCommands`. Compiled defaults prevent omitted/empty lists from advertising
unimplemented features; extra configured restrictions are merged into those lists.

The backend stores these capabilities at registration. Updating firmware or
appsettings alone does not refresh an already registered processor's database
record: re-register it to publish the updated capabilities. No new topics or backend
schema changes are required. Future additions to the .NET catalog must also be
added to the disabled lists until implemented; run
`python3 tests/tooling/test_capability_catalog.py` with the sibling NetworkMonitorLib
checkout to detect catalog drift.
