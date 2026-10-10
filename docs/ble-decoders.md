# BLE decoder port and reproduction

This ports the shared .NET BLE decoder implementation from NetworkMonitorLib
commit `c28c59a` into the ESP32 production endpoints. Read the sibling checkout's
`Objects/Connection/Ble/REPRODUCING.md`
for the detailed field tables, specification ambiguities and original fixtures.
The .NET files and tests are the behavioral reference; this is hand-written C,
not generated code or a second independent wire format.

## Design and source map

| .NET responsibility | ESP32 production file |
|---|---|
| `IBlePayloadDecoder`, immutable registry | `ble_decoder.h`, `ble_decoder.c` |
| Advertisement normalization | `nm_ble_decoder_select` in `ble_decoder.c` |
| AES operations | `ble_crypto.h`, `ble_crypto.c` (ESP-IDF PSA) |
| `VictronPayloadDecoder` | `ble_victron_decoder.c` |
| Victron record decoders and bit fields | `ble_victron_records.c` |
| `RuuviPayloadDecoder` | `ble_ruuvi_decoder.c` |
| `BTHomePayloadDecoder` | `ble_bthome_decoder.c` |
| Typed reading selection and generated automatic encodings | `ble_metric.*`, `ble_metric_catalogue.inc` |
| Connect orchestration, password parsing and metrics | `endpoint_ble.c` |
| Continuous capture, history and immutable snapshots | `ble_scanner.*`, `ble_buffer.*` |
| Cycle retention configuration and publication | `ble_cycle.*` |
| BLE default and effective collection window | `ble_endpoint_policy.h` |
| Per-connect protocol admission | `ble_filter.h` |

Each registry descriptor owns its format name, manufacturer/service selector,
key validator, cheap admission predicate and decode function. Descriptors and
layout tables are immutable. The callback copies every raw advertisement into
`ble_buffer`; it does no AES or model edits. Connects apply their own admission
and decoding rules to immutable cycle snapshots. See
[buffer policy and ownership](monitoring-parity.md) for timing, retention,
allocation failure and cross-task reference counting.

A raw packet remains limited to the legacy scanner's 255 bytes. Decoded reports
are limited to 8192 bytes and overflow fails explicitly. Ordinary messages
remain 256 bytes; the complete owned PSRAM diagnostic is transferred through
`nm_esp_result.detail_message` and released with `nm_esp_result_release`.
Raw-listen output grows with the new advertisements in the snapshot, without a
capture cap; allocation or formatting failure is an inconclusive local failure.
No additional scanner tasks or dependencies are introduced.

## Configuration and protocol behavior

Use `--format` in monitor Args (Username remains the existing Args fallback).
A targeted `blebroadcast` needs the actual BLE address; `blebroadcastlisten`
ignores its Address field, which is a frontend label. Password is a broadcast
key, not a pairing PIN. Hex (optional `0x`), base64 and literal key parsing follow
the .NET order; the protocol then validates the decoded byte length.

| Args | Default selector | Password |
|---|---|---|
| `--format victron` | Manufacturer `0x02E1` | 16-byte AES-128 broadcast key |
| `--format ruuvi` | Manufacturer `0x0499`, RAWv2 / format 5 | Empty |
| `--format bthome` | Service data UUID `0xFCD2`, v2 | Empty for plaintext; 16-byte AES-128 for encrypted packets |

Victron framing accepts direct instant-readout records and the product `0x10`
wrapper. Record type chooses the layout: solar `01`, battery monitor `02`,
inverter `03`, DC/DC `04`, SmartLithium `05`, Inverter RS `06`, AC charger `08`,
Battery Protect `09`, Lynx BMS `0A`, Multi RS `0B`, VE.Bus `0C`, DC energy meter
`0D`, Orion XS `0F`. GX `07` and test `00` are not scanner-admitted. An explicitly
supplied unknown record can still be displayed as decrypted hex, matching .NET.
The nonce's two little-endian bytes occupy the beginning of one zero-filled AES
counter block. The encrypted payload is 1–16 bytes. The first key byte is only a
filter/check; Victron broadcasts have no authenticated integrity tag, so a
wrong key with the same first byte cannot reliably be detected.

Victron fields use little-endian bit offsets relative to plaintext, including
packed signed fields. Compare unavailable sentinels before sign extension.
Battery Protect follows consecutive payload fields as documented in the .NET
reproduction notes. SmartLithium clipped cell values report bounds. Auxiliary
mode selects voltage, midpoint voltage or temperature in Kelvin converted to
Celsius. Keep the optional solar load-current field and original labels.

Ruuvi uses the published 24-byte format-5 payload, big-endian integers and its
individual unavailable markers. Older RAWv1, encrypted/custom formats and newer
Ruuvi formats are not supported by this decoder. The embedded device MAC is
reported separately from the advertiser address.

BTHome v2 supports the same numeric/binary object table, repeated labels,
button/dimmer events, UTF-8 text, raw bytes and display-only command objects as
.NET. Unknown IDs stop parsing while preserving earlier readings; truncated
objects, malformed UTF-8 and invalid binary values fail without partial readings.
Encryption uses AES-CCM, a four-byte MIC, no AAD, and the nonce:
`MAC in display order || D2 FC || info || counter little-endian`.
Authenticate before parsing. The actual packet's advertiser MAC is mandatory;
targeted raw overrides therefore need the advertiser address. Raw listen never decrypts.
The counter is reported, not persisted for replay prevention. Providing a key
does not force encrypted-only packets. Embedded NUL in BTHome text is rendered
as the literal `\0` because C diagnostics are NUL-terminated strings. Scalar
labels/values follow .NET; newline/trailing-whitespace details may differ.

Targeted `raw`, `aesgcm`, `aesctr`, payload selectors and raw overrides remain.
`--raw_payload` takes protocol data with optional company/UUID prefix, as in
.NET, and bypasses radio capture. `--payload raw` selects full AD records over
RF. Service normalization accepts the Bluetooth base UUID in 16-, 32- or
128-bit service-data AD blocks. Each connect applies its own protocol filter.

Targeted Victron fails early if its key is missing. Invalid live decodes are
ignored while considering the rest of the snapshot; invalid explicit overrides
return an error. Selected numeric values are averaged before encoding using the
shared v2 metric catalogue. The latest successfully decoded text stays intact;
solar short summaries retain semicolon formatting and full diagnostics use
lines. Raw listen succeeds at zero captures and does no decryption. Old format,
crypto and max-capture arguments are accepted for existing configurations but
ignored by raw listen. BLE command processors remain unsupported.

## Continuous-buffer regression procedure

Run sanitizer-enabled native tests as described in AGENTS.md, including
`native-ble_cycle`, `native-ble_buffer`, `native-ble_endpoint`, `native-state_adapter`,
`native-endpoint_execution` and `native-endpoint_contracts`. The buffer tests
exercise exact retention boundaries, maximum shared-address windows, daily
windows, snapshot readers surviving eviction/reset, failed packet/address/rule
and snapshot allocations, and simultaneous callback/publication. Endpoint tests
cover signed-current and voltage averages, exact measurement-window boundaries,
latest decoded text, empty windows, independent metrics sharing history, raw
captures beyond the former limit and no repeated raw captures. Run the .NET
fixture check and build the signed firmware with `tools/build-firmware.sh`.

For hardware validation, preserve enrollment and monitoring NVS. Observe several
processor cycles with targeted voltage/current monitors and, optionally, a raw
listen monitor. Confirm the 70s configured window, short probe execution,
readings averaged from all captured advertisements, latest text unchanged,
no duplicate raw collection, stable PSRAM usage across eviction, and continuing
backend saves/acknowledgements. Record the actual firmware and observations;
native passes alone do not establish RF or OTA behaviour. Use signed OTA for an
enrolled board; never factory-flash it merely to test a decoder.

## Specifications and references

- [Victron Extra Manufacturer Data, 2022-12-14 PDF](https://communityarchive.victronenergy.com/storage/attachments/extra-manufacturer-data-2022-12-14.pdf)
- [Victron advertising protocol discussion](https://communityarchive.victronenergy.com/questions/187303/victron-bluetooth-advertising-protocol.html)
- [Victron staff Orion XS layout and AC charger clarification](https://community.victronenergy.com/t/orion-xs-12v-12v-50a-bluetooth-advertising-data/2183)
- [Ruuvi RAWv2 / data format 5, including test vectors](https://docs.ruuvi.com/communication/bluetooth-advertisements/data-format-5-rawv2)
- [BTHome object format and examples](https://bthome.io/format/)
- [BTHome encryption and published authenticated vector](https://bthome.io/encryption/)
- [Shelly BLE documentation](https://shelly-api-docs.shelly.cloud/docs-ble/common/)

These are the sources used for the .NET implementation and this port; review
updated specs before claiming support for a new device or object.

## Repeatable verification

From the repository root, run the actual production code with native adapters:

```sh
cmake -S . -B /tmp/nm-esp-ble-tests -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build /tmp/nm-esp-ble-tests -j 6
ctest --test-dir /tmp/nm-esp-ble-tests --output-on-failure
./tools/build-firmware.sh
```

`tests/native/test_ble_endpoint.c` includes the production endpoint intentionally
for deterministic scanner/time fixtures and exercises the real decoder modules.
`tests/native/ble_crypto_adapter.c` is host-only OpenSSL-backed PSA; firmware
links ESP-IDF PSA. Tests cover all 13 Victron minimum lengths, product wrappers,
key checks, fixed packed-field vectors copied from the .NET test cases, changing
solar metrics, Ruuvi official readings/sentinels, BTHome official encryption,
wrong address, tampering, truncation, UTF-8, events, repeats, buffer overflow,
service-data capture and listen-without-key behavior. `test_ble_filter.c` checks
raw AD admission, wrong keys/addresses, listen admission and malformed lengths.
The full suite also guards unrelated monitoring and ownership contracts.

Useful independent vectors (synthetic/public keys only):

```text
Ruuvi RAWv2:
0512FC5394C37C0004FFFC040CAC364200CDCBB8334C884F
Temperature 24.3 C, humidity 53.49%, pressure 100044 Pa

BTHome plain service data, UUID prefixed:
D2FC4002C409037713
Temperature 25 C, humidity 49.83%

BTHome authenticated service data, UUID prefixed:
D2FC41E445F3C9962B332211006C7C4519
Key: 231D39C1D7CC1AB1AEE224CD096DB932
MAC: 54:48:E6:8F:80:A5
Temperature 25.06 C, humidity 50.55%, counter 1122867
```

Build/test is not deployment. The build script requires the existing private
OTA signing key, uses it without exposing/committing it, and checks the signed
application fits the existing 6 MiB OTA partition. Do not generate a replacement
key, change partitions, or flash an enrolled device just to validate this port.

For authorized physical-board validation, use the provisioning/OTA guide and
an existing BLE-capable configuration. Enable Victron instant readout and copy
its broadcast key; select a supported family with known live readings. Test a
RuuviTag broadcasting RAWv2 and a Shelly BLU or other BTHome v2 broadcaster;
confirm the protocol rather than assuming all models use it. Set each effective window (timeout times 10)
longer than its beacon interval. Compare full diagnostics with the .NET decoder
using the same payload/address, check changing solar samples and fixed statuses,
run raw listen with and without keys, and test several monitors together while
Wi-Fi/MQTT is active. Confirm complete new raw captures, window-filtered targeted
readings and stable memory after successive evictions.
Host vectors and signed builds do not establish physical RF/coexistence results.

## Validation record: continuous history port, 9 October 2026

- All 34 native CTest targets passed with AddressSanitizer and UBSan enabled.
  This includes the production state-cycle test for protection of skipped BLE
  monitors and the default 7000 ms timeout. A subsequent focused endpoint run
  also passed after explicitly exercising ignored legacy capture limits.
- The .NET fixture check passed: eight files and 113 deserialization assertions.
  Only the manifest's library source-commit reference needed refreshing;
  generated wire examples were unchanged.
- The ESP-IDF 6.1 signed production build passed, with no application compiler
  warnings. Existing SDK component/Kconfig notices remain. The signed app is
  `0x221000` bytes (2,232,320), leaving 65% of the 6 MiB OTA slot free.
  `espsecure verify-signature --version 2` verified its RSA signature against
  the existing signing key.
- The attached board was observed running 0.4.1 with its passive scanner active.
  The new app has not been installed and live averaging/memory/backend tests
  remain pending deployment authorization. No enrollment/configuration or
  monitoring NVS was overwritten. The firmware version remains 0.4.1; an OTA
  test needs a distinct version because same-version OTA is rejected.

## Adding another protocol or device

1. Obtain a primary wire specification and independent payload/key/address
   vectors. Establish company or service UUID, framing, byte order, unavailable
   values, key requirements and authenticated nonce/tag rules.
2. Add a `ble_<protocol>_decoder.c` exporting a const descriptor with key
   validation, cheap admission and synchronous decoding. Keep decryption out of
   admission. Register its pointer in `ble_decoder.c` and its declaration in the
   private header. No endpoint/scanner changes should be needed for the usual
   manufacturer or 16-bit service-data protocols.
3. For a Victron family, add a layout/field table in `ble_victron_records.c`;
   framing, crypto, registry and endpoints remain unchanged. Unknown/provisional
   types should not be admitted speculatively.
4. Wire new source files into both CMake files. Extend native tests using real
   production functions, independent expected readings, malformed packets,
   unavailable/signed extremes, key failures and output bounds.
5. Repeat sanitizer and signed-firmware checks, update this document and the
   .NET reproduction notes when behavior/spec knowledge changes. State separately
   what was checked on hardware.

## Automatic metrics

Examples: `--format bthome --metric temperature`, `--format ruuvi --metric humidity`,
`--format victron --metric state_of_charge`. Use one monitor per value. No user
scale/offset settings or JSON file are needed. `nm_ble_output_reading` exposes
typed physical values during decoding. The selected-reading sink records
availability and duplicate matches without allocating an array. The endpoint
encodes only a single available reading; unavailable/missing metrics return
`BLE Metric Error`. Listen continues to provide discovery diagnostics.

`ble_metric.c` uses the immutable .NET snapshot at
`tests/fixtures/ble-metric-encodings-v2.json`. Regenerate/check constants with
`python3 tools/update-ble-metrics.py` and `python3 tools/update-ble-metrics.py --check`.
The inverse is `physical = sample * scale + offset`, with 65535 reserved as
failure. Full native precision of wide counters cannot fit in 16 bits; use
the catalogue's scale to determine the half-step error bound. Fixed status
`BLE v2:<format>:<metric>` contains no changing readings. BTHome unit variants
use separate metric names; repeats keep occurrence suffixes.

Data/API uses the shared built-in catalogue for C processors. Apply the Data
Offset migration and deploy Data/API/UI before flashing this signed firmware.
Historical reading conversion is intentionally not preserved. Start a new
dataset when changing a metric/encoding. Manual scale/offset overrides are
unsupported on C. Listen durations use scale 10, but raw listening reads a cycle
snapshot without waiting for a timeout. Targeted measurement windows use the
10x multiplier; sensor samples have a separate internal result field and
are not duration-scaled. See [the full endpoint audit](endpoint-parity-audit.md). Tests/builds do not flash or erase the attached board.


## C lifecycle wiring and reproduction

`main.c` starts the single passive scanner through the existing startup path.
NimBLE callbacks copy raw packets into `ble_buffer` and never decode or mutate
monitor records. `state.c` calls `nm_ble_cycle_begin` with all configured monitor
infos before scheduling, and `nm_ble_cycle_complete` after accepted jobs drain
and delivery/persistence have been attempted. No BLE address/window rules live
in the state loop. Skipped enabled targeted monitors still reserve history;
disabled monitors and raw listeners do not reserve an address.

`ble_endpoint_policy.h` supplies the same effective lookback to retention and
endpoint dispatch. Zero remains zero in BLE monitor metadata; execution resolves
it to 7000 ms times 10. Explicit values remain unchanged. Ordinary endpoint
processor defaults retain their existing behaviour through endpoint policy.

Each BLE endpoint acquires a reference to the published immutable snapshot,
passes it to its decoding/raw collection implementation and releases it on every
return path. The ESP32 worker pool drains before publication, so queued work
cannot accidentally cross a snapshot replacement. This replaces .NET's explicit
per-connect snapshot attachment without introducing interfaces or a DI container.
The empty initial published view is normal; capture does not wait in a probe.

Run the sanitizer-enabled CMake/CTest commands above, including `native-ble_cycle`,
`native-ble_buffer`, `native-ble_endpoint` and `native-state_adapter`, followed by
`bash tests/dotnet/generate.sh --check` and `./tools/build-firmware.sh`.
`native-ble_cycle` verifies default/explicit windows, unchanged configuration,
ordinary endpoint defaults, longest-window selection, disabled monitors,
unprotected clearing and retained snapshot lifetime. The buffer tests inject
allocation failures and concurrent capture/read/publication; endpoint tests
verify averaging and latest decoded diagnostics. Build/test does not flash.


Validation of the C lifecycle separation (9 October 2026): all 35 CTest targets
passed with AddressSanitizer/UBSan. The source-linked .NET check verified eight
fixture files and 113 deserialization assertions against library commit
`224d3ea`; only the provenance manifest changed. The ESP-IDF 6.1 production build
passed without application compiler warnings and generated a signed `0x221000`
byte application, leaving 65% of the existing 6 MiB OTA slot free. Existing SDK
Kconfig notices remain. No board was flashed and physical averaging, Wi-Fi
coexistence and memory trends remain to be tested on that build.


### Physical USB deployment: 0.4.2, 10 October 2026

The signed 0.4.2 application passed RSA signature verification and was installed
on the attached ESP32-S3 over USB with `recover_serial.py --yes`, as explicitly
requested. Only the app and OTA selector were written; configuration, enrollment
and monitor NVS were preserved. This exercised USB installation, not HTTPS OTA.
The signed application remains `0x221000` bytes.

Serial observation showed the expected initial empty snapshot (targeted probes
returned BLE Error; raw listen succeeded), then three consecutive successful
current/voltage/raw-listen cycles. Backend PingInfos contained fixed Victron
metric statuses and plausible samples (current 32757/32758; voltage 34077), with
latest diagnostic text showing approximately -1.0 A and 13.09 V. Application
acknowledgements returned pending pings to zero after every observed cycle.

BLE packet counts across the first four cycles were 571, 894, 1256 and 1571;
owned bytes were 45377, 70890, 99488 and 124361, with one published snapshot and
zero recorded drops. Internal free heap stayed approximately 175-176 KiB in
these logs; PSRAM free remained above 7.1 MB. These are all-address retained
packet totals, including snapshot-held packets, not per-device sample counts.
They do not prove stable long-term retention or the number of readings averaged.
The existing endpoint log reports success and elapsed time, but does not report
its effective window, valid sample count or physical mean. Backend active
monitor records showed Timeout=59000 despite host settings of zero; the actual
board-side effective window needs explicit endpoint diagnostics before concluding
that its history has reached the intended retention horizon. Automated tests
cover averaging and eviction; the physical observations establish capture,
decoding, publication and acknowledgements, not live averaging sample counts.


A later physical sample at uptime 847 seconds reported BLE-owned bytes=338514,
packets=4282, snapshots=1 and dropped=0. PSRAM free was 6951416 bytes, internal
free heap 175535 bytes, minimum observed PSRAM free 4818580 bytes. Current and
voltage probes succeeded but took 6279/6109 ms. This sample still shows history
growth, not an established retention plateau; effective window/sample logging
remains necessary to explain retained history and processing cost precisely.

### Per-cycle retention diagnostics

`nm_ble_buffer` logs each captured/configured address after cycle publication and
live eviction. `retention_ms` is twice the longest configured window; zero means
unprotected. `new` counts advertisements since the previous snapshot.
`payload_runs` counts consecutive payload changes among those new advertisements
for that address (ignoring RSSI), not globally distinct measurements.
`before`, `live` and `evicted` show live-history counts around eviction;
`oldest_before_ms` and `oldest_live_ms` show packet ages at the same publication
cutoff. The cycle summary separates `snapshot_packets` from
`live_after_eviction`; these overlap and must not be added together.

With default targeted BLE settings, expect `retention_ms=140000` and
`oldest_live_ms<=140000`. Unprotected addresses should have `live=0` after each
successful eviction. `eviction_skipped=1` indicates incomplete protection rules,
which intentionally preserve history. Snapshots are published before eviction,
so their packet ages can exceed live retention until the next replacement.
Logging copies only counters and addresses under the existing publication lock,
then emits lines after unlocking; it prints no payloads or encryption keys.
Diagnostic allocation failure logs a warning and leaves monitoring unchanged.

Physical diagnostic run (10 October 2026, version 0.4.2 diagnostic image):
Victron FB:5E:68:47:AD:7F delivered 356, 365 and 357 advertisements in
approximately 69-second cycles, with 69, 70 and 69 consecutive payload runs.
At the third publication, 1,078 packets entered the snapshot; eviction removed
348 from live history, leaving 730. Oldest live age was 139,979 ms against
140,000 ms retention (`eviction_skipped=0`, zero dropped packets). The 1,078
allocated packets included 348 held only by the newly published snapshot.
This confirms protected eviction on the physical board; no unprotected address
was captured during these three cycles, so that case remains host-tested here.

`nm_ble_decode` additionally logs each targeted metric probe: window and snapshot
counts, packets outside the window, filter rejections, absent selected payloads,
decode attempts/successes/failures, valid samples, decoded records missing the
metric, and the physical-unit mean. `payload_runs` counts consecutive selected
payload changes among attempts; `repeated=attempted-payload_runs`. Repetitions
still contribute exactly as before. These counters identify whether memory is
holding valid repeated telemetry, unrelated packets or undecodable records;
no raw payload/key is logged and diagnostic text/wire samples are unchanged.

Decode diagnostic follow-up: the first post-boot snapshot held 354 advertisements
with 70 selected-payload runs. Both battery_current and battery_voltage probes
attempted and successfully decoded all 354, with 354 usable samples, 284
consecutive repeats, zero decode failures and zero missing metrics. The next
cycle added 331 advertisements (69 payload runs), bringing retained history to
685; `new` remained 331, not 685. Before this port, the scanner also used
`filter_duplicates=0`; the old endpoint waiters returned on their first match.

### Capture identity and replay investigation

The NimBLE discovery callback assigns `capture_id` and a monotonic arrival time
before submitting the advertisement to the buffer. Scanner `callback_totals`
logs arrivals, successful insertions and failures every ten seconds. Up to three
consecutive repeat examples per interval show callback IDs/times and FNV-1a
payload fingerprints (diagnostic labels, not collision-proof identities).
Buffer `capture_range` logs per-address new callback IDs, internal sequence IDs
and arrival times. Snapshot `duplicate_capture_ids` counts non-increasing IDs
in insertion order; zero is expected with the single scanner writer.

`nm_ble_raw` logs emitted ID/sequence/time ranges, intra-report duplicate IDs,
and three example emitted identities/fingerprints per report. Compare successive
ranges for the same monitor: disjoint increasing ranges prove there is no raw
replay. An overlap requires investigation, especially if the same snapshot is
served again. Filters can create holes in ranges, so overlap alone does not
prove an exact duplicate count. Metric logs also show successful decode ID
ranges; overlap there is expected with the configured rolling window.

Use the independent serial observer (no secrets/raw payloads printed):

```sh
./tools/idf-local.sh python tools/watch-ble-trace.py --port /dev/ttyACM0 --seconds 240
```

It prints `TRACE raw ... range_overlap=0 snapshot_advanced=1` when successive
nonempty raw reports have strictly increasing, disjoint capture IDs. It stores
only the preceding report's range per monitor. Probe jobs copy their monitor ID
for log attribution; no model objects are shared with workers.

Physical capture-ID verification (10 October 2026): raw monitor 76 emitted IDs
1–362, followed by 363–741. The observer reported `range_overlap=0` and
`snapshot_advanced=1`; both snapshots reported zero duplicate capture IDs.
Current and voltage probes each decoded all 362 first-window advertisements
(67 payload runs, 295 consecutive repeats), with zero decode failures or missing
metrics. Callback checkpoints showed equal arrivals and successful insertions
(e.g. 1,145/1,145, zero failures). Callback examples had equal fingerprints but
different capture IDs and arrival timestamps roughly 157 ms apart. Third-cycle
publication held 1,110 packets; eviction removed 353, leaving 757 live with
oldest age 139,961 ms. This run excludes buffer insertion duplication/raw replay
for the observed captures; it does not independently measure radio traffic
outside NimBLE. An independent BLE sniffer would be needed to verify that layer.

### Independent receiver check

On 10 October 2026, the host's separate Linux hci0 UART Bluetooth adapter was
used for a 25-second passive scan with duplicate filtering disabled (`hcitool`
and `btmon`, no NetworkMonitor/NimBLE code). It received 51 reports from
FB:5E:68:47:AD:7F between relative timestamps 2.666619 and 26.493057 seconds,
containing 25 distinct manufacturer payloads. Identical payload reports at
3.295265 and 3.448020 seconds were 152.755 ms apart. The receiver used 10 ms scan
interval/window, versus ESP32's 50 ms, so total reception rates are not directly
comparable. This independently confirms fast repeated reports; it does not
verify every ESP32 callback against an over-the-air sniffer. The Linux adapter's
original soft-blocked/down state was restored after capture.

Source review found one application scanner startup and host task, one buffer
insertion per discovery callback, no application GAP listener registration, and
no recursive discovery dispatch. The installed NimBLE host calls the scan
callback once per HCI advertisement report. Passive scan, continuous duration,
50 ms interval/window and disabled duplicate filtering match the pre-port
scanner; old endpoint waiters stopped at their first matching report.

Victron's protocol PDF discusses nonce changes assuming a once-per-second
change; it does not mandate a transmission interval. Do not treat that passage
as proof of a particular controller's advertisement cadence:
https://communityarchive.victronenergy.com/storage/attachments/extra-manufacturer-data-2022-12-14.pdf

A further independent 70.015-second passive Linux capture used the ESP32's
50 ms scan interval/window and disabled duplicate filtering. Filtering received
reports to FB:5E:68:47:AD:7F yielded 156 advertisements (2.23/s), 51 distinct
manufacturer payloads and 105 additional repeated copies. Payloads were seen
1–6 times each; repeated identical payloads arrived about 156–162 ms apart.
RSSI ranged from -80 to -73 dBm. This did NOT reproduce the ESP32's roughly
365 reports per window; the reception-rate difference remains unexplained.
The independent test confirms repetitions but cannot alone establish whether
the ESP32/controller reports extra copies or Linux misses transmissions.

### 50% scan-duty diagnostic trial (previous trial)

The scanner's initial and restart parameters are temporarily 100 ms interval,
50 ms window (`itvl=0x00A0`, `window=0x0050` in 0.625 ms units). The startup log
reports these settings. Passive mode, duplicate filtering, measurement windows,
retention and decoding are unchanged. This is a diagnostic trial, not a confirmed
fix; restore both intervals to `0x0050` to return to the preceding baseline.

Physical test on 10 October 2026: ESP32 first captured 190 advertisements with
67 payload runs in approximately 69 seconds; the preceding continuous-scan run
had 362 with 67 runs. Both current and voltage decoded all 190 successfully.
At that first publication a simultaneous independent Linux passive scan began,
using unchanged continuous 50/50 ms settings. During the next approximately
69-second ESP32 cycle it captured 193 new advertisements; Linux captured 207
Victron advertisements with 62 distinct payloads over 70.166 seconds. ESP32
snapshot duplicate-ID counts and dropped-packet counters remained zero.
The Linux adapter was restored to its original soft-blocked/off state.

The trial shows reduced listening duty reduces ESP32 reception counts; it does
not prove or exclude controller-level duplicate reporting. Receiver hardware,
scan timing and Wi-Fi coexistence differ. Do not interpret matching approximate
counts as proof of identical packet reception. The trial image keeps version
0.4.2; no release bump was requested for this experiment.

### 20% scan-duty diagnostic trial (current working tree/board)

Both initial and restart scan intervals are now 250 ms (`0x0190`), with the
50 ms window unchanged. Passive mode, duplicate filtering, 70-second endpoint
window, retention and averaging remain unchanged. Firmware version stays 0.4.2.

Physical run on 10 October 2026: first ESP32 cycle received 75 advertisements
with 56 payload groups; all 75 decoded successfully for current and voltage.
The next approximately 69-second cycle received 76 advertisements with 58 groups.
A simultaneous independent Linux continuous 50/50 ms passive scan received 224
Victron advertisements with 61 distinct payloads in 70.114 seconds. These group
counts are not an exact cross-receiver nonce comparison. ESP32 snapshot duplicate
IDs and dropped counts remained zero. After two cycles BLE owned memory was
13,217 bytes for 151 packets; this is not a steady-state memory measurement.
All 35 sanitizer host tests and the signed firmware build passed. The diagnostic
image was flashed preserving NVS; local Bluetooth was restored off/soft-blocked.

### Repeated payload storage

The buffer shares one immutable payload allocation for consecutive byte-identical
advertisements from the same normalized address. Its reference count counts the
stored receptions using that payload. A changed payload starts another allocation;
there is no manufacturer-specific deduplication or suppression of readings.
Reception records retain timestamp, RSSI, callback ID and sequence individually.
This is necessary for exact overlapping measurement windows, partial age-based
eviction and unchanged raw capture output. Snapshot readers still receive each
reception, so averaging keeps the original repetition weighting. This optimisation
reduces payload/address copies, not the number of logical readings or decodes.

Cycle resource logs distinguish `packets` (reception records) from `payloads`
(shared payload allocations); `bytes` includes both and snapshot pointer arrays.
Unique-payload traffic incurs a sharing header overhead, so compare measured bytes
rather than assuming a fixed saving. Native buffer tests cover a 100-reception
shared payload, a changed payload, partial eviction, immutable snapshots, original
RSSI/timestamps, allocation failure and complete release after reset.

2026-10-10 physical-board comparison: firmware 0.4.2 flashed over USB with
50 ms scan windows / 100 ms intervals (50% duty), enrollment/NVS preserved.
Before sharing, cycle two held 383 receptions in 33,401 history bytes. After
sharing, cycle two held 380 receptions / 134 payloads in 23,634 bytes (about
29% lower allocation with nearly equal reception counts). Subsequent publication
samples were 35,323 / 35,784 / 35,571 bytes, holding 568 / 575 / 569 receptions
and 201 / 204 / 205 payloads. Live history after eviction was 384 / 388 / 385
receptions; 184 / 187 / 184 expired receptions were removed. Snapshot ownership
explains why allocated receptions exceed live history. No capture drops or decode
failures were observed in these cycles. This is cycle-sampled allocation, not an
instrumented within-cycle peak. Serial evidence: `/tmp/ble-shared-50-board.log`;
previous baseline: `/tmp/esp32-half-duty-board.log`. Additional nearby-device
noise testing follows separately; these samples contained only the Victron address.

### One-second repeat suppression trial

Before allocating a reception record, compare against the last retained packet
for the same normalized address. Suppress only an identical length and exact
payload received less than 1,000 ms later. Changed payloads (including A/B/A)
always pass; an unchanged payload at exactly 1,000 ms passes. The anchor is the
last retained reception, never refreshed by suppressed repeats. RSSI changes
alone do not bypass suppression. This policy belongs to the buffer service;
there is no manufacturer-specific parsing, counter or extra logging.

`receive` success includes intentional suppression; existing scanner diagnostics
therefore say `accepted` rather than `inserted`. Allocation failures remain
failures and continue to mark incomplete snapshots. Only retained receptions
consume sequence numbers, averaging samples and raw-listener output. Capture
IDs can have gaps after suppression. Payload sharing remains for repeats kept
at least one second apart. Unprotected histories are still cleared at cycle
completion, so their suppression anchor also clears there.

This is a deliberate lossy capture policy: identical separate events within a
second cannot be distinguished without protocol identifiers. The mean weights
retained receptions, not every radio reception. Native tests cover timing bounds,
no-allocation suppression, changed lengths/data, independent addresses,
publication boundaries and unchanged snapshot ownership/eviction semantics.

Physical-board repeat-filter trial (2026-10-10, 50% scan duty, nearby phones/watch
active): first two populated measurement windows decoded 67 and 69 Victron
advertisements per metric, with no decode failures (roughly 190 before filtering).
Cycle publication allocations were 10,150 / 16,836 / 23,075 bytes. Cycle three
held 279 snapshot receptions (280 allocated at the subsequent stats sample due
to a new callback), 209 payload allocations; live history retained 139 Victron
receptions after evicting 65 expired Victron entries and all 75 unprotected
entries. Capture drops remained zero. Different nearby-device traffic means
this isn't a controlled whole-buffer percentage comparison. CPU utilisation
was not measured; only fewer decoder invocations were verified. Evidence:
`/tmp/ble-filter-board.log`. All 35 sanitizer-enabled host tests and firmware
build passed. Raw-output fixtures use distinct payloads; dedicated buffer tests
exercise suppression without allocations and the exact 1,000 ms boundary.

After the trial, temporary callback fingerprints/repeat examples were removed.
Existing callback totals, per-address/capture/decode/raw traces and cycle resource
summaries are DEBUG logs, leaving startup information and warnings/errors at
normal log levels. No repeat-suppression log or counter was added. The default
INFO firmware is therefore quiet without losing error diagnostics.
