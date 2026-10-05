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
| Scanner admission and capture delivery | `ble_filter.h`, `ble_scanner.*` |

Each registry descriptor owns its format name, manufacturer/service selector,
key validator, cheap admission predicate and decode function. Descriptors and
layout tables are immutable. Scanner waiters borrow descriptors for the process
lifetime and copy their address/key-check metadata; they retain no password or
caller-owned buffers. Advertisement spans are borrowed synchronously. The
endpoint owns decoded text and transfers the complete diagnostic through
`nm_esp_result.detail_message`; callers release it with `nm_esp_result_release`.
The callback only selects and checks packets: no AES, allocation or model edits.

The shared passive scanner and one bounded queue per probe worker are retained.
A payload remains limited to 255 bytes. Decoded reports are limited to 8192 bytes;
overflow fails explicitly. Listen reports reserve at most `512 + captures * 9000`
bytes in PSRAM for protocol captures (50 maximum, plus one temporary 8192-byte
decode buffer). Generic captures reserve at most `512 + captures * 1500` bytes for complete raw advertisements plus selected/decrypted payloads. Complete
raw advertisements accompany decoded text or errors in listen diagnostics.
Ordinary monitor messages remain bounded to 256 bytes; full details use the
existing diagnostic ownership path. There are no new tasks or dependencies.

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
an address-free raw override in listen mode cannot decrypt encrypted BTHome.
The counter is reported, not persisted for replay prevention. Providing a key
does not force encrypted-only packets. Embedded NUL in BTHome text is rendered
as the literal `\0` because C diagnostics are NUL-terminated strings. Scalar
labels/values follow .NET; newline/trailing-whitespace details may differ.

Existing `raw`, `aesgcm`, `aesctr`, payload selectors, raw overrides and capture
limits remain. `--raw_payload` takes protocol data with optional company/UUID
prefix, as in .NET; it skips RF scanning. Use `--payload raw` for full AD records
received over RF. Service normalization also accepts the Bluetooth base UUID
in 16-, 32- or 128-bit service-data AD blocks; no separate advertised UUID list
is required. Scanner admission is always specific to the requested protocol.

Targeted Victron retains early failure when its key is missing. Listen mode can
capture without a Victron key and reports a decode error beside raw bytes.
Targeted failed live decodes continue waiting within the original timeout;
invalid explicit overrides return an error. Listen succeeds at zero captures,
and records errors for admitted packets it cannot decode. Changing readings
stay in diagnostics/numeric samples, never in the fixed status table. All numeric fields are selectable using `--metric`; aliases remain supported.
Automatic scale and offset use the same reviewed v2 catalogue as .NET.
See the automatic encoding section of the sibling reproduction guide. Solar short summaries retain their
semicolon formatting; full diagnostic text uses lines.

BLE command processors remain unsupported on ESP32, as before this port. This
change ports the common decoder behavior into both supported BLE endpoints.
Passive scanning cannot obtain scan-response-only fields.

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
confirm the protocol rather than assuming all models use it. Set each timeout
longer than its beacon interval. Compare full diagnostics with the .NET decoder
using the same payload/address, check changing solar samples and fixed statuses,
run listen with and without keys, and test several monitors together while
Wi-Fi/MQTT is active. Confirm bounded captures and no stale packet reuse.
Host vectors and signed builds do not establish physical RF/coexistence results.

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
unsupported on C. Listen durations use scale 10, with the same 10x timeout
extension as .NET; sensor samples have a separate internal result field and
are not duration-scaled. See [the full endpoint audit](endpoint-parity-audit.md). Tests/builds do not flash or erase the attached board.
