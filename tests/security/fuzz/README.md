# Security fuzz harnesses

These harnesses exercise production C parsing code. They are supplemental to the
native tests and the signed-command integration test; they do not replace either.
Run them on a development host, never on a deployed processor.

## What is here

| Harness | Production path | Input bound |
|---|---|---:|
| `fuzz_camera_xml.c` | `camera_xml.c`: XML value extraction and escaping | 32 KiB |
| `fuzz_camera_jpeg.c` | `camera_jpeg.c`: length-prefixed RTP/JPEG packet assembly | Input is bounded by libFuzzer's `-max_len` |
| `fuzz_ble_decoders.c` | BLE decoder registry, metric parsing, Victron/Ruuvi/BTHome | 2–255 bytes |
| `fuzz_camera_rtsp.c` | Production `camera_rtsp.c`: URL/header/auth/SDP/response/session paths | 32 KiB |
| `fuzz_processor_dispatch.c` | Production `processor_commands.c`: JSON routing and dispatch | 150,000 deterministic mutations per run |

The RTSP harness uses a deterministic in-memory socket adapter. It stubs the
JPEG decoder because RTP/JPEG is fuzzed separately. The dispatcher harness uses
the recording adapters from `tests/native/test_processor_commands.c`; its
signature verifier is a test double, so it tests malformed JSON and routing, not
cryptographic verification. Keep the real signature checks enabled in all
integration and deployment tests.

## Prerequisites

- Clang with libFuzzer support (`clang` or `clang-19`)
- CMake, a C17 compiler, and the repository's initialized `third_party/yyjson`
  submodule
- Root native-test dependencies described in `docs/developer-reference.md`
- ESP-IDF's host-visible mbedTLS headers/library for the RTSP harness

## Build/run the libFuzzer harnesses

From the repository root, create an ignored output directory and set sanitizer
flags:

```sh
mkdir -p build-security-fuzz
export FUZZ_CC=clang
export FUZZ_FLAGS='-O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer'
```

The focused harnesses can be compiled with production sources as follows (add
the project's standard include paths and host adapters where noted):

```sh
$FUZZ_CC $FUZZ_FLAGS -Ifirmware/main \
  tests/security/fuzz/fuzz_camera_xml.c firmware/main/camera_xml.c \
  -o build-security-fuzz/fuzz_camera_xml

$FUZZ_CC $FUZZ_FLAGS -Ifirmware/main \
  tests/security/fuzz/fuzz_camera_jpeg.c firmware/main/camera_jpeg.c \
  -o build-security-fuzz/fuzz_camera_jpeg

$FUZZ_CC $FUZZ_FLAGS -Ifirmware/main \
  tests/security/fuzz/fuzz_ble_decoders.c firmware/main/ble_decoder.c \
  firmware/main/ble_metric.c firmware/main/ble_victron_decoder.c \
  firmware/main/ble_victron_records.c firmware/main/ble_ruuvi_decoder.c \
  firmware/main/ble_bthome_decoder.c firmware/main/ble_crypto.c \
  tests/native/ble_crypto_adapter.c -Itests/native/endpoint_stubs \
  -lcrypto -o build-security-fuzz/fuzz_ble_decoders
```

The RTSP harness includes `camera_rtsp.c` in its translation unit so private
parsers are reachable. Its only mbedTLS call is Base64 encoding for the RTSP
Digest request; the included adapter maps that call to OpenSSL's Base64 encoder.
The RTSP parser and session implementation are the production source. Do not
replace them with a reimplementation.

Build RTSP with:

```sh
$FUZZ_CC $FUZZ_FLAGS -Ifirmware/main -Itests/security/fuzz/stubs \
  tests/security/fuzz/fuzz_camera_rtsp.c firmware/main/cmd_arguments.c \
  tests/security/fuzz/mbedtls_base64_adapter.c -lcrypto \
  -o build-security-fuzz/fuzz_camera_rtsp
```

For corpus-based runs, pass a seed directory and a bounded budget, for example:

```sh
ASAN_OPTIONS=detect_leaks=0 build-security-fuzz/fuzz_camera_xml \
  -max_len=32768 -max_total_time=60
```

LibFuzzer starts with an empty synthetic corpus for this example. To preserve
seeds, pass a seed directory copied into `build-security-fuzz/`; LibFuzzer will
write new entries there. Keep crash artifacts outside the source tree until
triaged.

To target the approximate input counts recorded in the security report, use
these budgets after building the corresponding executables:

```sh
ASAN_OPTIONS=detect_leaks=0 build-security-fuzz/fuzz_camera_xml \
  -max_len=32768 -runs=5500000
ASAN_OPTIONS=detect_leaks=0 build-security-fuzz/fuzz_camera_jpeg \
  -max_len=65536 -runs=11489984
ASAN_OPTIONS=detect_leaks=0 build-security-fuzz/fuzz_ble_decoders \
  -max_len=255 -runs=125560
ASAN_OPTIONS=detect_leaks=0 build-security-fuzz/fuzz_camera_rtsp \
  -max_len=32768 -runs=2365702
```

These budgets reproduce the target count and parser coverage areas, not the
exact historical byte sequence: the old generated corpora were temporary and
libFuzzer mutations depend on its version, seed, and corpus. Record those values
for each future run. The RTSP campaign historically used two passes so the
second could reach deeper SDP/SETUP/PLAY states; use saved corpus output from the
first pass as input to the second pass when reproducing that progression.

## Dispatcher mutation run

The deterministic dispatcher smoke-fuzzer can be built against the same yyjson
configuration as the native target. This compiles the native test adapters and
the production dispatcher into one host executable:

```sh
cmake -S . -B build-security-fuzz -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-security-fuzz --target yyjson
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -std=c17 \
  -Wall -Wextra -Wpedantic -Werror -UNDEBUG -Dasm=__asm__ \
  -DYYJSON_DISABLE_INCR_READER -DYYJSON_DISABLE_NON_STANDARD -DYYJSON_DISABLE_UTILS \
  -Itests/stubs -Ifirmware/main -Ithird_party/yyjson/src \
  tests/security/fuzz/fuzz_processor_dispatch.c firmware/main/processor_commands.c \
  build-security-fuzz/third_party/yyjson/libyyjson.a \
  -o build-security-fuzz/fuzz_processor_dispatch
ASAN_OPTIONS=detect_leaks=0 build-security-fuzz/fuzz_processor_dispatch
```

The run is deterministic: seed `0x6d2b79f5`, 150,000 inputs. It mutates JSON
syntax, nesting, duplicate fields, AuthKey values, and command/connect data. It
uses a permissive signature test adapter from the native dispatcher test, so a
clean run is not evidence about signature cryptography.

## Prior campaign record

The initial campaigns were run from temporary `/tmp` harnesses. Their sources
are now preserved here; temporary corpora and binaries are not required. Recorded
results were:

- camera XML: approximately 5.5 million inputs;
- RTP/JPEG: 11,489,984 inputs;
- BLE decoders: 125,560 inputs;
- RTSP: 2,365,702 mutated sessions, including DESCRIBE/SETUP/PLAY and
  interleaved framing;
- dispatcher: 150,000 deterministic mutated inputs.

The old long campaigns were not rerun while packaging these harnesses. Use the
commands above to start a fresh bounded campaign. Record compiler version,
sanitizer flags, corpus, time/input budget, and any findings with future results.
