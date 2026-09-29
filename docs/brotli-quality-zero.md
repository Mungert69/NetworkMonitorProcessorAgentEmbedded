# Quality-zero-only Brotli build

The firmware keeps the upstream `BrotliEncoderCompress` API, quality zero,
standard Brotli stream format and existing base64/message envelopes. No backend
or application compression algorithm is replaced.

`cmake/brotli-quality-zero.cmake` specializes the pinned espressif/brotli 1.2.0
encoder after dependency setup. `tools/specialize_brotli.py` verifies the exact
upstream `encode.c` SHA-256 and generates a build-directory copy. Managed source
is never edited. A dependency change fails configuration until reviewed.

The generated encoder defaults to quality zero, rejects non-zero quality and
prepared dictionaries, and exposes constant quality to the compiler. It omits
dictionary initialization/cleanup because the one-pass path does not use them.
The encoder archive contains only the existing one-pass fragment, entropy,
bitstream, fast-log, memory, shared initialization/metablock helpers and
specialized encode sources. Function/data-section
garbage collection removes unreachable helpers. The stream encoder's existing
scratch allocations, output bounds, empty-input handling and uncompressed
fallback remain intact. Do not call internal fragment routines with buffers
sized for the public API.

The build enables upstream `BROTLI_ENCODER_CLEANUP_ON_OOM`: allocation failures
return an error and release resources instead of terminating the process.
The supported firmware contract is quality-zero encoding; this is deliberately
not a general-purpose replacement for the full Brotli library.

## Validation

First fetch the pinned dependency by building firmware with
`./tools/build-firmware.sh`. Then run:

```sh
cmake -S . -B build-q0-tests -DNM_TEST_BROTLI_Q0=ON \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-Os -fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-q0-tests -j4
ctest --test-dir build-q0-tests --output-on-failure
```

This compiles the actual specialized encoder for the state/publication adapter
tests and compares 78 complete compressed streams byte-for-byte with the same
pinned, unmodified upstream encoder. Cases cover empty/tiny inputs, block and
hash-table boundaries through 512 KiB, repeated data and pseudorandom data.
Tests also check undersized output, output guards, unsupported quality and
allocation failures with leak checks.

To check the shared backend's actual `StringCompressor` source and .NET decoder:

```sh
vector_dir=$(mktemp -d /tmp/nm-brotli-vectors.XXXXXX)
./build-q0-tests/test_brotli_q0 "$vector_dir"
dotnet run --project tests/dotnet/BrotliParity -- "$vector_dir"
```

The vectors are synthetic; no credentials or saved device state are used.
Host tests do not establish ESP32 runtime memory usage or OTA health. Build
the signed image and test it on the emulator/device separately before deployment.

When reviewing an upgrade, inspect the final ELF/map, not merely the archive's
size: there should be no static-dictionary tables, two-pass compressor or Zopfli
encoder in the linked application. Retain upstream source licensing notices.
