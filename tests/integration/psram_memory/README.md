# Isolated PSRAM / ROM-copy diagnostic

Unsigned, credential-free ESP-IDF application. Two tasks on different cores copy
PSRAM buffers with all source/destination alignments and lengths 0–64, checking
every byte and heap integrity. A volatile function pointer forces calls to the
real ROM `memcpy`, including zero-length calls (no compiler substitution).

The main task exercises the production typed model, JSON codec and
`nm_esp_storage_save/load` path: 50 hosts, 250 probe transactions, and one
Brotli quality-zero snapshot in the production `nmdata` namespace after each
transaction. It checks the stored header and raw length, reloads the snapshot,
compares all JSON fields, and decodes it into a fresh typed model. The second-core
copy workload continues during those NVS writes. Allocation, compression,
serialization, persistence and heap-integrity checks must all pass. No network
endpoints are probed, and this is not a substitute for the full processor test.
The test component keeps C assertions enabled in IDF Release builds; its PASS
marker is meaningful only when those checks execute.

Build from the repository root with ESP-IDF 6.1. First build the production
firmware once if its pinned Brotli component has not yet been fetched; this test
links that same component and applies the firmware's quality-zero specialization.

```sh
(cd tests/integration/psram_memory && \
  ../../../tools/idf-local.sh idf.py -B ../../../build-psram-memory reconfigure build merge-bin)
```

Run without TAP or a broker:

```sh
esp-emu --chip esp32s3 --psram-size 8M --net user \
  --firmware build-psram-memory/merged-binary.bin --timeout 900s \
  --exit-on PSRAM_MEMORY_INTEGRATION_PASS
```

Success prints `PSRAM_MEMORY_INTEGRATION_PASS`; a timeout without that marker
is incomplete, even if the emulator exits successfully. Slow hosts may need a
longer timeout. Do not use `--save-state`: each run starts with fresh test NVS.
This diagnostic was added to
investigate a stress-run crash in ROM `__memcpy_aux`; its presence is not a
claim that the cause is an emulator defect. Never deploy this image by OTA or
flash it over an enrolled processor. It contains no runnable processor agent.

The compressed-snapshot version passed on shivbot with esp-emu: all 250
transactions, production Brotli saves/loads and both copy tasks completed
with both PASS markers and no heap-integrity assertion failures. The final
snapshot was 91,640 raw bytes and 5,274 stored bytes. This isolated result
does not resolve the earlier full-processor stress crash or validate physical
flash/cache behaviour.
