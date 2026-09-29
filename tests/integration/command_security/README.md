# ESP-IDF command signature integration

Run `bash tests/integration/test-command-signatures.sh` from the repository root.
Requires the local EIM ESP-IDF 6.1 installation, esp-emu, .NET, and the sibling
NetworkMonitorData checkout with restored test dependencies.

The .NET signing tests generate ephemeral fixtures and their public key under
`/tmp/nm-command-signatures.*`. The runner embeds those files in a separate,
unsigned ESP32-S3 test app, builds with IDF's real PSA/mbedTLS implementation,
and runs it in an isolated emulator without TAP or broker credentials.
It exercises the production `command_security.c` and yyjson, with assertions
enabled: all 17 signed operations, a large init, wrong targets/operations/keys,
tampered signatures/payloads, malformed payloads and unsigned/downgrade cases.
Success requires `COMMAND_SECURITY_INTEGRATION_PASS`; panic, assertion, process
exit or timeout fails the run. The emulator is stopped after verification.
Eight concurrent IDF tasks also import/use/destroy PSA keys, verify GCM tags
of every length from 12 through 16 bytes, and reject tampering (400 valid and
400 invalid decryptions). Native BLE tests exercise the production decoder;
these emulator checks exercise the real PSA backend rather than its host adapter.

This validates the actual firmware crypto implementation against .NET fixtures;
it does not exercise broker delivery or OTA installation. Do not flash or stage
this test image as processor firmware. Its fixture key is test-only.
