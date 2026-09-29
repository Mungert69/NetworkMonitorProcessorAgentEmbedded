#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_dir="$(mktemp -d /tmp/nm-command-signatures.XXXXXX)"
echo "Signature test artifacts: $test_dir (ephemeral test public key only)"
NM_COMMAND_SIGNATURE_FIXTURES="$test_dir" dotnet test \
    "$repo_dir/../NetworkMonitorData/NetworkMonitorData.csproj" --no-restore \
    --filter 'FullyQualifiedName~ProcessorCommandSigningTests|FullyQualifiedName~BackendSignedRabbitRepoTests' --nologo
"$repo_dir/tools/idf-local.sh" idf.py -C "$repo_dir/tests/integration/command_security" \
    -B "$test_dir/build" -D "NM_SIGNATURE_FIXTURES=$test_dir" \
    -D "SDKCONFIG=$test_dir/sdkconfig" build
"$repo_dir/tools/idf-local.sh" esptool --chip esp32s3 merge-bin \
    --output "$test_dir/flash.bin" --flash-size 16MB \
    0x0 "$test_dir/build/bootloader/bootloader.bin" \
    0x8000 "$test_dir/build/partition_table/partition-table.bin" \
    0x10000 "$test_dir/build/command_security_test.bin"
python3 "$repo_dir/tests/integration/run_command_security.py" "$test_dir"
