#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -lt 1 || ! -d "$1" ]]; then
    echo 'Usage: tools/run-emulator.sh runtime/dev [emulator options]' >&2
    exit 2
fi
instance="$(realpath -e -- "$1")"
shift
# Refuse simultaneous writers to one enrolled identity.
exec 9>"${instance}/.lock"
flock -n 9 || { echo 'Emulator instance already in use.' >&2; exit 1; }
firmware="${instance}/merged-binary.bin"
emulator="${ESP_EMU_BIN:-${HOME}/.local/bin/esp-emu}"

if [[ ! -f "$firmware" ]]; then
    echo "Missing $firmware; run tools/provision-emulator.sh first" >&2
    exit 1
fi

if [[ "${NM_ESP_PERSIST:-1}" == 1 ]]; then
    runtime="${instance}/runtime-flash.bin"
    if [[ ! -f "$runtime" ]]; then
        install -m 600 "$firmware" "$runtime"
    fi
    firmware="$runtime"
fi

args=(--chip esp32s3 --firmware "$firmware" --psram-size 8M
      --net "${NM_ESP_NET:-user}" --timeout "${NM_ESP_TIMEOUT:-86400s}")
if [[ "${NM_ESP_PERSIST:-1}" == 1 ]]; then
    args+=(--save-state)
fi
if [[ -n "${NM_ESP_EXIT_ON-}" ]]; then
    args+=(--exit-on "${NM_ESP_EXIT_ON-}")
fi
exec "$emulator" "${args[@]}" "$@"
