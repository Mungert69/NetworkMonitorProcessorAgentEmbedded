#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo 'Usage: tools/device.sh inspect|flash|monitor --port /dev/serial/by-id/DEVICE [--config private-config.json]' >&2
    echo 'flash is for a NEW 16 MB ESP32-S3 only; it refuses nonblank processor state and never burns eFuses.' >&2
    exit 2
}

[[ $# -ge 3 ]] || usage
mode="$1"
shift
port=''
config=''
while (($#)); do
    case "$1" in
        --port) [[ $# -ge 2 ]] || usage; port="$2"; shift 2 ;;
        --config) [[ $# -ge 2 ]] || usage; config="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$mode" == inspect || "$mode" == flash || "$mode" == monitor ]] || usage
[[ -n "$port" ]] || usage
resolved_port="$(readlink -f -- "$port")"
if [[ ! -c "$resolved_port" || ! "$resolved_port" =~ ^/dev/tty(ACM|USB)[0-9]+$ ]]; then
    echo 'Port must resolve to an existing /dev/ttyACM* or /dev/ttyUSB* character device.' >&2
    exit 2
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${NM_IDF_BUILD_DIR:-${repo_dir}/firmware/build}"
[[ -d "$build_dir" ]] || { echo 'Run ./tools/build-firmware.sh first.' >&2; exit 2; }

if [[ "$mode" == monitor ]]; then
    exec "${repo_dir}/tools/idf-local.sh" \
        python -m serial.tools.miniterm "$resolved_port" 115200
fi

umask 077
workdir="$(mktemp -d "${build_dir}/device.XXXXXXXX")"
trap 'if [[ -n "$workdir" && -d "$workdir" ]]; then rm -r -- "$workdir"; fi' EXIT

if [[ "$mode" == flash ]]; then
    [[ -n "$config" ]] || usage
    resolved_config="$(readlink -f -- "$config")"
    if [[ ! -f "$resolved_config" || ! -r "$resolved_config" ]]; then
        echo 'Configuration file is missing or unreadable.' >&2
        exit 2
    fi
    permissions="$(stat -c %a "$resolved_config")"
    if (( (8#$permissions & 077) != 0 )); then
        echo 'Configuration contains credentials; chmod it to 600 before flashing.' >&2
        exit 2
    fi
    if ! jq -e '(.wifi_ssid | type == "string" and length > 0 and . != "myssid") and
                (.wifi_password | type == "string" and length >= 8 and . != "mypassword") and
                ((.AuthDevice == true or .AuthDevice == "true") or
                 (.broker_uri | type == "string" and startswith("mqtts://")))' \
            "$resolved_config" >/dev/null; then
        echo 'Physical flashing requires real Wi-Fi settings and OAuth enrollment or an mqtts:// broker.' >&2
        exit 2
    fi
    for file in bootloader/bootloader.bin partition_table/partition-table.bin \
                ota_data_initial.bin networkmonitor_processor_esp32.bin; do
        [[ -f "${build_dir}/${file}" ]] || { echo "Missing build artifact: ${file}" >&2; exit 2; }
    done
fi

preflight=(python "${repo_dir}/tools/device_preflight.py" --port "$resolved_port" \
    --output "${workdir}/preflight.json")
if [[ "$mode" == flash ]]; then preflight+=(--check-blank-state); fi
"${repo_dir}/tools/idf-local.sh" "${preflight[@]}"
if [[ "$mode" == inspect ]]; then exit 0; fi

mac="$(jq -r .mac "${workdir}/preflight.json")"
printf 'This will replace bootloader, partition table, OTA selector, config, and app on %s.\n' "$resolved_port"
printf 'Type the device MAC %s to confirm: ' "$mac"
IFS= read -r confirmation
if [[ "$confirmation" != "$mac" ]]; then
    echo 'Confirmation did not match; no flash writes performed.' >&2
    exit 2
fi

"${repo_dir}/tools/idf-local.sh" python "${repo_dir}/tools/nvs_config.py" \
    --config "$resolved_config" --output "${workdir}/nmconfig.bin"
"${repo_dir}/tools/idf-local.sh" python -m esptool --chip esp32s3 -p "$resolved_port" \
    erase_region 0x9000 0x6000
"${repo_dir}/tools/idf-local.sh" python -m esptool --chip esp32s3 -p "$resolved_port" \
    write_flash 0x0 "${build_dir}/bootloader/bootloader.bin" \
    0x8000 "${build_dir}/partition_table/partition-table.bin" \
    0xf000 "${build_dir}/ota_data_initial.bin" \
    0x12000 "${workdir}/nmconfig.bin" \
    0x20000 "${build_dir}/networkmonitor_processor_esp32.bin"
echo 'Initial flash complete. Use tools/device.sh monitor --port PORT to check flash/PSRAM, Wi-Fi and MQTT readiness.'
