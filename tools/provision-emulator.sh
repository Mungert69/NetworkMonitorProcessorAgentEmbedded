#!/usr/bin/env bash
set -euo pipefail
# Explicit config and instance directory: neither dev nor live is implicit.
if [[ $# != 4 || "$1" != --config || "$3" != --instance ]]; then
    echo 'Usage: tools/provision-emulator.sh --config private.json --instance runtime/dev' >&2
    exit 2
fi
config="$(realpath -e -- "$2")"
instance="$4"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$config" ]] || exit 2
umask 077
# Refuse to replace any existing instance, including enrolled flash.
mkdir -- "$instance"
instance="$(realpath -e -- "$instance")"
build_dir="${NM_IDF_BUILD_DIR:-${repo_dir}/firmware/build}"
[[ -d "$build_dir" ]] || { echo 'Build firmware before provisioning an emulator.' >&2; exit 2; }
"${repo_dir}/tools/idf-local.sh" python "${repo_dir}/tools/make_flash_image.py" \
    --config "$config" --build "$build_dir" --output-dir "$instance"
echo "Provisioned private emulator instance: $instance"
