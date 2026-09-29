#!/usr/bin/env bash
set -euo pipefail
# Builds the environment-independent signed application, never provisioned flash.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${NM_IDF_BUILD_DIR:-${repo_dir}/firmware/build}"
sdkconfig="sdkconfig.production"
key_link="${repo_dir}/firmware/private-ota-signing-key.pem"
created_key_link=false
umask 077
cleanup() {
    if [[ "$created_key_link" == true && -L "$key_link" ]]; then
        unlink -- "$key_link"
    fi
    if [[ -d "$build_dir" ]]; then chmod -R go-rwx "$build_dir"; fi
}
trap cleanup EXIT

key="${NM_OTA_SIGNING_KEY:-${repo_dir}/../securefiles/private-ota-signing-key.pem}"
if [[ ! -f "$key" ]]; then
    echo 'Missing original OTA signing key; set NM_OTA_SIGNING_KEY to its path. Do not replace an existing device trust key.' >&2
    exit 1
fi
key="$(realpath -e -- "$key")"
chmod 600 "$key"
if [[ -e "$key_link" || -L "$key_link" ]]; then
    linked_key="$(realpath -e -- "$key_link")"
    if [[ "$linked_key" != "$key" ]]; then
        echo "Refusing to use a different key already present at $key_link" >&2
        exit 1
    fi
else
    ln -s -- "$key" "$key_link"
    created_key_link=true
fi

cd "${repo_dir}/firmware"
"${repo_dir}/tools/idf-local.sh" idf.py -B "$build_dir" \
    -D "SDKCONFIG=$sdkconfig" reconfigure build
