#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
key="${NM_OTA_SIGNING_KEY:-${repo_dir}/../securefiles/private-ota-signing-key.pem}"
if [[ -e "$key" ]]; then
    echo 'Development OTA signing key already exists; preserving it.' >&2
    exit 0
fi
directory="$(realpath -e -- "$(dirname -- "$key")")"
filename="$(basename -- "$key")"
"${repo_dir}/tools/idf-local.sh" bash -c \
    'umask 077; test ! -e "$1" && espsecure.py generate_signing_key --version 2 "$1"' _ \
    "${directory}/${filename}"
echo 'Store this key safely. Losing or replacing it prevents OTA updates signed by the original key.'
