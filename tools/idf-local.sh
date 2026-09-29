#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
    echo 'Usage: tools/idf-local.sh COMMAND [ARG ...]' >&2
    exit 2
fi

if [[ -n "${EIM_BIN:-}" ]]; then
    eim="$EIM_BIN"
elif command -v eim >/dev/null 2>&1; then
    eim="$(command -v eim)"
elif [[ -x "${HOME}/.local/bin/eim" ]]; then
    eim="${HOME}/.local/bin/eim"
else
    echo 'ESP-IDF Installation Manager not found. Install EIM and ESP-IDF v6.1 for esp32s3; see docs/guide.md.' >&2
    exit 2
fi

idf_version="${NM_IDF_VERSION:-v6.1}"
command_line=''
printf -v command_line '%q ' "$@"
exec "$eim" run "$command_line" "$idf_version"
