#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
build="$repo/firmware/build-camera-capture"
cd "$repo/tests/integration/camera_capture"
"$repo/tools/idf-local.sh" idf.py -B "$build" -D "SDKCONFIG=$build/sdkconfig" reconfigure build merge-bin
