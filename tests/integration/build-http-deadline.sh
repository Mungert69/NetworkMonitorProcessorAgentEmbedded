#!/usr/bin/env bash
set -euo pipefail
umask 077
repo="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$repo/build-http-deadline"
# Dedicated ephemeral test CA/key. Never used by or copied to production firmware.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$repo/build-http-deadline/test-key.pem" \
    -out "$repo/build-http-deadline/test-cert.pem" -days 30 \
    -subj /CN=deadline.test -addext subjectAltName=DNS:deadline.test \
    -addext basicConstraints=critical,CA:TRUE
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$repo/build-http-deadline/untrusted-key.pem" \
    -out "$repo/build-http-deadline/untrusted-cert.pem" -days 2 \
    -subj /CN=untrusted-test-ca -addext subjectAltName=DNS:deadline.test \
    -addext basicConstraints=critical,CA:TRUE
# A leaf signed by the trusted test CA, but inside the HTTPS warning window.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$repo/build-http-deadline/near-key.pem" \
    -out "$repo/build-http-deadline/near.csr" -subj /CN=deadline.test
printf 'subjectAltName=DNS:deadline.test\nbasicConstraints=critical,CA:FALSE\n' > "$repo/build-http-deadline/near.ext"
openssl x509 -req -in "$repo/build-http-deadline/near.csr" \
    -CA "$repo/build-http-deadline/test-cert.pem" -CAkey "$repo/build-http-deadline/test-key.pem" \
    -CAcreateserial -days 2 -extfile "$repo/build-http-deadline/near.ext" \
    -out "$repo/build-http-deadline/near-cert.pem"
cd "$repo/tests/integration/http_deadline"
build_dir="$repo/build-http-deadline"
"$repo/tools/idf-local.sh" idf.py -B "$build_dir" \
    -D "SDKCONFIG=$build_dir/sdkconfig" reconfigure build merge-bin
