#!/usr/bin/env bash
set -euo pipefail

mkdir -p build
gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879
./build/test_rfc8879
