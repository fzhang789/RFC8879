$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Path build -Force | Out-Null
gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879.exe
.\build\test_rfc8879.exe
