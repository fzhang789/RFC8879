$ErrorActionPreference = 'Stop'

# Ensure execution from repository root
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $RepoRoot

# In PowerShell, call batch via cmd to avoid module-path parsing issues.
cmd /c tests\run_local_test.bat
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
New-Item -ItemType Directory -Path build -Force | Out-Null
gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879.exe
.\build\test_rfc8879.exe
