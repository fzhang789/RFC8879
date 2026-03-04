$ErrorActionPreference = 'Stop'

# Ensure execution from repository root
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $RepoRoot

# In PowerShell, call batch via cmd to avoid module-path parsing issues.
cmd /c tests\run_local_test.bat
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
