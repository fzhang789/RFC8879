@echo off
setlocal enabledelayedexpansion

if not exist build mkdir build

where cl >nul 2>nul
if %errorlevel%==0 (
    echo [INFO] Using MSVC cl
    cl /nologo /W4 /Iinclude src\hitls_cert_compress.c tests\test_hitls_cert_compress.c /Fe:build\test_rfc8879.exe
    if errorlevel 1 exit /b 1
    build\test_rfc8879.exe
    exit /b %errorlevel%
)

where gcc >nul 2>nul
if %errorlevel%==0 (
    echo [INFO] Using gcc (MinGW)
    gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879.exe
    if errorlevel 1 exit /b 1
    build\test_rfc8879.exe
    exit /b %errorlevel%
)

echo [ERROR] Neither cl nor gcc was found in PATH.
exit /b 1
