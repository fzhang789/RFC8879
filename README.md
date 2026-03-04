# RFC8879

本仓库实现了 RFC 8879 证书压缩的最小可运行框架，覆盖以下能力：

- `compress_certificate(27)` 扩展编解码。
- 客户端宣告/服务端选择算法（按服务端优先级求交集）。
- `CompressedCertificate` 握手消息打包与解析。
- 压缩方法注册表 + 默认算法注册（zlib/brotli/zstd）。
- 发送阈值控制、最大解压长度保护（16MB）。

> 说明：当前默认算法实现为 demo RLE 编解码器，用于验证框架链路，不依赖外部 zlib/brotli/zstd 动态库。

## Windows 优先运行方式

### 方式 1：直接运行批处理（推荐）

在 `cmd` 或 VSCode 终端中执行：

```bat
tests\run_local_test.bat
```

该脚本会自动检测并优先使用：

1. `cl` (MSVC)
2. `gcc` (MinGW)

并在 `build\test_rfc8879.exe` 生成并运行测试。

### 方式 2：手动命令（MinGW）

```powershell
New-Item -ItemType Directory -Path build -Force | Out-Null
gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879.exe
.\build\test_rfc8879.exe
```

### 方式 3：CMake + Visual Studio（MSVC）

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\test_rfc8879.exe
```

### VSCode + PowerShell 常见问题修复

1. 运行批处理时请使用 `./`（或 `cmd /c`），不要直接写 `tests\run_local_test.bat`。
   - 正确：`./tests/run_local_test.bat`
   - 或：`powershell -ExecutionPolicy Bypass -File tests/run_local_test.ps1`
2. 不要使用 VSCode 默认“编译当前文件”任务来编译 `tests/test_hitls_cert_compress.c`，
   因为该任务不会自动带 `-Iinclude`，也不会链接 `src/hitls_cert_compress.c`。
3. 本仓库已提供 `.vscode/tasks.json`，请使用任务：
   - `RFC8879: build test (MinGW gcc)`
   - `RFC8879: run test exe`

## Linux / macOS (bash)

```bash
bash tests/run_local_test.sh
```

## 与 openHiTLS 主仓接入关系

当前代码定位为 RFC8879 **PoC 骨架**（可单测验证），并非 openHiTLS 主仓可直接上线版本。详细差距见：

- `docs/openhitls_integration_readiness.md`
