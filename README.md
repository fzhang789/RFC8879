# RFC8879

本仓库实现了 RFC 8879 证书压缩的最小可运行框架，覆盖以下能力：

- `compress_certificate(27)` 扩展编解码。
- 客户端宣告/服务端选择算法（按服务端优先级求交集）。
- `CompressedCertificate` 握手消息打包与解析。
- 压缩方法注册表 + 默认算法注册（zlib/brotli/zstd）。
- 发送阈值控制、最大解压长度保护（16MB）。

> 说明：当前默认算法实现为 demo RLE 编解码器，用于验证框架链路，不依赖外部 zlib/brotli/zstd 动态库。

## 本地验证

### Linux / macOS (bash)

```bash
mkdir -p build
gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879
./build/test_rfc8879
```

### Windows (PowerShell + MinGW)

```powershell
New-Item -ItemType Directory -Path build -Force | Out-Null
gcc -Iinclude -Wall -Wextra -std=c11 src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o build/test_rfc8879.exe
.\build\test_rfc8879.exe
```

> 你截图中的报错 `cannot open output file /tmp/test_rfc8879.exe` 是因为 Windows 下通常没有 `/tmp` 目录。
> 因此请改为输出到仓库内 `build/` 目录。
```bash
gcc -Iinclude src/hitls_cert_compress.c tests/test_hitls_cert_compress.c -o /tmp/test_rfc8879
/tmp/test_rfc8879
```


## 与 openHiTLS 主仓接入关系

当前代码定位为 RFC8879 **PoC 骨架**（可单测验证），并非 openHiTLS 主仓可直接上线版本。详细差距见：

- `docs/openhitls_integration_readiness.md`
