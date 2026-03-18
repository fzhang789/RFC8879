# RFC8879 接入 openHiTLS 社区：下一步执行手册（含代码模板）

目标仓库：<https://gitcode.com/openHiTLS/openhitls>

> 你现在仓库里已经有可运行的 RFC8879 PoC 与 openHiTLS 风格 API。本文给的是“如何真正并入社区主仓”的落地动作和代码模板。
> 当前环境里直接访问 gitcode.com 可能被网络策略阻断（例如 `CONNECT tunnel failed, response 403`），所以我补充了本地分支准备脚本：`scripts/openhitls_upstream_push.sh`。

## 0. 先准备：社区接入前置条件

1. Fork 社区仓并拉取最新主干。
2. 建 4 个分支（M1~M4），每个分支只做一个目标，避免 MR 过大。
3. 先在你 fork 仓跑全量 CI，确认基线为绿。

建议命名：

- `feature/rfc8879-m1-skeleton`
- `feature/rfc8879-m2-zlib`
- `feature/rfc8879-m3-brotli-zstd`
- `feature/rfc8879-m4-security-perf`

## 1. M1 必做代码（可以直接开始提 MR）

M1 目标是“先让握手链路正确，哪怕只用 demo 压缩算法”。

### 1.1 接口与状态结构

把本仓已有的接口搬入 openHiTLS 对应模块（建议 TLS 1.3 extension / certificate pipeline 目录）：

- `HITLS_CertCompressCtx`
- `HITLS_CompressedCertificate`
- `HITLS_SSL_CTX` / `HITLS_SSL` 接入 API

可参考当前仓头文件：`include/hitls_cert_compress.h`。

### 1.2 必接入握手位置

服务端：

- 解析 ClientHello `compress_certificate(27)` 扩展。
- 依据服务端优先级选择算法。
- 发送证书时按协商结果决定走 `Certificate` 还是 `CompressedCertificate`。

客户端：

- 发送 `compress_certificate(27)` 扩展。
- 接收 `CompressedCertificate` 时先解压，再走原有证书验证。

### 1.3 直接可用的钩子代码模板

仓库已给你准备了可迁移代码模板（把占位类型名替换成 openHiTLS 实际类型即可）：

- `integration/openhitls/rfc8879_hooks_example.c`

覆盖了 4 个关键钩子：

1. `OHTLS_OnClientHelloCertCompressExt`（解析扩展）
2. `OHTLS_ServerSelectCertCompression`（选择算法）
3. `OHTLS_BuildCertificateFlight`（发送路径压缩/回退）
4. `OHTLS_ParseCompressedCertificate`（接收路径解压）

## 2. M2-M4 补齐项（社区评审通常会问）

### M2（zlib 首通）

- 替换 demo 压缩为真实 zlib。
- 增加与 OpenSSL 的互通测试（双向）。

### M3（brotli/zstd + 配置）

- 增加 brotli/zstd 宏开关、构建选项。
- 提供 `SSL_CTX`/`SSL` 级配置接口与查询接口。

### M4（安全与性能）

- 长度上限（<=16MB）和畸形输入防护。
- 性能数据：握手时延、CPU、内存、压缩率。

## 3. 给社区 MR 的最小“可合并证明”

每个 MR 请至少附：

1. 协议正确性：
   - 扩展解析/编码成功日志或单测。
2. 回退正确性：
   - 无交集算法时回退原生 `Certificate`。
3. 失败安全性：
   - 解压失败直接握手失败，不进入不一致状态。
4. 自动化测试：
   - 单测 + 互通最小场景。

## 4. 推荐你现在就执行的具体动作

1. 在 openHiTLS fork 建 `feature/rfc8879-m1-skeleton`。
2. 先迁移本仓 `include/hitls_cert_compress.h` 与 `src/hitls_cert_compress.c` 的 M1 相关部分。
3. 在握手链路按 `integration/openhitls/rfc8879_hooks_example.c` 挂 4 个钩子。
4. 通过单测后发起 M1 MR。
5. M1 合并后，再做 M2（zlib）MR，避免一次性大改被卡评审。

可用脚本（在你本机有 openHiTLS 仓库时执行）：  
`./scripts/openhitls_upstream_push.sh <openhitls_repo_path> <branch_name>`

---

如果你愿意，我下一步可以直接给你生成 **面向 openHiTLS 目录结构的“逐文件补丁清单”（每个文件改哪些函数）**，你拿去就能按文件落地。
