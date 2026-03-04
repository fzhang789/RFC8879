# openHiTLS 对齐 OpenSSL 的 RFC 8879 实施方案

本文档给出可直接落地到 openHiTLS 的实现路径，参考 OpenSSL 在 TLS 1.3 中对 RFC 8879（Certificate Compression）的设计：

- 扩展注册与能力协商。
- 压缩算法适配（zlib / brotli / zstd）。
- 握手消息处理（CompressedCertificate）。
- 配置接口、回退逻辑与兼容性测试。

## 1. 扩展与数据结构定义

### 1.1 常量

- ExtensionType：`compress_certificate(27)`。
- CertificateCompressionAlgorithm：
  - `zlib(1)`
  - `brotli(2)`
  - `zstd(3)`

在本仓库示例中已给出统一常量定义：`include/hitls_cert_compress.h`。

### 1.2 结构体扩展建议

在 openHiTLS 的 `SSL_CTX` 与 `SSL`（或同等会话对象）中增加：

- 本地支持算法位图/列表。
- 对端已宣告算法列表（ClientHello 扩展解析后保存）。
- 本次握手协商出的算法 ID（server 选择）。
- 运行时统计：
  - 原始证书消息长度。
  - 压缩后长度。
  - 是否启用压缩发送。

推荐增加独立上下文对象（示例：`HITLS_CertCompressCtx`），避免侵入握手主状态机。

## 2. 扩展注册与握手框架集成

### 2.1 ClientHello 发送

当客户端启用 RFC 8879 时，在 ClientHello 中发送 `compress_certificate`：

1. 遍历本地启用算法。
2. 写入 `algorithms<2..2^8-2>`。
3. 对 TLS 1.2 或更低版本不发送。

### 2.2 服务端解析与选择

服务端解析 ClientHello 后：

1. 验证扩展长度必须为偶数且非空。
2. 与服务端本地算法求交集。
3. 按服务端优先级选择单一算法并保存到握手上下文。
4. 若无交集，则继续常规 Certificate（不报错）。

### 2.3 Certificate / CompressedCertificate 分支

在发送证书链阶段：

- 若已协商算法且压缩收益明显（可设置最小阈值，比如 `>= 1024` 字节），发送 `CompressedCertificate`。
- 否则发送原始 `Certificate`。

在接收证书阶段：

- 若收到 `CompressedCertificate`：
  1. 读取 `algorithm` 与 `uncompressed_length`。
  2. 调用算法适配器解压。
  3. 以解压后的缓冲继续走现有证书解析与验证流程。
- 若收到 `Certificate`：维持现状。

## 3. 压缩算法适配层

建议使用“方法表注册”模式（已在 `src/hitls_cert_compress.c` 示例化）：

- 统一接口：`compress` / `decompress`。
- 统一注册 API：`HITLS_RegisterCertCompression`。
- 统一查询 API：`HITLS_GetCertCompression`。

### 3.1 zlib

- 编译宏建议：`HITLS_HAVE_ZLIB`。
- 映射 `compress2` / `uncompress`。
- 可配置等级：默认中等级（平衡 CPU 与收益）。

### 3.2 brotli

- 编译宏建议：`HITLS_HAVE_BROTLI`。
- 使用 Encoder/Decoder Stream 或 Buffer API。
- 推荐 window 与 quality 使用保守默认，避免握手 CPU 峰值过高。

### 3.3 zstd

- 编译宏建议：`HITLS_HAVE_ZSTD`。
- 使用单次压缩接口 + 最大输出长度保护。
- 解压前先校验上限，防止解压炸弹。

## 4. 配置接口（对齐 OpenSSL 使用体验）

建议新增如下 API：

- `SSL_CTX_add_cert_compression_alg(ctx, alg)`
- `SSL_add_cert_compression_alg(ssl, alg)`
- `SSL_CTX_set_cert_compression_enabled(ctx, onoff)`
- `SSL_get_negotiated_cert_compression(ssl)`

并支持配置文件或环境变量映射为算法列表，例如：

- `cert_compression = zstd,brotli,zlib`

## 5. 证书处理链路改造要点

1. **发送路径**：证书编码完成后再压缩，避免影响证书组装逻辑。
2. **接收路径**：解压后复用现有证书解析函数，减少分叉。
3. **内存控制**：
   - 严格校验 `uncompressed_length`（协议字段）。
   - 设置全局最大值（如 `<= 16MB`）。
4. **错误码分层**：区分“协商失败（可回退）”与“解压失败（握手失败）”。

## 6. 兼容性与回归测试矩阵

### 6.1 互通测试

- openHiTLS(client) ↔ OpenSSL(server)，分别测试 zlib/brotli/zstd。
- OpenSSL(client) ↔ openHiTLS(server)。
- 未启用扩展的旧端点 ↔ openHiTLS（确保回退到 Certificate）。

### 6.2 负向测试

- 扩展长度奇数。
- 算法未注册。
- `uncompressed_length` 与解压结果不一致。
- 压缩数据截断/篡改。

### 6.3 性能测试

- 证书链大小：1KB、4KB、16KB、64KB。
- 指标：握手 RTT、CPU、峰值内存、压缩率。
- 比较策略：不压缩 vs zlib/brotli/zstd。

## 7. 分阶段落地建议（可直接作为里程碑）

### M1：协议骨架

- 常量、结构体、扩展序列化/反序列化。
- 握手状态机分支（仅保留接口，不启用算法）。

### M2：zlib 首通

- 完成 zlib 适配。
- 客户端/服务端基础互通。
- 增加负向用例。

### M3：brotli + zstd

- 全部算法接入。
- 增加算法优先级策略与配置接口。

### M4：优化与稳定性

- DoS 防护、内存上限、压缩阈值。
- 与 OpenSSL/BoringSSL/NSS 互通验证。

---

## 仓库内示例文件

- `include/hitls_cert_compress.h`：扩展常量、结构、API 原型。
- `src/hitls_cert_compress.c`：扩展编解码与算法注册骨架。
- `tests/test_plan_rfc8879.md`：测试清单模板。

该示例可作为 openHiTLS 真实代码改造前的“最小可评审骨架”，先评审接口和流程，再接入实际握手与算法库。
