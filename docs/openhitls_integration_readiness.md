# RFC8879 代码对 openHiTLS 主仓接入可行性评估

## 结论

当前仓库代码**不能直接作为 openHiTLS 社区仓（https://gitcode.com/openHiTLS/openhitls）可上线实现**，只能作为“协议骨架 + 单元样例”。

## 已具备能力（可复用）

- RFC8879 扩展算法列表编解码。
- 服务端按优先级与客户端算法求交集。
- `CompressedCertificate` 结构打包/解析。
- 统一算法方法表（注册/查询）。

## 阻塞项（必须补齐）

1. **未接入真实握手状态机**
   - 尚未挂接到 openHiTLS 的 ClientHello / Certificate 发送与接收链路。
2. **未使用真实压缩库**
   - 当前 `HITLS_RegisterDefaultCertCompressionMethods` 使用 demo RLE，仅用于框架验证。
3. **缺少真实配置接口映射**
   - 尚未与 `SSL_CTX`/`SSL` 级配置、配置文件项、运行时查询 API 对齐。
4. **缺少互通回归**
   - 未完成 OpenSSL/BoringSSL/NSS 互通与性能压测。

## 建议落地路径

- 第一步：把本仓库 API 映射到 openHiTLS 的握手层，先实现“协商 + 分支 + 回退”。
- 第二步：替换 demo RLE 为 zlib/brotli/zstd 真实适配器（编译宏控制）。
- 第三步：补齐负向安全测试（畸形输入、长度上限、解压不一致）。
- 第四步：执行互通矩阵与性能基线，满足门禁后再合入主干。
