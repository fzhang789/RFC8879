# RFC8879 接入 openHiTLS 社区仓实操指南

目标社区仓：<https://gitcode.com/openHiTLS/openhitls>

本文档用于把当前 `RFC8879` PoC 代码以“可评审补丁”形式接入 openHiTLS 社区流程，重点是：

- 先合并协议骨架（低风险）。
- 再逐步合并真实算法适配（zlib/brotli/zstd）。
- 最后补齐互通与性能门禁。

## 1. 建议的提交流程（社区友好）

1. 在 GitCode 上 fork `openHiTLS/openhitls`。
2. 从主干新建特性分支（例如 `feature/rfc8879-cert-compress-m1`）。
3. 仅提交最小闭环能力（建议按 M1~M4 拆分）。
4. 提交 MR 时附上：
   - 设计说明（为何这样接入握手状态机）；
   - 风险评估（回退逻辑、最大解压长度）；
   - 测试证据（单测、互通、性能基线）。

## 2. 推荐分 4 个 MR 逐步接入

### MR-1（M1）：协议骨架与握手分支

- 接入 `compress_certificate(27)` 扩展解析/编码。
- 增加客户端宣告、服务端选择算法逻辑。
- 在证书发送/接收路径增加 `Certificate` vs `CompressedCertificate` 分支。
- 暂不引入真实第三方压缩库，保留空实现或 demo 实现。

### MR-2（M2）：zlib 首通

- 增加 `HITLS_HAVE_ZLIB` 编译宏与构建选项。
- 完成 zlib `compress/decompress` 适配。
- 打通 openHiTLS ↔ OpenSSL 的基础互通场景。

### MR-3（M3）：brotli / zstd 与配置接口

- 增加 `HITLS_HAVE_BROTLI`、`HITLS_HAVE_ZSTD`。
- 支持 `SSL_CTX`/`SSL` 级别启停与算法列表配置。
- 增加算法优先级和发送阈值策略。

### MR-4（M4）：安全与性能门禁

- 负向测试：畸形扩展、算法未注册、数据截断、长度不一致。
- DoS 防护：`uncompressed_length` 上限、解压失败及时终止握手。
- 性能测试：证书链大小分档对比（1KB/4KB/16KB/64KB）。

## 3. 与本仓 RFC8879 PoC 的映射关系

当前仓可优先复用下列内容并迁移到 openHiTLS 主仓：

- API/常量定义：`include/hitls_cert_compress.h`
- 协议编解码与算法注册骨架：`src/hitls_cert_compress.c`
- 测试规划模板：`tests/test_plan_rfc8879.md`

建议迁移策略：先保留接口和流程，再替换 demo RLE 为真实库适配。

## 4. 提交到社区时建议使用的 MR 模板（可直接拷贝）

```markdown
### 背景
实现 RFC 8879 证书压缩能力，降低证书链传输体积，优化 TLS 1.3 握手耗时。

### 本 MR 范围
- [ ] 扩展编解码
- [ ] 协商逻辑
- [ ] 发送/接收路径分支
- [ ] 算法适配（zlib/brotli/zstd）
- [ ] 配置接口
- [ ] 测试与性能数据

### 兼容性与风险
- 对未宣告扩展的对端保持回退到 Certificate。
- 解压长度上限保护：<= 16MB（可配置）。
- 解压失败视为握手失败，避免不一致状态。

### 测试
- 单元测试：
- 互通测试：
- 性能测试：
```

## 5. Git 命令参考（本地到社区）

> 以下命令在 openHiTLS 主仓本地克隆目录中执行。

```bash
git remote -v
git checkout -b feature/rfc8879-cert-compress-m1
# 复制并改造 RFC8879 相关文件后：
git add .
git commit -m "feat(tls13): add RFC8879 cert compression skeleton"
git push origin feature/rfc8879-cert-compress-m1
```

随后在 GitCode 网页发起 MR 到 `openHiTLS/openhitls` 主干分支。
