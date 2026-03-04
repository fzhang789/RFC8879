# RFC8879 兼容性测试清单（openHiTLS）

## 1. 功能正确性

- [ ] 客户端发送 `compress_certificate(27)` 扩展。
- [ ] 服务端成功解析算法列表。
- [ ] 协商成功时发送 `CompressedCertificate`。
- [ ] 未协商成功时回退发送 `Certificate`。

## 2. 算法覆盖

- [ ] zlib 压缩/解压成功。
- [ ] brotli 压缩/解压成功。
- [ ] zstd 压缩/解压成功。

## 3. 负向与安全

- [ ] 扩展长度非法（奇数）拒绝。
- [ ] 未注册算法拒绝解压。
- [ ] `uncompressed_length` 不匹配触发告警并失败。
- [ ] 畸形压缩数据握手失败。
- [ ] 超过最大证书消息长度直接失败。

## 4. 互通测试

- [ ] openHiTLS(client) ↔ OpenSSL(server)
- [ ] OpenSSL(client) ↔ openHiTLS(server)
- [ ] openHiTLS ↔ 不支持 RFC8879 的 TLS 端点（回退验证）

## 5. 性能

- [ ] 记录压缩率：`raw_size / compressed_size`。
- [ ] 记录握手 CPU 时间。
- [ ] 记录握手总耗时与峰值内存。
