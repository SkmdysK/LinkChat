# Stage Completion Matrix

**审计日期：**2026-09-05
**范围：**Link Chat v1.0 Rust kernel workspace

| 阶段 | 主要实现 | 状态 | 当前边界 |
| --- | --- | --- | --- |
| 00 | 规范审查、Lean 对照、workspace 冻结 | 完成 | `docs/protocol-freeze.md` 是历史冻结记录；协议变更仍需先更新权威规范和 Lean。 |
| 01 | 公共类型、错误模型、秘密类型、Receiver Package typed binding | 完成 | 私钥只通过受控 typed operation 使用；标准原语安全和 secure erasure 仍是外部边界。 |
| 02 | Wire 类型、canonical codec、domain separation、AAD、4096-byte Envelope、真实端点加解密组合 | 完成 | `RefinedState::process_encoded` 仍是明文 Lean 对齐入口，不是生产解密入口。 |
| 03 | CryptoProvider/Backend、Ed25519、X25519、ML-KEM-768、HKDF-SHA-256、ChaCha20-Poly1305、OS CSPRNG | 完成 | 测试不能替代 EUF-CMA、KEM/AEAD 安全证明或 CSPRNG 证明。 |
| 04 | 纯 Alice/Bob 交替状态机、replay、past/future turn、原子 package rotation | 完成 | 不含网络、磁盘、Mailbox 或 ACK 驱动状态推进。 |
| 05 | StateStorage、Current/Pending/Committed、generation、hash chain、marker、FileStateStorage、recover、fault injection | 完成 | `FileStateStorage::rollback_resistant()` 明确为 `false`；不提供 secure erasure 或跨进程锁。 |
| 06 | Transport/Mailbox traits、ACK/SACK、retry、TTL、dedup、恶意输入 harness | 完成 | 不实现生产服务器、DHT、Relay 或网络连接管理；控制帧不能推进核心状态。 |
| 07 | vectors、property、fuzz smoke、crash matrix、Lean/Rust bounded differential、真实双端测试 | 完成 | 有限轮数不能替代 Lean 全称定理、任意 PPT adversary 证明或密码学安全假设。 |
| 08 | opaque-handle FFI、稳定错误码、显式释放、caller-owned buffers、endpoint/message prepare/commit、CLI | 完成 | FFI 默认使用进程内 `MemoryEndpointStorage`；跨进程 durability 需显式 adapter。 |

## 已验证的边界

- 失败的 decode、身份/package 验证、KEM、HKDF、AEAD、payload 或 storage commit 不发布新状态。
- ACK、SACK、retry、Mailbox dedup 和 TTL 只产生传输/可用性结果，不推进 Turn、Receiver Package 或 consumed message state。
- `EndpointConfig::new_with_bootstrap_roots` 区分本地和对端 owner-bound bootstrap root；旧单 root 构造器仅为兼容便利路径。
- 阶段 07 测试覆盖 Alice/Bob 双向 Envelope、package rotation、身份签名、KEM、Header/Message AEAD 篡改和失败 no-state-change。

## 明确未实现的产品层

服务器、DHT、Relay、生产 Mailbox 服务、GUI、聊天客户端、账号系统、通用乱序、sequence/window、并发 core commit 和全球流量分析/侧信道保护不属于本 workspace 的阶段 00-08 交付物。
