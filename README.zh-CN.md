# LinkChat Rust 内核

**中文** | [English](README.md)

LinkChat Rust Kernel 是 LinkChat v1.0 协议的可执行研究工件，包含带类型约束的
Rust 实现，以及对协议精化状态转换模型的 Lean 形式化。

本仓库面向协议研究者、密码工程师、形式化方法研究者和独立实现者，提供一个小型、
可审计、集成边界明确的协议内核，而不是完整聊天产品。

## 研究范围

LinkChat 研究一种严格交替的端到端协议：每个端点独立控制自己的私有 Receiver
State，只发布经过密码学绑定的 Receiver Package 公共投影。对端可以提交经过认证的
消息，但不能选择诚实端点的下一个私有状态，也不能通过传输层行为推进应用轮次。

实现内容包括：类型化协议值；canonical wire 编解码；域分离 HKDF-SHA-256 和显式
AAD；Ed25519 身份认证；X25519 与 ML-KEM-768 混合密钥建立；ChaCha20-Poly1305；
严格 Alice/Bob 轮次交替；重放拒绝；失败不改状态；Current/Pending/Committed 存储
契约；以及 ACK、SACK、重试和去重不能推进协议状态的 Transport/Mailbox 接口。

仓库还包含验证向量、恶意输入测试、崩溃矩阵、有界 Rust/Lean 一致性检查、可选
opaque-handle C ABI 和开发 CLI。

本项目是协议内核和集成参考实现，不是聊天客户端、服务器、中继、DHT、GUI、账户
系统、身份提供商或生产 Mailbox 服务。

## 分层架构

```text
linkchat-types
    -> linkchat-protocol / linkchat-crypto
    -> linkchat-core
    -> linkchat-engine
    -> 由应用负责的 storage / transport / mailbox adapter
```

`linkchat-core` 只包含纯协议状态转换，不执行网络、Mailbox 或文件系统 I/O。
`linkchat-engine` 负责组合密码学、核心状态转换、存储和外层适配器，但不会把部署
逻辑塞进纯状态机。

## 安全边界与信任边界

代码实现了有界解析、canonical 重新编码检查、package 身份绑定、session/cipher
suite/turn/generation 校验、混合密钥派生、AEAD 认证和持久化提交顺序。接收路径必须
在准备新状态前完成 Envelope 与 package 验证，并在旧私有材料退休前完成 durable commit。

私钥、Receiver State、消息密钥、KEM shared secret 和其他秘密材料都通过类型化 API
隔离。可选 FFI 使用 opaque handle、稳定错误码和显式释放函数，不会跨 ABI 暴露 Rust
Vec、trait object、借用引用或私钥原始 bytes。

安全声明只覆盖明确写出的实现和模型边界。本仓库不替代对标准密码学原语、操作系统
CSPRNG、安全擦除、侧信道、文件系统 rollback resistance 或具体部署的安全分析。
需要 rollback resistance 的后端必须提供并诚实声明适当的平台级机制。

接入前请阅读 [`SECURITY.md`](SECURITY.md) 和配套协议规范。

## 构建与验证

工作区通过 `rust-toolchain.toml` 固定 Rust `1.96.0`。

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

可选开发命令：

```bash
cargo run -q -p linkchat-cli -- keygen
cargo run -q -p linkchat-cli -- pair 77
cargo run -q -p linkchat-cli -- test-vector
```

Lean 文件属于研究和一致性工件。有界测试和有限轮探索只说明已检查的情况，不能替代
任意对手密码学证明，也不能替代具体安全归约中的安全假设。

## 目录说明

| 路径 | 用途 |
| --- | --- |
| `crates/linkchat-types` | 公共标识符、长度、错误和秘密包装类型 |
| `crates/linkchat-protocol` | Wire 类型、canonical codec、domain、AAD 和 payload |
| `crates/linkchat-crypto` | CryptoProvider trait 和标准密码学后端 |
| `crates/linkchat-core` | 纯精化状态机和 Envelope 语义 |
| `crates/linkchat-engine` | crypto、core、storage 和 adapter 的组合层 |
| `crates/linkchat-storage` | 内存与文件存储契约 |
| `crates/linkchat-transport` | Transport trait、ACK/SACK、重试和恶意测试 |
| `crates/linkchat-mailbox` | Mailbox trait 和内存测试实现 |
| `crates/linkchat-verification` | 向量、fuzz smoke、崩溃测试和一致性检查 |
| `crates/linkchat-ffi` | 可选稳定 opaque-handle C ABI |
| `crates/linkchat-cli` | 可选开发与集成 CLI |
| `formalization/` | Lean 状态模型、游戏、归约和标准配置 |
| `docs/` | API、集成、存储、FFI 和阶段文档 |
| `vectors/` | 协议与恢复公开测试向量 |

## 配套研究仓库

与语言无关的规范、研究论文、规范术语、wire format、security model 和公开 JSON
向量维护在配套的 [`LinkChatDocuments`](https://github.com/SkmdysK/LinkChatDocuments)
仓库中。

实现新版本时，建议先阅读规范，再使用公开向量核对 wire 与状态机行为，最后选择存储
和传输适配器。

## 状态与许可证

这是一个带有明确非目标和外部安全假设的冻结研究内核版本，不代表无条件的生产就绪
或完整安全保证。

本项目采用 MIT License，详见 [`LICENSE`](LICENSE)。
