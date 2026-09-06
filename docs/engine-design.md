# Link Chat Engine 设计审计与 API 草案

**阶段：**02，端点加密组合后的设计审计（历史记录）
**日期：**2026-09-05

本文档保留阶段 02 的审计结论和 API 设计依据。阶段 02 之后，
`crates/linkchat-engine`、`FileStateStorage` 和消息 FFI 已按此边界实现；
本文档中的“后续实现”“尚未创建”和“缺口”只表示当时的阶段状态，不代表当前
workspace 的最终状态。当前完成度请参阅
`docs/stage-completion-matrix.md`。

本次设计同时对齐已接受的
外部形式化项目中的 `LinkChat-v1.0-Kernel-Decisions.md`。
该决策记录优先于旧版 Rust 设计草案，尤其是生产 endpoint 的本地状态、Header
中的 signed return Receiver Package、固定 PayloadFrame 和 bootstrap package-chain root。

## 1. 审计范围与工具链

本次审阅了：

- `README.md`
- `docs/protocol-freeze.md`
- `docs/module-layout.md`
- 当前 `linkchat-types`、`linkchat-protocol`、`linkchat-crypto`、
  `linkchat-core`、`linkchat-storage`、`linkchat-transport`、
  `linkchat-mailbox`、`linkchat-ffi` 和 `linkchat-cli` 的公开入口与关键模块。

工具链为 `rustc 1.96.0`、`cargo 1.96.0`。

## 2. 缺口审计结论

| 检查项 | 当前事实 | 阶段 00结论 |
| --- | --- | --- |
| `process_encoded` | `RefinedState::process_encoded` 调用 `decode_application_message`，做 canonical re-encode 后进入纯 `step`。 | 这是明文 `WireApplicationMessage` 入口，不是 `WireEnvelope` 接收入口。不能把它描述为端到端解密。 |
| Envelope 解密链 | `EndpointKernel::prepare_receive` 已组合 `WireEnvelope -> KEM decapsulation -> hybrid HKDF -> Header AEAD -> Message AEAD -> payload validation`。 | 当前 `EndpointEngine` 再将 prepare/commit/recover 绑定到 `EndpointStorage`；FFI 使用进程内 memory adapter。 |
| package auth | `EndpointKernel::prepare_receive` 会调用 package hash/signature 验证并检查返回包链。 | 当前 engine 在初始化、恢复和接收路径保留身份、公钥 projection、上下文和过期检查。 |
| package hash chain | `verify_receiver_package` 检查 `previous_package_hash` 与调用方给定值；storage model 也检查记录 hash 和 previous hash。 | 当前支持 owner-bound 的本地/对端 bootstrap roots；storage record hash 与 protocol package hash 仍是不同校验。 |
| 生产包 secret/public 绑定 | `ReceiverPackageFactory::generate` 从同一组 X25519/ML-KEM key pair 生成 public projection，并签名/hash。 | 当前 `PrivateReceiverPackage::from_keypairs`、storage restore 和 engine 验证拒绝不匹配配对；测试-only fixture 单独受 feature 限制。 |
| StateStorage 持久化 | `FaultInjectingMemoryStorage` 建模 Current/Pending/marker、durability barrier、恢复和故障点。 | `FileStateStorage` 已提供 fsync、原子发布和恢复；rollback resistance 明确为 false。 |
| FFI 消息能力 | FFI 支持 session handle、公开 package handle、canonical package 输出和公开 metadata。 | 当前还支持 endpoint bootstrap、send/receive prepare/commit、recover、稳定错误码和 caller-owned buffers。 |
| Wire package 交付位置 | `WireHeader` 已包含 `return_receiver_package`，并在构造和编解码时校验其上下文与固定长度。 | `EndpointKernel` 已使用该字段；阶段 02 不新增 package 交付字段。 |

阶段 02 当时的结论是结构化协议内核与测试边界；当前 workspace 已具备真实
无存储 Envelope 加密组合、storage-aware engine、文件存储后端和可选消息 FFI，
但仍不是包含服务器、DHT、Relay、GUI 或生产 Mailbox 的完整产品。

## 3. 冻结的依赖方向

后续组合层遵循以下方向：

```text
linkchat-types
    -> linkchat-protocol / linkchat-crypto
    -> linkchat-core
    -> linkchat-engine
    -> storage / transport / mailbox adapters
```

在当前 workspace 中，`linkchat-storage` 依赖 `linkchat-core`，
`linkchat-transport` 与 `linkchat-mailbox` 是独立边界。未来 engine 可以
依赖这些 trait 和类型，但不能让 core 依赖 engine、storage、transport、
mailbox 或 FFI。服务器、DHT、Relay、GUI 和聊天客户端仍属于 workspace
外部的集成者。

最新决策进一步规定：`RefinedState` 保留为 Lean 对齐和差分测试模型；生产
endpoint 不拥有对端私有 Receiver Package，只保存本地私有包和已验证的对端公开包。

## 4. Engine 的责任

`linkchat-engine` 只负责将以下步骤组合成 endpoint 操作：

1. 读取当前 endpoint 状态和公开 peer context。
2. 调用 protocol 的 bounded canonical decode/encode。
3. 调用 crypto provider 完成 KEM、HKDF、nonce、AAD 和 AEAD 操作。
4. 调用 core 完成纯的消息字段检查和 `PreparedStep` 状态转换。
5. 调用 storage 的 prepare/commit/recover 事务边界。
6. 返回应用结果、公开 snapshot、需要发布的公开 Receiver Package 或稳定错误分类。

Engine 不负责：

- 监听端口、DHT、Relay、Mailbox 服务、服务器路由或重试调度；
- 添加 sequence、窗口、通用乱序、并发 core commit 或 ACK 驱动状态；
- 修改 `RefinedState::step` 的纯语义；
- 把私钥、MessageKey、KEM shared secret、storage marker 或 CSPRNG 状态暴露给调用者。

## 5. Endpoint 状态模型

生产 `EndpointKernel` 的逻辑状态仍应视为一个不可分割的本地事务对象；当前
`EndpointEngine` 将其绑定到 `EndpointStorage` 的 prepare/commit/recover 事务：

```text
EndpointKernel
    session
    local Ed25519 identity secret (opaque)
    pinned peer Ed25519 identity public key
    local current PrivateReceiverPackage
    verified peer PublicReceiverPackage
    expected application turn
    consumed MessageId set
    local package generation and protocol package hash link
    outbound turn record, if prepared
    storage binding
```

公开查询只返回 `Session`、公开 Receiver Package 和公开状态快照。私有 package
必须通过受控 typed operation 被使用，而不是拆成可由调用者重新配对的 secret、
key id 和 token。`RefinedState` 只用于验证状态投影，不作为生产 endpoint 的
双端私有状态容器。

Engine 的成功接收事务必须满足：

```text
bounded decode
-> canonical re-encode
-> envelope context/token selection
-> X25519 + ML-KEM decapsulation
-> hybrid HKDF
-> Header AEAD open
-> Header context/type/hash-chain/package-auth validation
-> Message AEAD open
-> authenticated ApplicationMessage validation
-> locally generated fresh Receiver Package
-> core PreparedStep
-> storage prepare
-> durable commit
-> retire old private material
-> deliver payload
```

任何一步失败都必须返回错误而不改变 core state、Turn、consumed IDs、
当前/待定 package、generation 或 durable Current。旧私有 material 只能
在 storage commit 成功后退休。ACK、SACK、retry、timestamp 和 mailbox
delivery metadata 不在这条状态提交链中。

## 6. API 草案

以下是阶段 02 的约束性 API 草案。当前实际实现位于
`crates/linkchat-engine/src/lib.rs`，类型名称为 `EndpointEngine<B, S>`，并保留
相同的显式 prepare/commit 状态边界。

```rust
pub struct EndpointEngine<B, S> { /* all fields private */ }

pub struct EndpointConfig { /* verified SessionBootstrap and local policy */ }

pub struct PreparedSend {
    pub envelope: WireEnvelope,
    pub bytes: EncodedBytes,
}

pub struct PreparedReceive {
    pub payload: WireBytes,
    pub returned_receiver_package: PublicReceiverPackage,
    pub public_snapshot: PublicStateSnapshot,
}

impl<B, S> EndpointEngine<B, S> {
    pub fn create(crypto: B, storage: S, config: EndpointConfig, peer: PublicReceiverPackage) -> Result<Self, EngineError>;
    pub fn public_receiver_package(&self) -> &PublicReceiverPackage;
    pub fn public_snapshot(&self) -> PublicStateSnapshot;
    pub fn prepare_send(&mut self, message: OutgoingMessage) -> Result<PreparedSend, EngineError>;
    pub fn prepare_receive(&mut self, encoded: &[u8]) -> Result<PreparedReceive, EngineError>;
    pub fn commit_send(&mut self) -> Result<(), EngineError>;
    pub fn commit_receive(&mut self) -> Result<ReceiveResult, EngineError>;
    pub fn recover(&mut self) -> Result<RecoveryOutcome, EngineError>;
}
```

`commit_send`/`commit_receive` 的具体返回值仍需与阶段 05 storage transaction
协调；它们不能通过 Transport 或 Mailbox 自动触发。实现时应优先提供 typed
`OutgoingMessage` 和 typed receive result，限制裸字节只出现在 bounded wire
输入/输出边界。发送方可以重发同一份已准备 Envelope，但不得为同一 Turn
重新生成不同 MessageId 或 KEM 材料。

错误至少需要可区分：

- `Wire`：长度、版本、套件、canonical 或 Envelope 结构错误；
- `Crypto`：KEM、HKDF、AEAD、nonce 或签名验证失败；
- `CoreRejected`：wrong turn、past/future turn、replay、token/key mismatch；
- `Storage`：prepare、durability、commit、recovery 或 rollback capability 错误；
- `Transport`/`Mailbox`：外部可用性和投递失败。

错误显示文本不得包含秘密、token、密钥材料、完整 ciphertext 或 storage
内部记录内容。恶意输入错误应尽量使用稳定分类，避免把内部验证顺序
变成不必要的 oracle。

## 7. 各阶段的前置工作

阶段 00/02 当时停止在设计层，后续依赖如下；当前矩阵记录这些依赖的实现状态：

| 后续阶段 | Engine 所需前置能力 |
| --- | --- |
| 01 | 实际 X25519/ML-KEM private material、不可任意配对的 package 类型、身份公钥绑定、package hash/auth/expiration/chain 校验和 bootstrap root。 |
| 02 | `WireEnvelope` 全链路的 KEM/KDF/Header AEAD/Message AEAD 组合、固定 PayloadFrame 和 4096-byte canonical envelope。 |
| 03 | 稳定的 CryptoProvider/Backend API、低阶点/全零共享输出、nonce、RNG 和失败映射契约。 |
| 05 | 真实持久化 backend 或明确的 adapter capability，支持 endpoint-local private state、durable prepare/commit/recover 与 rollback-resistant 声明。 |
| 06 | 只传递 packet/event 的 Transport/Mailbox traits；ACK/SACK 不得触发 Engine 状态提交。 |
| 08 | 以 endpoint handle、显式释放、稳定错误码和 caller-owned buffers 扩展 FFI；不跨 ABI 传递 Rust `Vec`、trait object、借用引用或私钥。 |

## 8. 未决项与阻塞项

当前没有因协议字段位置而产生的新增猜测；`return_receiver_package`、固定
PayloadFrame 和 package-chain root 已由最新决策记录确定。以下是实现前置缺口，
不是允许修改协议架构的理由：

1. 规范、Lean、Kernel Decisions 和现有 Rust 的具体 wire schema 仍需在变更时
   继续逐项核对；当前 `WireHeader.return_receiver_package` 已是既有交付位置。
2. Lean 使用抽象 `SecretState` 和 `Nat`，没有覆盖真实 key bytes、4096-byte
   envelope、generation、durability 和 rollback resistance。Rust 测试不能
   把这些差异描述成 Lean 定理。
3. 普通文件系统的 rollback resistance、安全擦除和跨进程协调仍不是
   `FileStateStorage` 可以声明的能力；需要外部平台后端。
4. FFI endpoint 当前绑定 `MemoryEndpointStorage`，要实现跨进程持久化必须
   提供明确的 `EndpointStorage` adapter，不能把 memory backend 当作 durability。

## 9. 信任边界

Rust 代码可以检查 bounded allocation、canonical encoding、字段绑定、
状态机 no-state-change、typed secret 隔离和 trait 调用顺序。以下性质
仍是外部或实现后端的信任边界：

- Ed25519、X25519、ML-KEM-768、HKDF、ChaCha20-Poly1305 的标准密码学安全假设；
- 密码库实现和其侧信道行为；
- OS CSPRNG 的不可预测性和可用性；
- 真实文件系统的 fsync、原子发布、崩溃一致性、回滚抵抗和安全擦除；
- Transport/Mailbox 的可用性、延迟、丢包、重放、篡改和服务器隔离；
- FFI/WASM 调用方对指针、长度、生命周期和 caller-owned buffer 的遵守；
- 测试轮数、fuzz、property 和 bounded differential conformance 不替代任意 PPT adversary 证明或密码学安全证明。

## 10. 阶段 00范围结论

阶段 00/02 的历史交付只包含审计、冻结和 API 设计；当前实现已经创建并使用
`crates/linkchat-engine`，没有新增协议字段，也没有实现服务器、网络、DHT、
Relay、GUI 或聊天客户端。此处的历史范围结论不应覆盖当前阶段 01-08 的实现状态。
