# Link Chat v1.0 Protocol Freeze

**阶段：**00，规范审查、冻结与 workspace 初始化
**日期：**2026-09-05
**适用版本：**Link Chat v1.0-standardized

> **历史范围说明：**本文档记录阶段 00 的冻结审查，不代表当前 workspace
> 仍停留在“只记录、不实现”的阶段。当前实现状态和已完成阶段请参阅
> `docs/stage-completion-matrix.md`。

> **Kernel Amendment (2026-09-05):** The authoritative protocol now defines
> endpoint-local production state, Header-carried signed return Receiver
> Packages, bootstrap package-chain roots, fixed encrypted payload frames, and
> no production ACK/SACK API. The full accepted decision record is maintained
> in the external formalization project at `LinkChat-v1.0-Kernel-Decisions.md`.
> This workspace must implement that record before it is described as v1.0
> interoperable.

本文档只冻结阶段 00 已由协议规范、Lean 模型和项目计划共同支持的边界。它不实现业务逻辑、真实密码后端、磁盘、网络或 FFI。

## 权威输入

审查优先级为：协议规范 > Lean 形式化模型 > `project.md` > Rust 实现细节。

已检查文件：

- `project.md`（外部项目规范）
- `LinkChat-Standardized-v1.0.md`（外部协议规范）
- `LinkChat.lean`（外部 Lean 模型）
- `RefinedProtocol.lean`（外部 Lean 精化模型）
- `README.md`（本仓库）

外部形式化项目中的规范副本经过 SHA-256 一致性检查；本仓库只记录其文件名和优先级，不依赖开发机路径。

## 冻结的协议身份与状态字段

### 会话与顺序

| 概念 | 冻结语义 |
| --- | --- |
| `SessionId` | 会话绑定标识；所有相关 KDF、Hash、AEAD AD、签名上下文和消息检查必须绑定会话。具体 Rust 表示留给阶段 01。 |
| `Turn` | 非负、严格按 `Alice -> Bob -> Alice -> Bob -> ...` 交替；偶数 Turn 的 Leader 是 Alice，奇数 Turn 的 Leader 是 Bob。 |
| `MessageId` | Session 内唯一；成功处理后进入 `consumed_message_ids`，重复消息不得再次处理或提交。 |
| `KeyId` | 当前 Receiver Package 的公开密钥标识；必须与会话、Turn、Package 和消息上下文绑定。不能与 `MessageId` 或 `MailboxToken` 隐式互换。 |
| `MailboxToken` | OS CSPRNG 产生的 32-byte 一次性 Mailbox capability；不是 Message Key，也不是身份认证替代品。 |
| `PackageGeneration` / generation | Receiver Package 的本地代际元数据；成功轮换必须严格递增，旧代不能覆盖新代。规范明确要求 generation，但当前 Lean `RefinedState` 未单独建模该字段。 |

### Application 与 Receiver Package

`ApplicationMessage` 只允许包含规范和当前 Lean 模型已经定义的应用消息字段。Lean 中的 `RefinedMessage` 字段为：

```text
sessionId, turn, direction, messageId, receiverKeyId, receiverToken, payload
```

规范的认证 Header 另外包含：

```text
protocol_version, cipher_suite, session_id, turn, direction,
message_id, receiver_key_id, message_type,
sender_package_hash, receiver_package_hash
```

`message_id` 位于加密 Header 内，不是 Envelope 的明文字段。`ack_info`
不属于 Application Header；交付回执仍由 Transport/Control 层独立表达。

Receiver Package 是一个原子逻辑单位，必须区分私有包和公开 projection：

```text
PrivateReceiverPackage
    X25519 private key
    ML-KEM private key
    local generation metadata
    corresponding public package

PublicReceiverPackage
    session_id
    turn
    key_id
    X25519 public key
    ML-KEM public key
    mailbox_token
    expiration
    previous_package_hash
    package_auth
```

公开 projection 绝不包含 Receiver private key、旧 Message Key、CSPRNG 内部状态或其他本地秘密。Secret、public key、KeyId、Token 和 generation 不得由调用方分别提交或部分轮换。

### Envelope、ACK 与 Mailbox

规范定义的 `Envelope` 字段为：

```text
mailbox_token
x25519_kem_ciphertext
mlkem_ciphertext
encrypted_header
ciphertext
padding
```

固定总长度冻结为 **4096 bytes**。超出预算必须由规范定义的分片机制处理；不得静默改变 Envelope 格式。本阶段只记录预算约束，不实现编码或 padding。

`AckFrame` / `SackFrame` 只属于 Transport/Control 层：

```text
ACK: session_id, turn, direction, message_id, delivery_status
SACK: optional base, bitmap
```

ACK/SACK、retry、transport dedup、transport timestamp、Mailbox 可用性和投递状态不得推动核心 `Turn`、Receiver State、Receiver Package、Message Key generation 或 consumed-message 状态。ACK replay 只能得到独立的传输结果。

`MailboxRecord` 属于 Mailbox 层。Mailbox 是不可信的 key-value 边界，可以 drop、delay、duplicate、replay、modify、withhold 或返回任意字节；协议不承诺其可用性。TTL、过期、最大记录大小、最大返回数量、dedup 和错误不可用语义必须由后续 Mailbox trait 契约明确。

### Header AAD 与接收顺序

Header AEAD 的 AAD 必须在 Header 解密前可构造，因此 v1 的 `HeaderAD`
严格只绑定以下外层字段：

```text
protocol_version
cipher_suite
session_id
turn
direction
receiver_key_id
```

它不包含位于加密 Header 内的 `message_id`。接收顺序冻结为：

```text
derive HeaderKey/HeaderNonce
-> construct HeaderAD without message_id
-> Header AEAD open
-> validate canonical Header and all Header fields, including message_id
-> construct MessageAD with authenticated message_id
-> Message AEAD open
-> pending state
-> atomic commit
```

Header AEAD 对完整加密 Header（包括 `message_id`）提供认证；MessageAD
继续绑定 `message_id`，所以该裁决不新增 Envelope 字段，也不改变固定
4096-byte 布局。

## 冻结的密码套件与域分离

| 用途 | 冻结构件 |
| --- | --- |
| 长期身份认证 | Ed25519 |
| 经典 Receiver key | X25519 KeyGen |
| 经典封装 | X25519-based ephemeral DH/KEM wrapper |
| 后量子 Receiver key / 封装 | ML-KEM-768 |
| 密钥派生 | HKDF-SHA-256 |
| Hash | SHA-256 |
| 可选 MAC | HMAC-SHA-256 |
| 消息、Header、ACK 加密 | ChaCha20-Poly1305 |
| Receiver key、ephemeral key、Mailbox Token 随机性 | OS CSPRNG |

冻结的 domain labels：

```text
LinkChat/bootstrap/v1
LinkChat/hybrid/v1
LinkChat/message/v1
LinkChat/header/v1
LinkChat/nonce/v1
LinkChat/header-nonce/v1
LinkChat/ack/v1
LinkChat/path/v1
LinkChat/package-hash/v1
LinkChat/receiver-package-auth/v1
LinkChat/transcript-hash/v1
LinkChat/token-mac/v1
LinkChat/identity-signature/v1
```

Hybrid 输入使用 canonical context 绑定 `protocol_version`、`cipher_suite`、`session_id`、`turn`、接收方 `key_id`、X25519 ciphertext 和 ML-KEM ciphertext 及其 shared secrets；`PRK_hybrid` 使用 32-byte zero salt 的 HKDF-Extract。Message Key、Header Key、Nonce 和各类 AD 必须使用独立 domain，并绑定规范要求的 Session、Turn、Direction、KeyId、MessageId 等上下文。

Nonce 规则冻结为：Message nonce 是从 `HKDF-Extract(zero salt, MK)` 对 `LinkChat/nonce/v1` 上下文做 HKDF-Expand 后取 12 bytes；Header nonce 使用独立的 `LinkChat/header-nonce/v1` domain。调用方不得随意复用 nonce。

本阶段不选择密码库、版本或 feature，不实现 X25519 低阶点/全零共享输出处理，也不声称标准原语的计算安全性已经由 Rust 骨架证明。

## Canonical encoding 冻结边界

规范只冻结以下高层要求：

```text
type-tag || field-count || length-prefixed fields
```

编码必须唯一、确定、版本化，不依赖运行时内存布局；整数端序、长度编码、枚举数值、字段顺序、字段数量、未知字段策略、总长度和嵌套深度必须在实现前明确。Decode 必须先执行边界检查，拒绝截断、整数溢出、超长分配、非 canonical 输入、未知版本、错误套件和缺失必需字段。

Package hash 必须对 `CanonicalEncode("LinkChat/package-hash/v1", PackageBody)` 做 SHA-256；package auth 必须对 `CanonicalEncode("LinkChat/receiver-package-auth/v1", PackageBody)` 做 Ed25519 签名。Transcript hash 必须独立使用 `LinkChat/transcript-hash/v1`。

## 核心状态与 I/O 边界

纯核心只允许表达状态检查和状态转换：

```text
bounded decode
-> canonical/version/suite check
-> session/turn/key/token/message-id check
-> package/signature/identity binding validation
-> KEM/KDF
-> AEAD open
-> authenticated payload validation
-> local fresh ReceiverPackage
-> pending state
-> atomic commit
```

任何失败都必须 no-state-change：不改变秘密包、公开 projection、Turn、generation、consumed IDs 或持久状态。成功消息恰好推进一个 Turn，并将接收方的完整 Receiver Package 原子轮换为本地新鲜生成的包。Peer input、peer randomness、peer ciphertext、peer payload、ACK 或 path state 不能直接决定下一份本地 Receiver Secret。

`StateStorage` 必须表达 `load_current`、`prepare_commit`、`commit`、`recover`。持久记录至少区分 Current、Pending、Committed marker、generation、session id、turn、package hash、previous package hash、consumed IDs 和当前/前一 Receiver Package。提交顺序冻结为：

```text
校验并写入 Pending
-> durability barrier / fsync
-> 写入 commit marker
-> durability barrier / fsync
-> 原子发布为 Current
-> durability barrier / fsync
```

恢复只能选择完整旧 Current 或完整新 Committed 状态；Pending 未完成时不能冒充 Current。Rollback-resistant 是生产后端要求；安全擦除、fsync、原子 rename、硬件存储和 crash consistency 属于外部实现契约。

Transport 只传递原始 packet/event 和 delivery/retry/timestamp 元数据；Mailbox 只提供 token-keyed record 的 put/get 及其契约。两者不能直接写入核心 Receiver State，也不能把网络或磁盘框架带入纯状态机。

## Lean 对应关系与范围

`LinkChat.lean` 提供：

- `Endpoint`、`leader` 和严格交替。
- `ProtocolState`、`Message`、`valid`、`commit`、`step`。
- 非法输入 no-op、成功恰好推进一 Turn、消费 `messageId`、重放拒绝、过去/未来 Turn 拒绝和 peer-input non-interference。
- 抽象 `KEM` interface correctness，以及 hybrid/message/header key 的接口级正确性。

`RefinedProtocol.lean` 补充：

- `ReceiverPackage { secret, keyId, mailboxToken }`。
- `RefinedState`、`RefinedMessage`、`refinedValid`、`refinedCommit`、`refinedStep`。
- 私有 secret 与公开 key/token projection 作为包原子轮换。
- `refinedInvalidNoop`、`refinedReplayRejected`、`refinedKeyProjectionRotatesWithSecret`、`refinedPeerInputNonInterference`、`refinedContinuousCompromiseTrace` 及 Alice/Bob 对称结论。

Lean 模型使用 `Nat` 和抽象 `SecretState`，没有具体字节长度、4096-byte Envelope、真实密码实现、sequence、窗口、通用乱序、并发提交、ACK 状态推进或 crash durability 语义。Rust v1.0 不得自行加入这些缺失的核心语义。

## 未决冲突与推迟事项

以下内容在权威材料中没有形成足够具体且完全一致的可实现契约，因此阶段 00 不自行决定：

1. **外部规范副本。** 权威规范和 Lean 文件由外部形式化项目维护；集成者应通过版本化依赖或发布归档提供它们，不应依赖开发机绝对路径。
2. **Canonical 数值编码未冻结。** 规范推荐 `type-tag || field-count || length-prefixed fields`，但没有冻结 type tag 数值、field-count 的宽度/端序、长度整数宽度/端序、枚举编码、未知字段的精确处理规则或嵌套深度上限。
3. **Wire 字段表不完整。** 规范给出 Envelope、Header、公开 Receiver Package 和 ACK/SACK 的部分字段，但没有完整冻结 `WireApplicationMessage`、`WireMailboxRecord`、所有错误结果和 `message_type` 的逐字段 schema。
4. **`ApplicationMessage` 与 Header 的边界。** Lean 的 `RefinedMessage` 有 `payload`，规范 Header 的 `message_type` 属于加密 Header；`ack_info` 已明确不属于 Application Header，而是 wire-only 的 Transport/Control 元数据。永久约束要求 ACK/SACK 与应用层分离，故不纳入核心应用状态。
5. **Generation 与 Lean 不对齐。** 规范和 project.md 要求 generation、hash chain 和 rollback-resistant storage；`RefinedState` 只显式建模 package 的 secret/keyId/token，没有 generation、package hash、expiration 或 pending/current marker。Rust 可以记录为存储/包元数据，但不得声称已有 Lean 定理覆盖这些字段。
6. **Grace Window 未定量化。** 规范允许有限旧消息 Grace Window，但当前 Lean 只接受 `m.turn = s.turn`，没有 previous package、时间或窗口语义。阶段 00 冻结“不将窗口/乱序加入核心”；具体兼容策略须先补规范与 Lean。
7. **StateStorage 生产实现未定。** 提交顺序明确，但真实 fsync、原子发布、rollback resistance 和安全擦除能力依赖具体平台/文件系统；阶段 00 不实现或证明这些性质。
8. **密码库与失败策略未定。** 原语和 ML-KEM-768 已冻结，但密码库版本、X25519 低阶点/全零输出策略、ML-KEM 解封装统一错误映射、deterministic test RNG API 尚未冻结；阶段 03 再定义，不能在骨架中假定。
9. **错误分类未逐项定稿。** project.md 要求区分调用者错误、恶意输入、密码失败和存储失败，同时规范要求避免详细失败 Oracle；阶段 01/02/03/05 必须据此设计稳定且不泄露秘密的 typed errors。

这些事项是实现前的规格工作，不是本阶段的 Rust 业务实现。任何会改变协议语义的解决方案都必须先同步规范和 Lean 模型。

## 明确不实现

阶段 00 及 v1.0 Rust 内核范围不包含：

- 服务器、DHT、Relay、Onion 网络运营或 GUI/聊天客户端。
- sequence number、滑动窗口、通用乱序合并、并发提交、多消息并行核心语义。
- ACK/SACK 驱动 Turn、Receiver State、Receiver Package 或 Message Key rotation。
- 真实密码学后端、密码算法自造实现、磁盘存储、fsync、网络栈、Mailbox 服务或 FFI。
- 将测试、模拟轮数或 property/fuzz 结果表述为 Lean 普遍证明或 primitive/storage/CSPRNG 安全证明。

## 外部信任边界

以下性质不能由当前 Rust workspace 骨架或当前 Lean 模型单独证明：

- 线下身份验证及 Ed25519/X25519/ML-KEM 标准实现的计算安全性。
- X25519 wrapper、ML-KEM-768、HKDF-SHA-256、SHA-256、HMAC-SHA-256、ChaCha20-Poly1305 的具体安全保证和常数时间实现。
- OS CSPRNG 的不可预测性、密钥生成新鲜性、秘密内存保护和安全擦除。
- 文件系统的 fsync、原子 rename、crash consistency、rollback resistance 和硬件持久性。
- 外部 Transport/Mailbox 的可用性、隐私、路由匿名性、TTL 执行和恶意输入行为。
- 当前模型未覆盖的具体 wire 编码互操作性、bounded allocation 参数和完整错误 side-channel 分析。
