# Link Chat Protocol Specification v1.0

## Standardized Cryptographic Primitive Edition

**中文名称：基于物理信任锚点、接收端状态隔离、严格交替异步匿名通信的标准密码学协议**

**版本：v1.0-standardized**

**文档用途：**这是 Link Chat v1.0 的完整文字协议。它保留原协议的通信架构和状态机，只把内部密码学运算替换为标准密码学原语，供实现、形式化验证和后续查询使用。

---

# 0. 架构摘要

Link Chat v1.0 的固定架构为：

```text
安全线下物理信任
        ↓
Ed25519 身份绑定
        ↓
S0 / HKDF Bootstrap
        ↓
Alice Receiver State       Bob Receiver State
        ↓                           ↓
X25519 + ML-KEM Receiver Package
        ↓
严格交替 Turn
        ↓
X25519 KEM wrapper + ML-KEM
        ↓
HKDF-SHA-256 HybridSecret
        ↓
HKDF Message/Header/Nonce Key
        ↓
ChaCha20-Poly1305
        ↓
一次性随机 Mailbox Token
        ↓
不可信 DHT Mailbox
        ↓
匿名多跳传输
```

本版本不改变：

1. Alice 和 Bob 各自独立拥有 Receiver Secret State。
2. Receiver Secret State 永不跨设备直接共享。
3. Turn 严格按照 `Alice → Bob → Alice → Bob → ...` 交替。
4. 只有当前 Leader 可以发起新的 Application Turn。
5. 接收成功后，接收端本地生成新的 Receiver Package。
6. 消息经 DHT 异步传输，不要求双方同时在线。
7. Token 是 Mailbox capability，不承担 Message Key 职责。
8. 普通消息不使用长期身份签名。

---

# 1. 设计目标

## 1.1 初始身份可信

Alice 和 Bob 通过安全线下接触确认：

```text
Alice Identity Key ↔ Alice Device
Bob Identity Key   ↔ Bob Device
```

身份公钥使用 Ed25519，线下物理验证仍然是初始信任根。

## 1.2 消息前向安全

每条消息使用独立 Message Key。消息处理完成后，历史 Message Key 应被安全删除。未来状态泄露不应恢复已经删除的历史消息密钥或明文。

## 1.3 短暂失陷后的恢复

端点从短暂失陷中恢复后，必须使用新的 OS CSPRNG 输出生成新的 Receiver Package，而不能从对端输入或旧 Receiver State 直接派生。

## 1.4 单端点持续失陷隔离

当 Alice 被持续控制而 Bob 保持诚实时，攻击者可以完全控制 Alice 的本地状态和协议输入，但不能仅凭 Alice 的状态计算 Bob 后续独有的 Receiver Secret State。反方向同理。

## 1.5 匿名异步通信

消息允许按以下流程传输：

```text
发送方 PUT(token, envelope)
        ↓
不可信 DHT 保存
        ↓
接收方未来 GET(token)
```

网络传输使用动态多跳路径降低端点身份和直接网络位置暴露。

---

# 2. 安全边界

## 2.1 被完全攻陷端的本地明文

如果端点已经被完全控制，攻击者可以读取屏幕、明文、应用内存和本地状态。协议不承诺保护已进入被攻陷端点的明文。

## 2.2 双端同时完全失陷

如果 Alice 和 Bob 同时完全失陷，双方本地秘密可能全部暴露。

## 2.3 全球被动流量分析

协议不保证全球被动攻击者无法通过 timing、volume、intersection 或 burst pattern 进行长期相关分析。固定长度封装和多跳传输只提供缓解。

## 2.4 线下初始化被攻击

如果攻击者可以观察或篡改二维码、控制交换设备、冒充通信对象或干扰物理验证，初始信任锚点可能失效。

---

# 3. 标准密码学套件

| 协议用途 | 标准原语 |
| --- | --- |
| 长期身份认证 | Ed25519 |
| 经典接收端密钥 | X25519 KeyGen |
| 经典消息密钥封装 | X25519-based ephemeral DH/KEM wrapper |
| 后量子接收端密钥 | ML-KEM KeyGen |
| 后量子消息密钥封装 | ML-KEM |
| 密钥派生 | HKDF-SHA-256 |
| Hash | SHA-256 |
| 消息加密 | ChaCha20-Poly1305 |
| Header 加密 | ChaCha20-Poly1305 |
| ACK 加密 | ChaCha20-Poly1305 |
| 可选 MAC | HMAC-SHA-256 |
| Receiver Key 随机生成 | OS CSPRNG |
| Mailbox Token | OS CSPRNG 生成的 32-byte capability |
| Nonce | HKDF-SHA-256 派生 |

部署时必须固定 ML-KEM 参数集。本版本默认使用：

```text
ML-KEM-768
```

如果部署选择其他参数集，必须写入 `CipherSuite` 并在整个 Session 内保持不变。

---

# 4. Canonical Encoding 与 Domain Separation

## 4.1 Canonical Encoding

所有结构必须经过唯一、确定性的字节编码。不得使用语言运行时对象的内存布局。

```text
Byte = 8-bit unsigned integer
ByteString = finite byte sequence
```

推荐编码形式：

```text
type-tag || field-count || length-prefixed fields
```

整数使用固定端序，长度使用固定定义的无符号编码，枚举使用协议规定的固定数值。

## 4.2 KDF Domain

所有不同用途的 KDF 必须使用不同 domain：

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
LinkChat/transcript-hash/v1
LinkChat/token-mac/v1
LinkChat/identity-signature/v1
```

Domain label 必须作为 canonical encoded `info` 或输入前缀的一部分参与运算。

---

# 5. 基本术语

## 5.1 Identity Key

```text
IK_priv
IK_pub = Ed25519.PublicKey(IK_priv)
```

用途：初始线下身份验证、Receiver Package 生命周期认证、身份变更检测和重新配对。

普通聊天消息不附加长期 Ed25519 签名。

## 5.2 Receiver Secret State

```text
ARS_i = Alice Receiver Secret State at generation i
BRS_i = Bob Receiver Secret State at generation i
```

Receiver Secret State 包含本端的 X25519 私钥、ML-KEM 私钥以及本地生成元数据。它永不通过网络直接传输。

## 5.3 Receiver Public State

```text
RP_i = {
    classical_public_key,
    pq_public_key,
    key_id,
    mailbox_token,
    turn,
    expiration,
    previous_package_hash,
    package_auth
}
```

公开包不得包含 X25519 私钥、ML-KEM 私钥或 OS CSPRNG 内部状态。

## 5.4 Turn

```text
Turn 0
Turn 1
Turn 2
...
```

```text
Leader(t) = Alice, if t mod 2 = 0
Leader(t) = Bob,   if t mod 2 = 1
```

## 5.5 Mailbox Token

Mailbox Token 是一次性随机 DHT capability：

```text
T_i ← OS-CSPRNG(32 bytes)
```

Token 不是 Message Key，也不作为 KDF 密钥使用。

## 5.6 Message Key

```text
MK_i = 32-byte ChaCha20-Poly1305 key
```

每条 Application Message 使用独立的 `MK_i`。

## 5.7 Receiver Package

```text
ReceiverPackage = {
    session_id,
    turn,
    key_id,
    x25519_public_key,
    mlkem_public_key,
    mailbox_token,
    expiration,
    previous_package_hash,
    package_auth
}
```

对应的秘密包还包含 X25519 private key、ML-KEM private key 和公开包。秘密包只在拥有者设备存在。

---

# 6. 线下初始信任建立

## 6.1 交换内容

Alice 和 Bob 通过安全线下接触交换：

```text
ProtocolVersion
CipherSuite
IdentityPublicKey_A
IdentityPublicKey_B
SessionID
S0
InitialReceiverPublicPackage_A
InitialReceiverPublicPackage_B
InitialPathState
```

## 6.2 物理身份验证

双方确认：

```text
Alice ↔ Alice Device
Bob   ↔ Bob Device
```

并验证双方 Ed25519 公钥指纹、ProtocolVersion、CipherSuite 和 SessionID。

## 6.3 身份绑定签名

```text
binding = CanonicalEncode(
    "LinkChat/identity-binding/v1",
    protocol_version,
    cipher_suite,
    session_id,
    identity_public_key_A,
    identity_public_key_B
)
```

```text
sig_A = Ed25519.Sign(IK_priv_A, binding)
sig_B = Ed25519.Sign(IK_priv_B, binding)
```

线下指纹验证仍是信任根，Ed25519 是标准签名实现。

---

# 7. S0 Bootstrap

## 7.1 S0 用途

`S0` 只用于 bootstrap authentication、session binding 和 initial state confirmation。它不是后续 Receiver State 的长期根。

## 7.2 Bootstrap Key

```text
PRK_bootstrap = HKDF-Extract(
    salt = 32 zero bytes,
    IKM  = S0
)
```

```text
bootstrap_key = HKDF-Expand(
    PRK_bootstrap,
    CanonicalEncode(
        "LinkChat/bootstrap/v1",
        protocol_version,
        cipher_suite,
        session_id
    ),
    32
)
```

## 7.3 S0 删除

Bootstrap 完成后：

```text
S0 → secure erase
PRK_bootstrap → secure erase
bootstrap_key → secure erase
```

协议层保证后续状态不再引用 S0；物理擦除依赖实现和平台。

---

# 8. 初始 Receiver State

## 8.1 Alice

```text
seed_A_X  ← OS-CSPRNG
seed_A_PQ ← OS-CSPRNG
(ARSK_X_0, ARPK_X_0)   = X25519.KeyGen(seed_A_X)
(ARSK_PQ_0, ARPK_PQ_0) = ML-KEM.KeyGen(seed_A_PQ)
AToken_0 ← OS-CSPRNG(32 bytes)
```

## 8.2 Bob

```text
seed_B_X  ← OS-CSPRNG
seed_B_PQ ← OS-CSPRNG
(BRSK_X_0, BRPK_X_0)   = X25519.KeyGen(seed_B_X)
(BRSK_PQ_0, BRPK_PQ_0) = ML-KEM.KeyGen(seed_B_PQ)
BToken_0 ← OS-CSPRNG(32 bytes)
```

## 8.3 私钥边界

线下交换只传递 X25519/ML-KEM public key、KeyID 和 Token，不传递任何 Receiver private key 或 CSPRNG 状态。

---

# 9. Receiver Package 认证

## 9.1 Package Body

```text
PackageBody = CanonicalEncode(
    "LinkChat/receiver-package/v1",
    session_id,
    turn,
    key_id,
    x25519_public_key,
    mlkem_public_key,
    mailbox_token,
    expiration,
    previous_package_hash
)
```

## 9.2 Package Hash

```text
package_hash = SHA-256(
    CanonicalEncode("LinkChat/package-hash/v1", PackageBody)
)
```

## 9.3 Package Auth

```text
package_auth = Ed25519.Sign(
    IK_priv_owner,
    CanonicalEncode("LinkChat/receiver-package-auth/v1", PackageBody)
)
```

接收方必须用线下绑定的身份公钥验证 `package_auth`。

## 9.4 Package Binding

Package 必须绑定 `session_id`、`turn`、`key_id` 和 `previous_package_hash`。不同 Session、Turn 或 KeyID 的包不得互换使用。

---

# 10. Receiver State 核心规则

## 10.1 独立生成

下一代 Receiver State 必须由拥有者本地生成：

```text
(XSK_(i+1), XPK_(i+1))   ← X25519.KeyGen(OS-CSPRNG)
(PQSK_(i+1), PQPK_(i+1)) ← ML-KEM.KeyGen(OS-CSPRNG)
Token_(i+1)              ← OS-CSPRNG(32 bytes)
```

## 10.2 非干扰约束

以下输入不得直接决定下一 Receiver Secret State：

```text
peer plaintext
peer randomness
peer private key
peer ciphertext
peer ACK
peer selected secret
peer mailbox token
peer path state
peer message payload
```

这些输入最多影响是否接受消息、是否执行状态提交，不能指定下一份 X25519 私钥、ML-KEM 私钥或 Token。

## 10.3 不使用自定义 Ratchet

本协议不要求：

```text
ReceiverState_(i+1) = SHA-256(ReceiverState_i || peer_input)
```

本协议使用新的 OS CSPRNG 输出进行标准 KeyGen，以保持状态非干扰。

---

# 11. 严格轮流主导

```text
Turn 0 → Alice
Turn 1 → Bob
Turn 2 → Alice
Turn 3 → Bob
...
```

只有 `Leader(turn)` 可以发送 Application Turn。非 Leader 发送必须：

```text
reject
no state transition
no Receiver Package rotation
```

ACK 不改变 Application Turn 发送权。

---

# 12. Turn 状态

每个端点至少维护：

```text
current_turn
expected_turn
current_receiver_package
pending_receiver_package
previous_receiver_package
consumed_message_ids
last_confirmed_package_hash
commit_marker
```

状态生命周期：

```text
ACTIVE → PROCESSING → PENDING → COMMITTED → OLD → ERASED
```

任何认证、解密、Turn、Package 或状态链检查失败，都不得提交秘密状态变化。

---

# 13. Turn 0

假设：

```text
Turn 0 → Alice
```

Alice 使用 Bob 当前公开包：

```text
BRPK_X_0
BRPK_PQ_0
BToken_0
BKeyID_0
```

Alice 生成 X25519 ephemeral key 和 ML-KEM 封装，并向 Bob 发送 Turn 0 消息。Bob 使用本地 `BRSK_X_0` 和 `BRSK_PQ_0` 解封装。

---

# 14. 标准混合 KEM

## 14.1 X25519 经典部分

本协议使用 X25519-based ephemeral DH/KEM wrapper：

```text
(esk_X, epk_X) ← X25519.KeyGen(OS-CSPRNG)
ct_X = epk_X
ss_classical = X25519(esk_X, receiver_x25519_public_key)
```

接收方：

```text
ss_classical = X25519(receiver_x25519_private_key, ct_X)
```

具体实现必须使用经过审计的 X25519 封装，不得自行修改曲线、clamping 或输入检查规则。

## 14.2 ML-KEM 后量子部分

发送方：

```text
(ct_PQ, ss_pq) = ML-KEM.Encapsulate(receiver_mlkem_public_key)
```

接收方：

```text
ss_pq = ML-KEM.Decapsulate(receiver_mlkem_private_key, ct_PQ)
```

解封装失败必须使用统一失败处理，不得产生可被远程利用的详细错误 Oracle。

## 14.3 Hybrid PRK

```text
HybridInput = CanonicalEncode(
    "LinkChat/hybrid/v1",
    protocol_version,
    cipher_suite,
    session_id,
    turn,
    receiver_key_id,
    ct_X,
    ct_PQ,
    ss_classical,
    ss_pq
)
```

```text
PRK_hybrid = HKDF-Extract(
    salt = 32 zero bytes,
    IKM  = HybridInput
)
```

经典模式如果暂时不启用 ML-KEM，必须使用明确的 `CipherSuite` 和固定的空值编码。后量子模式不得静默省略 `ss_pq`。

## 14.4 Hybrid 安全边界

在 HKDF 和至少一个 KEM 保持安全、编码绑定正确且实现没有侧信道泄露的条件下，单独攻破另一部分不应直接推出最终会话密钥。

---

# 15. Message Key

```text
MessageInfo = CanonicalEncode(
    "LinkChat/message/v1",
    protocol_version,
    cipher_suite,
    session_id,
    turn,
    direction,
    message_id,
    receiver_key_id
)
```

```text
MK = HKDF-Expand(PRK_hybrid, MessageInfo, 32)
```

同一个 `MK` 只允许用于一条消息的一次加密。成功处理后必须删除 `MK` 和不再需要的临时 KEM 材料。

---

# 16. Header Key 与 Header Protection

## 16.1 Header Key

```text
HeaderInfo = CanonicalEncode(
    "LinkChat/header/v1",
    protocol_version,
    cipher_suite,
    session_id,
    turn,
    direction,
    receiver_key_id
)
```

```text
HK = HKDF-Expand(PRK_hybrid, HeaderInfo, 32)
```

## 16.2 逻辑 Header

```text
Header = {
    protocol_version,
    cipher_suite,
    session_id,
    turn,
    direction,
    message_id,
    receiver_key_id,
    message_type,
    ack_info,
    sender_package_hash,
    receiver_package_hash
}
```

## 16.3 Header 加密

```text
encrypted_header = ChaCha20-Poly1305.Seal(
    key = HK,
    nonce = header_nonce,
    associated_data = HeaderAD,
    plaintext = CanonicalEncode(Header)
)
```

Header 认证失败不得继续解密 Application Message 或提交状态。

---

# 17. Nonce

## 17.1 Message Nonce

```text
NonceInfo = CanonicalEncode(
    "LinkChat/nonce/v1",
    session_id,
    turn,
    direction,
    message_id,
    receiver_key_id
)
```

```text
message_nonce = first 12 bytes of HKDF-Expand(
    HKDF-Extract(32 zero bytes, MK),
    NonceInfo,
    12
)
```

Header Nonce 使用独立 domain：

```text
LinkChat/header-nonce/v1
```

## 17.2 Nonce 唯一性

Nonce 唯一性依赖：

1. 每条消息的 `MK` 唯一；
2. `message_id` 在 Session 内唯一；
3. Turn、Direction 和 KeyID 正确绑定；
4. canonical encoding 无歧义。

---

# 18. Associated Data

```text
MessageAD = CanonicalEncode(
    "LinkChat/message-ad/v1",
    protocol_version,
    cipher_suite,
    session_id,
    turn,
    direction,
    message_id,
    receiver_key_id
)
```

```text
HeaderAD = CanonicalEncode(
    "LinkChat/header-ad/v1",
    protocol_version,
    cipher_suite,
    session_id,
    turn,
    direction,
    message_id,
    receiver_key_id
)
```

因此消息不能被无检测地跨 Session、跨 Turn、跨 Direction 或跨 KeyID 重放。

---

# 19. 完整消息结构

```text
Envelope = {
    mailbox_token,
    x25519_kem_ciphertext,
    mlkem_ciphertext,
    encrypted_header,
    ciphertext,
    padding
}
```

字段含义：

```text
mailbox_token         = 当前接收方公开包中的一次性 Token
x25519_kem_ciphertext = X25519 ephemeral public value / wrapper ciphertext
mlkem_ciphertext      = ML-KEM ciphertext
encrypted_header      = Header 的 ChaCha20-Poly1305 密文
ciphertext            = Application plaintext 的 ChaCha20-Poly1305 密文
padding               = 固定长度填充
```

默认固定封装长度：

```text
4096 bytes
```

如果密文超过固定长度，必须使用协议配置的分片机制，不得静默改变包格式。

---

# 20. DHT Mailbox

## 20.1 写入

```text
PUT(mailbox_token, envelope)
```

## 20.2 读取

```text
GET(mailbox_token)
```

## 20.3 DHT 信任边界

DHT 节点是不可信 Key-Value 存储，可以 drop、delay、replay、modify、withhold 或返回 fake data。

DHT 节点不能在没有有效 KEM、Header AEAD、Message AEAD 和 Package 验证的情况下让接收端接受伪造消息。协议不保证 DHT 可用性。

---

# 21. Mailbox Token

## 21.1 生成

```text
T_i ← OS-CSPRNG(32 bytes)
```

## 21.2 职责分离

```text
Token          = DHT mailbox capability
MessageKey     = message confidentiality key
ReceiverSecret = receiver state authority
```

## 21.3 生命周期

```text
created → active → consumed → expired
```

消费后再次返回相同消息只能得到 Duplicate 结果，不得触发第二次状态提交。

## 21.4 可选 Token MAC

如果实现需要附带内部元数据：

```text
token_mac = HMAC-SHA-256(
    key = token_mac_key,
    message = CanonicalEncode(
        "LinkChat/token-mac/v1",
        token_metadata
    )
)
```

Token MAC 不得替代 Message AEAD。

---

# 22. Application Message 加密

```text
PRK_hybrid
    ↓
MK
    ↓
message_nonce
    ↓
ChaCha20-Poly1305.Seal
```

```text
ciphertext = ChaCha20-Poly1305.Seal(
    key = MK,
    nonce = message_nonce,
    associated_data = MessageAD,
    plaintext = application_plaintext
)
```

解密使用 `ChaCha20-Poly1305.Open`。Open 失败必须视为认证失败，不得继续解析明文或提交状态。

---

# 23. 接收处理流程

Bob 收到 Alice 的 Turn 0 Envelope 后按以下顺序处理：

```text
1. 读取 mailbox_token 对应的候选记录
2. 检查 SessionID 是否为当前 Session
3. 检查 Turn 是否等于 expected_turn
4. 检查 direction 是否等于 Leader(expected_turn)
5. 检查当前 Turn 是否确实由 Alice 主导
6. 检查 Receiver Package key_id
7. 检查 Package expiration
8. 验证 previous_package_hash
9. 使用当前 BRSK_X 解封装 X25519 部分
10. 使用当前 BRSK_PQ 解封装 ML-KEM 部分
11. 派生 PRK_hybrid
12. 派生 Header Key
13. 验证并解密 Header
14. 验证 Header 字段与预期状态一致
15. 派生 Message Key
16. 派生 Message Nonce
17. 验证 Message AEAD
18. 检查 message_id 是否已消费
19. 检查 Turn State
20. 本地生成下一 Receiver Package
21. 将下一包写入 pending state
22. 原子提交新状态
23. 记录 consumed_message_id
24. 将当前 Package 置为 OLD
25. 进入下一 Turn
26. 发送下一 Receiver Public Package
```

任何一步失败：

```text
NO STATE COMMIT
NO RECEIVER ROTATION
NO APPLICATION PROCESSING
```

---

# 24. Receiver State Rotation

假设 Bob 成功处理 Turn 0。Bob 本地生成：

```text
(BRSK_X_1, BRPK_X_1)   ← X25519.KeyGen(OS-CSPRNG)
(BRSK_PQ_1, BRPK_PQ_1) ← ML-KEM.KeyGen(OS-CSPRNG)
BToken_1               ← OS-CSPRNG(32 bytes)
BKeyID_1               ← locally unique key identifier
```

然后创建：

```text
BRP_1 = {
    session_id,
    turn = 1,
    key_id = BKeyID_1,
    x25519_public_key = BRPK_X_1,
    mlkem_public_key = BRPK_PQ_1,
    mailbox_token = BToken_1,
    expiration,
    previous_package_hash = Hash(BRP_0),
    package_auth
}
```

旧状态：

```text
BRSK_X_0  → OLD
BRSK_PQ_0 → OLD
BToken_0  → consumed/expired after grace window
```

新包中的 Secret、Public Key、KeyID 和 Token 必须作为一个 Receiver Package 原子切换。

---

# 25. 下一 Turn

Bob 成为 `Turn 1 Leader`。Alice 获得 `BRPK_X_1`、`BRPK_PQ_1`、`BToken_1` 和 `BKeyID_1`，但不能获得 `BRSK_X_1` 或 `BRSK_PQ_1`。

Bob 使用 Alice 当前公开包中的 `ARPK_X_0`、`ARPK_PQ_0`、`AToken_0` 和 `AKeyID_0` 发送 Turn 1。

---

# 26. Alice 接收 Turn 1

Alice 使用 `ARSK_X_0` 和 `ARSK_PQ_0` 解封装并解密 Bob 的 Turn 1。

成功后 Alice 本地生成：

```text
(ARSK_X_1, ARPK_X_1)   ← X25519.KeyGen(OS-CSPRNG)
(ARSK_PQ_1, ARPK_PQ_1) ← ML-KEM.KeyGen(OS-CSPRNG)
AToken_1               ← OS-CSPRNG(32 bytes)
AKeyID_1               ← locally unique key identifier
```

然后进入 `Turn 2 Leader = Alice`。

---

# 27. 关键状态所有权

```text
Alice Receiver Secret Authority = Alice device only
Bob Receiver Secret Authority   = Bob device only
```

Alice 的消息不能声明或写入 Bob 的任何私钥、Token 或 Receiver Package。Bob 的消息不能声明或写入 Alice 的对应秘密。

消息只提供 authenticated encrypted protocol input，不提供 receiver-secret-state authority。

---

# 28. 重放攻击

如果：

```text
turn < expected_turn
```

则：

```text
REPLAY
NO STATE TRANSITION
NO NEW RECEIVER PACKAGE
```

可以返回最小化 Duplicate/Replay 结果，但不得返回额外身份关联信息。

---

# 29. Future-Turn Attack

如果：

```text
turn > expected_turn
```

则：

```text
REJECT
NO KEY GENERATION
NO STATE ADVANCE
NO FUTURE PACKAGE ALLOCATION
```

不得因为未来 Turn 消耗 Receiver State、Token 或本地存储。

---

# 30. Duplicate Message

每条消息具有 Session 内唯一的 `message_id`。成功处理后记录：

```text
ConsumedMessageID
```

重复消息必须满足：

```text
same session_id
same turn
same direction
same message_id
same receiver_key_id
```

结果：

```text
Duplicate
NO new message processing
NO new state rotation
NO second commit
```

---

# 31. 丢包、延迟与乱序

DHT 和网络可能 drop、delay、replicate 或 reorder。接收端维护：

```text
CurrentPackage
PreviousPackage
PendingPackage
```

有限 Grace Window 内可接受合法延迟旧消息，但旧消息不能覆盖新状态，同一消息不能提交两次，旧 Package 不能替换当前 Package。Grace Window 结束后 Previous Secret 进入安全擦除流程。

---

# 32. ACK / SACK

ACK 属于 Transport 层：

```text
ACK = {
    session_id,
    turn,
    direction,
    message_id,
    delivery_status
}
```

可选 SACK：

```text
base
bitmap
```

ACK 必须使用当前会话的 AEAD 保护，但 ACK 不是 Receiver State、Receiver Package 或状态更新命令。ACK replay 不得直接触发 Receiver State rotation。

---

# 33. State Commit

消息处理采用临时状态：

```text
CurrentState
     ↓
temporary state
     ↓
KEM decapsulation
     ↓
HKDF derivation
     ↓
Header verification
     ↓
AEAD verification
     ↓
Turn validation
     ↓
Generate next Receiver Package
     ↓
PENDING
     ↓
atomic COMMIT
```

只有所有检查成功，才允许 `temporary state → persistent state`。任一检查失败时，临时状态丢弃，当前有效状态保持不变。

---

# 34. Crash Recovery

持久状态至少包括：

```text
session_id
current_turn
current_key_id
current_receiver_package
previous_receiver_package
pending_receiver_package
commit_marker
consumed_message_ids
last_confirmed_package_hash
```

恢复规则：

```text
commit_marker = committed
    → 采用新状态

commit_marker != committed
    → 丢弃 pending state
    → 保留旧状态
```

原子提交防止 double rotation、key reuse、rollback 和 duplicate commit。

---

# 35. Rollback Protection

每个 Receiver Package 包含：

```text
turn
key_id
previous_package_hash
```

接收端要求：

```text
turn strictly monotonic
previous_package_hash matches confirmed history
key_id is not an already retired key
```

旧 Package 必须 reject。未来 Package 只能 buffer 或 reject，不得自动覆盖当前状态。

---

# 36. Identity Authentication

## 36.1 正常在线验证

正常消息主要依赖：

```text
KEM shared secret
HKDF context binding
ChaCha20-Poly1305 authentication
```

## 36.2 长期身份签名使用范围

Ed25519 仅用于：

```text
offline identity binding
Receiver Package authentication
identity change confirmation
re-pairing
```

不要求每条聊天消息附带长期 Ed25519 签名。

## 36.3 Entity Authentication

如果 Bob 接受 Alice 的 Receiver Package，必须：

1. 验证 Ed25519 `package_auth`；
2. 使用线下已绑定的 `IdentityPublicKey_A`；
3. 检查 SessionID、Turn、KeyID 和 Package Hash；
4. 检查 Package 仍在有效期内。

---

# 37. Identity Change

如果某端发现：

```text
PeerIdentityPublicKey != expected_identity_public_key
```

立即：

```text
STOP
INVALIDATE SESSION
REJECT NEW PACKAGE
```

必须重新进行线下物理验证，不能仅通过网络消息自动替换身份。

---

# 38. KCI 边界

身份密钥泄露时，攻击者可能伪造依赖该身份签名的 Package。因此：

```text
identity key compromise → invalidate affected session
```

重新建立 Session 必须生成新的 SessionID、S0、Receiver State、Mailbox Token 和 Path State。

KCI 抗性不能被表述为“身份密钥泄露后所有历史和未来身份认证仍然安全”。

---

# 39. Session Independence

每次新 Session 使用：

```text
new SessionID
new S0
new Identity Binding Context
new Receiver State
new Receiver Package
new Mailbox Tokens
new Path State
```

所有 KDF、Hash、AEAD AD 和签名上下文都绑定 `session_id`。同一设备上的 Session 不能复用旧 Session 的 Receiver Secret、Token 或 Path Seed。

---

# 40. Receiver Secret Forward Secrecy

如果攻击者获得：

```text
BRSK_X_i
BRSK_PQ_i
```

且：

```text
BRSK_X_(i-1) 已安全删除
BRSK_PQ_(i-1) 已安全删除
```

则协议结构不再引用历史私钥。实际不可逆性依赖 X25519/ML-KEM 密钥生成、密钥删除、内存保护和平台假设。

---

# 41. Message Forward Secrecy

每条消息使用独立的：

```text
PRK_hybrid_i
MK_i
message_nonce_i
```

处理后删除 `MK_i`、临时 KEM secrets 和临时 plaintext buffers。未来状态不应自动包含历史 Message Key。

---

# 42. Post-Compromise Security

假设 Bob 在 `t0` 前被短暂攻陷，攻击者获得 Bob 的旧 Receiver State。Bob 恢复诚实后必须：

```text
(BRSK_X_(i+1), BRPK_X_(i+1))   ← X25519.KeyGen(OS-CSPRNG)
(BRSK_PQ_(i+1), BRPK_PQ_(i+1)) ← ML-KEM.KeyGen(OS-CSPRNG)
BToken_(i+1)                   ← OS-CSPRNG(32 bytes)
```

新状态不得由旧状态或 Alice 输入直接决定。在攻击者不再控制 Bob、本地 CSPRNG 安全且新包成功生效的条件下，未来消息可以恢复机密性。

---

# 43. Single-Endpoint State Isolation

假设：

```text
Alice permanently compromised
Bob honest
```

攻击者拥有：

```text
Alice Identity State
Alice Receiver State
Alice Message State
Alice plaintext
Alice randomness
Alice KEM inputs
Alice ciphertexts
Alice tokens
Alice network view
Alice DHT control
```

攻击者还可以发送任意消息、重放、延迟、丢弃和修改 DHT 记录。但 Bob 的下一状态必须满足：

```text
BRS_(i+1) = LocalGenerate_Bob(OS-CSPRNG)
```

Peer input 只能决定 accept 或 reject，不能决定 `BRS_X_(i+1)`、`BRS_PQ_(i+1)` 或 `BToken_(i+1)`。反向情况对 Alice 同理。

---

# 44. State Non-Interference

```text
View_A = {
    Alice secret state,
    Alice plaintext,
    Alice randomness,
    Alice ciphertext,
    Alice token,
    Alice identity state,
    network trace,
    DHT trace,
    replay results,
    injection results
}
```

在固定 Bob 本地状态和固定 Bob 本地 fresh 值 `rho_B` 时，对任意两个攻击者视图 `View_A1` 和 `View_A2`，若两次执行的接受/拒绝结果相同，则：

```text
BobNextState(View_A1, rho_B)
    =
BobNextState(View_A2, rho_B)
```

这是协议结构层的强形式 State Non-Interference。计算不可区分性还需要 CSPRNG、KEM、HKDF 和 AEAD 的安全假设。

---

# 45. State Injection Resistance

恶意 Alice 不能使 Bob 的下一 Receiver Package 等于攻击者任意指定的包 `P*`，除非：

```text
P* = BobOS_CSPRNGGeneratedPackage
```

恶意消息中的 key、token、ACK、ciphertext、selected secret 和 path state 都不能成为 Bob 新秘密的来源。

---

# 46. Continuous Compromise Containment

定义：

```text
Compromise(A) = continuous
Bob = honest forever
```

对于任意有限长度攻击轨迹，Alice views、messages、plaintexts、ciphertexts 和 DHT 行为可以任意不同。只要初始 Bob 状态相同、Bob 使用相同的本地 fresh Package 序列且每一步合法消息都被验证，两条轨迹最终的 Bob Receiver Package 相同。

---

# 47. Malicious Peer Cannot Grant Itself State Ownership

Alice 不能通过消息获得 Bob Receiver Secret Authority。任何协议输入都不得具有以下权限语义：

```text
MODIFY_RECEIVER_STATE
SET_RECEIVER_PRIVATE_KEY
SET_RECEIVER_TOKEN
ROLLBACK_RECEIVER_PACKAGE
```

消息只可请求状态机执行验证后的合法转换。

---

# 48. Replay、Fork 与 Ordering Resistance

## 48.1 Message Replay

旧消息不得第二次提交。

## 48.2 Package Replay

旧 Package 不得替换当前 Package。

## 48.3 ACK Replay

旧 ACK 不得推动密码状态。

## 48.4 Token Replay

已消费 Token 再次出现只能产生 Duplicate/Replay 结果。

## 48.5 State Fork

同一个合法 `Turn_i` 在单个端点上不得产生两个不同的已提交 `State_(i+1)`。必须通过原子提交和唯一 `message_id` 保证：

```text
one accepted turn → one committed next package
```

---

# 49. KEM 安全与解封装失败

实现必须使用经过审计的 X25519 和 ML-KEM 实现，并要求：

1. 正确的公私钥格式和长度检查；
2. 敏感运算使用常数时间实现；
3. 统一的解封装失败行为；
4. 不通过错误消息、时间或返回码暴露详细失败原因；
5. 不把恶意 ciphertext 直接转化为 Receiver State 输入。

---

# 50. KEM + HKDF + AEAD 组合

组合顺序固定为：

```text
X25519 / ML-KEM
        ↓
Canonical hybrid context
        ↓
HKDF-Extract
        ↓
HKDF-Expand
        ↓
Message Key / Header Key
        ↓
ChaCha20-Poly1305
```

不得直接把 KEM shared secret 当作 AEAD key、把 Token 当作 Message Key、把 Message Key 当作 Token，或省略 SessionID、Turn、Direction、KeyID 的绑定。

---

# 51. Header、Message 和 ACK 安全分离

至少使用独立的：

```text
message domain
header domain
header-nonce domain
message-nonce domain
ack domain
```

Header 认证失败不得触发 Message 解密和 Receiver State rotation。ACK 认证失败不得触发 Receiver State rotation。

---

# 52. Package Hash 与 Transcript Hash

Package Hash：

```text
SHA-256(
    CanonicalEncode("LinkChat/package-hash/v1", PackageBody)
)
```

Transcript Hash：

```text
SHA-256(
    CanonicalEncode("LinkChat/transcript-hash/v1", transcript_records)
)
```

Transcript Hash 不等于身份签名，不得单独解释为某人发送过消息的第三方证明。

---

# 53. Cryptographic Deniability

普通消息不要求长期 Ed25519 身份签名，而使用：

```text
KEM-derived secret
HKDF-derived key
AEAD authentication
```

因此仅凭网络 transcript，第三方不应自动获得一个可独立验证的长期身份签名证明。端点本地日志、运行时内存或另行保存的身份签名记录不在此声明范围内。

---

# 54. Path State 与匿名传输

## 54.1 Path State 分离

Path State 与以下状态独立：

```text
Receiver Secret
Mailbox Token
Message Key
```

不得直接定义：

```text
Path = f(ReceiverSecret)
ReceiverSecret = f(Path)
```

## 54.2 Path Key

```text
PathSeed ← OS-CSPRNG
```

```text
PathKey = HKDF-Expand(
    HKDF-Extract(32 zero bytes, PathSeed),
    CanonicalEncode("LinkChat/path/v1", session_id, turn),
    32
)
```

Path Seed 和 Receiver Secret 必须由独立输入产生。Path 更新不得直接写入 Receiver Secret。

## 54.3 多跳路径

传输可采用：

```text
Client → Guard → Middle Relay → Gateway → DHT
```

每个中继尽可能只知道 previous hop 和 next hop。协议不承诺抵抗全球被动流量分析。

---

# 55. DHT Record 安全

## 55.1 Confidentiality

DHT 节点只能看到 opaque envelope、Mailbox Token 和 transport metadata，正常情况下不能获得 Application plaintext。

## 55.2 Integrity

DHT 修改 Ciphertext、Header 或 KEM ciphertext 后，不能通过有效的 AEAD、KEM 和 Package 检查。

## 55.3 Replay

DHT 反复返回旧 Record 不得推进状态。

## 55.4 Availability Boundary

恶意 DHT 节点可以造成 drop、delay、withhold 和 availability loss。协议使用副本、冗余查询和重新发布提高可靠性，但不将可用性声明为密码学保证。

---

# 56. TTL 与副本

每条 DHT Record 可以有配置 TTL：

```text
TTL = configurable
```

TTL 表示客户端服务生命周期，不代表恶意 DHT 节点无法永久复制密文。

有效副本必须具有相同的 authenticated envelope 和消息身份。接收端只接受密码学验证成功的副本。

---

# 57. 设备边界与代理设备

默认 Primary Device 承担：

```text
Identity State
Receiver Secret State
session state
Mailbox State
Path State
```

其他设备不得直接获取完整身份秘密或 Receiver Secret。代理设备只能使用 typed capability：

```text
DISPLAY_MESSAGE
REQUEST_SEND_MESSAGE
ACK_MESSAGE
```

不得暴露：

```text
SIGN_ARBITRARY_BYTES
MODIFY_RECEIVER_STATE
EXPORT_RECEIVER_PRIVATE_KEY
```

---

# 58. 设备丢失

Primary Device 丢失后：

```text
旧 Session = terminated
旧 Receiver State = unavailable
旧 Mailbox State = invalidated where possible
```

恢复必须重新线下配对，生成新的 SessionID、S0、Receiver State、Receiver Package、Mailbox Token 和 Path State。不能只复制旧本地数据库恢复会话。

---

# 59. 随机数和安全擦除要求

以下材料必须来自 OS CSPRNG 或成熟密码库内部 CSPRNG：

```text
S0
X25519 Receiver Key
ML-KEM Receiver Key
X25519 Ephemeral Key
Mailbox Token
Path Seed
Session random values
```

旧材料在协议层不再引用后进入安全擦除流程。安全擦除还需要平台保证没有 swap copy、crash dump、snapshot 或 backup leakage。

---

# 60. 安全性质总表

| 安全性质 | 标准化 v1.0 状态 |
| --- | --- |
| 物理身份绑定 | 由安全线下信道假设支持 |
| Ed25519 身份认证 | 标准原语接口 |
| X25519 经典密钥协商 | 标准原语接口 |
| ML-KEM 后量子 KEM | 标准原语接口 |
| HKDF-SHA-256 | 标准 KDF |
| SHA-256 Package/Transcript Hash | 标准 Hash |
| ChaCha20-Poly1305 | 标准 AEAD |
| Message Key Isolation | 协议结构要求 |
| Message Forward Secrecy | 依赖 KeyGen、删除和 KEM 假设 |
| Receiver-State Forward Secrecy | 依赖独立 KeyGen 和删除 |
| Post-Compromise Security | 依赖恢复后 fresh KeyGen |
| Single-Endpoint State Isolation | 核心协议目标，状态机已形式化 |
| State Non-Interference | 核心协议性质，已形式化抽象模型 |
| State Injection Resistance | 核心协议性质，已形式化抽象模型 |
| Replay Protection | Turn、message_id、状态机 |
| Duplicate Protection | consumed_message_ids |
| State Fork Resistance | 原子提交和唯一消息消费 |
| Rollback Protection | Turn 单调性和 Package Hash 链 |
| Header Protection | 独立 Header Key + AEAD |
| Session Independence | SessionID 绑定和全新状态 |
| Mailbox Token Unpredictability | OS CSPRNG 假设 |
| Token/Message-Key Separation | 独立职责和 KDF domain |
| DHT Confidentiality | AEAD 假设 |
| DHT Integrity | AEAD/KEM/Package 验证 |
| DHT Availability | 不保证 |
| Path Confidentiality | 依赖匿名传输实现 |
| Global Traffic Analysis Resistance | 不保证，仅缓解 |
| Secure Deletion | 实现和平台假设 |
| Side-Channel Resistance | 实现和平台假设 |

---

# 61. 核心安全不变量

## 不变量 1：状态所有权分离

```text
Alice Receiver Secret Authority ≠ Bob Receiver Secret Authority
```

## 不变量 2：Alice 本地状态演化

```text
ARS_(i+1) = LocalGenerate_Alice(OS-CSPRNG)
```

## 不变量 3：Bob 本地状态演化

```text
BRS_(i+1) = LocalGenerate_Bob(OS-CSPRNG)
```

## 不变量 4：消息不拥有状态推进权

网络消息不能直接决定 AliceNextReceiverSecret 或 BobNextReceiverSecret。

## 不变量 5：只有当前 Leader 发送 Application Turn

```text
valid application turn → sender = Leader(turn)
```

## 不变量 6：ACK 不拥有密码状态推进权

## 不变量 7：认证失败不得提交状态

```text
authentication failure → no state commit
```

## 不变量 8：Receiver Package 原子轮换

```text
secret + public key + key_id + token
```

必须作为一个逻辑包一起切换。

## 不变量 9：Token 与 Message Key 分离

```text
Token ≠ Message Key
```

---

# 62. 完整通信状态图

```text
              Offline Physical Trust
                        │
                        ▼
                Ed25519 Identity Binding
                        │
                        ▼
                S0 / HKDF Bootstrap
                        │
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
       Alice Receiver Package  Bob Receiver Package
       X25519 + ML-KEM         X25519 + ML-KEM
             │                     │
             └──────────┬──────────┘
                        │
                  Turn 0: Alice
                        │
                        ▼
              X25519 + ML-KEM Encap
                        │
                        ▼
              HKDF Hybrid PRK
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
         Header Key          Message Key
              │                   │
              ▼                   ▼
          Header AEAD       Message AEAD
                        │
                        ▼
                    DHT Mailbox
                        │
                        ▼
                    Bob receives
                        │
                        ▼
             Bob local fresh Package
                        │
                        ▼
                  Turn 1: Bob
                        │
                        ▼
                    ...
```

---

# 63. 四层状态模型

```text
Identity State
       │
       ▼
Receiver Secret State
       │
       ▼
Message / KEM / AEAD State
       │
       ▼
Mailbox / Path / Transport State
```

四层必须保持边界：

```text
Identity State
    ≠ Receiver Secret State
    ≠ Message State
    ≠ Mailbox State
    ≠ Path State
```

某一层泄露不能在协议逻辑上自动获得其他层的全部状态。

---

# 64. 最终安全模型

攻击者允许：

```text
✓ 持续控制 Alice
✓ 获得 Alice 全部密码状态
✓ 控制 Alice 所有协议输入
✓ 伪造 Alice 应用消息
✓ 选择 Alice 明文和随机数
✓ 重放、延迟、丢弃、修改消息
✓ 控制部分 DHT
✓ 保存全部网络密文
```

但假设：

```text
✓ Bob 执行环境保持诚实
✓ Bob Receiver Secret 不被直接读取
✓ Bob 使用安全 OS CSPRNG
✓ Bob 的状态存储不被回滚破坏
✓ X25519、ML-KEM、HKDF、AEAD 实现正确且安全
```

目标：

```text
View_A ↛ BobFutureReceiverSecret
```

更准确的计算安全表述是：攻击者对 Bob 未来秘密与独立随机秘密的区分优势，应在指定模型下可约化到标准原语安全性和实现假设。

---

# 65. 协议终极设计原则

> 消息可以进入设备，但消息不能拥有设备秘密状态的所有权。

> 通信对端可以影响通信内容，却不能直接决定诚实端下一份秘密状态。

> 底层密码学使用标准原语；协议创新集中在独立 Receiver State、严格交替 Turn 和 State Non-Interference。

---

# 附录 A：标准算法调用清单

```text
IdentityPublicKey     = Ed25519.PublicKey(IK_priv)
IdentitySignature     = Ed25519.Sign(IK_priv, canonical_context)
IdentityVerify        = Ed25519.Verify(IK_pub, canonical_context, signature)

ReceiverXKeyPair      = X25519.KeyGen(OS-CSPRNG)
ReceiverPQKeyPair     = ML-KEM.KeyGen(OS-CSPRNG)
ClassicalSharedSecret = X25519(ephemeral_sk, receiver_pk)
PQSharedSecret        = ML-KEM.Decapsulate(receiver_sk, ct)

BootstrapPRK          = HKDF-Extract(zero_salt, S0)
HybridPRK             = HKDF-Extract(zero_salt, canonical_hybrid_input)
MessageKey            = HKDF-Expand(HybridPRK, message_info, 32)
HeaderKey             = HKDF-Expand(HybridPRK, header_info, 32)
Nonce                 = HKDF-Expand(HKDF-Extract(zero_salt, key), nonce_info, 12)
PathKey               = HKDF-Expand(HKDF-Extract(zero_salt, PathSeed), path_info, 32)

PackageHash           = SHA-256(canonical_package_hash_input)
TranscriptHash        = SHA-256(canonical_transcript_hash_input)
Token                 = OS-CSPRNG(32 bytes)
TokenMAC              = HMAC-SHA-256(token_mac_key, canonical_token_input)

HeaderCiphertext      = ChaCha20-Poly1305.Seal(HK, header_nonce, HeaderAD, Header)
MessageCiphertext     = ChaCha20-Poly1305.Seal(MK, message_nonce, MessageAD, plaintext)
```

---

# 附录 B：实现禁止事项

实现不得：

```text
1. 自行发明 Hash、KDF、AEAD、签名或随机数算法
2. 使用普通 hash 替代 Ed25519 身份认证
3. 直接把 Token 当作 Message Key
4. 直接把 KEM shared secret 当作 AEAD key
5. 用 peer input 派生 Receiver Private Key
6. 用 ACK 直接推进 Receiver State
7. 在认证失败后提交 pending state
8. 在重复消息上再次旋转 Receiver Package
9. 复用旧 Message Key
10. 省略 SessionID、Turn、Direction 或 KeyID 的 KDF/AEAD 绑定
11. 使用非 canonical serialization 计算 Package Hash
12. 把长期身份签名附加到普通消息而不评估可否认性影响
13. 把 Path State 与 Receiver Secret 直接互相派生
14. 将 DHT 可用性错误描述成密码学保证
15. 将安全擦除、侧信道和 CSPRNG 质量伪装成协议数学定理
```

---

# 附录 C：与 Lean 形式化项目的对应关系

```text
LinkChat.lean
    基础状态机、Turn、状态提交、重放和抽象 KEM 正确性

SecurityGames.lean
    攻击者视图、单端点状态隔离、连续失陷、FS/PCS 结构性接口

RefinedProtocol.lean
    ReceiverPackage 原子轮换模型：Secret + Public Key ID + Mailbox Token

StandardCrypto.lean
    Ed25519 / X25519 / ML-KEM / HKDF / SHA-256 /
    ChaCha20-Poly1305 / HMAC / OS CSPRNG 的标准原语接口
```

Lean 模型证明协议控制逻辑、状态所有权、输入非干扰和标准原语的接口级正确性。具体实现仍必须绑定经过审计的密码学库，并对计算安全、随机数、内存擦除、侧信道和存储回滚作出实现级证明或假设。

---

# 附录 D：安全声明的准确措辞

推荐对外使用以下表述：

> Link Chat v1.0-standardized 使用 Ed25519、X25519、ML-KEM、HKDF-SHA-256、SHA-256、ChaCha20-Poly1305、HMAC-SHA-256 和 OS CSPRNG 作为标准密码学构件，同时保留独立 Receiver State、严格交替 Turn、一次性 Mailbox Token 和匿名异步传输架构。

> 其核心形式化结果是：在诚实端本地状态和本地新鲜随机性保持私密的条件下，恶意对端可以控制协议输入，但不能直接控制诚实端下一份 Receiver Secret State。

> 完整的计算安全性需要在标准 KEM、KDF、AEAD、签名和实现安全假设上进一步完成归约证明；协议不承诺保护被完全攻陷端的本地明文、不承诺抵抗双端同时失陷，也不承诺消除全球流量分析。
