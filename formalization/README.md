# Link Chat v1.0 Lean Formalization

## 中文说明

本目录包含 Link Chat v1.0 协议的 Lean 4.31.0 机器检查形式化，重点覆盖
协议状态机、Receiver Package 轮换、攻击者观察模型以及安全归约中的概率记账。
它与 Rust 参考内核共同发布于 `LinkChat` 仓库；协议规范、测试向量和论文位于
`LinkChatDocuments` 仓库。

本形式化证明的是协议结构性质和显式的游戏/归约接口，不声称仅凭 Lean
符号模型证明 Ed25519、X25519、ML-KEM、HKDF、ChaCha20-Poly1305、CSPRNG、
安全擦除、存储回滚防护或侧信道防护的计算安全性。

## English

This directory contains the Lean 4.31.0 machine-checked formalization of the
Link Chat v1.0 protocol. It covers the protocol state machine, atomic Receiver
Package rotation, attacker observations, and probability bookkeeping for the
security reductions. It is released together with the Rust reference kernel
in the `LinkChat` repository; the specification, test vectors, and paper are
released in the `LinkChatDocuments` repository.

The formalization proves structural protocol properties and exposes explicit
game and reduction interfaces. It does not claim to derive the computational
security of Ed25519, X25519, ML-KEM, HKDF, ChaCha20-Poly1305, the OS CSPRNG,
secure erasure, rollback-resistant storage, or side-channel resistance from
the symbolic Lean model alone.

This directory contains a Lean 4.31.0 machine-checked formalization of the
protocol's core state-machine and security-game properties.

## Checked theorems

- unique alternating leader for every turn;
- invalid input performs no state commit;
- valid input advances exactly one turn and rotates only the receiver state;
- replayed messages are rejected and are idempotent;
- past and future turns are rejected;
- peer-controlled protocol input cannot choose the honest peer's next secret
  when the honest peer's local fresh value is fixed;
- state-injection resistance and bidirectional state non-interference;
- session/turn package binding at the modeled level;
- mailbox put/get token correctness;
- KEM, hybrid-secret, message-key, and header-key correctness, conditional on
  the abstract KEM correctness law.

`SecurityGames.lean` additionally models an attacker view containing Alice's
secrets, plaintexts, randomness, ciphertexts, tokens, network trace, and DHT
trace. It proves single-step and multi-step continuous-compromise
non-interference: arbitrary accepted peer views cannot change the honest
endpoint's next package when the honest endpoint's local fresh package is
fixed. It also includes structural FS rotation and PCS recovery lemmas.

`RefinedProtocol.lean` is the corrected package-level model. Secret state,
public key identifier, and mailbox token rotate atomically as one
`ReceiverPackage`; the multi-step theorem is proved in both directions.

`StandardCrypto.lean` binds the cryptographic boundaries to the reference
standard choices without changing the protocol architecture:

| Protocol boundary | Standard primitive |
| --- | --- |
| identity authentication | Ed25519 |
| classical key agreement/KEM wrapper | X25519 |
| post-quantum KEM | ML-KEM |
| bootstrap/message/header/nonce/ACK/path KDF | HKDF-SHA-256 with domain separation |
| package/transcript hash | SHA-256 with canonical encoding hooks |
| message and header protection | ChaCha20-Poly1305 |
| optional MAC | HMAC-SHA-256 |
| receiver keys and mailbox tokens | OS CSPRNG |

The API uses symbolic `Nat` values for encoded byte strings so the Lean model
stays dependency-free. A concrete implementation must instantiate the API
with real byte serialization and a vetted cryptographic library.

`ComputationalGames.lean` adds the formal security-game layer required by
`Problem.md`:

- `CompleteAdversaryView` includes Alice state, plaintexts, randomness,
  ciphertexts, tokens, network/DHT traces, Bob public/network/DHT outputs,
  ACK/error outputs, and accept/reject observations;
- `AdaptiveAdversary` receives the complete observation history, so the
  attacker is adaptive rather than a fixed attack-list enumerator;
- Alice-controlled input randomness and Bob hidden fresh-state sources are
  separate arguments;
- `realGameTrace` and `randomGameTrace` implement the Real/Random future-state
  challenge, and `SECCAdvantage` / `ComputationalSECC` expose the probability
  and negligible-bound interface;
- `FutureMessageGameConfig` now separates `realState` and `randomState`; the
  selected future state derives a message key and produces an actual
  challenge ciphertext from message id, associated data, and plaintext;
- `FutureMessageChallengeView` gives the distinguisher the complete protocol
  trace plus the exposed future-message ciphertext, while keeping challenge
  metadata identical between Real and Random;
- `FutureMessageConfidentialityGame` provides the message-level challenge
  needed to connect future-state secrecy to AEAD confidentiality;
- `adaptive_execute_peer_noninterference` proves the structural game hop for
  arbitrary adaptive accepted peer histories under the same honest fresh
  schedule;
- `ForwardSecrecyGame` and `PostCompromiseSecurityGame` are separate indexed
  game interfaces, with explicit past-erasure and post-compromise recovery
  boundaries;
- `AuthenticationSecurityGame` explicitly models identity, session, turn,
  key-id, and mailbox-token forgery attempts;
- `KCISecurityGame` has separate Alice-compromise and Bob-compromise
  directions;
- `SECCAdvantageComponents`, `composedSECCBound`, and
  `computational_secc_from_component_reduction` expose the intended reduction
  shape as the sum of X25519, ML-KEM, HKDF, AEAD, CSPRNG, and state-layer
  advantages;
- `ComputationalPrimitiveAssumptions` records the required CSPRNG, X25519,
  ML-KEM, HKDF-SHA-256, ChaCha20-Poly1305, erasure, storage, and side-channel
  assumptions.

The Future-State challenge is therefore not an internal-only random variable:
the Real and Random worlds use the same protocol trace and differ in the
challenge ciphertext generated from the selected future state. The ciphertext
generation function is deliberately an interface so a concrete instantiation
can use `standardMessageKey` and `standardEncrypt` from `StandardCrypto.lean`.

Timing and side-channel-visible protocol metadata are also explicit: each
execution observation records Bob's event time, logical message length,
fixed `4096`-byte Envelope length, state-update count, and Receiver Package
update count. These values are included in `CompleteAdversaryView` and in the
attacker capability matrix.

`ConcreteSecurityReductions.lean` adds concrete reduction bookkeeping for the
remaining games. It proves additive bounds for FS and PCS hybrid chains and
direct forgery-probability bounds for Authentication and both KCI compromise
directions. The component terms are explicitly named for erasure, recovery,
X25519, ML-KEM, HKDF, AEAD, randomness, Ed25519, and transcript/package
binding.

`ConcreteSecurityModel.lean` instantiates the probability and primitive-game
layer used by those reductions:

- `FiniteSampleSpace` fixes an explicit finite seed space, and
  `finiteUniformProbability` computes exact rational success probability as
  successful seeds divided by the sample-space size;
- `CSPRNGGame` models real hidden output versus an independent random-output
  experiment, with an explicit `CSPRNGSecurityCertificate`;
- `KEMSecurityGame` provides separate X25519 and ML-KEM encapsulated-secret
  games and adapters from `StandardCryptoAPI`;
- `KDFSecurityGame` connects HKDF-SHA-256 domain-separated derivation to a
  real/random key challenge;
- `AEADConfidentialityGame` is an M0/M1 challenge using the configured
  encryption function, while `AEADSecurityCertificate` also records an
  integrity-forgery experiment;
- `ConcretePrimitiveGameSuite` collects the named game certificates and the
  state-layer term into the six component advantages consumed by SECC;
- `AsymptoticNegligible` is the explicit epsilon-based negligible predicate
  used by this dependency-free model. `six_term_sum_negligible` proves closure
  under the six component advantages, and
  `computational_secc_from_primitive_game_suite` proves the final SECC theorem
  from the concrete reduction bound plus the six component proofs.

The named primitive security certificates remain cryptographic assumptions
about their explicit games; the file does not pretend to prove standard
primitive security from the symbolic `Nat` encodings. It does, however,
mechanically prove the probability bookkeeping and the final finite-sum
negligibility implication.

`ConcreteSECCReduction.lean` proves the additive hybrid reduction itself. It
defines the ordered games
`Real -> StateIsolated -> X25519Replaced -> MLKEMReplaced -> HKDFReplaced ->
AEADReplaced -> Random`, assigns one explicit advantage obligation to each
hop, and machine-checks:

```text
Adv_SECC <= Adv_State + Adv_X25519 + Adv_MLKEM + Adv_HKDF
             + Adv_AEAD + Adv_CSPRNG
```

The theorem `computational_secc_from_concrete_reduction` derives the
`ComputationalSECC` predicate from that bound and a negligible-bound proof.
The hop obligations and negligible proof remain the integration point for a
concrete probabilistic model and vetted cryptographic implementations; these
dependency-free Lean files do not claim to prove the computational security of
the named primitives from first principles.

The capability matrix is machine-checked: the attacker may control Alice,
network/DHT behavior, replay/modify/delay/drop messages, and observe Bob's
public/ACK/error outputs; Bob secret state, Bob fresh randomness, and Bob
storage mutation/rollback are outside this threat model.

`LinkChat-Standardized-v1.0.md` is the complete text protocol after the
standard primitive replacement. It preserves the original section structure,
state machine, alternating turns, Receiver Packages, DHT mailbox, anonymous
transport, security boundaries, and implementation constraints.

## Run

Run these commands from the root of this repository. The generated `.olean`
files are build artifacts and should not be committed.

```sh
lean -o LinkChat.olean LinkChat.lean
LEAN_PATH=. lean -o SecurityGames.olean SecurityGames.lean
LEAN_PATH=. lean -o RefinedProtocol.olean RefinedProtocol.lean
LEAN_PATH=. lean -o StandardCrypto.olean StandardCrypto.lean
LEAN_PATH=. lean -o ComputationalGames.olean ComputationalGames.lean
LEAN_PATH=. lean -o ConcreteSECCReduction.olean ConcreteSECCReduction.lean
LEAN_PATH=. lean -o ConcreteSecurityReductions.olean ConcreteSecurityReductions.lean
LEAN_PATH=. lean -o ConcreteSecurityModel.olean ConcreteSecurityModel.lean
```

The file intentionally models cryptographic primitives abstractly. The
following are assumptions outside this state-machine proof: computational KEM
security, HKDF security, AEAD confidentiality/integrity, secure erasure,
CSPRNG quality, rollback-resistant storage, and side-channel resistance.
Therefore this artifact is a formal proof of the protocol control/state
properties and a symbolic security-game interface, not a computational
security proof of X25519, ML-KEM, HKDF, or ChaCha20-Poly1305. In particular,
the Lean results establish view/state non-interference under fixed honest
freshness and provide the Real/Random, FS, and PCS reduction interfaces; they
do not by themselves establish a negligible-advantage bound. A concrete
computational theorem must instantiate `ProbabilitySemantics`, prove the
`SECCReduction.advantageBound`, and provide the negligible bound from the
standard primitive assumptions.
