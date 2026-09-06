# LinkChat Rust Kernel

[中文](README.zh-CN.md) | **English**

LinkChat Rust Kernel is an executable research artifact for the LinkChat v1.0
protocol. It combines a typed Rust implementation with a Lean formalization of
the protocol's refined state-transition model.

The repository is intended for protocol researchers, cryptographic engineers,
formal-methods researchers, and independent implementers who need a small,
auditable protocol core with explicit integration boundaries.

## Research Scope

LinkChat studies a strictly alternating end-to-end protocol in which each
endpoint controls its own private Receiver State and publishes only a
cryptographically bound Receiver Package projection. A peer may submit an
authenticated message, but cannot select the honest endpoint's next private
state or advance the application turn through transport behavior.

The implementation covers typed protocol values; canonical wire encoding;
domain-separated HKDF-SHA-256 and explicit AAD; Ed25519 identity
authentication; X25519 and ML-KEM-768 hybrid key establishment;
ChaCha20-Poly1305; strict Alice/Bob turn alternation; replay rejection;
no-state-change failures; Current/Pending/Committed storage contracts; and
transport/mailbox interfaces whose ACK, SACK, retry, and deduplication
operations cannot advance protocol state.

It also contains verification vectors, adversarial-input tests, crash matrices,
bounded Rust/Lean conformance checks, an optional opaque-handle C ABI, and a
development CLI.

This is a protocol kernel and integration reference. It is not a chat client,
server, relay, DHT, GUI, account system, identity provider, or production
mailbox service.

## Layered Architecture

```text
linkchat-types
    -> linkchat-protocol / linkchat-crypto
    -> linkchat-core
    -> linkchat-engine
    -> application-owned storage / transport / mailbox adapters
```

`linkchat-core` contains pure protocol state transitions and does not perform
network, mailbox, or filesystem I/O. `linkchat-engine` composes cryptography,
core transitions, storage, and outer adapters without moving deployment logic
into the pure state machine.

## Security and Trust Boundary

The code enforces bounded parsing, canonical re-encoding checks, package
identity binding, session/cipher-suite/turn/generation validation, hybrid key
derivation, AEAD authentication, and durable commit ordering. A receive path
must validate the envelope and package before preparing a new state, and must
complete the storage commit before retiring previous private material.

Private keys, Receiver State, message keys, KEM shared secrets, and other
secret material remain behind typed APIs. The optional FFI uses opaque handles,
stable error codes, and explicit release functions; it does not expose Rust
vectors, trait objects, borrowed references, or private-key bytes across the
ABI.

The security claims stop at the stated implementation and modeling boundary.
This repository does not prove the security of standard primitives, the OS
CSPRNG, secure erasure, side-channel resistance, filesystem rollback
resistance, or an arbitrary deployment. A backend requiring rollback resistance
must provide and honestly declare an appropriate platform mechanism.

Read [`SECURITY.md`](SECURITY.md) and the companion protocol specification
before integrating the kernel.

## Build and Verification

The workspace pins Rust `1.96.0` in `rust-toolchain.toml`.

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Optional development commands:

```bash
cargo run -q -p linkchat-cli -- keygen
cargo run -q -p linkchat-cli -- pair 77
cargo run -q -p linkchat-cli -- test-vector
```

Lean files are research and conformance artifacts. Bounded tests and finite
round exploration are evidence for checked cases; they are not a replacement
for an arbitrary-adversary cryptographic proof or the assumptions of a
concrete security reduction.

## Repository Map

| Path | Purpose |
| --- | --- |
| `crates/linkchat-types` | Public identifiers, lengths, errors, and secret wrappers |
| `crates/linkchat-protocol` | Wire types, canonical codec, domains, AAD, and payloads |
| `crates/linkchat-crypto` | Provider traits and the standard primitive backend |
| `crates/linkchat-core` | Pure refined state machine and envelope semantics |
| `crates/linkchat-engine` | Composition layer for crypto, core, storage, and adapters |
| `crates/linkchat-storage` | In-memory and filesystem storage contracts |
| `crates/linkchat-transport` | Transport traits, ACK/SACK, retry, and adversarial tests |
| `crates/linkchat-mailbox` | Mailbox traits and in-memory test implementation |
| `crates/linkchat-verification` | Vectors, fuzz smoke checks, crash tests, and conformance |
| `crates/linkchat-ffi` | Optional stable opaque-handle C ABI |
| `crates/linkchat-cli` | Optional development and integration CLI |
| `formalization/` | Lean state model, games, reductions, and standard profile |
| `docs/` | API, integration, storage, FFI, and stage documentation |
| `vectors/` | Public protocol and recovery test vectors |

## Companion Research Repository

The language-independent specification, research paper, normative terminology,
wire-format description, security model, and public JSON vectors are maintained
in [`LinkChatDocuments`](https://github.com/SkmdysK/LinkChatDocuments).

For a new implementation, read the specification first, then compare wire and
state-machine behavior against the public vectors before selecting storage and
transport adapters.

## Status and License

This is a frozen research-core release with explicit non-goals and external
security assumptions. It is not a claim of unconditional production readiness.

Released under the MIT License. See [`LICENSE`](LICENSE).
