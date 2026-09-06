# LinkChat Rust Kernel

LinkChat Rust Kernel is a Rust implementation of the Link Chat v1.0 protocol
kernel and its integration boundaries. It provides typed protocol values,
canonical wire encoding, a hybrid cryptographic backend, a pure alternating
state machine, storage contracts, transport/mailbox contracts, verification
harnesses, and optional C ABI/CLI adapters.

This repository is a kernel and integration reference. It is not a chat
client, server, DHT, relay, GUI, account system, or production mailbox
service.

## Workspace

The crates are layered as follows:

```text
linkchat-types
    -> linkchat-protocol / linkchat-crypto
    -> linkchat-core
    -> linkchat-engine
    -> application-owned storage / transport / mailbox adapters
```

The workspace also contains:

- `linkchat-storage`: memory fault model and filesystem storage adapter;
- `linkchat-transport` and `linkchat-mailbox`: outer-layer contracts and test
  implementations;
- `linkchat-verification`: vectors, bounded differential checks, fuzz smoke,
  and crash matrices;
- `linkchat-ffi`: optional opaque-handle C ABI;
- `linkchat-cli`: optional development and integration CLI.

## Security Model

The implementation enforces bounded canonical parsing, typed secret
separation, package identity binding, hybrid X25519/ML-KEM-768 encryption,
ChaCha20-Poly1305 authentication, no-state-change failures, and explicit
prepare/commit boundaries.

ACK, SACK, retry, transport deduplication, timestamps, and mailbox
availability do not advance the protocol state. Private keys, receiver
secrets, message keys, and KEM shared secrets do not cross the C ABI.

The project does not claim to prove the security of standard cryptographic
primitives, the OS CSPRNG, secure erasure, filesystem rollback resistance,
side-channel resistance, or arbitrary adversary security. Read
`crates/linkchat-crypto/SECURITY.md` and `docs/integration-guide.md` before
deploying an adapter.

## Build And Test

The repository pins Rust `1.96.0` in `rust-toolchain.toml`.

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The optional CLI can be exercised with:

```bash
cargo run -q -p linkchat-cli -- keygen
cargo run -q -p linkchat-cli -- pair 77
cargo run -q -p linkchat-cli -- test-vector
```

## Integration

Use `linkchat-engine` for endpoint composition. Keep network and mailbox
logic outside `linkchat-core`; deliver an authenticated payload to the
application only after receive commit succeeds. The bundled
`FileStateStorage` reports that ordinary filesystems are not rollback
resistant. Applications requiring that property must provide a backend that
can honestly declare it.

See:

- `docs/engine-api.md`
- `docs/integration-guide.md`
- `docs/storage-backend.md`
- `docs/server-adapter-contract.md`
- `docs/ffi-abi.md`
- `docs/stage-completion-matrix.md`

## License

Licensed under the MIT License. See `LICENSE`.
