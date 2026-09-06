# Contributing

Thank you for contributing to LinkChat Rust Kernel.

## Scope

This repository contains a protocol kernel and integration contracts. Pull
requests must preserve the existing boundaries: no server, DHT, relay, GUI,
chat client, generic reordering, concurrent core commit, or ACK-driven core
state transitions.

Protocol changes require synchronized updates to the wire specification,
Lean model, Rust implementation, vectors, tests, and documentation. Do not
describe bounded tests as universal protocol or cryptographic proofs.

## Before Opening A Pull Request

Run:

```text
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Do not commit `target/`, `.DS_Store`, local configuration, credentials,
private keys, generated binaries, or machine-specific paths. Keep secrets out
of logs, errors, examples, fixtures, and test output.

## Security Reports

Do not disclose suspected vulnerabilities in public issues. Use the private
reporting process documented in `SECURITY.md`.
