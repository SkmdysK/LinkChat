# Engine API

`linkchat-engine` is the Rust composition layer between the protocol core and
an application's storage boundary. It does not open sockets, route Mailbox
records, process ACK/SACK frames, or implement server policy.

## Construction

Use `EndpointConfig::from_identity_keypair` with the local Ed25519 identity,
the pinned peer Ed25519 public key, the session, endpoint direction, a shared
bootstrap package-chain root, expiration, and current time. This constructor is
a compatibility convenience. For the standardized owner-bound roots, use
`from_identity_keypair_with_bootstrap_roots` and provide one root for the local
owner and one for the peer owner. The engine creates the local X25519/ML-KEM
Receiver Package internally:

```rust
let config = EndpointConfig::from_identity_keypair(
    session,
    Endpoint::Alice,
    local_identity,
    peer_identity_public,
    bootstrap_previous_hash,
    expiration,
    now,
);
let mut endpoint = EndpointEngine::create(
    OsCryptoBackend::new(),
    storage_adapter,
    config,
    peer_public_package,
)?;
```

The equivalent explicit-root constructor is:

```rust
let config = EndpointConfig::from_identity_keypair_with_bootstrap_roots(
    session,
    Endpoint::Alice,
    local_identity,
    peer_identity_public,
    local_bootstrap_previous_hash,
    peer_bootstrap_previous_hash,
    expiration,
    now,
);
```

`create_with_local_package` is the recovery/bootstrap path for a private
package that has already been constructed by a trusted typed operation. The
engine verifies the local secret/public binding, peer package signature,
session, turn, generation, expiration, and previous package hash before
initializing storage. No public constructor accepts unrelated secret and
package material.

## Send and Receive

Every application operation has an explicit prepare/commit boundary:

```text
prepare_send -> caller delivers encoded Envelope -> commit_send
prepare_receive -> caller validates output/storage policy -> commit_receive
```

`prepare_send` returns an encoded fixed-size Envelope and a private pending
transition. `prepare_receive` performs bounded canonical decode, hybrid
X25519/ML-KEM decapsulation, HKDF, Header AEAD, Header/package checks, Message
AEAD, payload validation, and fresh Receiver Package generation. Neither
prepare method changes the published endpoint state.

Only `commit_send` or `commit_receive` calls the storage adapter and publishes
the next state. A stale prepare handle is rejected. Storage prepare or commit
failure leaves the engine's published kernel unchanged.

`ReceiveResult` returns the authenticated payload, message id, returned public
Receiver Package, and public snapshot. The package is delivered from the
existing `WireHeader.return_receiver_package` field; no new protocol field is
introduced.

## Error Categories

`EngineError` distinguishes configuration, wire, cryptographic, pure-core
rejection, retryable transport, and storage failures. Error formatting does
not include private keys, tokens, Message Keys, KEM shared secrets, or storage
record contents.

## Storage Adapter Boundary

`EndpointStorage` is intentionally small: `initialize`, `load_current`,
`prepare_commit`, `commit`, and `recover`. An adapter must durably publish its
next state before `EndpointEngine` replaces its in-memory kernel. The bundled
`MemoryEndpointStorage` is for in-process integration and tests. It is not a
production crash-durable backend.

`linkchat-storage::FileStateStorage` is the filesystem transaction backend, but
it does not directly implement the engine's `EndpointStorage` trait. An
application must provide the adapter between those boundaries and preserve the
ordering and rollback capability declaration documented in
`docs/storage-backend.md`. `recover_at(now)` can be used when recovery must
validate package expiration against a fresh caller-supplied time.

## Non-Responsibilities

Transport and Mailbox adapters deliver opaque bytes and availability metadata.
They must not call commit methods because of ACK, SACK, retry, duplicate, or
timestamp events. The engine also does not provide anonymous routing, traffic
analysis resistance, side-channel resistance, or a server availability
guarantee.
