# Link Chat Rust Kernel Module Layout

The kernel keeps its existing crate boundaries and public API, while the
largest crates are physically split by responsibility under `src/modules/`.
The crate root remains a small composition boundary so the current private
invariants and public paths are unchanged during this refactor.

## Dependency Direction

The kernel is organized as a one-way dependency graph:

```text
linkchat-types
      |
      +--> linkchat-protocol
      +--> linkchat-crypto
                |
                v
          linkchat-core

linkchat-core ---> linkchat-engine ---> external storage adapter
      |
      +--> linkchat-storage

linkchat-transport ----> integration layer
linkchat-mailbox  ----> integration layer
linkchat-verification -> test and conformance tooling
linkchat-ffi           -> optional C ABI boundary
linkchat-cli           -> optional operator tooling
```

`linkchat-engine` is the storage-aware composition layer. It combines the
crypto/core operations with an `EndpointStorage` trait, while
`linkchat-storage` supplies standalone state-storage backends such as
`FileStateStorage`. The core does not depend on engine or storage.

The protocol core does not depend on the transport, mailbox, FFI, or CLI
crates. This prevents delivery acknowledgements, mailbox availability, or
integration concerns from becoming protocol state transitions.

## Protocol

- `foundation.rs`: imports, wire constants, tags, and field counts.
- `errors.rs`: bounded codec errors and conversions.
- `wire_types.rs`: public wire values and canonical encoding facade types.
- `payload.rs`: fixed-size `PayloadFrame` encoding and validation.
- `codec.rs`: bounded decoder and primitive field readers.
- `encoders.rs`: canonical encoders and decoders for protocol objects.
- `domain.rs`: domain separation labels and AAD builders.
- `tests.rs`: protocol codec and boundary tests.

## Core

- `foundation.rs`: core imports and crypto length constants.
- `endpoint_session.rs`: endpoint, session, and turn context.
- `packages.rs`: public/private receiver packages and package authentication.
- `message.rs`: application message representation.
- `errors.rs`: rejection and core error taxonomy.
- `transition.rs`: pure state transition and prepared commit result.
- `snapshot.rs`: public state projection.
- `tests.rs`: state-machine and package tests.

## Crypto

- `foundation.rs`: typed keys, key pairs, and shared constants.
- `traits.rs`: `CryptoBackend` and provider contracts.
- `rng.rs`: production and deterministic test randomness sources.
- `primitives.rs`: primitive helper implementations.
- `backend.rs`: standard backend implementation.
- `tests.rs`: known-answer and primitive boundary tests.

## Storage and transport

- Storage is split into state model, error taxonomy, fault-injectable memory
  backend, hash/integrity helpers, and tests.
- Transport is split into common packet/control contracts, FIFO memory
  transport, adversarial harness, and tests.

This layout deliberately does not add server, DHT, relay, GUI, sequence
window, concurrent core updates, or ACK-driven state transitions.

## Shared Types

`linkchat-types` is split into stable contract categories:

- `constants.rs`: frozen protocol sizes and allocation bounds.
- `errors.rs`: construction and bounded-value errors.
- `identifiers.rs`: session, message, turn, generation, version, and suite types.
- `lengths.rs`: bounded envelope-length type.
- `secrets.rs`: fixed-size public/secret byte wrappers and opaque receiver secrets.
- `tests.rs`: type-level boundary tests.

The crate root only re-exports these types. New public values should be added
to the smallest applicable module rather than to `lib.rs`.

## Mailbox and Verification

`linkchat-mailbox` is an availability adapter boundary:

- `foundation.rs`: `Mailbox` trait, TTL/time values, and result status.
- `errors.rs`: stable mailbox error taxonomy.
- `memory.rs`: test-only in-memory implementation.
- `tests.rs`: mailbox contract tests.

`docs/server-adapter-contract.md` defines the external server/relay boundary,
including opaque packet transport, token-keyed Mailbox routing, canonical
record helpers, retry metadata, TTL, and the prohibition on ACK/SACK-driven
core state changes.

`linkchat-verification` keeps the public observation model in
`observations.rs`. Its large finite-trace fixtures live in `tests.rs` and are
not part of the production kernel API.

## FFI and CLI

`linkchat-ffi` separates the ABI surface from its implementation machinery:

- `foundation.rs`: C-compatible metadata and error codes.
- `registry.rs`: opaque-handle storage.
- `helpers.rs`: panic, pointer, canonical-wire, and buffer helpers.
- `api.rs`: exported C functions.
- `tests.rs`: ABI lifecycle and buffer-safety tests.

`linkchat-cli` separates command implementations, hex/argument parsing, and
error formatting. It remains an optional tool and is not a dependency of the
kernel crates.

## Extension Rules

Future integrations should follow these rules:

1. Add protocol fields only in `linkchat-protocol` after updating the frozen
   wire specification and conformance vectors.
2. Add cryptographic backends behind `CryptoBackend`; do not expose primitive
   library types through `linkchat-core`.
3. Keep `linkchat-core` transitions pure and synchronous; ACK/SACK/retry remain
   transport concerns.
4. Implement durable state in `linkchat-storage` through the prepare/commit/
   recover contract; do not let adapters mutate core state directly.
5. Put server, relay, DHT, GUI, language bindings, and application policy in
   crates outside this kernel workspace or in explicitly optional adapter
   crates.
