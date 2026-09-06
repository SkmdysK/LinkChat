# Integration Guide

This workspace provides a protocol kernel and integration contracts. It does
not provide a server, DHT, relay, GUI, account system, or chat client.

## Recommended Flow

1. Create or restore an endpoint with `linkchat-engine`, using distinct
   owner-bound bootstrap roots when the session bootstrap defines them.
2. Publish only the public Receiver Package and pinned identity public key to
   the external rendezvous or server layer.
3. Use a `Transport` adapter to carry opaque packet bytes.
4. Use a `Mailbox` adapter to route canonical `MailboxRecord` values by the
   opaque Mailbox Token.
5. Pass candidate Envelope bytes to `EndpointEngine::prepare_receive`.
6. Deliver the authenticated payload only after `commit_receive` succeeds.
7. Publish the returned public Receiver Package after the commit succeeds.

The server never decrypts an Envelope and never owns endpoint private package
material. ACK/SACK, retries, delivery timestamps, deduplication, and TTL are
availability observations only; they do not advance the protocol state.

## Rust Adapter Shape

The application supplies an implementation of `linkchat_engine::EndpointStorage`
for the endpoint-local state. Its commit sequence must be equivalent to:

```text
validate candidate
-> durable Pending
-> durable commit marker
-> atomic Current publication
-> durable directory/barrier sync
-> retire obsolete records only after publication
```

For filesystem deployments, review `docs/storage-backend.md` and reject the
backend when rollback resistance is required but the platform cannot provide
it. The bundled `FileStateStorage` explicitly reports that ordinary filesystems
are not rollback resistant.

## Server Responsibilities

The integration server may implement:

- authenticated application account policy outside the protocol kernel;
- opaque packet transport and retry scheduling;
- token-keyed Mailbox storage with TTL and size limits;
- ACK/SACK delivery reporting;
- connection, rate-limit, quota, and availability policy.

It must not manufacture Receiver Packages, alter Envelope bytes, read private
endpoint state, or treat delivery success as application acceptance. See
`docs/server-adapter-contract.md` for trait-level examples.

## Failure Handling

Classify failures by boundary:

- transport or Mailbox unavailable: retry/availability outcome;
- malformed, unauthenticated, replayed, wrong-turn, or wrong-context Envelope:
  endpoint rejection with no state change;
- crypto failure: endpoint cryptographic failure with no state change;
- storage prepare/commit/recover failure: storage failure with no published
  state change.

Do not retry a protocol rejection as if it were a transport failure.

## Security Boundary

The implementation provides bounded canonical parsing, typed secret handling,
identity/package authentication, hybrid encryption composition, pure state
transitions, and tested storage ordering. Standard primitive security, the OS
CSPRNG, secure erasure, filesystem durability, rollback protection, and the
calling process's memory safety remain external trust boundaries.

The project does not prove anonymity, traffic-analysis protection, side-channel
resistance, malicious-server availability, or arbitrary PPT adversary security.
