# Server Adapter Contract

This workspace provides contracts for a server, relay, or mailbox service to
implement. It does not implement a server, DHT, relay, socket listener, or
routing product.

## Trust Boundary

Transport and Mailbox are untrusted availability boundaries. They may drop,
delay, duplicate, reorder, replay, modify, withhold, or reject data. The
endpoint remains responsible for canonical decoding, KEM decapsulation, AEAD
verification, package identity checks, replay checks, and durable core commit.

An adapter must never receive or persist endpoint private Receiver Package
material, identity private keys, MessageKey values, KEM shared secrets, or
CSPRNG state. The server may route by the opaque `MailboxToken`, but that
token is a capability for routing and is not endpoint authentication.

## Transport

Implement `linkchat_transport::Transport` for packet delivery:

```rust
use linkchat_transport::{PacketBytes, Transport, TransportEvent};

struct ServerTransport;

impl Transport for ServerTransport {
    type Error = ServerTransportError;

    fn send(&mut self, packet: PacketBytes) -> Result<(), Self::Error> {
        // Route or queue opaque bytes. Do not call linkchat-core here.
        let _ = packet;
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<TransportEvent>, Self::Error> {
        Ok(None)
    }
}
```

`TransportEvent` carries only opaque packet bytes, `DeliveryStatus`, a logical
timestamp, and retry metadata. `TransportEvent::decode_control` and
`ControlFrame::decode_canonical` are for ACK/SACK handling at this boundary.
ACK, SACK, retry counts, timestamps, delivery status, and transport dedup must
not advance Turn, Receiver State, Receiver Package, MessageId consumption, or
any application state.

An adapter may report these operations independently:

- packet send/receive;
- drop, delay, duplicate, reorder, replay, and unavailable outcomes;
- retry and retransmission metadata;
- canonical ACK/SACK control frames.

None of these operations authenticates an application message. A received
application candidate must be passed as bytes to the endpoint engine, which
alone decides whether a state transition is accepted and durably committed.

## Mailbox

Implement `linkchat_mailbox::Mailbox` for token-keyed storage:

```rust
use linkchat_mailbox::{Mailbox, MailboxTtl, PutStatus};
use linkchat_protocol::MailboxRecord;
use linkchat_types::MailboxToken;

struct ServerMailbox;

impl Mailbox for ServerMailbox {
    type Error = ServerMailboxError;

    fn put(
        &mut self,
        token: &MailboxToken,
        record: MailboxRecord,
        ttl: MailboxTtl,
    ) -> Result<PutStatus, Self::Error> {
        let _ = (token, record, ttl);
        Ok(PutStatus::Inserted)
    }

    fn get(
        &mut self,
        token: &MailboxToken,
        maximum_records: usize,
    ) -> Result<Vec<MailboxRecord>, Self::Error> {
        let _ = (token, maximum_records);
        Ok(Vec::new())
    }
}
```

For byte-oriented service APIs, use `decode_canonical_record` before storage
and `encode_canonical_record` when returning a record. Enforce the service's
maximum record size, maximum return count, TTL clock and duplicate policy at
the Mailbox boundary. A `Duplicate` result means the canonical record was
already stored; it is not a protocol replay decision.

The adapter must define whether TTL is based on a monotonic logical clock or a
wall clock, how clock rollback is handled, and what availability guarantees it
offers. It must not claim endpoint rollback resistance unless it has a separate
trusted monotonic storage mechanism.

## Endpoint Integration

The safe order is:

```text
Transport/Mailbox receive
-> bounded endpoint decode
-> cryptographic and package verification
-> pure core transition
-> storage prepare/commit
-> application delivery
```

Transport or Mailbox errors are retryable/availability outcomes. Core rejection
and cryptographic failure are endpoint outcomes. Neither outcome grants the
server permission to mutate endpoint state. Servers cannot decrypt envelopes,
cannot manufacture valid Receiver Packages, and cannot force ACK/SACK traffic
to advance the protocol.

The contracts do not prove server confidentiality, availability, anonymity,
traffic-analysis resistance, side-channel resistance, or correctness of an
adapter's memory and persistence implementation.
