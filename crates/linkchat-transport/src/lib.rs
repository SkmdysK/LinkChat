//! Transport/control contracts and test-only adversarial in-memory transport.
//!
//! Transport events carry opaque wire bytes and delivery metadata. They do
//! not expose or mutate `linkchat-core` state. ACK/SACK validation is kept in
//! this layer and is deliberately separate from application-message
//! processing.

#[path = "modules/adversarial.rs"]
mod adversarial;
#[path = "modules/foundation.rs"]
mod foundation;
#[path = "modules/memory.rs"]
mod memory;

pub use adversarial::{
    AdversarialTransportHarness, AdversaryEndpoint, AttackKind, AttackObservation,
};
pub use foundation::{
    AckFrame, ControlFrame, MAX_TRANSPORT_PACKET_SIZE, PacketBytes, RetryMetadata, SackFrame,
    Transport, TransportError, TransportEvent, TransportTimestamp,
};
pub use memory::InMemoryTransport;

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
