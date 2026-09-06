use linkchat_protocol::DeliveryStatus;
use linkchat_transport::TransportTimestamp;

/// The challenge component recorded by a verification observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Challenge {
    None,
    Real,
    Random,
}

/// The externally visible result of a bounded verification action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptReject {
    Accepted,
    Rejected,
}

/// A network observation label. It intentionally carries no secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkObservation {
    Delivered,
    Dropped,
    Delayed,
    Duplicated,
    Reordered,
}

/// A DHT/Mailbox observation label. It intentionally carries no token bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhtObservation {
    Put,
    Get,
    Expired,
    Unavailable,
}

/// Complete finite observation aligned with Lean `CompleteAdversaryView`.
///
/// Each field is an explicit observable or protocol response. Internal test
/// variables are not represented as public observations by this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteAdversaryView {
    pub challenge: Challenge,
    pub event_time: TransportTimestamp,
    pub logical_length: usize,
    pub envelope_length: usize,
    pub ack: Option<DeliveryStatus>,
    pub error: Option<&'static str>,
    pub accept_reject: AcceptReject,
    pub state_update_count: u64,
    pub package_update_count: u64,
    pub network_observations: Vec<NetworkObservation>,
    pub dht_observations: Vec<DhtObservation>,
}
