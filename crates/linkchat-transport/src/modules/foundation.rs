use std::fmt;

use linkchat_protocol::{DeliveryStatus, WireError, decode_ack, decode_sack, encode};
use linkchat_types::{MAX_ENVELOPE_SIZE, TypeError};

pub use linkchat_protocol::{AckFrame, SackFrame};

/// The maximum opaque packet allocation accepted by the test transport.
pub const MAX_TRANSPORT_PACKET_SIZE: usize = MAX_ENVELOPE_SIZE;

/// Opaque raw wire packet bytes.  This is transport data, not a secret type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketBytes(Vec<u8>);

impl PacketBytes {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransportError> {
        Self::from_vec(bytes.to_vec())
    }

    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, TransportError> {
        if bytes.len() > MAX_TRANSPORT_PACKET_SIZE {
            return Err(TransportError::PacketTooLarge {
                actual: bytes.len(),
                maximum: MAX_TRANSPORT_PACKET_SIZE,
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for PacketBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A logical transport timestamp.  Production implementations must define
/// their clock and monotonicity contract; the memory backend uses ticks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportTimestamp(u64);

impl TransportTimestamp {
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// Retry metadata is delivery bookkeeping only, never protocol state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RetryMetadata {
    attempt: u32,
    retransmission: bool,
}

impl RetryMetadata {
    pub const fn new(attempt: u32, retransmission: bool) -> Self {
        Self {
            attempt,
            retransmission,
        }
    }

    pub const fn attempt(self) -> u32 {
        self.attempt
    }

    pub const fn is_retransmission(self) -> bool {
        self.retransmission
    }
}

/// A packet plus transport-only delivery metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportEvent {
    packet: PacketBytes,
    delivery_status: DeliveryStatus,
    timestamp: TransportTimestamp,
    retry: RetryMetadata,
}

impl TransportEvent {
    pub fn new(
        packet: PacketBytes,
        delivery_status: DeliveryStatus,
        timestamp: TransportTimestamp,
        retry: RetryMetadata,
    ) -> Self {
        Self {
            packet,
            delivery_status,
            timestamp,
            retry,
        }
    }

    pub fn packet(&self) -> &PacketBytes {
        &self.packet
    }

    pub const fn delivery_status(&self) -> DeliveryStatus {
        self.delivery_status
    }

    pub const fn timestamp(&self) -> TransportTimestamp {
        self.timestamp
    }

    pub const fn retry(&self) -> RetryMetadata {
        self.retry
    }

    /// Decodes this event as a canonical ACK/SACK control frame.  A transport
    /// adapter may use this helper for control traffic, but must never forward
    /// the result into `linkchat-core` as an application transition.
    pub fn decode_control(&self) -> Result<ControlFrame, TransportError> {
        ControlFrame::decode_canonical(self.packet.as_bytes())
    }
}

/// Transport failures that do not contain packet or secret bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    Unavailable,
    PacketTooLarge { actual: usize, maximum: usize },
    InvalidControlFrame,
    Wire(WireError),
    Type(TypeError),
    DelayOverflow,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("transport unavailable"),
            Self::PacketTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "packet size {actual} exceeds transport maximum {maximum}"
                )
            }
            Self::InvalidControlFrame => formatter.write_str("invalid ACK/SACK control frame"),
            Self::Wire(error) => error.fmt(formatter),
            Self::Type(error) => error.fmt(formatter),
            Self::DelayOverflow => formatter.write_str("transport delay overflow"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<WireError> for TransportError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<TypeError> for TransportError {
    fn from(error: TypeError) -> Self {
        Self::Type(error)
    }
}

/// Raw packet transport contract for an external server or relay adapter.
///
/// Implementations may add routing, buffering, drop/delay/retry policy and
/// delivery metadata, but must not call core state transitions as a side effect
/// of send, receive, retry, or ACK/SACK handling.  `PacketBytes` are opaque;
/// endpoint code owns canonical decoding and cryptographic verification.
pub trait Transport {
    type Error;

    fn send(&mut self, packet: PacketBytes) -> Result<(), Self::Error>;
    fn receive(&mut self) -> Result<Option<TransportEvent>, Self::Error>;
}

/// A validated transport/control frame.  Application messages are excluded.
#[derive(Clone, PartialEq, Eq)]
pub enum ControlFrame {
    Ack(AckFrame),
    Sack(SackFrame),
}

impl ControlFrame {
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, TransportError> {
        if let Ok(ack) = decode_ack(bytes) {
            let encoded = encode(&ack)?;
            if encoded.as_bytes() != bytes {
                return Err(TransportError::InvalidControlFrame);
            }
            return Ok(Self::Ack(ack));
        }
        if let Ok(sack) = decode_sack(bytes) {
            let encoded = encode(&sack)?;
            if encoded.as_bytes() != bytes {
                return Err(TransportError::InvalidControlFrame);
            }
            return Ok(Self::Sack(sack));
        }
        Err(TransportError::InvalidControlFrame)
    }

    pub fn encode_canonical(&self) -> Result<PacketBytes, TransportError> {
        let encoded = match self {
            Self::Ack(ack) => encode(ack)?,
            Self::Sack(sack) => encode(sack)?,
        };
        PacketBytes::from_vec(encoded.into_vec())
    }

    pub const fn is_ack(&self) -> bool {
        matches!(self, Self::Ack(_))
    }

    pub const fn is_sack(&self) -> bool {
        matches!(self, Self::Sack(_))
    }
}
