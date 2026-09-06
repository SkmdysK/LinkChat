use linkchat_protocol::{MailboxRecord, MailboxRecord as WireMailboxRecord};
use linkchat_types::MailboxToken;

use crate::MailboxError;

/// Decodes one canonical MailboxRecord at a server adapter boundary.
pub fn decode_canonical_record(bytes: &[u8]) -> Result<MailboxRecord, MailboxError> {
    Ok(linkchat_protocol::decode_mailbox_record(bytes)?)
}

/// Encodes one MailboxRecord in its unique canonical wire representation.
pub fn encode_canonical_record(record: &WireMailboxRecord) -> Result<Vec<u8>, MailboxError> {
    Ok(linkchat_protocol::encode(record)?.into_vec())
}

/// Maximum canonical record size accepted by the in-memory test backend.
pub const MAX_MAILBOX_RECORD_SIZE: usize = 8 * 1024;
/// Default maximum number of records returned by one `get` operation.
pub const DEFAULT_MAX_RETURN_COUNT: usize = 16;
/// Default logical TTL for records inserted into the test backend.
pub const DEFAULT_TTL_TICKS: u64 = 1024;

/// Logical, non-wall-clock TTL used by a Mailbox implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxTtl(u64);

impl MailboxTtl {
    pub const fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }

    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// Logical Mailbox time. Production implementations must document the clock
/// and persistence/monotonicity properties they provide.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxTimestamp(u64);

impl MailboxTimestamp {
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// Result of a successful put. Exact canonical duplicates are idempotent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutStatus {
    Inserted,
    Duplicate,
}

/// Token-keyed Mailbox interface for an external server adapter.
///
/// Implementations must route only by the supplied opaque token, enforce their
/// documented TTL and size/return limits, and define how duplicate, drop,
/// replay, delay and unavailable outcomes are reported. They must treat both
/// records and tokens as untrusted input and must not perform core state
/// transitions. Mailbox success is delivery availability only; it is never
/// protocol acceptance or a replacement for endpoint authentication.
pub trait Mailbox {
    type Error;

    fn put(
        &mut self,
        token: &MailboxToken,
        record: MailboxRecord,
        ttl: MailboxTtl,
    ) -> Result<PutStatus, Self::Error>;

    fn get(
        &mut self,
        token: &MailboxToken,
        maximum_records: usize,
    ) -> Result<Vec<MailboxRecord>, Self::Error>;
}
