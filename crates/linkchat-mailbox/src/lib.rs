//! Token-keyed Mailbox contracts and a test-only in-memory backend.
//!
//! A Mailbox is an untrusted availability boundary. It stores complete
//! canonical [`MailboxRecord`] values and never invokes or mutates the pure
//! protocol core. TTL, deduplication, limits, and availability are local
//! Mailbox concerns; they do not represent protocol progress.

#[path = "modules/errors.rs"]
mod errors;
#[path = "modules/foundation.rs"]
mod foundation;
#[path = "modules/memory.rs"]
mod memory;

pub use errors::MailboxError;
pub use foundation::{
    DEFAULT_MAX_RETURN_COUNT, DEFAULT_TTL_TICKS, MAX_MAILBOX_RECORD_SIZE, Mailbox,
    MailboxTimestamp, MailboxTtl, PutStatus, decode_canonical_record, encode_canonical_record,
};
pub use memory::InMemoryMailbox;

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
