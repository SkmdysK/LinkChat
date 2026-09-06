use linkchat_protocol::{MailboxRecord, encode};
use linkchat_types::MailboxToken;

use super::errors::MailboxError;
use super::foundation::{
    DEFAULT_MAX_RETURN_COUNT, MAX_MAILBOX_RECORD_SIZE, Mailbox, MailboxTimestamp, MailboxTtl,
    PutStatus,
};

struct StoredRecord {
    record: MailboxRecord,
    canonical: Vec<u8>,
    expires_at: MailboxTimestamp,
}

/// Test-only in-memory Mailbox. It models TTL, exact canonical deduplication,
/// bounded returns, and injected unavailability; it is not a server.
pub struct InMemoryMailbox {
    records: Vec<StoredRecord>,
    clock: MailboxTimestamp,
    available: bool,
    max_record_size: usize,
    max_return_count: usize,
}

impl InMemoryMailbox {
    pub fn new() -> Self {
        Self::with_limits(MAX_MAILBOX_RECORD_SIZE, DEFAULT_MAX_RETURN_COUNT)
    }

    pub fn with_limits(max_record_size: usize, max_return_count: usize) -> Self {
        Self {
            records: Vec::new(),
            clock: MailboxTimestamp::default(),
            available: true,
            max_record_size,
            max_return_count,
        }
    }

    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    pub const fn is_available(&self) -> bool {
        self.available
    }

    pub const fn now(&self) -> MailboxTimestamp {
        self.clock
    }

    pub const fn max_record_size(&self) -> usize {
        self.max_record_size
    }

    pub const fn max_return_count(&self) -> usize {
        self.max_return_count
    }

    pub fn advance_time(&mut self, ticks: u64) -> Result<(), MailboxError> {
        let next = self
            .clock
            .ticks()
            .checked_add(ticks)
            .ok_or(MailboxError::TtlOverflow)?;
        self.clock = MailboxTimestamp::new(next);
        self.remove_expired();
        Ok(())
    }

    pub fn stored_count(&self) -> usize {
        self.records.len()
    }

    pub fn remove_expired(&mut self) {
        let now = self.clock;
        self.records.retain(|stored| stored.expires_at > now);
    }

    fn ensure_available(&self) -> Result<(), MailboxError> {
        if self.available {
            Ok(())
        } else {
            Err(MailboxError::Unavailable)
        }
    }

    fn validate_record(
        &self,
        token: &MailboxToken,
        record: &MailboxRecord,
    ) -> Result<Vec<u8>, MailboxError> {
        if record.token() != token {
            return Err(MailboxError::TokenMismatch);
        }
        let canonical = encode(record)?.into_vec();
        if canonical.len() > self.max_record_size {
            return Err(MailboxError::RecordTooLarge {
                actual: canonical.len(),
                maximum: self.max_record_size,
            });
        }
        Ok(canonical)
    }
}

impl Default for InMemoryMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox for InMemoryMailbox {
    type Error = MailboxError;

    fn put(
        &mut self,
        token: &MailboxToken,
        record: MailboxRecord,
        ttl: MailboxTtl,
    ) -> Result<PutStatus, Self::Error> {
        self.ensure_available()?;
        self.remove_expired();
        let canonical = self.validate_record(token, &record)?;
        let expires_at = MailboxTimestamp::new(
            self.clock
                .ticks()
                .checked_add(ttl.ticks())
                .ok_or(MailboxError::TtlOverflow)?,
        );
        if self.records.iter().any(|stored| {
            stored.record.token() == token && stored.canonical.as_slice() == canonical.as_slice()
        }) {
            return Ok(PutStatus::Duplicate);
        }
        self.records.push(StoredRecord {
            record,
            canonical,
            expires_at,
        });
        Ok(PutStatus::Inserted)
    }

    fn get(
        &mut self,
        token: &MailboxToken,
        maximum_records: usize,
    ) -> Result<Vec<MailboxRecord>, Self::Error> {
        self.ensure_available()?;
        if maximum_records > self.max_return_count {
            return Err(MailboxError::ReturnLimitExceeded {
                requested: maximum_records,
                maximum: self.max_return_count,
            });
        }
        self.remove_expired();
        Ok(self
            .records
            .iter()
            .filter(|stored| stored.record.token() == token)
            .take(maximum_records)
            .map(|stored| stored.record.clone())
            .collect())
    }
}
