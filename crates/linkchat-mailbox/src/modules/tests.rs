use crate::{
    InMemoryMailbox, MAX_MAILBOX_RECORD_SIZE, Mailbox, MailboxError, MailboxTtl, PutStatus,
};
use linkchat_protocol::MailboxRecord;
use linkchat_protocol::{CIPHERTEXT_LEN, ENCRYPTED_HEADER_LEN, WireBytes, WireEnvelope};
use linkchat_types::{
    MAILBOX_TOKEN_LEN, ML_KEM_768_CIPHERTEXT_LEN, MailboxToken, X25519_PUBLIC_KEY_LEN,
};

fn record(token_byte: u8) -> MailboxRecord {
    let token = MailboxToken::from_array([token_byte; MAILBOX_TOKEN_LEN]);
    let envelope = WireEnvelope::new(
        token.clone(),
        WireBytes::from_bytes(&[1; X25519_PUBLIC_KEY_LEN]).unwrap(),
        WireBytes::from_bytes(&[2; ML_KEM_768_CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[3; ENCRYPTED_HEADER_LEN]).unwrap(),
        WireBytes::from_vec(vec![4; CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[]).unwrap(),
    )
    .unwrap();
    MailboxRecord::new(token, envelope).unwrap()
}

#[test]
fn put_get_and_exact_dedup_are_mailbox_only() {
    let token = MailboxToken::from_array([7; MAILBOX_TOKEN_LEN]);
    let mut mailbox = InMemoryMailbox::new();
    assert_eq!(
        mailbox.put(&token, record(7), MailboxTtl::from_ticks(10)),
        Ok(PutStatus::Inserted)
    );
    assert_eq!(
        mailbox.put(&token, record(7), MailboxTtl::from_ticks(10)),
        Ok(PutStatus::Duplicate)
    );
    assert_eq!(mailbox.get(&token, 4).unwrap().len(), 1);
    assert_eq!(mailbox.stored_count(), 1);
}

#[test]
fn ttl_expiration_and_return_limit_are_enforced() {
    let token = MailboxToken::from_array([8; MAILBOX_TOKEN_LEN]);
    let mut mailbox = InMemoryMailbox::with_limits(MAX_MAILBOX_RECORD_SIZE, 1);
    mailbox
        .put(&token, record(8), MailboxTtl::from_ticks(3))
        .unwrap();
    assert!(matches!(
        mailbox.get(&token, 2),
        Err(MailboxError::ReturnLimitExceeded { .. })
    ));
    mailbox.advance_time(3).unwrap();
    assert!(mailbox.get(&token, 1).unwrap().is_empty());
}

#[test]
fn mismatch_size_and_unavailable_are_rejected_without_mutation() {
    let token = MailboxToken::from_array([9; MAILBOX_TOKEN_LEN]);
    let other = MailboxToken::from_array([10; MAILBOX_TOKEN_LEN]);
    let mut mailbox = InMemoryMailbox::with_limits(1, 1);
    assert!(matches!(
        mailbox.put(&token, record(9), MailboxTtl::from_ticks(1)),
        Err(MailboxError::RecordTooLarge { .. })
    ));
    assert_eq!(mailbox.stored_count(), 0);
    mailbox.set_available(false);
    assert!(matches!(
        mailbox.put(&other, record(9), MailboxTtl::from_ticks(1)),
        Err(MailboxError::Unavailable)
    ));
    assert!(matches!(
        mailbox.get(&other, 1),
        Err(MailboxError::Unavailable)
    ));
}

#[test]
fn canonical_record_helpers_round_trip_for_byte_adapters() {
    let original = record(12);
    let encoded = crate::encode_canonical_record(&original).unwrap();
    let decoded = crate::decode_canonical_record(&encoded).unwrap();
    assert!(decoded == original);
}
