use crate::domain;
use crate::{
    AckFrame, CIPHERTEXT_LEN, DeliveryStatus, Direction, ED25519_SIGNATURE_LEN,
    ENCRYPTED_HEADER_LEN, MAX_FIELD_LEN, ML_KEM_768_PUBLIC_KEY_LEN, MailboxRecord, SackFrame,
    WireApplicationMessage, WireBytes, WireEnvelope, WireError, WireReceiverPackage, decode_ack,
    decode_application_message, decode_envelope, decode_mailbox_record, decode_receiver_package,
    decode_sack, encode,
};
use linkchat_types::{
    CipherSuite, HASH_LEN, KeyId, MAILBOX_TOKEN_LEN, MAX_ENVELOPE_SIZE, ML_KEM_768_CIPHERTEXT_LEN,
    MailboxToken, MessageId, PackageGeneration, PackageHash, ProtocolVersion, SessionId, Turn,
    X25519_PUBLIC_KEY_LEN, X25519PublicKey,
};

fn token() -> MailboxToken {
    MailboxToken::from_array([7; MAILBOX_TOKEN_LEN])
}

fn app_message() -> WireApplicationMessage {
    WireApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(11),
        Turn::new(2),
        Direction::Alice,
        MessageId::new(19),
        KeyId::new(23),
        token(),
        WireBytes::from_bytes(b"payload").unwrap(),
    )
}

fn envelope() -> WireEnvelope {
    WireEnvelope::new(
        token(),
        WireBytes::from_bytes(&[1; X25519_PUBLIC_KEY_LEN]).unwrap(),
        WireBytes::from_bytes(&[2; ML_KEM_768_CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[3; ENCRYPTED_HEADER_LEN]).unwrap(),
        WireBytes::from_bytes(&vec![4; CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[]).unwrap(),
    )
    .unwrap()
}

#[test]
fn application_message_round_trips_canonically() {
    let message = app_message();
    let encoded = encode(&message).unwrap();
    let decoded = decode_application_message(encoded.as_bytes()).unwrap();
    assert!(decoded == message);
    assert_eq!(encode(&decoded).unwrap(), encoded);
}

#[test]
fn receiver_package_round_trips_without_private_fields() {
    let package = WireReceiverPackage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(3),
        PackageGeneration::new(4),
        KeyId::new(5),
        X25519PublicKey::from_array([6; X25519_PUBLIC_KEY_LEN]),
        WireBytes::from_bytes(&[7; ML_KEM_768_PUBLIC_KEY_LEN]).unwrap(),
        token(),
        123,
        PackageHash::from_array([8; HASH_LEN]),
        WireBytes::from_bytes(&[9; ED25519_SIGNATURE_LEN]).unwrap(),
    )
    .unwrap();
    let encoded = encode(&package).unwrap();
    let decoded = decode_receiver_package(encoded.as_bytes()).unwrap();
    assert!(decoded == package);
    assert!(
        !encoded
            .as_bytes()
            .windows(32)
            .any(|window| window == [0; 32])
    );
}

#[test]
fn envelope_is_exactly_4096_bytes() {
    let envelope = envelope();
    let encoded = encode(&envelope).unwrap();
    assert_eq!(encoded.as_bytes().len(), MAX_ENVELOPE_SIZE);
    assert!(decode_envelope(encoded.as_bytes()).unwrap() == envelope);
}

#[test]
fn envelope_rejects_wrong_component_lengths() {
    let result = WireEnvelope::new(
        token(),
        WireBytes::from_bytes(&[1; 31]).unwrap(),
        WireBytes::from_bytes(&[2; ML_KEM_768_CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[3; 64]).unwrap(),
        WireBytes::from_bytes(&[4; 64]).unwrap(),
        WireBytes::from_bytes(&[0; 1]).unwrap(),
    );
    assert!(matches!(
        result,
        Err(WireError::InvalidEnvelopeComponent { .. })
    ));
}

#[test]
fn malformed_and_noncanonical_inputs_are_rejected() {
    let encoded = encode(&app_message()).unwrap();
    assert!(matches!(
        decode_application_message(&encoded.as_bytes()[..encoded.as_bytes().len() - 1]),
        Err(WireError::Truncated { .. })
    ));

    let mut trailing = encoded.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        decode_application_message(&trailing),
        Err(WireError::TrailingBytes { .. })
    ));

    let mut unknown_version = encoded.as_bytes().to_vec();
    unknown_version[1] = 0;
    unknown_version[2] = 2;
    assert!(matches!(
        decode_application_message(&unknown_version),
        Err(WireError::InvalidFormatVersion { .. })
    ));

    let mut unknown_suite = encoded.as_bytes().to_vec();
    // First field begins after the 9-byte object header and its 4-byte length.
    unknown_suite[13] = 0;
    unknown_suite[14] = 99;
    assert!(matches!(
        decode_application_message(&unknown_suite),
        Err(WireError::InvalidCipherSuite { .. })
    ));
}

#[test]
fn ack_and_sack_are_distinct_from_application_messages() {
    let ack = AckFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(2),
        DeliveryStatus::Accepted,
    );
    let sack = SackFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(2),
        WireBytes::from_bytes(&[0xaa]).unwrap(),
    )
    .unwrap();
    let ack_bytes = encode(&ack).unwrap();
    let sack_bytes = encode(&sack).unwrap();
    assert!(decode_application_message(ack_bytes.as_bytes()).is_err());
    assert!(decode_application_message(sack_bytes.as_bytes()).is_err());
    assert!(decode_ack(ack_bytes.as_bytes()).is_ok());
    assert!(decode_sack(sack_bytes.as_bytes()).is_ok());
}

#[test]
fn mailbox_record_binds_token_to_envelope() {
    let envelope = envelope();
    let record = MailboxRecord::new(token(), envelope.clone()).unwrap();
    let encoded = encode(&record).unwrap();
    assert!(decode_mailbox_record(encoded.as_bytes()).unwrap() == record);
    assert!(MailboxRecord::new(MailboxToken::from_array([8; 32]), envelope).is_err());
}

#[test]
fn aad_and_domain_contexts_are_centralized_and_bound() {
    let a = domain::message_aad(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(2),
        KeyId::new(3),
    )
    .unwrap();
    let b = domain::header_aad(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        KeyId::new(3),
    )
    .unwrap();
    let c = domain::message_aad(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(1),
        Direction::Alice,
        MessageId::new(2),
        KeyId::new(3),
    )
    .unwrap();
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert!(
        a.as_bytes()
            .windows(domain::MESSAGE_AD.len())
            .any(|window| { window == domain::MESSAGE_AD })
    );

    // HeaderAD is intentionally computable before the encrypted message_id is known.
    // The API has no message_id argument, while MessageAD remains message-specific.
    let header_aad_again = domain::header_aad(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        KeyId::new(3),
    )
    .unwrap();
    assert_eq!(b, header_aad_again);

    let nonce = domain::nonce_info(
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(2),
        KeyId::new(3),
    )
    .unwrap();
    let header_nonce = domain::header_nonce_info(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(1),
        Turn::new(0),
        Direction::Alice,
        KeyId::new(3),
    )
    .unwrap();
    assert_ne!(nonce, header_nonce);
    assert!(
        nonce
            .as_bytes()
            .windows(domain::NONCE.len())
            .any(|window| window == domain::NONCE)
    );
}

#[test]
fn decoded_values_are_rejected_if_not_canonical() {
    let mut encoded = encode(&app_message()).unwrap().into_vec();
    encoded[0] = 0;
    assert!(matches!(
        decode_application_message(&encoded),
        Err(WireError::InvalidTypeTag { .. })
    ));

    let mut encoded = encode(&app_message()).unwrap().into_vec();
    encoded.push(0);
    assert!(matches!(
        decode_application_message(&encoded),
        Err(WireError::TrailingBytes { .. })
    ));
}

#[test]
fn oversized_variable_field_is_rejected_before_allocation() {
    let mut encoded = encode(&app_message()).unwrap().into_vec();
    let payload_length_offset = encoded.len() - 7 - 4;
    encoded[payload_length_offset..payload_length_offset + 4]
        .copy_from_slice(&((MAX_FIELD_LEN as u32) + 1).to_be_bytes());
    assert!(matches!(
        decode_application_message(&encoded),
        Err(WireError::FieldTooLong { .. })
    ));
}

#[test]
fn envelope_length_type_is_used_for_budget_checks() {
    assert_eq!(
        linkchat_types::EnvelopeLength::fixed().get(),
        MAX_ENVELOPE_SIZE
    );
}
