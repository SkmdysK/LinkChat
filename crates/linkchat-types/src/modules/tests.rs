use std::fmt;

use super::*;
use zeroize::Zeroize;

#[test]
fn turn_and_generation_advance_once() {
    assert_eq!(Turn::new(0).next().unwrap(), Turn::new(1));
    assert_eq!(
        PackageGeneration::new(7).advance().unwrap(),
        PackageGeneration::new(8)
    );
}

#[test]
fn monotonic_counters_report_overflow() {
    assert_eq!(
        Turn::new(u64::MAX).next(),
        Err(TypeError::ArithmeticOverflow { type_name: "Turn" })
    );
    assert_eq!(
        PackageGeneration::new(u64::MAX).next(),
        Err(TypeError::ArithmeticOverflow {
            type_name: "PackageGeneration"
        })
    );
}

#[test]
fn identifiers_are_distinct_newtypes() {
    let message_id = MessageId::new(9);
    let key_id = KeyId::new(9);
    let session_id = SessionId::new(9);
    assert_eq!(message_id.get(), key_id.get());
    assert_eq!(session_id.get(), 9);
}

#[test]
fn protocol_version_and_suite_are_checked() {
    assert_eq!(
        ProtocolVersion::try_supported(1, 0).unwrap(),
        ProtocolVersion::V1_0
    );
    assert_eq!(
        ProtocolVersion::try_supported(2, 0),
        Err(TypeError::UnsupportedProtocolVersion { major: 2, minor: 0 })
    );
    assert_eq!(CipherSuite::try_from_id(1).unwrap(), CipherSuite::current());
    assert_eq!(
        CipherSuite::try_from_id(77),
        Err(TypeError::UnsupportedCipherSuite { id: 77 })
    );
    assert_eq!(
        ProtocolVersion::new(0, 1),
        Err(TypeError::ValueOutOfRange {
            type_name: "ProtocolVersion.major",
            value: 0,
        })
    );
}

#[test]
fn fixed_length_types_reject_invalid_input() {
    assert!(matches!(
        MailboxToken::from_bytes(&[0; MAILBOX_TOKEN_LEN - 1]),
        Err(TypeError::InvalidLength {
            type_name: "MailboxToken",
            ..
        })
    ));
    assert!(PackageHash::from_bytes(&[0; HASH_LEN]).is_ok());
    assert!(X25519PublicKey::from_bytes(&[0; X25519_PUBLIC_KEY_LEN]).is_ok());
    assert!(MlKemCiphertext::from_bytes(&[0; ML_KEM_768_CIPHERTEXT_LEN]).is_ok());
    assert!(MessageKey::from_bytes(&[0; MESSAGE_KEY_LEN]).is_ok());
    assert!(Nonce::from_bytes(&[0; NONCE_LEN]).is_ok());
    assert!(SharedSecret::from_bytes(&[0; SHARED_SECRET_LEN]).is_ok());
    assert!(SharedSecret::from_bytes(&[0; SHARED_SECRET_LEN - 1]).is_err());
    assert!(MlKemCiphertext::from_bytes(&[0; ML_KEM_768_CIPHERTEXT_LEN - 1]).is_err());
}

#[test]
fn receiver_secret_is_bounded_and_zeroizable() {
    assert!(matches!(
        ReceiverSecret::from_bytes(&[]),
        Err(TypeError::EmptyValue {
            type_name: "ReceiverSecret"
        })
    ));
    assert!(matches!(
        ReceiverSecret::from_bytes(&vec![0; MAX_RECEIVER_SECRET_LEN + 1]),
        Err(TypeError::LengthExceedsMaximum {
            type_name: "ReceiverSecret",
            ..
        })
    ));

    let mut secret = ReceiverSecret::from_bytes(&[7; 32]).unwrap();
    assert_eq!(secret.len(), 32);
    secret.zeroize();
    assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn envelope_length_obeys_fixed_budget() {
    assert!(EnvelopeLength::new(MAX_ENVELOPE_SIZE).unwrap().is_fixed());
    assert_eq!(EnvelopeLength::fixed().get(), MAX_ENVELOPE_SIZE);
    assert_eq!(
        EnvelopeLength::new(MAX_ENVELOPE_SIZE + 1),
        Err(TypeError::LengthExceedsMaximum {
            type_name: "EnvelopeLength",
            maximum: MAX_ENVELOPE_SIZE,
            actual: MAX_ENVELOPE_SIZE + 1,
        })
    );
}

#[test]
fn public_types_can_be_debugged_without_secret_types_following_suit() {
    fn assert_debug<T: fmt::Debug>() {}

    assert_debug::<PackageHash>();
    assert_debug::<X25519PublicKey>();
    assert_debug::<MlKemCiphertext>();
    assert_debug::<Nonce>();
    // MailboxToken, ReceiverSecret, MessageKey, and SharedSecret
    // intentionally do not implement Debug.
}
