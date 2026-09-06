//! Versioned wire types and canonical encoding for Link Chat v1.0.
//!
//! The codec is deliberately stateless. It does not perform cryptography,
//! network I/O, storage, or protocol state transitions.

mod codec;
pub mod domain;
mod encoders;
mod errors;
mod foundation;
mod payload;
mod wire_types;

pub use errors::WireError;
pub use foundation::{
    AEAD_TAG_LEN, CANONICAL_FORMAT_VERSION, CIPHERTEXT_LEN, ED25519_SIGNATURE_LEN,
    ENCRYPTED_HEADER_LEN, HEADER_FIELD_COUNT, MAX_APPLICATION_PAYLOAD_LEN, MAX_FIELD_LEN,
    MAX_NESTING_DEPTH, ML_KEM_768_PUBLIC_KEY_LEN, PAYLOAD_FRAME_LEN, WIRE_HEADER_LEN,
    WIRE_RECEIVER_PACKAGE_LEN,
};
pub use payload::{
    decode_ack, decode_application_message, decode_envelope, decode_header, decode_mailbox_record,
    decode_payload_frame, decode_receiver_package, decode_sack, domain_input, encode_payload_frame,
};
pub use wire_types::{
    AckFrame, CanonicalEncode, DeliveryStatus, Direction, EncodedBytes, MailboxRecord, MessageType,
    SackFrame, WireApplicationMessage, WireBytes, WireEnvelope, WireHeader, WireReceiverPackage,
    encode,
};

#[cfg(test)]
mod tests;
