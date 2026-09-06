pub use linkchat_types::MAX_ENVELOPE_SIZE;

pub const CANONICAL_FORMAT_VERSION: u16 = 1;
pub const MAX_FIELD_LEN: usize = 64 * 1024;
pub const MAX_NESTING_DEPTH: usize = 2;
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const AEAD_TAG_LEN: usize = 16;

/// The canonical encoded length of a public Receiver Package.
pub const WIRE_RECEIVER_PACKAGE_LEN: usize = 1439;
/// The number of fields in the encrypted logical Header.
pub const HEADER_FIELD_COUNT: usize = 10;
/// The canonical encoded length of the logical Header.
pub const WIRE_HEADER_LEN: usize = 1588;
/// The fixed encrypted Header length, including its AEAD tag.
pub const ENCRYPTED_HEADER_LEN: usize = WIRE_HEADER_LEN + AEAD_TAG_LEN;
/// The fixed plaintext payload frame length.
pub const PAYLOAD_FRAME_LEN: usize = 1291;
/// The maximum application payload after the two-byte logical length prefix.
pub const MAX_APPLICATION_PAYLOAD_LEN: usize = PAYLOAD_FRAME_LEN - 2;
/// The fixed ciphertext field length, including its AEAD tag.
pub const CIPHERTEXT_LEN: usize = PAYLOAD_FRAME_LEN + AEAD_TAG_LEN;

pub(crate) const OBJECT_HEADER_LEN: usize = 9;
pub(crate) const FIELD_LENGTH_LEN: usize = 4;

pub(crate) const TAG_APPLICATION_MESSAGE: u8 = 0x01;
pub(crate) const TAG_RECEIVER_PACKAGE: u8 = 0x02;
pub(crate) const TAG_ENVELOPE: u8 = 0x03;
pub(crate) const TAG_ACK: u8 = 0x04;
pub(crate) const TAG_SACK: u8 = 0x05;
pub(crate) const TAG_MAILBOX_RECORD: u8 = 0x06;
pub(crate) const TAG_HEADER: u8 = 0x07;
pub(crate) const TAG_CONTEXT: u8 = 0x7f;

pub(crate) const FIELD_APPLICATION_MESSAGE: usize = 8;
pub(crate) const FIELD_RECEIVER_PACKAGE: usize = 11;
pub(crate) const FIELD_ENVELOPE: usize = 6;
pub(crate) const FIELD_ACK: usize = 6;
pub(crate) const FIELD_SACK: usize = 6;
pub(crate) const FIELD_MAILBOX_RECORD: usize = 2;
pub(crate) const FIELD_HEADER: usize = HEADER_FIELD_COUNT;
