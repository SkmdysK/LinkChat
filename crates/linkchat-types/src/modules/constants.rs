/// The fixed envelope budget mandated by the v1.0 protocol specification.
pub const MAX_ENVELOPE_SIZE: usize = 4096;
/// The fixed capability size mandated for mailbox tokens.
pub const MAILBOX_TOKEN_LEN: usize = 32;
/// The X25519 public value size.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// The ML-KEM-768 public key size.
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
/// The ML-KEM-768 ciphertext size.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// The ChaCha20-Poly1305 key size.
pub const MESSAGE_KEY_LEN: usize = 32;
/// The HKDF-derived nonce size used by ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;
/// The SHA-256 digest size.
pub const HASH_LEN: usize = 32;
/// The fixed size of HKDF and KEM shared-secret values.
pub const SHARED_SECRET_LEN: usize = 32;
/// A local allocation bound for the opaque receiver secret container.
pub const MAX_RECEIVER_SECRET_LEN: usize = 64 * 1024;
