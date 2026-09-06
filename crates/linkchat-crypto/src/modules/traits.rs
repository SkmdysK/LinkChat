/// Primitive contract for later protocol layers.
pub trait CryptoBackend {
    /// Draws bytes from the provider's randomness source.
    fn random_bytes(&mut self, length: usize) -> Result<Vec<u8>, CryptoError>;
    /// Generate an Ed25519 identity key pair.
    fn generate_ed25519_keypair(&mut self) -> Result<Ed25519KeyPair, CryptoError>;
    /// Sign the supplied message bytes.
    fn ed25519_sign(
        &self,
        secret_key: &Ed25519SecretKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, CryptoError>;
    /// Verify a signature; a validly encoded bad signature returns `Ok(false)`.
    fn ed25519_verify(
        &self,
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<bool, CryptoError>;

    /// Generate an X25519 receiver key pair.
    fn generate_x25519_keypair(&mut self) -> Result<X25519KeyPair, CryptoError>;
    /// Encapsulate with a fresh ephemeral X25519 key. The wrapper ciphertext is 32 bytes.
    fn x25519_encapsulate(
        &mut self,
        recipient: &X25519PublicKey,
    ) -> Result<(X25519PublicKey, SharedSecret), CryptoError>;
    /// Decapsulate and reject low-order/all-zero shared output.
    fn x25519_decapsulate(
        &self,
        secret_key: &X25519SecretKey,
        ciphertext: &X25519PublicKey,
    ) -> Result<SharedSecret, CryptoError>;

    /// Generate an ML-KEM-768 key pair.
    fn generate_mlkem768_keypair(&mut self) -> Result<MlKemKeyPair, CryptoError>;
    /// Encapsulate to an ML-KEM-768 public key.
    fn mlkem768_encapsulate(
        &mut self,
        recipient: &MlKemPublicKey,
    ) -> Result<(MlKemCiphertext, SharedSecret), CryptoError>;
    /// Decapsulate with stable failure mapping.
    fn mlkem768_decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> Result<SharedSecret, CryptoError>;

    /// HKDF-SHA-256 extract with a fixed 32-byte zero salt and explicit domain.
    fn hkdf_extract(&self, domain: &[u8], ikm: &[u8]) -> Result<SharedSecret, CryptoError>;
    /// HKDF-SHA-256 expand to 32 bytes with explicit domain and context.
    fn hkdf_expand_32(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<SharedSecret, CryptoError>;
    /// Derive a message/header key using explicit domain and context.
    fn derive_message_key(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<MessageKey, CryptoError>;
    /// Derive a 12-byte protocol nonce. Callers cannot pass arbitrary nonce bytes here.
    fn derive_nonce(
        &self,
        prk: &SharedSecret,
        domain: &[u8],
        info: &[u8],
    ) -> Result<Nonce, CryptoError>;

    /// Compute SHA-256.
    fn sha256(&self, message: &[u8]) -> PackageHash;
    /// Compute HMAC-SHA-256 with a typed 32-byte key.
    fn hmac_sha256(&self, key: &SharedSecret, message: &[u8]) -> HmacTag;
    /// Seal using a protocol-derived nonce and explicit AAD.
    fn seal(
        &self,
        key: &MessageKey,
        nonce: &Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    /// Open using a protocol-derived nonce and explicit AAD.
    fn open(
        &self,
        key: &MessageKey,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Marker trait for providers satisfying the Link Chat crypto boundary.
pub trait CryptoProvider: CryptoBackend {}

impl<T: CryptoBackend> CryptoProvider for T {}
use crate::foundation::*;
use linkchat_types::{
    MessageKey, MlKemCiphertext, Nonce, PackageHash, SharedSecret, X25519PublicKey,
};
