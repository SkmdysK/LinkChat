use std::fmt;

use linkchat_types::{HASH_LEN, ReceiverSecret, X25519PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub(crate) const ED25519_SECRET_KEY_LEN: usize = 32;
pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;
pub(crate) const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
pub(crate) const ML_KEM_768_SEED_LEN: usize = 64;
pub(crate) const SHARED_SECRET_LEN: usize = 32;
pub(crate) const HKDF_ZERO_SALT: [u8; HASH_LEN] = [0; HASH_LEN];

/// Stable provider errors. Values never contain secret or ciphertext bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The operating system CSPRNG could not provide bytes.
    RandomnessUnavailable,
    /// A fixed-size input had the wrong length.
    InvalidLength {
        primitive: &'static str,
        expected: usize,
        actual: usize,
    },
    /// A serialized key failed validation.
    InvalidKey,
    /// X25519 received a low-order point or produced an all-zero output.
    LowOrderPoint,
    /// A KEM ciphertext was malformed.
    InvalidCiphertext,
    /// AEAD authentication failed.
    AuthenticationFailed,
    /// A domain or context exceeded the bounded framing format.
    InvalidKdfLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => f.write_str("cryptographic randomness unavailable"),
            Self::InvalidLength {
                primitive,
                expected,
                actual,
            } => write!(f, "{primitive} requires {expected} bytes, got {actual}"),
            Self::InvalidKey => f.write_str("invalid cryptographic key"),
            Self::LowOrderPoint => f.write_str("invalid low-order X25519 point"),
            Self::InvalidCiphertext => f.write_str("invalid cryptographic ciphertext"),
            Self::AuthenticationFailed => f.write_str("cryptographic authentication failed"),
            Self::InvalidKdfLength => f.write_str("unsupported HKDF input or output length"),
        }
    }
}

impl std::error::Error for CryptoError {}

macro_rules! secret_bytes {
    ($name:ident, $length:expr, $label:literal) => {
        #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name(ReceiverSecret);

        impl $name {
            pub const LEN: usize = $length;

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                if bytes.len() != $length {
                    return Err(CryptoError::InvalidLength {
                        primitive: $label,
                        expected: $length,
                        actual: bytes.len(),
                    });
                }
                ReceiverSecret::from_bytes(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::InvalidKey)
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
    };
}

macro_rules! public_bytes {
    ($name:ident, $length:expr, $label:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const LEN: usize = $length;

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                <[u8; $length]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::InvalidLength {
                        primitive: $label,
                        expected: $length,
                        actual: bytes.len(),
                    })
            }

            pub const fn from_array(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            pub const fn into_array(self) -> [u8; $length] {
                self.0
            }
        }
    };
}

secret_bytes!(
    Ed25519SecretKey,
    ED25519_SECRET_KEY_LEN,
    "Ed25519 secret key"
);
secret_bytes!(X25519SecretKey, X25519PublicKey::LEN, "X25519 secret key");
secret_bytes!(MlKemSecretKey, ML_KEM_768_SEED_LEN, "ML-KEM-768 seed");
secret_bytes!(HmacTag, HASH_LEN, "HMAC-SHA-256 tag");

public_bytes!(
    Ed25519PublicKey,
    ED25519_PUBLIC_KEY_LEN,
    "Ed25519 public key"
);
public_bytes!(Ed25519Signature, ED25519_SIGNATURE_LEN, "Ed25519 signature");
public_bytes!(
    MlKemPublicKey,
    ML_KEM_768_PUBLIC_KEY_LEN,
    "ML-KEM-768 public key"
);

/// An Ed25519 identity key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519KeyPair {
    /// Secret signing key.
    pub secret_key: Ed25519SecretKey,
    /// Public verification key.
    pub public_key: Ed25519PublicKey,
}

/// An X25519 receiver key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519KeyPair {
    /// Secret DH key.
    pub secret_key: X25519SecretKey,
    /// Public DH key.
    pub public_key: X25519PublicKey,
}

/// An ML-KEM-768 receiver key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemKeyPair {
    /// Secret 64-byte ML-KEM seed.
    pub secret_key: MlKemSecretKey,
    /// Public encapsulation key.
    pub public_key: MlKemPublicKey,
}
