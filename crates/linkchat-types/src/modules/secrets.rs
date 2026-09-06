use zeroize::{Zeroize, ZeroizeOnDrop};

use super::constants::{
    HASH_LEN, MAILBOX_TOKEN_LEN, MAX_RECEIVER_SECRET_LEN, MESSAGE_KEY_LEN,
    ML_KEM_768_CIPHERTEXT_LEN, NONCE_LEN, SHARED_SECRET_LEN, X25519_PUBLIC_KEY_LEN,
};
use super::errors::TypeError;

macro_rules! fixed_bytes_type {
    (
        $(#[$meta:meta])* $name:ident, $length:expr, $type_label:literal, secret
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const LEN: usize = $length;

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypeError> {
                let array = <[u8; $length]>::try_from(bytes).map_err(|_| {
                    TypeError::InvalidLength {
                        type_name: $type_label,
                        expected: $length,
                        actual: bytes.len(),
                    }
                })?;
                Ok(Self(array))
            }

            pub const fn from_array(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            pub fn into_array(self) -> [u8; $length] {
                self.0
            }
        }
    };
    (
        $(#[$meta:meta])* $name:ident, $length:expr, $type_label:literal, public
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const LEN: usize = $length;

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypeError> {
                let array = <[u8; $length]>::try_from(bytes).map_err(|_| {
                    TypeError::InvalidLength {
                        type_name: $type_label,
                        expected: $length,
                        actual: bytes.len(),
                    }
                })?;
                Ok(Self(array))
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

fixed_bytes_type! {
    /// A 32-byte mailbox capability. It intentionally has no `Debug` or
    /// `Display` implementation to avoid accidental logging.
    MailboxToken, MAILBOX_TOKEN_LEN, "MailboxToken", secret
}

fixed_bytes_type! {
    /// A SHA-256 package or transcript hash.
    PackageHash, HASH_LEN, "PackageHash", public
}

fixed_bytes_type! {
    /// An X25519 public key.
    X25519PublicKey, X25519_PUBLIC_KEY_LEN, "X25519PublicKey", public
}

fixed_bytes_type! {
    /// An ML-KEM-768 ciphertext.
    MlKemCiphertext, ML_KEM_768_CIPHERTEXT_LEN, "MlKemCiphertext", public
}

fixed_bytes_type! {
    /// A ChaCha20-Poly1305 message key. It intentionally has no `Debug` or
    /// `Display` implementation.
    MessageKey, MESSAGE_KEY_LEN, "MessageKey", secret
}

fixed_bytes_type! {
    /// A protocol nonce. Nonces are not generated through this type; later
    /// crypto code is responsible for applying the frozen derivation rule.
    Nonce, NONCE_LEN, "Nonce", public
}

fixed_bytes_type! {
    /// A KEM-derived shared secret. It intentionally has no `Debug` or
    /// `Display` implementation.
    SharedSecret, SHARED_SECRET_LEN, "SharedSecret", secret
}

/// An opaque receiver secret container for the composite local secret state.
///
/// The concrete X25519 and ML-KEM private-key layout is deliberately deferred
/// to the crypto provider. This type only enforces non-empty, bounded storage
/// and zeroizes its contents when dropped. Zeroization remains an
/// implementation and platform trust boundary; it is not a Rust proof of
/// secure erasure.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ReceiverSecret {
    bytes: Box<[u8]>,
}

impl ReceiverSecret {
    /// Creates an opaque receiver secret without exposing a bare byte-vector
    /// API to callers.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypeError> {
        if bytes.is_empty() {
            return Err(TypeError::EmptyValue {
                type_name: "ReceiverSecret",
            });
        }
        if bytes.len() > MAX_RECEIVER_SECRET_LEN {
            return Err(TypeError::LengthExceedsMaximum {
                type_name: "ReceiverSecret",
                maximum: MAX_RECEIVER_SECRET_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: Box::from(bytes),
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrows the secret for a crypto-provider operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
