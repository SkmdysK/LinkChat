//! Standard cryptographic provider for Link Chat v1.0.
//!
//! This crate contains primitive wrappers only. It does not implement the
//! protocol state machine, sequence/window semantics, storage, networking, or
//! FFI. Primitive security remains an external trust boundary.

#[path = "modules/backend.rs"]
mod backend;
#[path = "modules/foundation.rs"]
mod foundation;
#[path = "modules/primitives.rs"]
mod primitives;
#[path = "modules/rng.rs"]
mod rng;
#[path = "modules/traits.rs"]
mod traits;

pub use foundation::{
    CryptoError, Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, HmacTag,
    MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, X25519KeyPair, X25519SecretKey,
};
pub use primitives::{mlkem768_public_from_secret, x25519_public_from_secret};
pub use rng::OsCryptoBackend;
pub use traits::{CryptoBackend, CryptoProvider};

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
