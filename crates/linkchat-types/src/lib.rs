//! Shared, strongly typed values for the Link Chat protocol.
//!
//! This crate contains no protocol transitions and performs no I/O. Wire
//! encoding and state-machine behavior belong to later crates.

mod modules {
    pub mod constants;
    pub mod errors;
    pub mod identifiers;
    pub mod lengths;
    pub mod secrets;
}

pub use modules::constants::*;
pub use modules::errors::TypeError;
pub use modules::identifiers::{
    CipherSuite, KeyId, MessageId, PackageGeneration, ProtocolVersion, SessionId, Turn,
};
pub use modules::lengths::EnvelopeLength;
pub use modules::secrets::{
    MailboxToken, MessageKey, MlKemCiphertext, Nonce, PackageHash, ReceiverSecret, SharedSecret,
    X25519PublicKey,
};

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
