/// Stable semantic rejection categories for invalid pure-core input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    UnsupportedProtocolVersion,
    UnsupportedCipherSuite,
    SessionMismatch,
    PastTurn,
    FutureTurn,
    WrongLeader,
    ReceiverKeyMismatch,
    ReceiverTokenMismatch,
    Replay,
    FreshPackageSessionMismatch,
    FreshPackageContextMismatch,
    FreshPackageTurnMismatch,
    FreshPackageGenerationNotAdvanced,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::UnsupportedProtocolVersion => "unsupported protocol version",
            Self::UnsupportedCipherSuite => "unsupported cipher suite",
            Self::SessionMismatch => "session mismatch",
            Self::PastTurn => "past turn",
            Self::FutureTurn => "future turn",
            Self::WrongLeader => "message direction is not the current leader",
            Self::ReceiverKeyMismatch => "receiver key id mismatch",
            Self::ReceiverTokenMismatch => "receiver token mismatch",
            Self::Replay => "message id was already consumed",
            Self::FreshPackageSessionMismatch => "fresh package session mismatch",
            Self::FreshPackageContextMismatch => "fresh package context mismatch",
            Self::FreshPackageTurnMismatch => "fresh package turn mismatch",
            Self::FreshPackageGenerationNotAdvanced => "fresh package generation was not advanced",
        };
        formatter.write_str(text)
    }
}

/// Errors while converting or canonically decoding core inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreError {
    Type(TypeError),
    Crypto(CryptoError),
    Wire(WireError),
    NonCanonical,
    InvalidPublicPackage { field: &'static str },
    PrivatePublicKeyMismatch,
    PackageContextMismatch,
    PackageTurnMismatch,
    PackageGenerationMismatch,
    PackageChainMismatch,
    PackageExpired,
    PackageAuthenticationInvalid,
    EnvelopeContextMismatch { field: &'static str },
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
            Self::Wire(error) => error.fmt(formatter),
            Self::NonCanonical => formatter.write_str("non-canonical core input"),
            Self::InvalidPublicPackage { field } => {
                write!(formatter, "invalid public receiver package field {field}")
            }
            Self::PrivatePublicKeyMismatch => {
                formatter.write_str("receiver private and public keys do not match")
            }
            Self::PackageContextMismatch => {
                formatter.write_str("receiver package context mismatch")
            }
            Self::PackageTurnMismatch => formatter.write_str("receiver package turn mismatch"),
            Self::PackageGenerationMismatch => {
                formatter.write_str("receiver package generation mismatch")
            }
            Self::PackageChainMismatch => formatter.write_str("receiver package chain mismatch"),
            Self::PackageExpired => formatter.write_str("receiver package is expired"),
            Self::PackageAuthenticationInvalid => {
                formatter.write_str("receiver package authentication failed")
            }
            Self::EnvelopeContextMismatch { field } => {
                write!(formatter, "encrypted envelope context mismatch: {field}")
            }
        }
    }
}

impl std::error::Error for CoreError {}

impl From<TypeError> for CoreError {
    fn from(error: TypeError) -> Self {
        Self::Type(error)
    }
}

impl From<CryptoError> for CoreError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<WireError> for CoreError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
use std::fmt;

use linkchat_crypto::CryptoError;
use linkchat_protocol::WireError;
use linkchat_types::TypeError;
