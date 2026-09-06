use std::fmt;

use linkchat_crypto::CryptoError;
use linkchat_protocol::WireError;

#[derive(Debug)]
pub(crate) enum CliError {
    Usage(&'static str),
    InvalidHex(&'static str),
    InvalidValue(&'static str),
    Io,
    Wire(WireError),
    Crypto(CryptoError),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::InvalidHex(name) => write!(formatter, "invalid hexadecimal input: {name}"),
            Self::InvalidValue(name) => write!(formatter, "invalid value: {name}"),
            Self::Io => formatter.write_str("unable to read the requested input"),
            Self::Wire(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CliError {}

impl From<WireError> for CliError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<CryptoError> for CliError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}
