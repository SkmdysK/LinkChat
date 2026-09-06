use std::fmt;

use linkchat_types::MAX_ENVELOPE_SIZE;

/// Errors returned by bounded canonical encoding and decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    Truncated {
        offset: usize,
        needed: usize,
    },
    TrailingBytes {
        offset: usize,
    },
    InvalidTypeTag {
        actual: u8,
    },
    InvalidFormatVersion {
        actual: u16,
    },
    InvalidVersion {
        major: u16,
        minor: u16,
    },
    InvalidCipherSuite {
        id: u16,
    },
    InvalidFieldCount {
        expected: usize,
        actual: usize,
    },
    MissingRequiredField {
        field: &'static str,
    },
    InvalidFieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    FieldTooLong {
        field: &'static str,
        actual: usize,
    },
    InvalidEnum {
        field: &'static str,
        value: u8,
    },
    IntegerOverflow,
    NestingDepthExceeded,
    NonCanonical,
    InvalidEnvelopeLength {
        actual: usize,
    },
    EnvelopeBudgetExceeded {
        actual: usize,
        maximum: usize,
    },
    InvalidEnvelopeComponent {
        field: &'static str,
    },
    InvalidHeaderComponent {
        field: &'static str,
    },
    Type(linkchat_types::TypeError),
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, needed } => {
                write!(
                    formatter,
                    "truncated input at {offset}, need {needed} bytes"
                )
            }
            Self::TrailingBytes { offset } => write!(formatter, "trailing bytes at {offset}"),
            Self::InvalidTypeTag { actual } => write!(formatter, "invalid type tag {actual:#x}"),
            Self::InvalidFormatVersion { actual } => {
                write!(formatter, "invalid canonical format version {actual}")
            }
            Self::InvalidVersion { major, minor } => {
                write!(formatter, "unsupported protocol version {major}.{minor}")
            }
            Self::InvalidCipherSuite { id } => write!(formatter, "unsupported cipher suite {id}"),
            Self::InvalidFieldCount { expected, actual } => {
                write!(formatter, "expected {expected} fields, got {actual}")
            }
            Self::MissingRequiredField { field } => write!(formatter, "missing field {field}"),
            Self::InvalidFieldLength {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "field {field} requires {expected} bytes, got {actual}"
            ),
            Self::FieldTooLong { field, actual } => {
                write!(formatter, "field {field} is too long: {actual} bytes")
            }
            Self::InvalidEnum { field, value } => {
                write!(formatter, "invalid {field} value {value}")
            }
            Self::IntegerOverflow => write!(formatter, "integer overflow in wire length"),
            Self::NestingDepthExceeded => write!(formatter, "wire nesting depth exceeded"),
            Self::NonCanonical => write!(formatter, "non-canonical wire encoding"),
            Self::InvalidEnvelopeLength { actual } => {
                write!(
                    formatter,
                    "envelope must be exactly {MAX_ENVELOPE_SIZE} bytes, got {actual}"
                )
            }
            Self::EnvelopeBudgetExceeded { actual, maximum } => {
                write!(formatter, "envelope size {actual} exceeds budget {maximum}")
            }
            Self::InvalidEnvelopeComponent { field } => {
                write!(formatter, "invalid envelope component {field}")
            }
            Self::InvalidHeaderComponent { field } => {
                write!(formatter, "invalid header component {field}")
            }
            Self::Type(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for WireError {}

impl From<linkchat_types::TypeError> for WireError {
    fn from(error: linkchat_types::TypeError) -> Self {
        Self::Type(error)
    }
}
