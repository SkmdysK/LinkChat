use std::fmt;

/// Errors raised while constructing or advancing public protocol values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeError {
    /// A byte sequence does not have the required fixed length.
    InvalidLength {
        type_name: &'static str,
        expected: usize,
        actual: usize,
    },
    /// An opaque variable-length value was empty.
    EmptyValue { type_name: &'static str },
    /// A value exceeds a local or protocol maximum.
    LengthExceedsMaximum {
        type_name: &'static str,
        maximum: usize,
        actual: usize,
    },
    /// A numeric value is outside the type's permitted range.
    ValueOutOfRange { type_name: &'static str, value: u64 },
    /// A monotonic counter cannot be advanced further.
    ArithmeticOverflow { type_name: &'static str },
    /// A protocol version is not supported by this implementation.
    UnsupportedProtocolVersion { major: u16, minor: u16 },
    /// A cipher suite identifier is not supported by this implementation.
    UnsupportedCipherSuite { id: u16 },
}

impl fmt::Display for TypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                type_name,
                expected,
                actual,
            } => write!(
                formatter,
                "{type_name} requires {expected} bytes, got {actual}"
            ),
            Self::EmptyValue { type_name } => write!(formatter, "{type_name} must not be empty"),
            Self::LengthExceedsMaximum {
                type_name,
                maximum,
                actual,
            } => write!(
                formatter,
                "{type_name} exceeds maximum length {maximum}: got {actual}"
            ),
            Self::ValueOutOfRange { type_name, value } => {
                write!(formatter, "{type_name} value {value} is out of range")
            }
            Self::ArithmeticOverflow { type_name } => {
                write!(formatter, "{type_name} cannot be advanced further")
            }
            Self::UnsupportedProtocolVersion { major, minor } => {
                write!(formatter, "unsupported protocol version {major}.{minor}")
            }
            Self::UnsupportedCipherSuite { id } => {
                write!(formatter, "unsupported cipher suite id {id}")
            }
        }
    }
}

impl std::error::Error for TypeError {}
