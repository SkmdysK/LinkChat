use std::fmt;

use linkchat_protocol::WireError;
use linkchat_types::TypeError;

/// Mailbox failures contain no token, record, envelope, or secret bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailboxError {
    Unavailable,
    TokenMismatch,
    RecordTooLarge { actual: usize, maximum: usize },
    ReturnLimitExceeded { requested: usize, maximum: usize },
    TtlOverflow,
    Wire(WireError),
    Type(TypeError),
}

impl fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("mailbox unavailable"),
            Self::TokenMismatch => formatter.write_str("record token does not match put token"),
            Self::RecordTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "mailbox record size {actual} exceeds maximum {maximum}"
                )
            }
            Self::ReturnLimitExceeded { requested, maximum } => write!(
                formatter,
                "mailbox return count {requested} exceeds maximum {maximum}"
            ),
            Self::TtlOverflow => formatter.write_str("mailbox TTL overflow"),
            Self::Wire(error) => error.fmt(formatter),
            Self::Type(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MailboxError {}

impl From<WireError> for MailboxError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<TypeError> for MailboxError {
    fn from(error: TypeError) -> Self {
        Self::Type(error)
    }
}
