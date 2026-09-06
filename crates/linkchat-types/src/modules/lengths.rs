use super::constants::MAX_ENVELOPE_SIZE;
use super::errors::TypeError;

/// A bounded envelope length. Values may describe partial buffers during
/// bounded parsing, but never exceed the fixed v1.0 envelope budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvelopeLength(u16);

impl EnvelopeLength {
    pub const MAX: usize = MAX_ENVELOPE_SIZE;

    pub fn new(length: usize) -> Result<Self, TypeError> {
        if length > Self::MAX {
            return Err(TypeError::LengthExceedsMaximum {
                type_name: "EnvelopeLength",
                maximum: Self::MAX,
                actual: length,
            });
        }
        Ok(Self(length as u16))
    }

    pub const fn fixed() -> Self {
        Self(MAX_ENVELOPE_SIZE as u16)
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub const fn is_fixed(self) -> bool {
        self.0 as usize == MAX_ENVELOPE_SIZE
    }
}
