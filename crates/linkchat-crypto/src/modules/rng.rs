use crate::foundation::*;
use rand_core::{Infallible, TryCryptoRng, TryRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) trait RandomSource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError>;
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct FixedRandomSource {
    bytes: [u8; SHARED_SECRET_LEN],
    offset: usize,
}

impl FixedRandomSource {
    pub(crate) fn new(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, output: &mut [u8]) {
        let end = self.offset.saturating_add(output.len());
        assert!(
            end <= self.bytes.len(),
            "KEM consumed unexpected random length"
        );
        output.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
    }
}

impl TryRng for FixedRandomSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.take(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.take(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.take(output);
        Ok(())
    }
}

impl TryCryptoRng for FixedRandomSource {}

pub(crate) struct OsRandomSource;

impl RandomSource for OsRandomSource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(output).map_err(|_| CryptoError::RandomnessUnavailable)
    }
}

/// Production provider backed by the OS CSPRNG.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsCryptoBackend;

impl OsCryptoBackend {
    /// Construct the production provider. No deterministic test RNG is reachable from this path.
    pub const fn new() -> Self {
        Self
    }
}
