use std::io::{Cursor, Read};

use crate::errors::StorageError;
use crate::helpers::{hash_state, max_package_generation, validate_state_context, zero_hash};
use linkchat_core::{PublicStateSnapshot, RefinedState};
use linkchat_crypto::{CryptoBackend, OsCryptoBackend};
use linkchat_types::{PackageGeneration, PackageHash, SessionId, Turn};

/// The durable lifecycle of a state record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Current,
    Pending,
    Committed,
}

/// A complete state record with its storage binding metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredState {
    kind: RecordKind,
    state: RefinedState,
    generation: PackageGeneration,
    package_hash: PackageHash,
    previous_package_hash: PackageHash,
}

impl StoredState {
    /// Builds the initial record.  Its previous hash is the all-zero root.
    pub fn initial(state: RefinedState) -> Self {
        let generation = max_package_generation(&state);
        let previous_package_hash = zero_hash();
        let package_hash = hash_state(&state, generation, previous_package_hash);
        Self {
            kind: RecordKind::Current,
            state,
            generation,
            package_hash,
            previous_package_hash,
        }
    }

    /// Builds a candidate next record from a pure-core state transition.
    /// The candidate is marked Pending until the storage transaction commits.
    pub fn pending_from(current: &StoredState, state: RefinedState) -> Result<Self, StorageError> {
        if current.kind != RecordKind::Current {
            return Err(StorageError::InvalidRecordKind {
                expected: RecordKind::Current,
                actual: current.kind,
            });
        }
        validate_state_context(&state, current.session_id())?;
        let expected_generation = current
            .generation
            .next()
            .map_err(|_| StorageError::GenerationOverflow)?;
        let generation = expected_generation;
        let package_hash = hash_state(&state, generation, current.package_hash);
        Ok(Self {
            kind: RecordKind::Pending,
            state,
            generation,
            package_hash,
            previous_package_hash: current.package_hash,
        })
    }

    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    pub const fn generation(&self) -> PackageGeneration {
        self.generation
    }

    pub const fn package_hash(&self) -> PackageHash {
        self.package_hash
    }

    pub const fn previous_package_hash(&self) -> PackageHash {
        self.previous_package_hash
    }

    pub fn state(&self) -> &RefinedState {
        &self.state
    }

    pub fn public_snapshot(&self) -> PublicStateSnapshot {
        self.state.public_snapshot()
    }

    pub const fn session_id(&self) -> SessionId {
        self.state.session().session_id()
    }

    pub const fn turn(&self) -> Turn {
        self.state.turn()
    }

    pub(crate) fn as_current(&self) -> Self {
        let mut current = self.clone();
        current.kind = RecordKind::Current;
        current
    }

    pub(crate) fn as_committed(&self) -> Self {
        let mut committed = self.clone();
        committed.kind = RecordKind::Committed;
        committed
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), StorageError> {
        validate_state_context(&self.state, self.session_id())?;
        let expected_hash = hash_state(&self.state, self.generation, self.previous_package_hash);
        if expected_hash != self.package_hash {
            return Err(StorageError::PackageHashMismatch);
        }
        Ok(())
    }

    pub(crate) fn to_storage_bytes(&self) -> Result<Vec<u8>, StorageError> {
        let mut body = Vec::new();
        body.extend_from_slice(b"LCST");
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(match self.kind {
            RecordKind::Current => 0,
            RecordKind::Pending => 1,
            RecordKind::Committed => 2,
        });
        body.extend_from_slice(&self.generation.get().to_be_bytes());
        body.extend_from_slice(self.package_hash.as_bytes());
        body.extend_from_slice(self.previous_package_hash.as_bytes());
        self.state
            .write_storage_to(&mut body)
            .map_err(|_| StorageError::Io)?;
        let record_hash = storage_record_hash(&body);
        body.extend_from_slice(record_hash.as_bytes());
        Ok(body)
    }

    pub(crate) fn from_storage_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        const HEADER_LEN: usize = 4 + 2 + 1 + 8 + 32 + 32;
        const HASH_LEN: usize = 32;
        if bytes.len() < HEADER_LEN + HASH_LEN {
            return Err(StorageError::CorruptRecord);
        }
        let body_len = bytes.len() - HASH_LEN;
        let body = &bytes[..body_len];
        let stored_hash =
            PackageHash::from_bytes(&bytes[body_len..]).map_err(|_| StorageError::CorruptRecord)?;
        if storage_record_hash(body) != stored_hash {
            return Err(StorageError::CorruptRecord);
        }
        let mut reader = Cursor::new(body);
        let mut magic = [0; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| StorageError::CorruptRecord)?;
        if &magic != b"LCST" || read_u16(&mut reader)? != 1 {
            return Err(StorageError::CorruptRecord);
        }
        let kind = match read_u8(&mut reader)? {
            0 => RecordKind::Current,
            1 => RecordKind::Pending,
            2 => RecordKind::Committed,
            _ => return Err(StorageError::CorruptRecord),
        };
        let generation = PackageGeneration::new(read_u64(&mut reader)?);
        let package_hash = read_hash(&mut reader)?;
        let previous_package_hash = read_hash(&mut reader)?;
        let state = RefinedState::read_storage_from(&mut reader)
            .map_err(|_| StorageError::CorruptRecord)?;
        if reader.position() as usize != body.len() {
            return Err(StorageError::CorruptRecord);
        }
        let record = Self {
            kind,
            state,
            generation,
            package_hash,
            previous_package_hash,
        };
        record.validate_integrity()?;
        Ok(record)
    }
}

fn storage_record_hash(body: &[u8]) -> PackageHash {
    let mut input = Vec::with_capacity(28 + body.len());
    input.extend_from_slice(b"LinkChat/storage-record/v1");
    input.extend_from_slice(body);
    OsCryptoBackend::new().sha256(&input)
}

fn read_u8(reader: &mut Cursor<&[u8]>) -> Result<u8, StorageError> {
    let mut value = [0; 1];
    reader
        .read_exact(&mut value)
        .map_err(|_| StorageError::CorruptRecord)?;
    Ok(value[0])
}

fn read_u16(reader: &mut Cursor<&[u8]>) -> Result<u16, StorageError> {
    let mut value = [0; 2];
    reader
        .read_exact(&mut value)
        .map_err(|_| StorageError::CorruptRecord)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u64(reader: &mut Cursor<&[u8]>) -> Result<u64, StorageError> {
    let mut value = [0; 8];
    reader
        .read_exact(&mut value)
        .map_err(|_| StorageError::CorruptRecord)?;
    Ok(u64::from_be_bytes(value))
}

fn read_hash(reader: &mut Cursor<&[u8]>) -> Result<PackageHash, StorageError> {
    let mut value = [0; 32];
    reader
        .read_exact(&mut value)
        .map_err(|_| StorageError::CorruptRecord)?;
    Ok(PackageHash::from_array(value))
}

/// The opaque handle returned by prepare and required by commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommitHandle {
    pub(crate) generation: PackageGeneration,
    pub(crate) package_hash: PackageHash,
}

impl CommitHandle {
    pub const fn generation(self) -> PackageGeneration {
        self.generation
    }

    pub const fn package_hash(self) -> PackageHash {
        self.package_hash
    }
}

/// Recovery outcome after examining durable Current, Pending and marker data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryChoice {
    ExistingCurrent,
    CompletedPending,
}

pub struct RecoveryResult {
    pub(crate) choice: RecoveryChoice,
    pub(crate) state: StoredState,
    pub(crate) retired_previous: bool,
}

impl RecoveryResult {
    pub const fn choice(&self) -> RecoveryChoice {
        self.choice
    }

    pub fn state(&self) -> &StoredState {
        &self.state
    }

    pub const fn retired_previous(&self) -> bool {
        self.retired_previous
    }
}
