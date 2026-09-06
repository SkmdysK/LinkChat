/// Fault points in the required prepare/commit/recovery ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    None,
    PrepareBefore,
    PendingWritten,
    PendingDurabilityBarrier,
    CommitMarkerBefore,
    CommitMarkerAfter,
    CurrentPublishBefore,
    CurrentPublishAfter,
    OldSecretRetirementBefore,
    OldSecretRetirementAfter,
    RecoveryBefore,
    RecoveryAfter,
}

/// Stable storage failures.  No variant contains secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    EmptyStorage,
    InvalidRecordKind {
        expected: RecordKind,
        actual: RecordKind,
    },
    GenerationOverflow,
    GenerationNotNext {
        current: PackageGeneration,
        candidate: PackageGeneration,
    },
    TurnNotNext {
        current: Turn,
        candidate: Turn,
    },
    GenerationMismatch {
        stored: PackageGeneration,
        derived: PackageGeneration,
    },
    GenerationRegression,
    SessionMismatch,
    TurnMismatch,
    PackageHashMismatch,
    PreviousPackageHashMismatch,
    CommitHandleMismatch,
    NoPendingRecord,
    MarkerMismatch,
    RollbackResistantRequired,
    InjectedFault(FaultPoint),
    RecoveryInProgress,
    Io,
    CorruptRecord,
    PendingExists,
    CurrentExists,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStorage => formatter.write_str("storage has no current record"),
            Self::InvalidRecordKind { expected, actual } => {
                write!(formatter, "expected {expected:?} record, got {actual:?}")
            }
            Self::GenerationOverflow => formatter.write_str("storage generation overflow"),
            Self::GenerationNotNext { current, candidate } => write!(
                formatter,
                "candidate generation {} is not next after {}",
                candidate.get(),
                current.get()
            ),
            Self::TurnNotNext { current, candidate } => write!(
                formatter,
                "candidate turn {} is not next after {}",
                candidate.get(),
                current.get()
            ),
            Self::GenerationMismatch { stored, derived } => write!(
                formatter,
                "stored generation {} differs from state generation {}",
                stored.get(),
                derived.get()
            ),
            Self::GenerationRegression => formatter.write_str("storage generation regression"),
            Self::SessionMismatch => formatter.write_str("storage session mismatch"),
            Self::TurnMismatch => formatter.write_str("storage turn mismatch"),
            Self::PackageHashMismatch => formatter.write_str("storage package hash mismatch"),
            Self::PreviousPackageHashMismatch => {
                formatter.write_str("storage previous package hash mismatch")
            }
            Self::CommitHandleMismatch => formatter.write_str("commit handle mismatch"),
            Self::NoPendingRecord => formatter.write_str("no pending record"),
            Self::MarkerMismatch => formatter.write_str("committed marker mismatch"),
            Self::RollbackResistantRequired => {
                formatter.write_str("backend is not rollback resistant")
            }
            Self::InjectedFault(point) => write!(formatter, "injected fault at {point:?}"),
            Self::RecoveryInProgress => formatter.write_str("recovery is already in progress"),
            Self::Io => formatter.write_str("storage I/O failed"),
            Self::CorruptRecord => formatter.write_str("storage record is corrupt or unsupported"),
            Self::PendingExists => formatter.write_str("storage already has a pending commit"),
            Self::CurrentExists => formatter.write_str("storage already has a current record"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Storage capability contract.  A production backend must return true from
/// `rollback_resistant`; this test backend deliberately returns false.
pub trait StateStorage {
    type Error;

    fn load_current(&self) -> Result<StoredState, Self::Error>;
    fn prepare_commit(&mut self, next: &StoredState) -> Result<CommitHandle, Self::Error>;
    fn commit(&mut self, handle: CommitHandle) -> Result<(), Self::Error>;
    fn recover(&mut self) -> Result<RecoveryResult, Self::Error>;
    fn rollback_resistant(&self) -> bool;
}
use std::fmt;

use crate::model::{CommitHandle, RecordKind, RecoveryResult, StoredState};
use linkchat_types::{PackageGeneration, Turn};
