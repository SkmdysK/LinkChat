/// An in-memory backend that exposes every crash boundary for tests.
///
/// It maintains separate volatile and durable images.  A simulated crash
/// discards volatile data and keeps only the durable image, just as a real
/// backend must recover from the last completed durability barrier.
pub struct FaultInjectingMemoryStorage {
    durable_current: Option<StoredState>,
    durable_pending: Option<StoredState>,
    durable_marker: Option<CommitHandle>,
    volatile_current: Option<StoredState>,
    volatile_pending: Option<StoredState>,
    volatile_marker: Option<CommitHandle>,
    pending_handle: Option<CommitHandle>,
    durable_retired_generations: Vec<PackageGeneration>,
    retired_generations: Vec<PackageGeneration>,
    fault_point: FaultPoint,
    recovery_in_progress: bool,
}

impl FaultInjectingMemoryStorage {
    pub fn new(initial: StoredState) -> Result<Self, StorageError> {
        initial.validate_integrity()?;
        if initial.kind() != RecordKind::Current {
            return Err(StorageError::InvalidRecordKind {
                expected: RecordKind::Current,
                actual: initial.kind(),
            });
        }
        Ok(Self {
            durable_current: Some(initial.clone()),
            durable_pending: None,
            durable_marker: None,
            volatile_current: Some(initial),
            volatile_pending: None,
            volatile_marker: None,
            pending_handle: None,
            durable_retired_generations: Vec::new(),
            retired_generations: Vec::new(),
            fault_point: FaultPoint::None,
            recovery_in_progress: false,
        })
    }

    pub fn set_fault(&mut self, point: FaultPoint) {
        self.fault_point = point;
    }

    pub const fn fault_point(&self) -> FaultPoint {
        self.fault_point
    }

    pub fn simulate_crash(&mut self) {
        self.volatile_current = self.durable_current.clone();
        self.volatile_pending = self.durable_pending.clone();
        self.volatile_marker = self.durable_marker;
        self.retired_generations = self.durable_retired_generations.clone();
        self.pending_handle = None;
        self.recovery_in_progress = false;
    }

    pub fn pending(&self) -> Option<&StoredState> {
        self.volatile_pending.as_ref()
    }

    pub fn committed_marker(&self) -> Option<CommitHandle> {
        self.volatile_marker
    }

    pub fn current(&self) -> Option<&StoredState> {
        self.volatile_current.as_ref()
    }

    pub fn retired_generations(&self) -> &[PackageGeneration] {
        &self.retired_generations
    }

    fn fault(&mut self, point: FaultPoint) -> Result<(), StorageError> {
        if self.fault_point == point {
            self.fault_point = FaultPoint::None;
            Err(StorageError::InjectedFault(point))
        } else {
            Ok(())
        }
    }

    fn durable_pending_barrier(&mut self) {
        self.durable_pending = self.volatile_pending.clone();
    }

    fn durable_marker_barrier(&mut self) {
        self.durable_marker = self.volatile_marker;
    }

    fn durable_current_barrier(&mut self) {
        self.durable_current = self.volatile_current.clone();
    }

    fn validate_candidate(&self, next: &StoredState) -> Result<(), StorageError> {
        next.validate_integrity()?;
        if next.kind() != RecordKind::Pending {
            return Err(StorageError::InvalidRecordKind {
                expected: RecordKind::Pending,
                actual: next.kind(),
            });
        }
        let current = self.load_current()?;
        if next.session_id() != current.session_id() {
            return Err(StorageError::SessionMismatch);
        }
        if next.generation()
            != current
                .generation()
                .next()
                .map_err(|_| StorageError::GenerationOverflow)?
        {
            return Err(StorageError::GenerationNotNext {
                current: current.generation(),
                candidate: next.generation(),
            });
        }
        if next.previous_package_hash() != current.package_hash() {
            return Err(StorageError::PreviousPackageHashMismatch);
        }
        let expected_turn = current
            .turn()
            .next()
            .map_err(|_| StorageError::TurnMismatch)?;
        if next.turn() != expected_turn {
            return Err(StorageError::TurnNotNext {
                current: current.turn(),
                candidate: next.turn(),
            });
        }
        Ok(())
    }

    fn retire_previous(&mut self, previous: &StoredState) -> Result<(), StorageError> {
        self.fault(FaultPoint::OldSecretRetirementBefore)?;
        if !self.retired_generations.contains(&previous.generation()) {
            self.retired_generations.push(previous.generation());
        }
        self.durable_retired_generations = self.retired_generations.clone();
        self.fault(FaultPoint::OldSecretRetirementAfter)?;
        Ok(())
    }
}

impl StateStorage for FaultInjectingMemoryStorage {
    type Error = StorageError;

    fn load_current(&self) -> Result<StoredState, Self::Error> {
        self.volatile_current
            .clone()
            .ok_or(StorageError::EmptyStorage)
    }

    fn prepare_commit(&mut self, next: &StoredState) -> Result<CommitHandle, Self::Error> {
        self.fault(FaultPoint::PrepareBefore)?;
        self.validate_candidate(next)?;
        let handle = CommitHandle {
            generation: next.generation(),
            package_hash: next.package_hash(),
        };
        self.volatile_pending = Some(next.clone());
        self.pending_handle = Some(handle);
        self.fault(FaultPoint::PendingWritten)?;
        self.durable_pending_barrier();
        self.fault(FaultPoint::PendingDurabilityBarrier)?;
        Ok(handle)
    }

    fn commit(&mut self, handle: CommitHandle) -> Result<(), Self::Error> {
        self.fault(FaultPoint::CommitMarkerBefore)?;
        let pending = self
            .volatile_pending
            .clone()
            .ok_or(StorageError::NoPendingRecord)?;
        if self.pending_handle != Some(handle)
            || pending.generation() != handle.generation()
            || pending.package_hash() != handle.package_hash()
        {
            return Err(StorageError::CommitHandleMismatch);
        }
        let current = self.load_current()?;
        if pending.previous_package_hash() != current.package_hash() {
            return Err(StorageError::PreviousPackageHashMismatch);
        }
        if pending.generation() <= current.generation() {
            return Err(StorageError::GenerationRegression);
        }
        self.volatile_marker = Some(handle);
        self.durable_marker_barrier();
        self.fault(FaultPoint::CommitMarkerAfter)?;
        self.fault(FaultPoint::CurrentPublishBefore)?;
        self.volatile_current = Some(pending.as_current());
        self.durable_current_barrier();
        self.fault(FaultPoint::CurrentPublishAfter)?;
        self.retire_previous(&current)?;
        self.volatile_pending = None;
        self.durable_pending = None;
        self.volatile_marker = None;
        self.durable_marker = None;
        self.pending_handle = None;
        Ok(())
    }

    fn recover(&mut self) -> Result<RecoveryResult, Self::Error> {
        if self.recovery_in_progress {
            return Err(StorageError::RecoveryInProgress);
        }
        self.recovery_in_progress = true;
        if let Err(error) = self.fault(FaultPoint::RecoveryBefore) {
            self.recovery_in_progress = false;
            return Err(error);
        }
        let result = (|| {
            let current = self
                .durable_current
                .clone()
                .ok_or(StorageError::EmptyStorage)?;
            current.validate_integrity()?;
            let Some(pending) = self.durable_pending.clone() else {
                self.volatile_current = Some(current.clone());
                self.volatile_pending = None;
                self.volatile_marker = None;
                return Ok(RecoveryResult {
                    choice: RecoveryChoice::ExistingCurrent,
                    state: current,
                    retired_previous: false,
                });
            };
            pending.validate_integrity()?;
            let Some(marker) = self.durable_marker else {
                self.volatile_current = Some(current.clone());
                self.volatile_pending = None;
                self.durable_pending = None;
                self.volatile_marker = None;
                return Ok(RecoveryResult {
                    choice: RecoveryChoice::ExistingCurrent,
                    state: current,
                    retired_previous: false,
                });
            };
            if current.package_hash() == pending.package_hash()
                && marker.generation() == pending.generation()
            {
                self.volatile_current = Some(current.clone());
                self.volatile_pending = None;
                self.durable_pending = None;
                self.volatile_marker = None;
                self.durable_marker = None;
                let retired_generation =
                    PackageGeneration::new(pending.generation().get().saturating_sub(1));
                if !self.retired_generations.contains(&retired_generation) {
                    self.retired_generations.push(retired_generation);
                }
                self.durable_retired_generations = self.retired_generations.clone();
                return Ok(RecoveryResult {
                    choice: RecoveryChoice::CompletedPending,
                    state: current,
                    retired_previous: true,
                });
            }
            if marker.generation() != pending.generation()
                || marker.package_hash() != pending.package_hash()
                || pending.previous_package_hash() != current.package_hash()
                || pending.generation() <= current.generation()
            {
                return Err(StorageError::MarkerMismatch);
            }
            let committed = pending.as_committed();
            let current_record = committed.as_current();
            self.volatile_current = Some(current_record.clone());
            self.durable_current = Some(current_record.clone());
            self.volatile_pending = None;
            self.durable_pending = None;
            self.volatile_marker = None;
            self.durable_marker = None;
            if !self.retired_generations.contains(&current.generation()) {
                self.retired_generations.push(current.generation());
            }
            self.durable_retired_generations = self.retired_generations.clone();
            Ok(RecoveryResult {
                choice: RecoveryChoice::CompletedPending,
                state: current_record,
                retired_previous: true,
            })
        })();
        self.recovery_in_progress = false;
        self.fault(FaultPoint::RecoveryAfter)?;
        result
    }

    fn rollback_resistant(&self) -> bool {
        false
    }
}
use crate::errors::{FaultPoint, StateStorage, StorageError};
use crate::model::{CommitHandle, RecordKind, RecoveryChoice, RecoveryResult, StoredState};
use linkchat_types::PackageGeneration;
