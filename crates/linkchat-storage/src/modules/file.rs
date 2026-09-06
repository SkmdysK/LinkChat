//! Local filesystem StateStorage implementation.
//!
//! The backend uses separate Current, Pending and commit-marker files. Every
//! visible replacement is preceded by a synced temporary file and followed by
//! a directory sync. This gives the protocol's required crash ordering on
//! filesystems that honor the platform's fsync/rename contract.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::errors::{StateStorage, StorageError};
use crate::model::{CommitHandle, RecordKind, RecoveryChoice, RecoveryResult, StoredState};
use linkchat_crypto::{CryptoBackend, OsCryptoBackend};
use linkchat_types::{PackageGeneration, PackageHash};

const CURRENT_FILE: &str = "current.bin";
const PENDING_FILE: &str = "pending.bin";
const MARKER_FILE: &str = "commit.marker";
const MARKER_MAGIC: &[u8; 4] = b"LCMK";
const MARKER_VERSION: u16 = 1;

/// A filesystem-backed transactional state store.
pub struct FileStateStorage {
    root: PathBuf,
    pending_handle: Option<CommitHandle>,
    recovery_in_progress: bool,
}

impl FileStateStorage {
    /// Creates a new store and publishes its initial Current record.
    pub fn create(path: impl AsRef<Path>, initial: StoredState) -> Result<Self, StorageError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|_| StorageError::Io)?;
        if root.join(CURRENT_FILE).exists() {
            return Err(StorageError::CurrentExists);
        }
        if initial.kind() != RecordKind::Current {
            return Err(StorageError::InvalidRecordKind {
                expected: RecordKind::Current,
                actual: initial.kind(),
            });
        }
        initial.validate_integrity()?;
        let store = Self {
            root,
            pending_handle: None,
            recovery_in_progress: false,
        };
        store.write_record(CURRENT_FILE, &initial)?;
        Ok(store)
    }

    /// Opens an existing store directory. Recovery remains explicit through
    /// [`StateStorage::recover`], so callers can handle that outcome visibly.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = path.as_ref().to_path_buf();
        let metadata = fs::metadata(&root).map_err(|_| StorageError::Io)?;
        if !metadata.is_dir() {
            return Err(StorageError::Io);
        }
        Ok(Self {
            root,
            pending_handle: None,
            recovery_in_progress: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    fn file_path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn read_record(&self, name: &str) -> Result<Option<StoredState>, StorageError> {
        match fs::read(self.file_path(name)) {
            Ok(bytes) => StoredState::from_storage_bytes(&bytes).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StorageError::Io),
        }
    }

    fn write_record(&self, name: &str, record: &StoredState) -> Result<(), StorageError> {
        let bytes = record.to_storage_bytes()?;
        self.write_atomic(name, &bytes)
    }

    fn write_marker(&self, handle: CommitHandle) -> Result<(), StorageError> {
        let mut bytes = Vec::with_capacity(4 + 2 + 8 + 32 + 32);
        bytes.extend_from_slice(MARKER_MAGIC);
        bytes.extend_from_slice(&MARKER_VERSION.to_be_bytes());
        bytes.extend_from_slice(&handle.generation().get().to_be_bytes());
        bytes.extend_from_slice(handle.package_hash().as_bytes());
        let checksum = marker_hash(&bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        self.write_atomic(MARKER_FILE, &bytes)
    }

    fn read_marker(&self) -> Result<Option<CommitHandle>, StorageError> {
        let bytes = match fs::read(self.file_path(MARKER_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StorageError::Io),
        };
        if bytes.len() != 4 + 2 + 8 + 32 + 32 {
            return Err(StorageError::CorruptRecord);
        }
        let body_len = bytes.len() - 32;
        if marker_hash(&bytes[..body_len])
            != PackageHash::from_bytes(&bytes[body_len..])
                .map_err(|_| StorageError::CorruptRecord)?
        {
            return Err(StorageError::CorruptRecord);
        }
        if &bytes[..4] != MARKER_MAGIC || u16::from_be_bytes([bytes[4], bytes[5]]) != MARKER_VERSION
        {
            return Err(StorageError::CorruptRecord);
        }
        let generation = PackageGeneration::new(u64::from_be_bytes(
            bytes[6..14]
                .try_into()
                .map_err(|_| StorageError::CorruptRecord)?,
        ));
        let package_hash =
            PackageHash::from_bytes(&bytes[14..46]).map_err(|_| StorageError::CorruptRecord)?;
        Ok(Some(CommitHandle {
            generation,
            package_hash,
        }))
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let path = self.file_path(name);
        let temp = self.file_path(&format!(".{name}.tmp"));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .map_err(|_| StorageError::Io)?;
        file.write_all(bytes).map_err(|_| StorageError::Io)?;
        file.sync_all().map_err(|_| StorageError::Io)?;
        drop(file);
        fs::rename(&temp, &path).map_err(|_| StorageError::Io)?;
        self.sync_directory()
    }

    fn remove_durable(&self, name: &str) -> Result<(), StorageError> {
        match fs::remove_file(self.file_path(name)) {
            Ok(()) => self.sync_directory(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StorageError::Io),
        }
    }

    fn sync_directory(&self) -> Result<(), StorageError> {
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StorageError::Io)
    }

    fn validate_candidate(
        &self,
        current: &StoredState,
        next: &StoredState,
    ) -> Result<(), StorageError> {
        next.validate_integrity()?;
        if next.kind() != RecordKind::Pending {
            return Err(StorageError::InvalidRecordKind {
                expected: RecordKind::Pending,
                actual: next.kind(),
            });
        }
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
}

impl StateStorage for FileStateStorage {
    type Error = StorageError;

    fn load_current(&self) -> Result<StoredState, Self::Error> {
        let current = self
            .read_record(CURRENT_FILE)?
            .ok_or(StorageError::EmptyStorage)?;
        if current.kind() != RecordKind::Current {
            return Err(StorageError::InvalidRecordKind {
                expected: RecordKind::Current,
                actual: current.kind(),
            });
        }
        current.validate_integrity()?;
        Ok(current)
    }

    fn prepare_commit(&mut self, next: &StoredState) -> Result<CommitHandle, Self::Error> {
        if self.read_record(PENDING_FILE)?.is_some() || self.read_marker()?.is_some() {
            return Err(StorageError::PendingExists);
        }
        let current = self.load_current()?;
        self.validate_candidate(&current, next)?;
        let handle = CommitHandle {
            generation: next.generation(),
            package_hash: next.package_hash(),
        };
        self.write_record(PENDING_FILE, next)?;
        self.pending_handle = Some(handle);
        Ok(handle)
    }

    fn commit(&mut self, handle: CommitHandle) -> Result<(), Self::Error> {
        let pending = self
            .read_record(PENDING_FILE)?
            .ok_or(StorageError::NoPendingRecord)?;
        if pending.kind() != RecordKind::Pending
            || self.pending_handle != Some(handle)
            || pending.generation() != handle.generation()
            || pending.package_hash() != handle.package_hash()
        {
            return Err(StorageError::CommitHandleMismatch);
        }
        let current = self.load_current()?;
        self.validate_candidate(&current, &pending)?;
        self.write_marker(handle)?;
        self.write_record(CURRENT_FILE, &pending.as_current())?;
        self.remove_durable(PENDING_FILE)?;
        self.remove_durable(MARKER_FILE)?;
        self.pending_handle = None;
        Ok(())
    }

    fn recover(&mut self) -> Result<RecoveryResult, Self::Error> {
        if self.recovery_in_progress {
            return Err(StorageError::RecoveryInProgress);
        }
        self.recovery_in_progress = true;
        let result = self.recover_inner();
        self.recovery_in_progress = false;
        self.pending_handle = None;
        result
    }

    fn rollback_resistant(&self) -> bool {
        false
    }
}

impl FileStateStorage {
    fn recover_inner(&mut self) -> Result<RecoveryResult, StorageError> {
        let current = self.load_current()?;
        let pending = self.read_record(PENDING_FILE)?;
        let marker = self.read_marker()?;
        match (pending, marker) {
            (None, None) => Ok(RecoveryResult {
                choice: RecoveryChoice::ExistingCurrent,
                state: current,
                retired_previous: false,
            }),
            (None, Some(marker)) => {
                if marker.generation() != current.generation()
                    || marker.package_hash() != current.package_hash()
                {
                    return Err(StorageError::MarkerMismatch);
                }
                self.remove_durable(MARKER_FILE)?;
                Ok(RecoveryResult {
                    choice: RecoveryChoice::CompletedPending,
                    state: current,
                    retired_previous: true,
                })
            }
            (Some(pending), None) => {
                if pending.kind() != RecordKind::Pending {
                    return Err(StorageError::InvalidRecordKind {
                        expected: RecordKind::Pending,
                        actual: pending.kind(),
                    });
                }
                self.remove_durable(PENDING_FILE)?;
                Ok(RecoveryResult {
                    choice: RecoveryChoice::ExistingCurrent,
                    state: current,
                    retired_previous: false,
                })
            }
            (Some(pending), Some(marker)) => {
                if pending.kind() != RecordKind::Pending
                    || marker.generation() != pending.generation()
                    || marker.package_hash() != pending.package_hash()
                {
                    return Err(StorageError::MarkerMismatch);
                }
                if current.generation() == pending.generation()
                    && current.package_hash() == pending.package_hash()
                {
                    self.remove_durable(PENDING_FILE)?;
                    self.remove_durable(MARKER_FILE)?;
                    return Ok(RecoveryResult {
                        choice: RecoveryChoice::CompletedPending,
                        state: current,
                        retired_previous: true,
                    });
                }
                self.validate_candidate(&current, &pending)?;
                self.write_record(CURRENT_FILE, &pending.as_current())?;
                self.remove_durable(PENDING_FILE)?;
                self.remove_durable(MARKER_FILE)?;
                Ok(RecoveryResult {
                    choice: RecoveryChoice::CompletedPending,
                    state: pending.as_current(),
                    retired_previous: true,
                })
            }
        }
    }
}

fn marker_hash(body: &[u8]) -> PackageHash {
    let mut input = Vec::with_capacity(28 + body.len());
    input.extend_from_slice(b"LinkChat/storage-marker/v1");
    input.extend_from_slice(body);
    OsCryptoBackend::new().sha256(&input)
}
