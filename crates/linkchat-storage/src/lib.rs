//! Transactional local state storage contracts and local backends.
//!
//! `FileStateStorage` provides fsync and atomic-publication ordering for local
//! filesystems, but deliberately does not claim rollback resistance or secure
//! erasure. `FaultInjectingMemoryStorage` remains the crash-order test model.

#[path = "modules/errors.rs"]
mod errors;
#[path = "modules/file.rs"]
mod file;
#[path = "modules/helpers.rs"]
mod helpers;
#[path = "modules/memory.rs"]
mod memory;
#[path = "modules/model.rs"]
mod model;

pub use errors::{FaultPoint, StateStorage, StorageError};
pub use file::FileStateStorage;
pub use helpers::require_rollback_resistant;
pub use memory::FaultInjectingMemoryStorage;
pub use model::{CommitHandle, RecordKind, RecoveryChoice, RecoveryResult, StoredState};

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
