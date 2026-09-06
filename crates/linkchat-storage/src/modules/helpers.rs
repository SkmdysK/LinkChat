/// A production backend cannot be honestly supplied by this phase because
/// filesystem durability, atomic publication, rollback resistance and secure
/// erasure are platform contracts.  This helper exposes the required gate.
pub fn require_rollback_resistant<S: StateStorage>(storage: &S) -> Result<(), StorageError> {
    if storage.rollback_resistant() {
        Ok(())
    } else {
        Err(StorageError::RollbackResistantRequired)
    }
}

pub(crate) fn zero_hash() -> PackageHash {
    PackageHash::from_array([0; 32])
}

pub(crate) fn max_package_generation(state: &RefinedState) -> PackageGeneration {
    state
        .alice_public_package()
        .generation()
        .max(state.bob_public_package().generation())
}

pub(crate) fn validate_state_context(
    state: &RefinedState,
    session_id: SessionId,
) -> Result<(), StorageError> {
    if state.session().session_id() != session_id {
        return Err(StorageError::SessionMismatch);
    }
    if state.alice_public_package().session_id() != session_id
        || state.bob_public_package().session_id() != session_id
    {
        return Err(StorageError::SessionMismatch);
    }
    Ok(())
}

pub(crate) fn hash_state(
    state: &RefinedState,
    generation: PackageGeneration,
    previous_package_hash: PackageHash,
) -> PackageHash {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(b"LinkChat/package-hash/v1");
    bytes.extend_from_slice(&state.session().session_id().get().to_be_bytes());
    bytes.extend_from_slice(&state.turn().get().to_be_bytes());
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    bytes.extend_from_slice(previous_package_hash.as_bytes());
    for package in [state.alice_public_package(), state.bob_public_package()] {
        bytes.extend_from_slice(&package.turn().get().to_be_bytes());
        bytes.extend_from_slice(&package.generation().get().to_be_bytes());
        bytes.extend_from_slice(&package.key_id().get().to_be_bytes());
        bytes.extend_from_slice(package.x25519_public_key().as_bytes());
        bytes.extend_from_slice(package.mlkem_public_key().as_bytes());
        bytes.extend_from_slice(package.mailbox_token().as_bytes());
        bytes.extend_from_slice(&package.expiration().to_be_bytes());
        bytes.extend_from_slice(package.previous_package_hash().as_bytes());
        bytes.extend_from_slice(package.package_auth().as_bytes());
    }
    for message_id in state.consumed_message_ids() {
        bytes.extend_from_slice(&message_id.get().to_be_bytes());
    }
    OsCryptoBackend::new().sha256(&bytes)
}
use crate::{StateStorage, StorageError};
use linkchat_core::RefinedState;
use linkchat_crypto::{CryptoBackend, OsCryptoBackend};
use linkchat_types::{PackageGeneration, PackageHash, SessionId};
