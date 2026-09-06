use crate::{
    FaultInjectingMemoryStorage, FaultPoint, RecordKind, RecoveryChoice, StateStorage,
    StorageError, StoredState, require_rollback_resistant,
};
use linkchat_core::{
    ApplicationMessage, Endpoint, PrivateReceiverPackage, PublicReceiverPackage, RefinedState,
    Session,
};
use linkchat_protocol::WireBytes;
use linkchat_types::{
    CipherSuite, KeyId, MailboxToken, MessageId, PackageGeneration, PackageHash, ProtocolVersion,
    SessionId, Turn, X25519PublicKey,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const ML_KEM_PUBLIC_KEY_LEN: usize = 1184;

fn package(
    session_id: SessionId,
    turn: Turn,
    generation: PackageGeneration,
    key_id: KeyId,
    byte: u8,
) -> PrivateReceiverPackage {
    let public = PublicReceiverPackage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        session_id,
        turn,
        generation,
        key_id,
        X25519PublicKey::from_array([byte; 32]),
        WireBytes::from_vec(vec![byte; ML_KEM_PUBLIC_KEY_LEN]).unwrap(),
        MailboxToken::from_array([byte; 32]),
        0,
        PackageHash::from_array([byte; 32]),
        WireBytes::from_vec(vec![byte; 64]).unwrap(),
    )
    .unwrap();
    PrivateReceiverPackage::for_testing(public).unwrap()
}

fn initial_state() -> RefinedState {
    let session_id = SessionId::new(7);
    RefinedState::new(
        Session::new(session_id),
        package(
            session_id,
            Turn::new(0),
            PackageGeneration::new(0),
            KeyId::new(1),
            1,
        ),
        package(
            session_id,
            Turn::new(0),
            PackageGeneration::new(0),
            KeyId::new(2),
            2,
        ),
    )
    .unwrap()
}

fn next_state() -> RefinedState {
    let initial = initial_state();
    let message = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        initial.session().session_id(),
        Turn::new(0),
        Endpoint::Alice,
        MessageId::new(10),
        KeyId::new(2),
        initial.bob_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"payload").unwrap(),
    );
    let next_bob = package(
        initial.session().session_id(),
        Turn::new(1),
        PackageGeneration::new(1),
        KeyId::new(3),
        3,
    );
    initial.step(&message, next_bob).into_state()
}

fn storage() -> FaultInjectingMemoryStorage {
    FaultInjectingMemoryStorage::new(StoredState::initial(initial_state())).unwrap()
}

fn temp_storage_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "linkchat-storage-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn pending(storage: &FaultInjectingMemoryStorage) -> StoredState {
    StoredState::pending_from(&storage.load_current().unwrap(), next_state()).unwrap()
}

#[test]
fn prepare_commit_publishes_complete_next_state_and_retires_old_after_durable_publish() {
    let mut storage = storage();
    let candidate = pending(&storage);
    let handle = storage.prepare_commit(&candidate).unwrap();
    assert_eq!(
        storage.load_current().unwrap().generation(),
        PackageGeneration::new(0)
    );
    assert_eq!(storage.pending().unwrap().kind(), RecordKind::Pending);
    storage.commit(handle).unwrap();
    let current = storage.load_current().unwrap();
    assert_eq!(current.generation(), PackageGeneration::new(1));
    assert_eq!(
        current.previous_package_hash(),
        candidate.previous_package_hash()
    );
    assert_eq!(storage.retired_generations(), &[PackageGeneration::new(0)]);
    assert!(storage.pending().is_none());
}

#[test]
fn pending_is_not_current_and_recovery_discards_uncommitted_pending() {
    let mut storage = storage();
    let candidate = pending(&storage);
    storage.set_fault(FaultPoint::PendingWritten);
    assert!(storage.prepare_commit(&candidate).is_err());
    storage.simulate_crash();
    let recovered = storage.recover().unwrap();
    assert_eq!(recovered.choice(), RecoveryChoice::ExistingCurrent);
    assert_eq!(recovered.state().generation(), PackageGeneration::new(0));
}

#[test]
fn committed_marker_allows_recovery_to_complete_new_state() {
    let mut storage = storage();
    let candidate = pending(&storage);
    let handle = storage.prepare_commit(&candidate).unwrap();
    storage.set_fault(FaultPoint::CurrentPublishBefore);
    assert!(storage.commit(handle).is_err());
    storage.simulate_crash();
    let recovered = storage.recover().unwrap();
    assert_eq!(recovered.choice(), RecoveryChoice::CompletedPending);
    assert_eq!(recovered.state().generation(), PackageGeneration::new(1));
    assert!(recovered.retired_previous());
    assert_eq!(storage.retired_generations(), &[PackageGeneration::new(0)]);
    assert!(storage.pending().is_none());
    assert!(storage.committed_marker().is_none());
}

#[test]
fn repeated_commit_and_old_generation_are_rejected() {
    let mut storage = storage();
    let candidate = pending(&storage);
    let handle = storage.prepare_commit(&candidate).unwrap();
    storage.commit(handle).unwrap();
    assert_eq!(storage.commit(handle), Err(StorageError::NoPendingRecord));

    let old = storage.prepare_commit(&candidate);
    assert!(matches!(
        old,
        Err(StorageError::GenerationNotNext {
            current,
            candidate,
        }) if current == PackageGeneration::new(1)
            && candidate == PackageGeneration::new(1)
    ));
}

#[test]
fn hash_chain_and_rollback_capability_are_explicit() {
    let mut storage = storage();
    assert!(!storage.rollback_resistant());
    assert_eq!(
        require_rollback_resistant(&storage),
        Err(StorageError::RollbackResistantRequired)
    );
    let candidate = pending(&storage);
    assert_ne!(candidate.package_hash(), candidate.previous_package_hash());
    let handle = storage.prepare_commit(&candidate).unwrap();
    storage.commit(handle).unwrap();
    assert_eq!(
        storage.load_current().unwrap().package_hash(),
        candidate.package_hash()
    );
    assert_eq!(
        storage.load_current().unwrap().previous_package_hash(),
        candidate.previous_package_hash()
    );
}

#[test]
fn fault_matrix_preserves_old_current_until_new_current_is_durable() {
    for point in [
        FaultPoint::PrepareBefore,
        FaultPoint::PendingWritten,
        FaultPoint::PendingDurabilityBarrier,
        FaultPoint::CommitMarkerBefore,
        FaultPoint::CommitMarkerAfter,
        FaultPoint::CurrentPublishBefore,
        FaultPoint::CurrentPublishAfter,
        FaultPoint::OldSecretRetirementBefore,
        FaultPoint::OldSecretRetirementAfter,
    ] {
        let mut storage = storage();
        let candidate = pending(&storage);
        storage.set_fault(point);
        let prepared = storage.prepare_commit(&candidate);
        if prepared.is_err() {
            storage.simulate_crash();
            let recovered = storage.recover();
            assert!(recovered.is_ok(), "fault point {point:?}");
            assert!(recovered.unwrap().state().generation() <= PackageGeneration::new(1));
            continue;
        }
        let result = storage.commit(prepared.unwrap());
        if result.is_err() {
            storage.simulate_crash();
            let recovered = storage.recover();
            assert!(recovered.is_ok(), "fault point {point:?}");
            let generation = recovered.unwrap().state().generation();
            assert!(
                generation == PackageGeneration::new(0) || generation == PackageGeneration::new(1)
            );
        } else {
            assert_eq!(
                storage.load_current().unwrap().generation(),
                PackageGeneration::new(1)
            );
        }
    }
}

#[test]
fn recovery_faults_are_reported_without_half_state() {
    let mut storage = storage();
    storage.set_fault(FaultPoint::RecoveryBefore);
    assert!(matches!(
        storage.recover(),
        Err(StorageError::InjectedFault(FaultPoint::RecoveryBefore))
    ));
    storage.set_fault(FaultPoint::None);
    assert_eq!(
        storage.recover().unwrap().state().generation(),
        PackageGeneration::new(0)
    );
}

#[test]
fn file_storage_round_trips_private_packages_and_public_state() {
    let path = temp_storage_path("round-trip");
    let initial = StoredState::initial(initial_state());
    let storage = crate::FileStateStorage::create(&path, initial.clone()).unwrap();
    let restored = crate::FileStateStorage::open(&path)
        .unwrap()
        .load_current()
        .unwrap();
    assert!(restored == initial);
    assert!(restored.state().public_snapshot() == initial.state().public_snapshot());
    assert!(restored.state().alice_public_package() == initial.state().alice_public_package());
    assert!(restored.state().bob_public_package() == initial.state().bob_public_package());
    assert!(!storage.rollback_resistant());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn file_storage_commit_survives_reopen_and_retires_pending_files() {
    let path = temp_storage_path("commit");
    let initial = StoredState::initial(initial_state());
    let mut storage = crate::FileStateStorage::create(&path, initial).unwrap();
    let candidate =
        StoredState::pending_from(&storage.load_current().unwrap(), next_state()).unwrap();
    let handle = storage.prepare_commit(&candidate).unwrap();
    storage.commit(handle).unwrap();

    let mut reopened = crate::FileStateStorage::open(&path).unwrap();
    let recovered = reopened.recover().unwrap();
    assert_eq!(recovered.choice(), RecoveryChoice::ExistingCurrent);
    assert_eq!(recovered.state().generation(), PackageGeneration::new(1));
    assert!(!path.join("pending.bin").exists());
    assert!(!path.join("commit.marker").exists());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn file_storage_discards_uncommitted_pending_after_reopen() {
    let path = temp_storage_path("pending");
    let initial = StoredState::initial(initial_state());
    let mut storage = crate::FileStateStorage::create(&path, initial).unwrap();
    let candidate =
        StoredState::pending_from(&storage.load_current().unwrap(), next_state()).unwrap();
    storage.prepare_commit(&candidate).unwrap();
    drop(storage);

    let mut reopened = crate::FileStateStorage::open(&path).unwrap();
    let recovered = reopened.recover().unwrap();
    assert_eq!(recovered.choice(), RecoveryChoice::ExistingCurrent);
    assert_eq!(recovered.state().generation(), PackageGeneration::new(0));
    assert!(!path.join("pending.bin").exists());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn file_storage_rejects_tampered_records_without_loading_state() {
    let path = temp_storage_path("tamper");
    let initial = StoredState::initial(initial_state());
    crate::FileStateStorage::create(&path, initial).unwrap();
    let current_path = path.join("current.bin");
    let mut bytes = fs::read(&current_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(current_path, bytes).unwrap();
    let storage = crate::FileStateStorage::open(&path).unwrap();
    assert!(matches!(
        storage.load_current(),
        Err(StorageError::CorruptRecord)
    ));
    fs::remove_dir_all(path).unwrap();
}
