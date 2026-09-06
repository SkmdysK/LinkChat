//! Bounded verification tests for protocol conformance.
//!
//! These tests exercise finite inputs and finite traces. They do not replace
//! Lean's universal structural theorems, primitive security assumptions,
//! CSPRNG assumptions, or production storage durability contracts.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::Command;

use crate::{AcceptReject, Challenge, CompleteAdversaryView, DhtObservation, NetworkObservation};
use linkchat_core::{
    ApplicationMessage, CoreError, Endpoint, EndpointKernel, PrivateReceiverPackage,
    PublicReceiverPackage, ReceiverPackageFactory, RefinedState, Session, StepOutcome,
    package_chain_root, receiver_package_hash, verify_receiver_package,
};
use linkchat_crypto::{CryptoBackend, CryptoError, OsCryptoBackend};
use linkchat_mailbox::{InMemoryMailbox, Mailbox, MailboxError, MailboxTtl, PutStatus};
use linkchat_protocol::{
    AckFrame, CIPHERTEXT_LEN, DeliveryStatus, Direction, ED25519_SIGNATURE_LEN,
    ENCRYPTED_HEADER_LEN, ML_KEM_768_PUBLIC_KEY_LEN, MailboxRecord, SackFrame, WireBytes,
    WireEnvelope, decode_ack, decode_application_message, decode_envelope, decode_mailbox_record,
    decode_receiver_package, decode_sack, encode,
};
use linkchat_storage::{
    FaultInjectingMemoryStorage, FaultPoint, RecordKind, RecoveryChoice, StateStorage, StoredState,
};
use linkchat_transport::{
    ControlFrame, InMemoryTransport, PacketBytes, Transport, TransportTimestamp,
};
use linkchat_types::{
    CipherSuite, HASH_LEN, KeyId, MAILBOX_TOKEN_LEN, MessageId, PackageGeneration, PackageHash,
    ProtocolVersion, SessionId, Turn, X25519_PUBLIC_KEY_LEN, X25519PublicKey,
};

const ML_KEM_PUBLIC_KEY_LEN: usize = ML_KEM_768_PUBLIC_KEY_LEN;

fn package(
    session_id: SessionId,
    turn: Turn,
    generation: PackageGeneration,
    key_id: KeyId,
    token_byte: u8,
    _secret_byte: u8,
) -> PrivateReceiverPackage {
    let public = PublicReceiverPackage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        session_id,
        turn,
        generation,
        key_id,
        X25519PublicKey::from_array([token_byte; X25519_PUBLIC_KEY_LEN]),
        WireBytes::from_vec(vec![token_byte; ML_KEM_PUBLIC_KEY_LEN]).unwrap(),
        linkchat_types::MailboxToken::from_array([token_byte; MAILBOX_TOKEN_LEN]),
        0,
        PackageHash::from_array([token_byte; HASH_LEN]),
        WireBytes::from_vec(vec![token_byte; ED25519_SIGNATURE_LEN]).unwrap(),
    )
    .unwrap();
    PrivateReceiverPackage::for_testing(public).unwrap()
}

fn initial_state() -> RefinedState {
    let session_id = SessionId::new(9);
    RefinedState::new(
        Session::new(session_id),
        package(
            session_id,
            Turn::new(0),
            PackageGeneration::new(0),
            KeyId::new(10),
            11,
            101,
        ),
        package(
            session_id,
            Turn::new(0),
            PackageGeneration::new(0),
            KeyId::new(20),
            22,
            202,
        ),
    )
    .unwrap()
}

fn alice_message(
    _state: &RefinedState,
    session_id: SessionId,
    turn: Turn,
    key_id: KeyId,
    token_byte: u8,
    id: u64,
) -> ApplicationMessage {
    ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        session_id,
        turn,
        Endpoint::Alice,
        MessageId::new(id),
        key_id,
        linkchat_types::MailboxToken::from_array([token_byte; MAILBOX_TOKEN_LEN]),
        WireBytes::from_bytes(b"bounded-test-payload").unwrap(),
    )
}

fn valid_alice_message(state: &RefinedState, id: u64) -> ApplicationMessage {
    alice_message(
        state,
        state.session().session_id(),
        state.turn(),
        state.bob_public_package().key_id(),
        state.bob_public_package().mailbox_token().as_bytes()[0],
        id,
    )
}

fn next_bob(state: &RefinedState, key: u64, token: u8, secret: u8) -> PrivateReceiverPackage {
    package(
        state.session().session_id(),
        Turn::new(1),
        PackageGeneration::new(1),
        KeyId::new(key),
        token,
        secret,
    )
}

fn next_alice(state: &RefinedState, key: u64, token: u8, secret: u8) -> PrivateReceiverPackage {
    package(
        state.session().session_id(),
        Turn::new(2),
        PackageGeneration::new(1),
        KeyId::new(key),
        token,
        secret,
    )
}

fn mailbox_record(token_byte: u8) -> MailboxRecord {
    let token = linkchat_types::MailboxToken::from_array([token_byte; MAILBOX_TOKEN_LEN]);
    let envelope = WireEnvelope::new(
        token.clone(),
        WireBytes::from_bytes(&[1; X25519_PUBLIC_KEY_LEN]).unwrap(),
        WireBytes::from_bytes(&[2; linkchat_types::ML_KEM_768_CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[3; ENCRYPTED_HEADER_LEN]).unwrap(),
        WireBytes::from_vec(vec![4; CIPHERTEXT_LEN]).unwrap(),
        WireBytes::from_bytes(&[]).unwrap(),
    )
    .unwrap();
    MailboxRecord::new(token, envelope).unwrap()
}

#[test]
fn vector_manifest_has_all_frozen_categories_and_fields() {
    let manifest = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/manifest.tsv"
    ));
    let required = [
        "bootstrap",
        "identity",
        "receiver-package",
        "message",
        "header",
        "token",
        "replay",
        "rollback",
        "storage-recovery",
        "kem",
        "hkdf",
        "aead",
    ];
    let rows: Vec<&str> = manifest.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(
        rows.first().copied(),
        Some(
            "category\tprotocol_version\tcipher_suite\tcanonical_input\texpected_output_or_error\tstate_transition\tturn\tgeneration"
        )
    );
    for category in required {
        let row = rows
            .iter()
            .find(|line| line.starts_with(&format!("{category}\t")))
            .copied()
            .unwrap_or_else(|| panic!("missing vector category {category}"));
        assert_eq!(row.split('\t').count(), 8);
        let vector_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors")
            .join(category)
            .join("vector.md");
        assert!(vector_path.is_file(), "missing vector file {vector_path:?}");
    }
}

#[test]
fn canonical_vectors_are_stable_and_public_packages_exclude_secret_bytes() {
    let state = initial_state();
    let message = valid_alice_message(&state, 7);
    let wire_message = message.to_wire();
    let encoded = encode(&wire_message).unwrap();
    let decoded = decode_application_message(encoded.as_bytes()).unwrap();
    assert!(encode(&decoded).unwrap() == encoded);

    let public = state.bob_public_package().to_wire().unwrap();
    let public_encoded = encode(&public).unwrap();
    assert!(
        !public_encoded
            .as_bytes()
            .windows(32)
            .any(|window| window == [202; 32])
    );
    assert_eq!(
        state.bob_public_package().generation(),
        PackageGeneration::new(0)
    );
}

#[test]
fn property_valid_inputs_advance_once_and_invalid_inputs_are_noop() {
    for index in 0..256_u64 {
        let state = initial_state();
        let message = valid_alice_message(&state, 1000 + index);
        let next = next_bob(
            &state,
            100 + index,
            40 + (index % 200) as u8,
            80 + (index % 100) as u8,
        );
        let outcome = state.step(&message, next);
        let next_state = match outcome {
            StepOutcome::Accepted(prepared) => prepared.apply(),
            StepOutcome::Rejected { .. } => panic!("valid bounded input was rejected"),
        };
        assert_eq!(next_state.turn(), Turn::new(1));
        assert_eq!(
            next_state.consumed_message_ids(),
            &[MessageId::new(1000 + index)]
        );
        assert!(next_state.alice_public_package() == state.alice_public_package());
        assert_eq!(
            next_state.bob_public_package().generation(),
            PackageGeneration::new(1)
        );
    }

    let state = initial_state();
    let base = state.public_snapshot();
    let invalid_messages = [
        alice_message(
            &state,
            SessionId::new(99),
            Turn::new(0),
            KeyId::new(20),
            22,
            1,
        ),
        alice_message(
            &state,
            SessionId::new(9),
            Turn::new(0),
            KeyId::new(999),
            22,
            2,
        ),
        alice_message(
            &state,
            SessionId::new(9),
            Turn::new(0),
            KeyId::new(20),
            99,
            3,
        ),
        alice_message(
            &state,
            SessionId::new(9),
            Turn::new(2),
            KeyId::new(20),
            22,
            4,
        ),
        ApplicationMessage::new(
            ProtocolVersion::V1_0,
            CipherSuite::current(),
            SessionId::new(9),
            Turn::new(0),
            Endpoint::Bob,
            MessageId::new(5),
            KeyId::new(10),
            linkchat_types::MailboxToken::from_array([11; MAILBOX_TOKEN_LEN]),
            WireBytes::from_bytes(b"wrong leader").unwrap(),
        ),
    ];
    for message in invalid_messages {
        let outcome = state.step(&message, next_bob(&state, 30, 31, 32));
        assert!(!outcome.is_accepted());
        assert!(outcome.state().public_snapshot() == base);
    }

    let accepted = state.step(
        &valid_alice_message(&state, 88),
        next_bob(&state, 31, 32, 33),
    );
    let after = accepted.into_state();
    let replay = after.step(
        &valid_alice_message(&state, 88),
        next_alice(&after, 40, 41, 42),
    );
    assert!(!replay.is_accepted());
    assert!(replay.state().public_snapshot() == after.public_snapshot());
}

#[test]
fn property_old_generation_cannot_cover_new_generation_and_crash_recovery_is_atomic() {
    let initial = initial_state();
    let mut storage =
        FaultInjectingMemoryStorage::new(StoredState::initial(initial.clone())).unwrap();
    let accepted = initial.step(
        &valid_alice_message(&initial, 12),
        next_bob(&initial, 31, 32, 33),
    );
    let next = accepted.into_state();
    let candidate = StoredState::pending_from(&storage.load_current().unwrap(), next).unwrap();
    let handle = storage.prepare_commit(&candidate).unwrap();
    storage.commit(handle).unwrap();
    assert_eq!(
        storage.load_current().unwrap().generation(),
        PackageGeneration::new(1)
    );
    assert!(matches!(
        storage.prepare_commit(&candidate),
        Err(linkchat_storage::StorageError::GenerationNotNext { .. })
    ));

    for fault in [
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
        let initial = initial_state();
        let mut storage =
            FaultInjectingMemoryStorage::new(StoredState::initial(initial.clone())).unwrap();
        let next = initial
            .step(
                &valid_alice_message(&initial, 13),
                next_bob(&initial, 31, 32, 33),
            )
            .into_state();
        let candidate = StoredState::pending_from(&storage.load_current().unwrap(), next).unwrap();
        storage.set_fault(fault);
        let prepared = storage.prepare_commit(&candidate);
        if let Ok(handle) = prepared {
            let _ = storage.commit(handle);
        }
        storage.simulate_crash();
        let recovered = storage.recover().unwrap();
        assert!(matches!(
            recovered.choice(),
            RecoveryChoice::ExistingCurrent | RecoveryChoice::CompletedPending
        ));
        assert!(matches!(recovered.state().kind(), RecordKind::Current));
        assert!(recovered.state().generation() <= PackageGeneration::new(1));
    }
}

#[test]
fn ack_transport_and_mailbox_observations_do_not_update_core_state() {
    let state = initial_state();
    let before = state.public_snapshot();
    let ack = AckFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(9),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(7),
        DeliveryStatus::Accepted,
    );
    let sack = SackFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(9),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(7),
        WireBytes::from_bytes(&[0xaa, 0x55]).unwrap(),
    )
    .unwrap();
    let mut transport = InMemoryTransport::new();
    transport
        .send(ControlFrame::Ack(ack).encode_canonical().unwrap())
        .unwrap();
    transport
        .send(ControlFrame::Sack(sack).encode_canonical().unwrap())
        .unwrap();
    while let Some(event) = transport.receive().unwrap() {
        assert!(ControlFrame::decode_canonical(event.packet().as_bytes()).is_ok());
        assert!(state.public_snapshot() == before);
    }

    let token = state.bob_public_package().mailbox_token().clone();
    let mut mailbox = InMemoryMailbox::new();
    assert_eq!(
        mailbox.put(&token, mailbox_record(22), MailboxTtl::from_ticks(5)),
        Ok(PutStatus::Inserted)
    );
    assert_eq!(
        mailbox.put(&token, mailbox_record(22), MailboxTtl::from_ticks(5)),
        Ok(PutStatus::Duplicate)
    );
    mailbox.advance_time(5).unwrap();
    assert!(mailbox.get(&token, 1).unwrap().is_empty());
    assert!(state.public_snapshot() == before);
}

#[test]
fn complete_adversary_view_records_all_required_observables() {
    let view = CompleteAdversaryView {
        challenge: Challenge::Real,
        event_time: TransportTimestamp::new(4),
        logical_length: 128,
        envelope_length: linkchat_types::MAX_ENVELOPE_SIZE,
        ack: Some(DeliveryStatus::Accepted),
        error: None,
        accept_reject: AcceptReject::Accepted,
        state_update_count: 1,
        package_update_count: 1,
        network_observations: vec![NetworkObservation::Delivered],
        dht_observations: vec![DhtObservation::Get],
    };
    assert_eq!(view.challenge, Challenge::Real);
    assert_eq!(view.event_time.ticks(), 4);
    assert_eq!(view.logical_length, 128);
    assert_eq!(view.envelope_length, 4096);
    assert_eq!(view.ack, Some(DeliveryStatus::Accepted));
    assert_eq!(view.accept_reject, AcceptReject::Accepted);
    assert_eq!(view.state_update_count, 1);
    assert_eq!(view.package_update_count, 1);
    assert_eq!(
        view.network_observations,
        vec![NetworkObservation::Delivered]
    );
    assert_eq!(view.dht_observations, vec![DhtObservation::Get]);
}

#[test]
fn fuzz_smoke_rejects_mutated_wire_inputs_without_panics() {
    let state = initial_state();
    let next = next_bob(&state, 31, 32, 33);
    let valid_message = encode(&valid_alice_message(&state, 99).to_wire())
        .unwrap()
        .into_vec();
    let valid_package = encode(&state.bob_public_package().to_wire().unwrap())
        .unwrap()
        .into_vec();
    let valid_ack = encode(&AckFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(9),
        Turn::new(0),
        Direction::Alice,
        MessageId::new(99),
        DeliveryStatus::Accepted,
    ))
    .unwrap()
    .into_vec();
    let valid_sack = encode(
        &SackFrame::new(
            ProtocolVersion::V1_0,
            CipherSuite::current(),
            SessionId::new(9),
            Turn::new(0),
            Direction::Alice,
            MessageId::new(99),
            WireBytes::from_bytes(&[1, 2, 3]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .into_vec();
    let mut corpus = vec![
        Vec::new(),
        vec![0xff],
        vec![0; 9],
        vec![0xff; 64],
        valid_message,
        valid_package,
        valid_ack,
        valid_sack,
    ];
    for seed in 0..512_u64 {
        let mut bytes = vec![0_u8; seed as usize % 257];
        let mut value = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for byte in &mut bytes {
            value ^= value << 7;
            value ^= value >> 9;
            *byte = value as u8;
        }
        if seed % 4 == 0 && bytes.len() >= 5 {
            bytes[0] = 0x01;
            bytes[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        corpus.push(bytes);
    }
    for bytes in corpus {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = decode_application_message(&bytes);
            let _ = decode_receiver_package(&bytes);
            let _ = decode_envelope(&bytes);
            let _ = decode_ack(&bytes);
            let _ = decode_sack(&bytes);
            let _ = decode_mailbox_record(&bytes);
            let _ = ControlFrame::decode_canonical(&bytes);
            let _ = state.process_encoded(&bytes, next.clone());
            let _ = PacketBytes::from_bytes(&bytes);
        }));
        assert!(
            result.is_ok(),
            "wire fuzz input panicked: {} bytes",
            bytes.len()
        );
    }
    let mut crypto = OsCryptoBackend::new();
    for len in 0..=linkchat_types::ML_KEM_768_CIPHERTEXT_LEN + 2 {
        let bytes = vec![0x42; len];
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = linkchat_types::MlKemCiphertext::from_bytes(&bytes);
            let _ = X25519PublicKey::from_bytes(&bytes);
        }));
        assert!(result.is_ok());
    }
    let receiver = crypto.generate_x25519_keypair().unwrap();
    assert!(matches!(
        crypto.x25519_decapsulate(
            &receiver.secret_key,
            &X25519PublicKey::from_array([0; X25519_PUBLIC_KEY_LEN]),
        ),
        Err(CryptoError::LowOrderPoint)
    ));
}

#[test]
fn lean_bounded_oracle_matches_rust_core_projection() {
    let Some(formalization_dir) =
        std::env::var_os("LINKCHAT_FORMALIZATION_DIR").map(std::path::PathBuf::from)
    else {
        eprintln!("LINKCHAT_FORMALIZATION_DIR is not set; bounded differential test skipped");
        return;
    };
    let oracle =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/lean/BoundedOracle.lean");
    if !Path::new("/usr/bin/lean").exists()
        && Command::new("lean").arg("--version").output().is_err()
    {
        eprintln!("Lean unavailable; bounded differential test skipped");
        return;
    }
    let output = Command::new("lean")
        .env("LEAN_PATH", &formalization_dir)
        .arg("--run")
        .arg(&oracle)
        .output()
        .expect("failed to launch Lean bounded oracle");
    assert!(
        output.status.success(),
        "Lean oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lean_lines: Vec<String> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();

    let base = initial_state();
    let alice_valid = valid_alice_message(&base, 7);
    let after_alice = base
        .step(&alice_valid, next_bob(&base, 21, 23, 33))
        .into_state();
    let bob_valid = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(9),
        Turn::new(1),
        Endpoint::Bob,
        MessageId::new(8),
        KeyId::new(10),
        linkchat_types::MailboxToken::from_array([11; MAILBOX_TOKEN_LEN]),
        WireBytes::from_bytes(b"payload").unwrap(),
    );
    let cases = [
        (
            "base-valid",
            base.clone(),
            alice_valid.clone(),
            next_bob(&base, 21, 23, 33),
        ),
        (
            "base-wrong-session",
            base.clone(),
            alice_message(
                &base,
                SessionId::new(99),
                Turn::new(0),
                KeyId::new(20),
                22,
                7,
            ),
            next_bob(&base, 21, 23, 33),
        ),
        (
            "base-wrong-key",
            base.clone(),
            alice_message(
                &base,
                SessionId::new(9),
                Turn::new(0),
                KeyId::new(999),
                22,
                7,
            ),
            next_bob(&base, 21, 23, 33),
        ),
        (
            "base-wrong-token",
            base.clone(),
            alice_message(
                &base,
                SessionId::new(9),
                Turn::new(0),
                KeyId::new(20),
                99,
                7,
            ),
            next_bob(&base, 21, 23, 33),
        ),
        (
            "base-future",
            base.clone(),
            alice_message(
                &base,
                SessionId::new(9),
                Turn::new(2),
                KeyId::new(20),
                22,
                7,
            ),
            next_bob(&base, 21, 23, 33),
        ),
        (
            "after-alice-replay",
            after_alice.clone(),
            alice_valid,
            next_alice(&after_alice, 12, 24, 44),
        ),
        (
            "after-alice-valid-bob",
            after_alice.clone(),
            bob_valid,
            next_alice(&after_alice, 12, 24, 44),
        ),
    ];
    let rust_lines: Vec<String> = cases
        .into_iter()
        .map(|(label, state, message, next)| {
            let accepted = state.validate(&message).is_ok();
            let resulting = state.step(&message, next).into_state();
            let alice = resulting.alice_public_package();
            let bob = resulting.bob_public_package();
            let consumed = resulting
                .consumed_message_ids()
                .iter()
                .map(|id| id.get().to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{label}|{}|{}|{}|{}|{}|{}|{}",
                u8::from(accepted),
                resulting.turn().get(),
                alice.key_id().get(),
                bob.key_id().get(),
                alice.mailbox_token().as_bytes()[0],
                bob.mailbox_token().as_bytes()[0],
                if consumed.is_empty() { "-" } else { &consumed },
            )
        })
        .collect();
    assert!(
        rust_lines == lean_lines,
        "Lean/Rust bounded mismatch\nLean: {lean_lines:?}\nRust: {rust_lines:?}"
    );
}

#[test]
fn mailbox_error_paths_are_stable_and_noop() {
    let state = initial_state();
    let before = state.public_snapshot();
    let token = state.bob_public_package().mailbox_token().clone();
    let mut mailbox = InMemoryMailbox::with_limits(1, 1);
    assert!(matches!(
        mailbox.put(&token, mailbox_record(22), MailboxTtl::from_ticks(1)),
        Err(MailboxError::RecordTooLarge { .. })
    ));
    assert_eq!(mailbox.stored_count(), 0);
    mailbox.set_available(false);
    assert!(matches!(
        mailbox.get(&token, 1),
        Err(MailboxError::Unavailable)
    ));
    assert!(state.public_snapshot() == before);
}

fn real_endpoint_pair() -> (
    OsCryptoBackend,
    EndpointKernel,
    EndpointKernel,
    linkchat_crypto::Ed25519KeyPair,
    linkchat_crypto::Ed25519KeyPair,
) {
    let mut backend = OsCryptoBackend::new();
    let alice_identity = backend.generate_ed25519_keypair().unwrap();
    let bob_identity = backend.generate_ed25519_keypair().unwrap();
    let session = Session::new(SessionId::new(707));
    let alice_root = package_chain_root(
        &backend,
        session,
        &alice_identity.public_key,
        &bob_identity.public_key,
        Endpoint::Alice,
    )
    .unwrap();
    let bob_root = package_chain_root(
        &backend,
        session,
        &alice_identity.public_key,
        &bob_identity.public_key,
        Endpoint::Bob,
    )
    .unwrap();
    let alice_package = ReceiverPackageFactory::generate(
        &mut backend,
        session,
        &alice_identity.secret_key,
        Turn::new(0),
        PackageGeneration::new(0),
        100,
        alice_root,
    )
    .unwrap();
    let bob_package = ReceiverPackageFactory::generate(
        &mut backend,
        session,
        &bob_identity.secret_key,
        Turn::new(0),
        PackageGeneration::new(0),
        100,
        bob_root,
    )
    .unwrap();
    let alice = EndpointKernel::new(
        &backend,
        session,
        Endpoint::Alice,
        alice_package.clone(),
        bob_package.public_projection().clone(),
        alice_identity.secret_key.clone(),
        bob_identity.public_key,
        Turn::new(0),
        1,
    )
    .unwrap();
    let bob = EndpointKernel::new(
        &backend,
        session,
        Endpoint::Bob,
        bob_package,
        alice_package.public_projection().clone(),
        bob_identity.secret_key.clone(),
        alice_identity.public_key,
        Turn::new(0),
        1,
    )
    .unwrap();
    (backend, alice, bob, alice_identity, bob_identity)
}

#[test]
fn endpoint_e2e_rotation_authentication_and_tamper_paths_are_explicit() {
    let (mut backend, alice, bob, alice_identity, bob_identity) = real_endpoint_pair();
    let alice_initial = alice.public_snapshot();
    let bob_initial = bob.public_snapshot();

    let alice_send = alice
        .prepare_send(&mut backend, MessageId::new(1), b"hello", 1)
        .unwrap();
    let encoded = encode(alice_send.envelope()).unwrap();
    let alice_after_send = alice_send.commit();
    assert_eq!(alice_after_send.turn(), Turn::new(1));
    assert!(
        alice_after_send.public_snapshot().alice_public_package()
            == alice_initial.alice_public_package()
    );

    let bob_receive = bob
        .prepare_receive(&mut backend, encoded.as_bytes(), 1, 100)
        .unwrap();
    assert_eq!(bob_receive.plaintext().as_bytes(), b"hello");
    let returned_alice = bob_receive.returned_receiver_package().clone();
    verify_receiver_package(
        &backend,
        &returned_alice,
        Session::new(SessionId::new(707)),
        &alice_identity.public_key,
        Turn::new(0),
        PackageGeneration::new(0),
        alice_initial.alice_public_package().previous_package_hash(),
        1,
    )
    .unwrap();
    assert_eq!(
        receiver_package_hash(&backend, &returned_alice).unwrap(),
        receiver_package_hash(&backend, alice_initial.alice_public_package()).unwrap()
    );
    let bob_after_receive = bob_receive.commit();
    assert_eq!(bob_after_receive.turn(), Turn::new(1));
    assert_eq!(
        bob_after_receive
            .public_snapshot()
            .bob_public_package()
            .generation(),
        PackageGeneration::new(1)
    );

    let bob_send = bob_after_receive
        .prepare_send(&mut backend, MessageId::new(2), b"world", 1)
        .unwrap();
    let reverse_encoded = encode(bob_send.envelope()).unwrap();
    let bob_after_send = bob_send.commit();
    let alice_receive = alice_after_send
        .prepare_receive(&mut backend, reverse_encoded.as_bytes(), 1, 100)
        .unwrap();
    assert_eq!(alice_receive.plaintext().as_bytes(), b"world");
    let alice_after_receive = alice_receive.commit();
    assert_eq!(alice_after_receive.turn(), Turn::new(2));
    assert_eq!(
        alice_after_receive
            .public_snapshot()
            .alice_public_package()
            .generation(),
        PackageGeneration::new(1)
    );
    assert!(
        bob_after_send
            .public_snapshot()
            .bob_public_package()
            .generation()
            == PackageGeneration::new(1)
    );
    verify_receiver_package(
        &backend,
        alice_after_receive.public_snapshot().bob_public_package(),
        Session::new(SessionId::new(707)),
        &bob_identity.public_key,
        Turn::new(1),
        PackageGeneration::new(1),
        receiver_package_hash(&backend, bob_initial.bob_public_package()).unwrap(),
        1,
    )
    .unwrap();

    let prepared = alice
        .prepare_send(&mut backend, MessageId::new(9), b"tamper", 1)
        .unwrap();
    let original = prepared.envelope().clone();
    let mut header = original.encrypted_header().as_bytes().to_vec();
    header[0] ^= 1;
    let tampered_header = WireEnvelope::new(
        original.mailbox_token().clone(),
        original.x25519_kem_ciphertext().clone(),
        original.mlkem_ciphertext().clone(),
        WireBytes::from_bytes(&header).unwrap(),
        original.ciphertext().clone(),
        original.padding().clone(),
    )
    .unwrap();
    let bob_before = bob.public_snapshot();
    assert!(
        bob.prepare_receive(
            &mut backend,
            encode(&tampered_header).unwrap().as_bytes(),
            1,
            100
        )
        .is_err()
    );
    assert!(bob.public_snapshot() == bob_before);

    let mut payload = original.ciphertext().as_bytes().to_vec();
    payload[0] ^= 1;
    let tampered_payload = WireEnvelope::new(
        original.mailbox_token().clone(),
        original.x25519_kem_ciphertext().clone(),
        original.mlkem_ciphertext().clone(),
        original.encrypted_header().clone(),
        WireBytes::from_bytes(&payload).unwrap(),
        original.padding().clone(),
    )
    .unwrap();
    let bob_before = bob.public_snapshot();
    assert!(
        bob.prepare_receive(
            &mut backend,
            encode(&tampered_payload).unwrap().as_bytes(),
            1,
            100
        )
        .is_err()
    );
    assert!(bob.public_snapshot() == bob_before);

    let wrong_token = WireEnvelope::new(
        linkchat_types::MailboxToken::from_array([0xaa; MAILBOX_TOKEN_LEN]),
        original.x25519_kem_ciphertext().clone(),
        original.mlkem_ciphertext().clone(),
        original.encrypted_header().clone(),
        original.ciphertext().clone(),
        original.padding().clone(),
    )
    .unwrap();
    assert!(matches!(
        bob.prepare_receive(
            &mut backend,
            encode(&wrong_token).unwrap().as_bytes(),
            1,
            100
        ),
        Err(CoreError::EnvelopeContextMismatch {
            field: "mailbox token"
        })
    ));
    assert!(bob.public_snapshot() == bob_before);
}
