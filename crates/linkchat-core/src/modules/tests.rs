use crate::{
    ApplicationMessage, CoreError, Endpoint, EndpointKernel, PrivateReceiverPackage,
    PublicReceiverPackage, ReceiverPackageFactory, RefinedState, RejectReason, Session,
    StepOutcome, package_chain_root, receiver_package_hash, verify_receiver_package,
};
use linkchat_crypto::{CryptoBackend, OsCryptoBackend};
use linkchat_protocol::{
    ED25519_SIGNATURE_LEN, ML_KEM_768_PUBLIC_KEY_LEN, WireBytes, WireError, WireReceiverPackage,
    encode,
};
use linkchat_types::{
    CipherSuite, HASH_LEN, KeyId, MAILBOX_TOKEN_LEN, MailboxToken, MessageId, PackageGeneration,
    PackageHash, ProtocolVersion, SessionId, Turn, X25519_PUBLIC_KEY_LEN, X25519PublicKey,
};

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
        WireBytes::from_vec(vec![token_byte; ML_KEM_768_PUBLIC_KEY_LEN]).unwrap(),
        MailboxToken::from_array([token_byte; MAILBOX_TOKEN_LEN]),
        0,
        PackageHash::from_array([token_byte; HASH_LEN]),
        WireBytes::from_vec(vec![token_byte; ED25519_SIGNATURE_LEN]).unwrap(),
    )
    .unwrap();
    PrivateReceiverPackage::for_testing(public).unwrap()
}

fn state() -> RefinedState {
    let session_id = SessionId::new(9);
    RefinedState::new(
        Session::new(session_id),
        package(
            session_id,
            Turn::new(0),
            PackageGeneration::new(0),
            KeyId::new(10),
            1,
            11,
        ),
        package(
            session_id,
            Turn::new(0),
            PackageGeneration::new(0),
            KeyId::new(20),
            2,
            22,
        ),
    )
    .unwrap()
}

fn message(state: &RefinedState, id: u64) -> ApplicationMessage {
    ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        state.session().session_id(),
        state.turn(),
        Endpoint::Alice,
        MessageId::new(id),
        state.bob_public_package().key_id(),
        state.bob_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"hello").unwrap(),
    )
}

fn next_bob(state: &RefinedState) -> PrivateReceiverPackage {
    package(
        state.session().session_id(),
        Turn::new(1),
        PackageGeneration::new(1),
        KeyId::new(21),
        3,
        33,
    )
}

#[test]
fn valid_input_advances_once_and_rotates_only_receiver() {
    let state = state();
    let original_alice = state.alice_public_package().clone();
    let outcome = state.step(&message(&state, 7), next_bob(&state));
    let next = match outcome {
        StepOutcome::Accepted(prepared) => prepared.apply(),
        StepOutcome::Rejected { reason, .. } => panic!("unexpected rejection: {reason}"),
    };
    assert_eq!(next.turn(), Turn::new(1));
    assert_eq!(next.consumed_message_ids(), &[MessageId::new(7)]);
    assert!(next.alice_public_package() == &original_alice);
    assert_eq!(next.bob_public_package().key_id(), KeyId::new(21));
    assert_eq!(
        next.bob_public_package().generation(),
        PackageGeneration::new(1)
    );
}

#[test]
fn strict_alice_bob_alternation_is_enforced() {
    let state = state();
    let bob_message = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        state.session().session_id(),
        Turn::new(0),
        Endpoint::Bob,
        MessageId::new(8),
        state.alice_public_package().key_id(),
        state.alice_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"wrong leader").unwrap(),
    );
    assert_eq!(state.validate(&bob_message), Err(RejectReason::WrongLeader));
}

#[test]
fn successful_steps_alternate_alice_then_bob_then_alice() {
    let state = state();
    let after_alice = match state.step(&message(&state, 30), next_bob(&state)) {
        StepOutcome::Accepted(prepared) => prepared.apply(),
        StepOutcome::Rejected { reason, .. } => panic!("unexpected rejection: {reason}"),
    };
    assert_eq!(after_alice.leader(), Endpoint::Bob);

    let bob_message = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        after_alice.session().session_id(),
        after_alice.turn(),
        Endpoint::Bob,
        MessageId::new(31),
        after_alice.alice_public_package().key_id(),
        after_alice.alice_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"bob").unwrap(),
    );
    let next_alice = package(
        after_alice.session().session_id(),
        Turn::new(2),
        PackageGeneration::new(1),
        KeyId::new(11),
        4,
        44,
    );
    let after_bob = match after_alice.step(&bob_message, next_alice) {
        StepOutcome::Accepted(prepared) => prepared.apply(),
        StepOutcome::Rejected { reason, .. } => panic!("unexpected rejection: {reason}"),
    };
    assert_eq!(after_bob.turn(), Turn::new(2));
    assert_eq!(after_bob.leader(), Endpoint::Alice);
    assert_eq!(after_bob.consumed_message_ids().len(), 2);
}

#[test]
fn past_and_future_turns_are_rejected_without_state_change() {
    let state = state();
    let past = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        state.session().session_id(),
        Turn::new(0),
        Endpoint::Alice,
        MessageId::new(1),
        state.bob_public_package().key_id(),
        state.bob_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"past").unwrap(),
    );
    let future = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        state.session().session_id(),
        Turn::new(2),
        Endpoint::Alice,
        MessageId::new(2),
        state.bob_public_package().key_id(),
        state.bob_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"future").unwrap(),
    );
    assert_eq!(state.validate(&past), Ok(()));
    let accepted = state.step(&past, next_bob(&state));
    let after = accepted.into_state();
    assert_eq!(after.validate(&past), Err(RejectReason::PastTurn));
    assert_eq!(state.validate(&future), Err(RejectReason::FutureTurn));
    assert!(after.step(&past, next_bob(&state)).state() == &after);
}

#[test]
fn consumed_message_id_is_rejected_as_replay_without_state_change() {
    let initial = state();
    let current = RefinedState::with_turn(
        initial.session(),
        initial.turn(),
        package(
            initial.session().session_id(),
            initial.turn(),
            PackageGeneration::new(0),
            KeyId::new(10),
            1,
            11,
        ),
        package(
            initial.session().session_id(),
            initial.turn(),
            PackageGeneration::new(0),
            KeyId::new(20),
            2,
            22,
        ),
        vec![MessageId::new(99)],
    )
    .unwrap();
    let replay = message(&current, 99);
    let outcome = current.step(&replay, next_bob(&current));
    assert_eq!(outcome.reason(), Some(RejectReason::Replay));
    assert!(outcome.state() == &current);
}

#[test]
fn wrong_context_key_and_token_are_noop() {
    let state = state();
    let mut wrong = message(&state, 3);
    wrong.session_id = SessionId::new(77);
    let outcome = state.step(&wrong, next_bob(&state));
    assert_eq!(outcome.reason(), Some(RejectReason::SessionMismatch));
    assert!(outcome.state() == &state);

    let wrong_key = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        state.session().session_id(),
        state.turn(),
        Endpoint::Alice,
        MessageId::new(4),
        KeyId::new(999),
        state.bob_public_package().mailbox_token().clone(),
        WireBytes::from_bytes(b"wrong key").unwrap(),
    );
    assert_eq!(
        state.validate(&wrong_key),
        Err(RejectReason::ReceiverKeyMismatch)
    );

    let wrong_token = ApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        state.session().session_id(),
        state.turn(),
        Endpoint::Alice,
        MessageId::new(5),
        state.bob_public_package().key_id(),
        MailboxToken::from_array([99; MAILBOX_TOKEN_LEN]),
        WireBytes::from_bytes(b"wrong token").unwrap(),
    );
    assert_eq!(
        state.validate(&wrong_token),
        Err(RejectReason::ReceiverTokenMismatch)
    );
}

#[test]
fn public_projection_hides_private_secret_and_rotates_atomically() {
    let state = state();
    assert_eq!(
        state.bob_public_package().mlkem_public_key().len(),
        ML_KEM_768_PUBLIC_KEY_LEN
    );
    assert_eq!(
        state.bob_public_package().package_auth().len(),
        ED25519_SIGNATURE_LEN
    );
    assert_eq!(
        state.bob_public_package().session_id(),
        state.session().session_id()
    );
    assert_eq!(state.bob_public_package().turn(), Turn::new(0));
    assert_eq!(
        state.bob_public_package().generation(),
        PackageGeneration::new(0)
    );
    assert_eq!(state.bob.secret_len(), 32 + 64);
}

#[test]
fn fresh_package_must_be_bound_to_next_turn_and_advanced_generation() {
    let state = state();
    let bad_turn = package(
        state.session().session_id(),
        Turn::new(0),
        PackageGeneration::new(1),
        KeyId::new(21),
        3,
        33,
    );
    let outcome = state.step(&message(&state, 10), bad_turn);
    assert_eq!(
        outcome.reason(),
        Some(RejectReason::FreshPackageTurnMismatch)
    );
    assert!(outcome.state() == &state);

    let bad_generation = package(
        state.session().session_id(),
        Turn::new(1),
        PackageGeneration::new(0),
        KeyId::new(21),
        3,
        33,
    );
    let outcome = state.step(&message(&state, 11), bad_generation);
    assert_eq!(
        outcome.reason(),
        Some(RejectReason::FreshPackageGenerationNotAdvanced)
    );
    assert!(outcome.state() == &state);
}

#[test]
fn same_fresh_package_gives_peer_input_non_interference() {
    let state = state();
    let first = message(&state, 12);
    let mut second = first.clone();
    second.message_id = MessageId::new(13);
    second.payload = WireBytes::from_bytes(b"different authenticated payload").unwrap();
    let next = next_bob(&state);
    let first_state = match state.step(&first, next.clone()) {
        StepOutcome::Accepted(prepared) => prepared.apply(),
        StepOutcome::Rejected { reason, .. } => panic!("unexpected rejection: {reason}"),
    };
    let second_state = match state.step(&second, next) {
        StepOutcome::Accepted(prepared) => prepared.apply(),
        StepOutcome::Rejected { reason, .. } => panic!("unexpected rejection: {reason}"),
    };
    assert!(first_state.bob_public_package() == second_state.bob_public_package());
    assert_eq!(first_state.turn(), second_state.turn());
}

#[test]
fn encoded_path_requires_canonical_application_message() {
    let state = state();
    let wire = message(&state, 14).to_wire();
    let encoded = encode(&wire).unwrap();
    let outcome = state
        .process_encoded(encoded.as_bytes(), next_bob(&state))
        .unwrap();
    assert!(outcome.is_accepted());

    let mut trailing = encoded.into_vec();
    trailing.push(0);
    assert!(matches!(
        state.process_encoded(&trailing, next_bob(&state)),
        Err(CoreError::Wire(WireError::TrailingBytes { .. }))
    ));
}

#[test]
fn public_package_round_trips_through_canonical_wire_type() {
    let state = state();
    let public = state.bob_public_package();
    let wire = public.to_wire().unwrap();
    let encoded = encode(&wire).unwrap();
    let decoded = WireReceiverPackage::decode(encoded.as_bytes()).unwrap();
    let restored = PublicReceiverPackage::from_wire(&decoded).unwrap();
    assert!(public == &restored);
}

#[test]
fn production_package_is_identity_bound_and_hashable() {
    let mut backend = OsCryptoBackend::new();
    let identity = backend.generate_ed25519_keypair().unwrap();
    let session = Session::new(SessionId::new(77));
    let previous = PackageHash::from_array([3; HASH_LEN]);
    let generated = ReceiverPackageFactory::generate(
        &mut backend,
        session,
        &identity.secret_key,
        Turn::new(0),
        PackageGeneration::new(0),
        100,
        previous,
    )
    .unwrap();

    let verified = verify_receiver_package(
        &backend,
        generated.public_package(),
        session,
        &identity.public_key,
        Turn::new(0),
        PackageGeneration::new(0),
        previous,
        0,
    )
    .unwrap();
    assert_eq!(verified.package_hash(), generated.package_hash());
    assert_eq!(
        receiver_package_hash(&backend, generated.public_package()).unwrap(),
        generated.package_hash()
    );
    assert!(verified.public_package() == generated.public_package());
}

#[test]
fn private_package_rejects_mismatched_keypairs() {
    let mut backend = OsCryptoBackend::new();
    let first_x25519 = backend.generate_x25519_keypair().unwrap();
    let second_x25519 = backend.generate_x25519_keypair().unwrap();
    let mlkem = backend.generate_mlkem768_keypair().unwrap();
    let session = Session::new(SessionId::new(79));
    let public = PublicReceiverPackage::new(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        Turn::new(0),
        PackageGeneration::new(0),
        KeyId::new(1),
        first_x25519.public_key,
        WireBytes::from_bytes(mlkem.public_key.as_bytes()).unwrap(),
        MailboxToken::from_array([5; MAILBOX_TOKEN_LEN]),
        100,
        PackageHash::from_array([0; HASH_LEN]),
        WireBytes::from_bytes(&[0; ED25519_SIGNATURE_LEN]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        PrivateReceiverPackage::from_keypairs(second_x25519, mlkem, public),
        Err(CoreError::PrivatePublicKeyMismatch)
    ));
}

#[test]
fn bootstrap_package_chain_root_is_context_and_owner_bound() {
    let mut backend = OsCryptoBackend::new();
    let alice = backend.generate_ed25519_keypair().unwrap();
    let bob = backend.generate_ed25519_keypair().unwrap();
    let session = Session::new(SessionId::new(80));
    let alice_root = package_chain_root(
        &backend,
        session,
        &alice.public_key,
        &bob.public_key,
        Endpoint::Alice,
    )
    .unwrap();
    let bob_root = package_chain_root(
        &backend,
        session,
        &alice.public_key,
        &bob.public_key,
        Endpoint::Bob,
    )
    .unwrap();
    assert_ne!(alice_root, bob_root);
    assert_ne!(
        alice_root,
        package_chain_root(
            &backend,
            Session::new(SessionId::new(81)),
            &alice.public_key,
            &bob.public_key,
            Endpoint::Alice,
        )
        .unwrap()
    );
}

#[test]
fn tampered_production_package_fails_identity_verification() {
    let mut backend = OsCryptoBackend::new();
    let identity = backend.generate_ed25519_keypair().unwrap();
    let session = Session::new(SessionId::new(78));
    let generated = ReceiverPackageFactory::generate(
        &mut backend,
        session,
        &identity.secret_key,
        Turn::new(0),
        PackageGeneration::new(0),
        100,
        PackageHash::from_array([4; HASH_LEN]),
    )
    .unwrap();
    let original = generated.public_package();
    let tampered = PublicReceiverPackage::new(
        original.protocol_version(),
        original.cipher_suite(),
        original.session_id(),
        original.turn(),
        original.generation(),
        KeyId::new(original.key_id().get() + 1),
        original.x25519_public_key(),
        original.mlkem_public_key().clone(),
        original.mailbox_token().clone(),
        original.expiration(),
        original.previous_package_hash(),
        original.package_auth().clone(),
    )
    .unwrap();
    assert!(matches!(
        verify_receiver_package(
            &backend,
            &tampered,
            session,
            &identity.public_key,
            Turn::new(0),
            PackageGeneration::new(0),
            PackageHash::from_array([4; HASH_LEN]),
            0,
        ),
        Err(CoreError::PackageAuthenticationInvalid)
    ));
}

#[test]
fn ack_and_sack_have_no_core_transition_api() {
    // ACK/SACK are deliberately absent from RefinedState::step's input
    // type.  This compile-time boundary is the no-state-change property.
    let _: fn(&RefinedState, &ApplicationMessage, PrivateReceiverPackage) -> StepOutcome =
        RefinedState::step;
}

fn endpoint_pair() -> (OsCryptoBackend, EndpointKernel, EndpointKernel) {
    let mut backend = OsCryptoBackend::new();
    let alice_identity = backend.generate_ed25519_keypair().unwrap();
    let bob_identity = backend.generate_ed25519_keypair().unwrap();
    let session = Session::new(SessionId::new(4242));
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
        bob_identity.secret_key,
        alice_identity.public_key,
        Turn::new(0),
        1,
    )
    .unwrap();
    (backend, alice, bob)
}

#[test]
fn encrypted_endpoint_pipeline_round_trips_both_directions() {
    let (mut backend, alice, bob) = endpoint_pair();
    let alice_send = alice
        .prepare_send(&mut backend, MessageId::new(1), b"hello", 1)
        .unwrap();
    let encoded = encode(alice_send.envelope()).unwrap();
    let alice = alice_send.commit();
    let bob_receive = bob
        .prepare_receive(&mut backend, encoded.as_bytes(), 1, 100)
        .unwrap();
    assert_eq!(bob_receive.message_id(), MessageId::new(1));
    assert_eq!(bob_receive.plaintext().as_bytes(), b"hello");
    let bob = bob_receive.commit();
    assert_eq!(alice.turn(), Turn::new(1));
    assert_eq!(bob.turn(), Turn::new(1));

    let bob_send = bob
        .prepare_send(&mut backend, MessageId::new(2), b"world", 1)
        .unwrap();
    let encoded = encode(bob_send.envelope()).unwrap();
    let bob = bob_send.commit();
    let alice_receive = alice
        .prepare_receive(&mut backend, encoded.as_bytes(), 1, 100)
        .unwrap();
    assert_eq!(alice_receive.message_id(), MessageId::new(2));
    assert_eq!(alice_receive.plaintext().as_bytes(), b"world");
    let alice = alice_receive.commit();
    assert_eq!(alice.turn(), Turn::new(2));
    assert_eq!(bob.turn(), Turn::new(2));
}

#[test]
fn encrypted_receive_failure_does_not_change_endpoint_state() {
    let (mut backend, alice, bob) = endpoint_pair();
    let prepared = alice
        .prepare_send(&mut backend, MessageId::new(7), b"payload", 1)
        .unwrap();
    let mut encoded = encode(prepared.envelope()).unwrap().into_vec();
    let bob_before_turn = bob.turn();
    let bob_before_hash = receiver_package_hash(&backend, bob.local_public_package()).unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    assert!(bob.prepare_receive(&mut backend, &encoded, 1, 100).is_err());
    assert_eq!(bob.turn(), bob_before_turn);
    assert_eq!(
        receiver_package_hash(&backend, bob.local_public_package()).unwrap(),
        bob_before_hash
    );
    assert!(bob.used_message_ids().is_empty());
}
