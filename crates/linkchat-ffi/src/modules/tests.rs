use crate::{
    LC_ERR_BUFFER_TOO_SMALL, LC_ERR_CRYPTO, LC_ERR_INVALID_HANDLE, LC_ERR_NULL_POINTER,
    LC_ERR_REJECTED, LC_ERR_WIRE, LC_OK, LinkChatEndpointMetadata, LinkChatPackageMetadata,
    LinkChatReceiveMetadata, linkchat_bootstrap_create, linkchat_bootstrap_destroy,
    linkchat_bootstrap_identity_write, linkchat_bootstrap_package_encoded_len,
    linkchat_bootstrap_package_write, linkchat_endpoint_create,
    linkchat_endpoint_create_from_bootstrap, linkchat_endpoint_destroy, linkchat_endpoint_metadata,
    linkchat_endpoint_package_encoded_len, linkchat_endpoint_package_write,
    linkchat_endpoint_receive_commit, linkchat_endpoint_receive_prepare, linkchat_endpoint_recover,
    linkchat_endpoint_send_commit, linkchat_endpoint_send_prepare, linkchat_package_destroy,
    linkchat_package_encoded_len, linkchat_package_metadata, linkchat_package_open,
    linkchat_package_write, linkchat_session_create, linkchat_session_destroy, linkchat_session_id,
};
use linkchat_core::{
    Endpoint, PrivateReceiverPackage, PublicReceiverPackage, ReceiverPackageFactory, Session,
};
use linkchat_crypto::{CryptoBackend, Ed25519KeyPair, OsCryptoBackend};
use linkchat_engine::{EndpointConfig, EndpointEngine, MemoryEndpointStorage};
use linkchat_protocol::{
    ED25519_SIGNATURE_LEN, ML_KEM_768_PUBLIC_KEY_LEN, WireBytes, WireReceiverPackage, encode,
};
use linkchat_types::{
    CipherSuite, KeyId, MAILBOX_TOKEN_LEN, MessageId, PackageGeneration, PackageHash,
    ProtocolVersion, SessionId, Turn, X25519PublicKey,
};

fn generated_package(session_id: u64) -> (Ed25519KeyPair, PrivateReceiverPackage, Vec<u8>) {
    let mut backend = OsCryptoBackend::new();
    let identity = backend.generate_ed25519_keypair().unwrap();
    let package = ReceiverPackageFactory::generate(
        &mut backend,
        Session::new(SessionId::new(session_id)),
        &identity.secret_key,
        Turn::new(0),
        PackageGeneration::new(0),
        100,
        PackageHash::from_array([0; 32]),
    )
    .unwrap();
    let bytes = encode(&package.public_projection().to_wire().unwrap())
        .unwrap()
        .into_vec();
    (identity, package, bytes)
}

fn create_ffi_endpoint(
    session_id: u64,
    endpoint: u8,
    peer_identity: [u8; 32],
    peer_package: &[u8],
) -> u64 {
    let mut handle = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_create(
                session_id,
                endpoint,
                peer_identity.as_ptr(),
                [0; 32].as_ptr(),
                peer_package.as_ptr(),
                peer_package.len(),
                100,
                1,
                &mut handle,
            )
        },
        LC_OK
    );
    handle
}

fn export_bootstrap(session_id: u64, endpoint: u8) -> (u64, [u8; 32], Vec<u8>) {
    let mut bootstrap = 0;
    assert_eq!(
        unsafe {
            linkchat_bootstrap_create(
                session_id,
                endpoint,
                [0; 32].as_ptr(),
                100,
                1,
                &mut bootstrap,
            )
        },
        LC_OK
    );
    let mut identity = [0; 32];
    let mut identity_written = 0;
    assert_eq!(
        unsafe {
            linkchat_bootstrap_identity_write(
                bootstrap,
                identity.as_mut_ptr(),
                identity.len(),
                &mut identity_written,
            )
        },
        LC_OK
    );
    assert_eq!(identity_written, identity.len());

    let mut package_len = 0;
    assert_eq!(
        unsafe { linkchat_bootstrap_package_encoded_len(bootstrap, &mut package_len) },
        LC_OK
    );
    let mut package = vec![0; package_len];
    let mut package_written = 0;
    assert_eq!(
        unsafe {
            linkchat_bootstrap_package_write(
                bootstrap,
                package.as_mut_ptr(),
                package.len(),
                &mut package_written,
            )
        },
        LC_OK
    );
    assert_eq!(package_written, package_len);
    (bootstrap, identity, package)
}

fn package_bytes() -> Vec<u8> {
    let package = WireReceiverPackage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(77),
        Turn::new(0),
        PackageGeneration::new(0),
        KeyId::new(9),
        X25519PublicKey::from_array([3; 32]),
        WireBytes::from_vec(vec![4; ML_KEM_768_PUBLIC_KEY_LEN]).unwrap(),
        linkchat_types::MailboxToken::from_array([5; MAILBOX_TOKEN_LEN]),
        123,
        PackageHash::from_array([6; 32]),
        WireBytes::from_vec(vec![7; ED25519_SIGNATURE_LEN]).unwrap(),
    )
    .unwrap();
    encode(&package).unwrap().into_vec()
}

#[test]
fn lifecycle_and_wrong_handle_kind_are_stable() {
    let mut handle = 0;
    assert_eq!(unsafe { linkchat_session_create(42, &mut handle) }, LC_OK);
    let mut session_id = 0;
    assert_eq!(
        unsafe { linkchat_session_id(handle, &mut session_id) },
        LC_OK
    );
    assert_eq!(session_id, 42);
    assert_eq!(
        unsafe { linkchat_package_destroy(handle) },
        LC_ERR_INVALID_HANDLE
    );
    assert_eq!(unsafe { linkchat_session_destroy(handle) }, LC_OK);
    assert_eq!(
        unsafe { linkchat_session_destroy(handle) },
        LC_ERR_INVALID_HANDLE
    );
    assert_eq!(
        unsafe { linkchat_session_create(42, std::ptr::null_mut()) },
        LC_ERR_NULL_POINTER
    );
}

#[test]
fn malformed_input_does_not_create_a_package_handle() {
    let malformed = b"not-a-package";
    let mut handle = 0;
    assert_eq!(
        unsafe { linkchat_package_open(malformed.as_ptr(), malformed.len(), &mut handle) },
        LC_ERR_WIRE
    );
    assert_eq!(
        unsafe { linkchat_package_destroy(handle) },
        LC_ERR_INVALID_HANDLE
    );
    assert_eq!(
        unsafe { linkchat_package_open(std::ptr::null(), malformed.len(), &mut handle) },
        LC_ERR_NULL_POINTER
    );
}

#[test]
fn output_buffer_is_queryable_and_never_partially_written() {
    let bytes = package_bytes();
    let mut handle = 0;
    assert_eq!(
        unsafe { linkchat_package_open(bytes.as_ptr(), bytes.len(), &mut handle) },
        LC_OK
    );

    let mut required = 0;
    assert_eq!(
        unsafe { linkchat_package_encoded_len(handle, &mut required) },
        LC_OK
    );
    assert_eq!(required, bytes.len());

    let mut short = vec![0xa5; required - 1];
    let mut written = 0;
    assert_eq!(
        unsafe { linkchat_package_write(handle, short.as_mut_ptr(), short.len(), &mut written) },
        LC_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(written, required);
    assert!(short.iter().all(|byte| *byte == 0xa5));

    let mut output = vec![0; required];
    assert_eq!(
        unsafe { linkchat_package_write(handle, output.as_mut_ptr(), output.len(), &mut written) },
        LC_OK
    );
    assert_eq!(written, required);
    assert_eq!(output, bytes);

    let mut metadata = LinkChatPackageMetadata {
        protocol_major: 0,
        protocol_minor: 0,
        cipher_suite: 0,
        session_id: 0,
        turn: 0,
        generation: 0,
        key_id: 0,
        expiration: 0,
        x25519_public_key: [0; 32],
        mlkem_public_key_len: 0,
        package_auth_len: 0,
    };
    assert_eq!(
        unsafe { linkchat_package_metadata(handle, &mut metadata) },
        LC_OK
    );
    assert_eq!(metadata.session_id, 77);
    assert_eq!(
        metadata.mlkem_public_key_len,
        ML_KEM_768_PUBLIC_KEY_LEN as u32
    );
    assert_eq!(metadata.package_auth_len, ED25519_SIGNATURE_LEN as u32);
    assert_eq!(unsafe { linkchat_package_destroy(handle) }, LC_OK);
}

#[test]
fn endpoint_metadata_and_public_package_export_are_secret_free() {
    let (peer_identity, _, peer_bytes) = generated_package(801);
    let handle = create_ffi_endpoint(801, 0, peer_identity.public_key.into_array(), &peer_bytes);

    let mut metadata = LinkChatEndpointMetadata {
        session_id: 0,
        endpoint: 0,
        reserved: [0; 7],
        turn: 0,
        consumed_message_count: 0,
        local_identity_public: [0; 32],
        peer_identity_public: [0; 32],
        local_generation: 0,
        local_key_id: 0,
        local_expiration: 0,
        local_x25519_public_key: [0; 32],
        local_mlkem_public_key_len: 0,
        local_package_auth_len: 0,
        peer_generation: 0,
        peer_key_id: 0,
        peer_expiration: 0,
        peer_x25519_public_key: [0; 32],
        peer_mlkem_public_key_len: 0,
        peer_package_auth_len: 0,
    };
    assert_eq!(
        unsafe { linkchat_endpoint_metadata(handle, &mut metadata) },
        LC_OK
    );
    assert_eq!(metadata.session_id, 801);
    assert_eq!(metadata.endpoint, 0);
    assert_eq!(
        metadata.peer_identity_public,
        peer_identity.public_key.into_array()
    );
    assert_ne!(metadata.local_identity_public, [0; 32]);
    assert_eq!(
        metadata.local_mlkem_public_key_len,
        ML_KEM_768_PUBLIC_KEY_LEN as u32
    );
    assert_eq!(
        metadata.local_package_auth_len,
        ED25519_SIGNATURE_LEN as u32
    );

    let mut required = 0;
    assert_eq!(
        unsafe { linkchat_endpoint_package_encoded_len(handle, &mut required) },
        LC_OK
    );
    let mut short = vec![0xa5; required.saturating_sub(1)];
    let mut written = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_package_write(handle, short.as_mut_ptr(), short.len(), &mut written)
        },
        LC_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(written, required);
    assert!(short.iter().all(|byte| *byte == 0xa5));

    assert_eq!(unsafe { linkchat_endpoint_recover(handle) }, LC_OK);
    assert_eq!(unsafe { linkchat_endpoint_destroy(handle) }, LC_OK);
    assert_eq!(
        unsafe { linkchat_endpoint_recover(handle) },
        LC_ERR_INVALID_HANDLE
    );
}

#[test]
fn endpoint_rejects_wrong_peer_identity_without_creating_handle() {
    let (_, _, peer_bytes) = generated_package(802);
    let mut handle = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_create(
                802,
                0,
                [0; 32].as_ptr(),
                [0; 32].as_ptr(),
                peer_bytes.as_ptr(),
                peer_bytes.len(),
                100,
                1,
                &mut handle,
            )
        },
        LC_ERR_CRYPTO
    );
    assert_eq!(
        unsafe { linkchat_endpoint_destroy(handle) },
        LC_ERR_INVALID_HANDLE
    );
}

#[test]
fn short_send_output_does_not_create_prepare_or_advance_turn() {
    let (peer_identity, _, peer_bytes) = generated_package(803);
    let handle = create_ffi_endpoint(803, 0, peer_identity.public_key.into_array(), &peer_bytes);
    let mut before = LinkChatEndpointMetadata {
        session_id: 0,
        endpoint: 0,
        reserved: [0; 7],
        turn: 0,
        consumed_message_count: 0,
        local_identity_public: [0; 32],
        peer_identity_public: [0; 32],
        local_generation: 0,
        local_key_id: 0,
        local_expiration: 0,
        local_x25519_public_key: [0; 32],
        local_mlkem_public_key_len: 0,
        local_package_auth_len: 0,
        peer_generation: 0,
        peer_key_id: 0,
        peer_expiration: 0,
        peer_x25519_public_key: [0; 32],
        peer_mlkem_public_key_len: 0,
        peer_package_auth_len: 0,
    };
    assert_eq!(
        unsafe { linkchat_endpoint_metadata(handle, &mut before) },
        LC_OK
    );

    let mut short = vec![0xa5; 8];
    let mut written = 0;
    let mut prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_send_prepare(
                handle,
                1,
                b"hello".as_ptr(),
                5,
                1,
                short.as_mut_ptr(),
                short.len(),
                &mut written,
                &mut prepare,
            )
        },
        LC_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(written, 4096);
    assert_eq!(prepare, 0);
    assert!(short.iter().all(|byte| *byte == 0xa5));

    let mut after = before;
    assert_eq!(
        unsafe { linkchat_endpoint_metadata(handle, &mut after) },
        LC_OK
    );
    assert_eq!(after.turn, before.turn);
    assert_eq!(
        unsafe { linkchat_endpoint_send_commit(prepare) },
        LC_ERR_INVALID_HANDLE
    );
    assert_eq!(unsafe { linkchat_endpoint_destroy(handle) }, LC_OK);
}

#[test]
fn ffi_receive_commit_is_atomic_across_output_sizing_and_replay() {
    let session_id = 804;
    let (alice_identity, alice_package, alice_bytes) = generated_package(session_id);
    let bob_handle = create_ffi_endpoint(
        session_id,
        1,
        alice_identity.public_key.into_array(),
        &alice_bytes,
    );

    let mut bob_metadata = LinkChatEndpointMetadata {
        session_id: 0,
        endpoint: 0,
        reserved: [0; 7],
        turn: 0,
        consumed_message_count: 0,
        local_identity_public: [0; 32],
        peer_identity_public: [0; 32],
        local_generation: 0,
        local_key_id: 0,
        local_expiration: 0,
        local_x25519_public_key: [0; 32],
        local_mlkem_public_key_len: 0,
        local_package_auth_len: 0,
        peer_generation: 0,
        peer_key_id: 0,
        peer_expiration: 0,
        peer_x25519_public_key: [0; 32],
        peer_mlkem_public_key_len: 0,
        peer_package_auth_len: 0,
    };
    assert_eq!(
        unsafe { linkchat_endpoint_metadata(bob_handle, &mut bob_metadata) },
        LC_OK
    );

    let mut bob_package_len = 0;
    assert_eq!(
        unsafe { linkchat_endpoint_package_encoded_len(bob_handle, &mut bob_package_len) },
        LC_OK
    );
    let mut bob_package_bytes = vec![0; bob_package_len];
    let mut bob_package_written = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_package_write(
                bob_handle,
                bob_package_bytes.as_mut_ptr(),
                bob_package_bytes.len(),
                &mut bob_package_written,
            )
        },
        LC_OK
    );
    let bob_wire = crate::helpers::canonical_package(&bob_package_bytes).unwrap();
    let bob_package = PublicReceiverPackage::from_wire(&bob_wire).unwrap();
    let alice_config = EndpointConfig::new(
        Session::new(SessionId::new(session_id)),
        Endpoint::Alice,
        alice_identity.secret_key,
        alice_identity.public_key,
        linkchat_crypto::Ed25519PublicKey::from_array(bob_metadata.local_identity_public),
        PackageHash::from_array([0; 32]),
        100,
        1,
    );
    let mut alice = EndpointEngine::create_with_local_package(
        OsCryptoBackend::new(),
        MemoryEndpointStorage::empty(),
        alice_config,
        alice_package,
        bob_package,
    )
    .unwrap();
    let prepared = alice.prepare_send(MessageId::new(17), b"hello", 1).unwrap();
    let envelope = prepared.encoded().clone();
    alice.commit_send(prepared).unwrap();

    let mut receive_prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_prepare(
                bob_handle,
                envelope.as_bytes().as_ptr(),
                envelope.as_bytes().len(),
                1,
                100,
                &mut receive_prepare,
            )
        },
        LC_OK
    );

    let mut payload_out = vec![0xa5; 2];
    let mut package_out = vec![0xa5; 2];
    let mut payload_written = 0;
    let mut package_written = 0;
    let mut receive_metadata = LinkChatReceiveMetadata {
        message_id: 99,
        payload_len: 99,
        returned_package_len: 99,
    };
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_commit(
                receive_prepare,
                payload_out.as_mut_ptr(),
                payload_out.len(),
                &mut payload_written,
                package_out.as_mut_ptr(),
                package_out.len(),
                &mut package_written,
                &mut receive_metadata,
            )
        },
        LC_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(payload_written, 5);
    assert!(package_written > package_out.len());
    assert!(payload_out.iter().all(|byte| *byte == 0xa5));
    assert!(package_out.iter().all(|byte| *byte == 0xa5));
    assert_eq!(receive_metadata.message_id, 99);

    let mut payload_out = vec![0; payload_written];
    let mut package_out = vec![0; package_written];
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_commit(
                receive_prepare,
                payload_out.as_mut_ptr(),
                payload_out.len(),
                &mut payload_written,
                package_out.as_mut_ptr(),
                package_out.len(),
                &mut package_written,
                &mut receive_metadata,
            )
        },
        LC_OK
    );
    assert_eq!(payload_out, b"hello");
    assert_eq!(receive_metadata.message_id, 17);

    let mut replay_prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_prepare(
                bob_handle,
                envelope.as_bytes().as_ptr(),
                envelope.as_bytes().len(),
                1,
                100,
                &mut replay_prepare,
            )
        },
        LC_ERR_REJECTED
    );
    let mut after = bob_metadata;
    assert_eq!(
        unsafe { linkchat_endpoint_metadata(bob_handle, &mut after) },
        LC_OK
    );
    assert_eq!(after.turn, 1);
    assert_eq!(after.consumed_message_count, 1);
    assert_eq!(unsafe { linkchat_endpoint_destroy(bob_handle) }, LC_OK);
}

#[test]
fn endpoint_destroy_removes_pending_prepare_handles() {
    let (peer_identity, _, peer_bytes) = generated_package(805);
    let endpoint = create_ffi_endpoint(805, 0, peer_identity.public_key.into_array(), &peer_bytes);
    let mut output = vec![0; 4096];
    let mut written = 0;
    let mut prepared = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_send_prepare(
                endpoint,
                1,
                b"x".as_ptr(),
                1,
                1,
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                &mut prepared,
            )
        },
        LC_OK
    );
    assert_ne!(prepared, 0);
    assert_eq!(unsafe { linkchat_endpoint_destroy(endpoint) }, LC_OK);
    assert_eq!(
        unsafe { linkchat_endpoint_send_commit(prepared) },
        LC_ERR_INVALID_HANDLE
    );
}

#[test]
fn two_ffi_endpoints_bootstrap_and_exchange_both_directions() {
    let session_id = 806;
    let (alice_bootstrap, alice_identity, alice_package) = export_bootstrap(session_id, 0);
    let (bob_bootstrap, bob_identity, bob_package) = export_bootstrap(session_id, 1);

    let mut alice = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_create_from_bootstrap(
                alice_bootstrap,
                bob_identity.as_ptr(),
                bob_package.as_ptr(),
                bob_package.len(),
                &mut alice,
            )
        },
        LC_OK
    );
    let mut bob = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_create_from_bootstrap(
                bob_bootstrap,
                alice_identity.as_ptr(),
                alice_package.as_ptr(),
                alice_package.len(),
                &mut bob,
            )
        },
        LC_OK
    );
    assert_eq!(
        unsafe { linkchat_bootstrap_destroy(alice_bootstrap) },
        LC_ERR_INVALID_HANDLE
    );
    assert_eq!(
        unsafe { linkchat_bootstrap_destroy(bob_bootstrap) },
        LC_ERR_INVALID_HANDLE
    );

    let mut envelope = vec![0; 4096];
    let mut envelope_written = 0;
    let mut send_prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_send_prepare(
                alice,
                1,
                b"hello".as_ptr(),
                5,
                1,
                envelope.as_mut_ptr(),
                envelope.len(),
                &mut envelope_written,
                &mut send_prepare,
            )
        },
        LC_OK
    );
    assert_eq!(envelope_written, 4096);
    assert_eq!(
        unsafe { linkchat_endpoint_send_commit(send_prepare) },
        LC_OK
    );

    let mut receive_prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_prepare(
                bob,
                envelope.as_ptr(),
                envelope.len(),
                1,
                100,
                &mut receive_prepare,
            )
        },
        LC_OK
    );
    let mut payload_out = vec![0xa5; 1];
    let mut package_out = vec![0xa5; 1];
    let mut payload_written = 0;
    let mut package_written = 0;
    let mut metadata = LinkChatReceiveMetadata {
        message_id: 99,
        payload_len: 99,
        returned_package_len: 99,
    };
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_commit(
                receive_prepare,
                payload_out.as_mut_ptr(),
                payload_out.len(),
                &mut payload_written,
                package_out.as_mut_ptr(),
                package_out.len(),
                &mut package_written,
                &mut metadata,
            )
        },
        LC_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(metadata.message_id, 99);
    assert!(payload_written > payload_out.len());
    assert!(package_written > package_out.len());
    assert!(payload_out.iter().all(|byte| *byte == 0xa5));
    assert!(package_out.iter().all(|byte| *byte == 0xa5));

    payload_out.resize(payload_written, 0);
    package_out.resize(package_written, 0);
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_commit(
                receive_prepare,
                payload_out.as_mut_ptr(),
                payload_out.len(),
                &mut payload_written,
                package_out.as_mut_ptr(),
                package_out.len(),
                &mut package_written,
                &mut metadata,
            )
        },
        LC_OK
    );
    assert_eq!(&payload_out[..5], b"hello");
    assert_eq!(metadata.message_id, 1);

    let mut bob_envelope = vec![0; 4096];
    let mut bob_envelope_written = 0;
    let mut bob_send_prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_send_prepare(
                bob,
                2,
                b"world".as_ptr(),
                5,
                1,
                bob_envelope.as_mut_ptr(),
                bob_envelope.len(),
                &mut bob_envelope_written,
                &mut bob_send_prepare,
            )
        },
        LC_OK
    );
    assert_eq!(
        unsafe { linkchat_endpoint_send_commit(bob_send_prepare) },
        LC_OK
    );

    let mut alice_receive_prepare = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_prepare(
                alice,
                bob_envelope.as_ptr(),
                bob_envelope.len(),
                1,
                100,
                &mut alice_receive_prepare,
            )
        },
        LC_OK
    );
    let mut alice_payload = vec![0; 5];
    let mut alice_package = vec![0; 2048];
    let mut alice_payload_written = 0;
    let mut alice_package_written = 0;
    assert_eq!(
        unsafe {
            linkchat_endpoint_receive_commit(
                alice_receive_prepare,
                alice_payload.as_mut_ptr(),
                alice_payload.len(),
                &mut alice_payload_written,
                alice_package.as_mut_ptr(),
                alice_package.len(),
                &mut alice_package_written,
                &mut metadata,
            )
        },
        LC_OK
    );
    assert_eq!(&alice_payload[..5], b"world");
    assert_eq!(metadata.message_id, 2);

    assert_eq!(unsafe { linkchat_endpoint_destroy(alice) }, LC_OK);
    assert_eq!(unsafe { linkchat_endpoint_destroy(bob) }, LC_OK);
}
