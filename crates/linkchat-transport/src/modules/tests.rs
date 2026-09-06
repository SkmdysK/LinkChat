use crate::{
    AckFrame, AdversarialTransportHarness, AdversaryEndpoint, AttackKind, ControlFrame,
    InMemoryTransport, PacketBytes, RetryMetadata, SackFrame, Transport, TransportTimestamp,
};
use linkchat_core::{PrivateReceiverPackage, PublicReceiverPackage, RefinedState, Session};
use linkchat_protocol::DeliveryStatus;
use linkchat_protocol::{ED25519_SIGNATURE_LEN, ML_KEM_768_PUBLIC_KEY_LEN, WireBytes};
use linkchat_types::{
    CipherSuite, HASH_LEN, KeyId, MAILBOX_TOKEN_LEN, PackageGeneration, PackageHash,
    ProtocolVersion, SessionId, Turn, X25519_PUBLIC_KEY_LEN, X25519PublicKey,
};

fn packet(byte: u8) -> PacketBytes {
    PacketBytes::from_bytes(&[byte; 4]).unwrap()
}

fn package(byte: u8) -> PrivateReceiverPackage {
    let public = PublicReceiverPackage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(41),
        Turn::new(0),
        PackageGeneration::new(0),
        KeyId::new(byte as u64),
        X25519PublicKey::from_array([byte; X25519_PUBLIC_KEY_LEN]),
        WireBytes::from_vec(vec![byte; ML_KEM_768_PUBLIC_KEY_LEN]).unwrap(),
        linkchat_types::MailboxToken::from_array([byte; MAILBOX_TOKEN_LEN]),
        0,
        PackageHash::from_array([byte; HASH_LEN]),
        WireBytes::from_vec(vec![byte; ED25519_SIGNATURE_LEN]).unwrap(),
    )
    .unwrap();
    PrivateReceiverPackage::for_testing(public).unwrap()
}

#[test]
fn in_memory_transport_carries_metadata_without_core_state() {
    let mut transport = InMemoryTransport::new();
    transport.send(packet(1)).unwrap();
    let event = transport.receive().unwrap().unwrap();
    assert_eq!(event.delivery_status(), DeliveryStatus::Accepted);
    assert_eq!(event.retry(), RetryMetadata::default());
    assert_eq!(event.timestamp(), TransportTimestamp::default());
}

#[test]
fn control_frames_are_separate_and_canonical() {
    let ack = AckFrame::new(
        linkchat_types::ProtocolVersion::V1_0,
        linkchat_types::CipherSuite::current(),
        linkchat_types::SessionId::new(1),
        linkchat_types::Turn::new(0),
        linkchat_protocol::Direction::Alice,
        linkchat_types::MessageId::new(3),
        DeliveryStatus::Accepted,
    );
    let packet = ControlFrame::Ack(ack).encode_canonical().unwrap();
    let decoded = ControlFrame::decode_canonical(packet.as_bytes()).unwrap();
    assert!(decoded.is_ack());
    assert!(!decoded.is_sack());
    assert!(ControlFrame::decode_canonical(b"invalid").is_err());
}

#[test]
fn transport_event_control_decode_does_not_become_application_state() {
    let ack = AckFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(2),
        Turn::new(0),
        linkchat_protocol::Direction::Alice,
        linkchat_types::MessageId::new(4),
        DeliveryStatus::Accepted,
    );
    let packet = ControlFrame::Ack(ack).encode_canonical().unwrap();
    let event = crate::TransportEvent::new(
        packet,
        DeliveryStatus::Accepted,
        TransportTimestamp::default(),
        RetryMetadata::default(),
    );
    assert!(event.decode_control().unwrap().is_ack());
    assert!(!event.decode_control().unwrap().is_sack());
}

#[test]
fn ack_and_sack_delivery_do_not_change_core_public_snapshot() {
    let state =
        RefinedState::new(Session::new(SessionId::new(41)), package(1), package(2)).unwrap();
    let before = state.public_snapshot();
    let ack = AckFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(41),
        Turn::new(0),
        linkchat_protocol::Direction::Alice,
        linkchat_types::MessageId::new(3),
        DeliveryStatus::Accepted,
    );
    let sack = SackFrame::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(41),
        Turn::new(0),
        linkchat_protocol::Direction::Alice,
        linkchat_types::MessageId::new(3),
        WireBytes::from_bytes(&[0xaa]).unwrap(),
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
}

#[test]
fn adversarial_harness_supports_drop_delay_duplicate_and_reorder() {
    let mut harness = AdversarialTransportHarness::new();
    harness.plan_drop();
    harness.send(packet(1)).unwrap();
    assert!(harness.receive().unwrap().is_none());

    harness.plan_delay(5);
    harness.send(packet(2)).unwrap();
    assert!(harness.receive().unwrap().is_none());
    harness.advance_time(5).unwrap();
    assert_eq!(harness.receive().unwrap().unwrap().packet(), &packet(2));

    harness.plan_duplicate(2);
    harness.send(packet(3)).unwrap();
    assert_eq!(harness.receive().unwrap().unwrap().packet(), &packet(3));
    assert!(
        harness
            .receive()
            .unwrap()
            .unwrap()
            .retry()
            .is_retransmission()
    );

    harness.plan_reorder();
    harness.send(packet(4)).unwrap();
    harness.send(packet(5)).unwrap();
    assert_eq!(harness.receive().unwrap().unwrap().packet(), &packet(5));
    assert_eq!(harness.receive().unwrap().unwrap().packet(), &packet(4));
}

#[test]
fn malicious_input_labels_are_transport_observations_only() {
    let mut harness = AdversarialTransportHarness::new();
    harness.inject_malformed_packet(&[0xff, 0x00]).unwrap();
    harness.inject_invalid_ack(&[0x01]).unwrap();
    harness.inject_invalid_sack(&[0x02]).unwrap();
    harness.replay_old_package(packet(7)).unwrap();
    harness.attempt_rollback(packet(6)).unwrap();
    harness
        .inject_malicious_endpoint(AdversaryEndpoint::Alice, packet(8))
        .unwrap();
    let observations = harness.observations();
    assert!(
        observations
            .iter()
            .any(|x| x.kind() == AttackKind::MalformedPacket)
    );
    assert!(
        observations
            .iter()
            .any(|x| x.kind() == AttackKind::InvalidAck)
    );
    assert!(
        observations
            .iter()
            .any(|x| x.kind() == AttackKind::InvalidSack)
    );
    assert!(
        observations
            .iter()
            .any(|x| x.kind() == AttackKind::OldPackageReplay)
    );
    assert!(
        observations
            .iter()
            .any(|x| x.kind() == AttackKind::RollbackAttempt)
    );
    assert!(observations.iter().any(|x| {
        x.kind() == AttackKind::MaliciousEndpoint && x.endpoint() == Some(AdversaryEndpoint::Alice)
    }));
}
