use crate::commands::{keygen, run, test_vector};
use crate::encoding::{hex_decode, hex_encode};
use linkchat_protocol::decode_application_message;

#[test]
fn keygen_outputs_public_material_only() {
    let output = keygen().unwrap();
    assert!(output.contains("ed25519_public_key="));
    assert!(output.contains("x25519_public_key="));
    assert!(output.contains("mlkem_public_key="));
    assert!(!output.contains("secret"));
    assert!(!output.contains("private"));
}

#[test]
fn manifest_is_available_to_the_cli() {
    let output = test_vector(&["test-vector".to_string()]).unwrap();
    assert!(output.contains("vector_manifest_rows=12"));
}

#[test]
fn hex_codec_round_trips() {
    let bytes = [0x00, 0x01, 0xab, 0xff];
    assert_eq!(
        hex_decode("test", &hex_encode(&bytes), None).unwrap(),
        bytes
    );
}

#[test]
fn message_encode_command_uses_all_wire_arguments() {
    let args = vec![
        "encode".to_string(),
        "message".to_string(),
        "9".to_string(),
        "0".to_string(),
        "alice".to_string(),
        "1".to_string(),
        "20".to_string(),
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        "0102".to_string(),
    ];
    let encoded = run(&args).unwrap();
    let decoded =
        decode_application_message(&hex_decode("encoded", encoded.trim(), None).unwrap()).unwrap();
    assert_eq!(decoded.session_id().get(), 9);
    assert_eq!(decoded.turn().get(), 0);
    assert_eq!(decoded.message_id().get(), 1);
    assert_eq!(decoded.payload().as_bytes(), [1, 2]);
}
