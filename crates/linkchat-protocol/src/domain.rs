//! Centralized domain separation labels and AAD builders.

use crate::codec::{encode_header, push_fixed_field, push_id_field, push_u8_field, push_u16_field};
use crate::errors::WireError;
use crate::foundation::TAG_CONTEXT;
use crate::wire_types::{Direction, EncodedBytes};
use linkchat_types::{CipherSuite, KeyId, MessageId, ProtocolVersion, SessionId, Turn};

pub const BOOTSTRAP: &[u8] = b"LinkChat/bootstrap/v1";
pub const HYBRID: &[u8] = b"LinkChat/hybrid/v1";
pub const MESSAGE: &[u8] = b"LinkChat/message/v1";
pub const HEADER: &[u8] = b"LinkChat/header/v1";
pub const NONCE: &[u8] = b"LinkChat/nonce/v1";
pub const HEADER_NONCE: &[u8] = b"LinkChat/header-nonce/v1";
pub const ACK: &[u8] = b"LinkChat/ack/v1";
pub const PATH: &[u8] = b"LinkChat/path/v1";
pub const PACKAGE_HASH: &[u8] = b"LinkChat/package-hash/v1";
pub const PACKAGE_CHAIN_ROOT: &[u8] = b"LinkChat/package-chain-root/v1";
pub const RECEIVER_PACKAGE_AUTH: &[u8] = b"LinkChat/receiver-package-auth/v1";
pub const TRANSCRIPT_HASH: &[u8] = b"LinkChat/transcript-hash/v1";
pub const TOKEN_MAC: &[u8] = b"LinkChat/token-mac/v1";
pub const IDENTITY_SIGNATURE: &[u8] = b"LinkChat/identity-signature/v1";
pub const MESSAGE_AD: &[u8] = b"LinkChat/message-ad/v1";
pub const HEADER_AD: &[u8] = b"LinkChat/header-ad/v1";

fn context_header(output: &mut Vec<u8>, field_count: usize) -> Result<(), WireError> {
    encode_header(output, TAG_CONTEXT, field_count)
}

#[derive(Clone, Copy)]
struct AadContext {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
}

fn aad(
    domain: &[u8],
    context: AadContext,
    message_id: Option<MessageId>,
) -> Result<EncodedBytes, WireError> {
    let fields = if message_id.is_some() { 9 } else { 8 };
    let mut output = Vec::new();
    context_header(&mut output, fields)?;
    push_fixed_field(&mut output, domain)?;
    push_u16_field(&mut output, context.protocol_version.major())?;
    push_u16_field(&mut output, context.protocol_version.minor())?;
    push_u16_field(&mut output, context.cipher_suite.id())?;
    push_id_field(&mut output, context.session_id.get())?;
    push_id_field(&mut output, context.turn.get())?;
    push_u8_field(&mut output, context.direction as u8)?;
    if let Some(message_id) = message_id {
        push_id_field(&mut output, message_id.get())?;
    }
    push_id_field(&mut output, context.receiver_key_id.get())?;
    Ok(EncodedBytes(output))
}

fn nonce_context(
    domain: &[u8],
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    message_id: MessageId,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    let mut output = Vec::new();
    context_header(&mut output, 6)?;
    push_fixed_field(&mut output, domain)?;
    push_id_field(&mut output, session_id.get())?;
    push_id_field(&mut output, turn.get())?;
    push_u8_field(&mut output, direction as u8)?;
    push_id_field(&mut output, message_id.get())?;
    push_id_field(&mut output, receiver_key_id.get())?;
    Ok(EncodedBytes(output))
}

fn context(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
) -> AadContext {
    AadContext {
        protocol_version,
        cipher_suite,
        session_id,
        turn,
        direction,
        receiver_key_id,
    }
}

pub fn message_aad(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    message_id: MessageId,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    aad(
        MESSAGE_AD,
        context(
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            receiver_key_id,
        ),
        Some(message_id),
    )
}

pub fn header_aad(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    aad(
        HEADER_AD,
        context(
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            receiver_key_id,
        ),
        None,
    )
}

pub fn header_info(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    aad(
        HEADER,
        context(
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            receiver_key_id,
        ),
        None,
    )
}

pub fn message_info(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    message_id: MessageId,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    aad(
        MESSAGE,
        context(
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            receiver_key_id,
        ),
        Some(message_id),
    )
}

/// Canonical context for message nonce derivation.
pub fn nonce_info(
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    message_id: MessageId,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    nonce_context(
        NONCE,
        session_id,
        turn,
        direction,
        message_id,
        receiver_key_id,
    )
}

/// Canonical context for header nonce derivation.
pub fn header_nonce_info(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
) -> Result<EncodedBytes, WireError> {
    aad(
        HEADER_NONCE,
        context(
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            receiver_key_id,
        ),
        None,
    )
}

/// Canonical HybridInput for the v1.0 KEM composition.
#[allow(clippy::too_many_arguments)]
pub fn hybrid_info(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    receiver_key_id: KeyId,
    x25519_ciphertext: &[u8],
    mlkem_ciphertext: &[u8],
    classical_shared_secret: &[u8],
    pq_shared_secret: &[u8],
) -> Result<EncodedBytes, WireError> {
    let mut output = Vec::new();
    context_header(&mut output, 11)?;
    push_fixed_field(&mut output, HYBRID)?;
    push_u16_field(&mut output, protocol_version.major())?;
    push_u16_field(&mut output, protocol_version.minor())?;
    push_u16_field(&mut output, cipher_suite.id())?;
    push_id_field(&mut output, session_id.get())?;
    push_id_field(&mut output, turn.get())?;
    push_id_field(&mut output, receiver_key_id.get())?;
    push_fixed_field(&mut output, x25519_ciphertext)?;
    push_fixed_field(&mut output, mlkem_ciphertext)?;
    push_fixed_field(&mut output, classical_shared_secret)?;
    push_fixed_field(&mut output, pq_shared_secret)?;
    Ok(EncodedBytes(output))
}

/// Canonical bootstrap input for a per-owner Receiver Package chain root.
///
/// Identity keys are passed as fixed-length byte strings at this protocol
/// boundary so `linkchat-protocol` remains independent of `linkchat-crypto`.
pub fn package_chain_root_info(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    alice_identity_public_key: &[u8],
    bob_identity_public_key: &[u8],
    owner: Direction,
) -> Result<EncodedBytes, WireError> {
    let mut output = Vec::new();
    context_header(&mut output, 8)?;
    push_fixed_field(&mut output, PACKAGE_CHAIN_ROOT)?;
    push_u16_field(&mut output, protocol_version.major())?;
    push_u16_field(&mut output, protocol_version.minor())?;
    push_u16_field(&mut output, cipher_suite.id())?;
    push_id_field(&mut output, session_id.get())?;
    push_fixed_field(&mut output, alice_identity_public_key)?;
    push_fixed_field(&mut output, bob_identity_public_key)?;
    push_u8_field(&mut output, owner as u8)?;
    Ok(EncodedBytes(output))
}
