/// Application-level input to the pure state machine.
#[derive(Clone, PartialEq, Eq)]
pub struct ApplicationMessage {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_id: SessionId,
    pub(crate) turn: Turn,
    pub(crate) direction: Endpoint,
    pub(crate) message_id: MessageId,
    pub(crate) receiver_key_id: KeyId,
    pub(crate) receiver_token: MailboxToken,
    pub(crate) payload: WireBytes,
}

impl ApplicationMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        direction: Endpoint,
        message_id: MessageId,
        receiver_key_id: KeyId,
        receiver_token: MailboxToken,
        payload: WireBytes,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            message_id,
            receiver_key_id,
            receiver_token,
            payload,
        }
    }

    pub fn from_wire(message: &WireApplicationMessage) -> Self {
        Self::new(
            message.protocol_version(),
            message.cipher_suite(),
            message.session_id(),
            message.turn(),
            Endpoint::from_direction(message.direction()),
            message.message_id(),
            message.receiver_key_id(),
            message.receiver_token().clone(),
            message.payload().clone(),
        )
    }

    pub fn to_wire(&self) -> WireApplicationMessage {
        WireApplicationMessage::new(
            self.protocol_version,
            self.cipher_suite,
            self.session_id,
            self.turn,
            self.direction.direction(),
            self.message_id,
            self.receiver_key_id,
            self.receiver_token.clone(),
            self.payload.clone(),
        )
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn turn(&self) -> Turn {
        self.turn
    }

    pub const fn direction(&self) -> Endpoint {
        self.direction
    }

    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub const fn receiver_key_id(&self) -> KeyId {
        self.receiver_key_id
    }

    pub fn receiver_token(&self) -> &MailboxToken {
        &self.receiver_token
    }

    pub fn payload(&self) -> &WireBytes {
        &self.payload
    }
}
use crate::Endpoint;
use linkchat_protocol::{WireApplicationMessage, WireBytes};
use linkchat_types::{
    CipherSuite, KeyId, MailboxToken, MessageId, ProtocolVersion, SessionId, Turn,
};
