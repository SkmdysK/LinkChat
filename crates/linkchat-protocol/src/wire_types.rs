use crate::codec::{
    encode_header_with_version, finish, push_fixed_field, push_id_field, push_u16_field,
    push_u64_field,
};
use crate::errors::WireError;
use crate::foundation::{
    CIPHERTEXT_LEN, ED25519_SIGNATURE_LEN, ENCRYPTED_HEADER_LEN, FIELD_LENGTH_LEN, MAX_FIELD_LEN,
    ML_KEM_768_PUBLIC_KEY_LEN, OBJECT_HEADER_LEN, TAG_RECEIVER_PACKAGE,
};
use linkchat_types::{
    CipherSuite, KeyId, MAILBOX_TOKEN_LEN, MAX_ENVELOPE_SIZE, ML_KEM_768_CIPHERTEXT_LEN,
    MailboxToken, MessageId, PackageGeneration, PackageHash, ProtocolVersion, SessionId, Turn,
    X25519_PUBLIC_KEY_LEN, X25519PublicKey,
};

/// Opaque bounded bytes used for wire fields and authenticated payloads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WireBytes(pub(crate) Vec<u8>);

impl WireBytes {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_vec(bytes.to_vec())
    }

    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(WireError::FieldTooLong {
                field: "wire bytes",
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Direction is a wire-level enum, kept separate from application payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Alice = 0,
    Bob = 1,
}

impl Direction {
    pub(crate) fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::Alice),
            1 => Ok(Self::Bob),
            _ => Err(WireError::InvalidEnum {
                field: "direction",
                value,
            }),
        }
    }
}

/// Delivery outcomes are transport/control metadata, not core state commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeliveryStatus {
    Accepted = 0,
    Rejected = 1,
    Duplicate = 2,
    Replay = 3,
}

impl DeliveryStatus {
    pub(crate) fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Duplicate),
            3 => Ok(Self::Replay),
            _ => Err(WireError::InvalidEnum {
                field: "delivery_status",
                value,
            }),
        }
    }
}

/// A wire application message containing only application-level fields.
#[derive(Clone, PartialEq, Eq)]
pub struct WireApplicationMessage {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_id: SessionId,
    pub(crate) turn: Turn,
    pub(crate) direction: Direction,
    pub(crate) message_id: MessageId,
    pub(crate) receiver_key_id: KeyId,
    pub(crate) receiver_token: MailboxToken,
    pub(crate) payload: WireBytes,
}

impl WireApplicationMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        direction: Direction,
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

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn turn(&self) -> Turn {
        self.turn
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn receiver_key_id(&self) -> KeyId {
        self.receiver_key_id
    }

    pub fn receiver_token(&self) -> &MailboxToken {
        &self.receiver_token
    }

    pub fn payload(&self) -> &WireBytes {
        &self.payload
    }
}

/// The public Receiver Package projection. Private receiver secrets cannot be
/// represented by this type and therefore cannot be encoded accidentally.
#[derive(Clone, PartialEq, Eq)]
pub struct WireReceiverPackage {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_id: SessionId,
    pub(crate) turn: Turn,
    pub(crate) generation: PackageGeneration,
    pub(crate) key_id: KeyId,
    pub(crate) x25519_public_key: X25519PublicKey,
    pub(crate) mlkem_public_key: WireBytes,
    pub(crate) mailbox_token: MailboxToken,
    pub(crate) expiration: u64,
    pub(crate) previous_package_hash: PackageHash,
    pub(crate) package_auth: WireBytes,
}

impl WireReceiverPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        generation: PackageGeneration,
        key_id: KeyId,
        x25519_public_key: X25519PublicKey,
        mlkem_public_key: WireBytes,
        mailbox_token: MailboxToken,
        expiration: u64,
        previous_package_hash: PackageHash,
        package_auth: WireBytes,
    ) -> Result<Self, WireError> {
        if mlkem_public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(WireError::InvalidFieldLength {
                field: "mlkem_public_key",
                expected: ML_KEM_768_PUBLIC_KEY_LEN,
                actual: mlkem_public_key.len(),
            });
        }
        if package_auth.len() != ED25519_SIGNATURE_LEN {
            return Err(WireError::InvalidFieldLength {
                field: "package_auth",
                expected: ED25519_SIGNATURE_LEN,
                actual: package_auth.len(),
            });
        }
        Ok(Self {
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            generation,
            key_id,
            x25519_public_key,
            mlkem_public_key,
            mailbox_token,
            expiration,
            previous_package_hash,
            package_auth,
        })
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn turn(&self) -> Turn {
        self.turn
    }

    pub fn generation(&self) -> PackageGeneration {
        self.generation
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn x25519_public_key(&self) -> X25519PublicKey {
        self.x25519_public_key
    }

    pub fn mlkem_public_key(&self) -> &WireBytes {
        &self.mlkem_public_key
    }

    pub fn mailbox_token(&self) -> &MailboxToken {
        &self.mailbox_token
    }

    pub fn expiration(&self) -> u64 {
        self.expiration
    }

    pub fn previous_package_hash(&self) -> PackageHash {
        self.previous_package_hash
    }

    pub fn package_auth(&self) -> &WireBytes {
        &self.package_auth
    }

    /// Encodes the signed/hash-bound PackageBody without `package_auth`.
    pub fn encode_package_body(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header_with_version(&mut output, TAG_RECEIVER_PACKAGE, self.protocol_version, 10)?;
        push_u16_field(&mut output, self.cipher_suite.id())?;
        push_id_field(&mut output, self.session_id.get())?;
        push_id_field(&mut output, self.turn.get())?;
        push_id_field(&mut output, self.generation.get())?;
        push_id_field(&mut output, self.key_id.get())?;
        push_fixed_field(&mut output, self.x25519_public_key.as_bytes())?;
        push_fixed_field(&mut output, self.mlkem_public_key.as_bytes())?;
        push_fixed_field(&mut output, self.mailbox_token.as_bytes())?;
        push_u64_field(&mut output, self.expiration)?;
        push_fixed_field(&mut output, self.previous_package_hash.as_bytes())?;
        finish(output)
    }
}

/// The only application message type standardized by v1.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    Application = 0,
}

impl MessageType {
    pub(crate) fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::Application),
            _ => Err(WireError::InvalidEnum {
                field: "message_type",
                value,
            }),
        }
    }
}

/// The authenticated logical Header carried inside an Application Envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct WireHeader {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_id: SessionId,
    pub(crate) turn: Turn,
    pub(crate) direction: Direction,
    pub(crate) message_id: MessageId,
    pub(crate) receiver_key_id: KeyId,
    pub(crate) message_type: MessageType,
    pub(crate) sender_package_hash: PackageHash,
    pub(crate) receiver_package_hash: PackageHash,
    pub(crate) return_receiver_package: WireReceiverPackage,
}

impl WireHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        direction: Direction,
        message_id: MessageId,
        receiver_key_id: KeyId,
        message_type: MessageType,
        sender_package_hash: PackageHash,
        receiver_package_hash: PackageHash,
        return_receiver_package: WireReceiverPackage,
    ) -> Result<Self, WireError> {
        if return_receiver_package.protocol_version() != protocol_version
            || return_receiver_package.cipher_suite() != cipher_suite
            || return_receiver_package.session_id() != session_id
            || return_receiver_package.turn() != turn
        {
            return Err(WireError::InvalidHeaderComponent {
                field: "return_receiver_package context",
            });
        }
        Ok(Self {
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            message_id,
            receiver_key_id,
            message_type,
            sender_package_hash,
            receiver_package_hash,
            return_receiver_package,
        })
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub fn turn(&self) -> Turn {
        self.turn
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn message_id(&self) -> MessageId {
        self.message_id
    }
    pub fn receiver_key_id(&self) -> KeyId {
        self.receiver_key_id
    }
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }
    pub fn sender_package_hash(&self) -> PackageHash {
        self.sender_package_hash
    }
    pub fn receiver_package_hash(&self) -> PackageHash {
        self.receiver_package_hash
    }
    pub fn return_receiver_package(&self) -> &WireReceiverPackage {
        &self.return_receiver_package
    }
}

/// A fixed-size encrypted envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct WireEnvelope {
    pub(crate) mailbox_token: MailboxToken,
    pub(crate) x25519_kem_ciphertext: WireBytes,
    pub(crate) mlkem_ciphertext: WireBytes,
    pub(crate) encrypted_header: WireBytes,
    pub(crate) ciphertext: WireBytes,
    pub(crate) padding: WireBytes,
}

impl WireEnvelope {
    pub fn new(
        mailbox_token: MailboxToken,
        x25519_kem_ciphertext: WireBytes,
        mlkem_ciphertext: WireBytes,
        encrypted_header: WireBytes,
        ciphertext: WireBytes,
        padding: WireBytes,
    ) -> Result<Self, WireError> {
        let envelope = Self {
            mailbox_token,
            x25519_kem_ciphertext,
            mlkem_ciphertext,
            encrypted_header,
            ciphertext,
            padding,
        };
        envelope.validate_components()?;
        let encoded_len = envelope.encoded_len()?;
        if encoded_len != MAX_ENVELOPE_SIZE {
            return Err(WireError::InvalidEnvelopeLength {
                actual: encoded_len,
            });
        }
        Ok(envelope)
    }

    pub(crate) fn validate_components(&self) -> Result<(), WireError> {
        if self.x25519_kem_ciphertext.len() != X25519_PUBLIC_KEY_LEN {
            return Err(WireError::InvalidEnvelopeComponent {
                field: "x25519_kem_ciphertext",
            });
        }
        if self.mlkem_ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
            return Err(WireError::InvalidEnvelopeComponent {
                field: "mlkem_ciphertext",
            });
        }
        if self.encrypted_header.len() != ENCRYPTED_HEADER_LEN {
            return Err(WireError::InvalidEnvelopeComponent {
                field: "encrypted_header",
            });
        }
        if self.ciphertext.len() != CIPHERTEXT_LEN {
            return Err(WireError::InvalidEnvelopeComponent {
                field: "ciphertext",
            });
        }
        if !self.padding.is_empty() {
            return Err(WireError::InvalidEnvelopeComponent { field: "padding" });
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> Result<usize, WireError> {
        let lengths = [
            MAILBOX_TOKEN_LEN,
            self.x25519_kem_ciphertext.len(),
            self.mlkem_ciphertext.len(),
            self.encrypted_header.len(),
            self.ciphertext.len(),
            self.padding.len(),
        ];
        let fields = lengths.iter().try_fold(OBJECT_HEADER_LEN, |total, len| {
            total
                .checked_add(FIELD_LENGTH_LEN)
                .and_then(|value| value.checked_add(*len))
                .ok_or(WireError::IntegerOverflow)
        })?;
        Ok(fields)
    }

    pub fn max_ciphertext_len(encrypted_header_len: usize) -> Result<usize, WireError> {
        if encrypted_header_len != ENCRYPTED_HEADER_LEN {
            return Err(WireError::InvalidEnvelopeComponent {
                field: "encrypted_header",
            });
        }
        Ok(CIPHERTEXT_LEN)
    }

    pub fn mailbox_token(&self) -> &MailboxToken {
        &self.mailbox_token
    }

    pub fn x25519_kem_ciphertext(&self) -> &WireBytes {
        &self.x25519_kem_ciphertext
    }

    pub fn mlkem_ciphertext(&self) -> &WireBytes {
        &self.mlkem_ciphertext
    }

    pub fn encrypted_header(&self) -> &WireBytes {
        &self.encrypted_header
    }

    pub fn ciphertext(&self) -> &WireBytes {
        &self.ciphertext
    }

    pub fn padding(&self) -> &WireBytes {
        &self.padding
    }
}

/// An authenticated transport acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckFrame {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_id: SessionId,
    pub(crate) turn: Turn,
    pub(crate) direction: Direction,
    pub(crate) message_id: MessageId,
    pub(crate) delivery_status: DeliveryStatus,
}

impl AckFrame {
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        direction: Direction,
        message_id: MessageId,
        delivery_status: DeliveryStatus,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            message_id,
            delivery_status,
        }
    }
}

/// A transport-level selective acknowledgement. It has no core state effect.
#[derive(Clone, PartialEq, Eq)]
pub struct SackFrame {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_id: SessionId,
    pub(crate) turn: Turn,
    pub(crate) direction: Direction,
    pub(crate) base: MessageId,
    pub(crate) bitmap: WireBytes,
}

impl SackFrame {
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        direction: Direction,
        base: MessageId,
        bitmap: WireBytes,
    ) -> Result<Self, WireError> {
        if bitmap.is_empty() {
            return Err(WireError::MissingRequiredField { field: "bitmap" });
        }
        Ok(Self {
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            direction,
            base,
            bitmap,
        })
    }
}

/// A Mailbox record containing an opaque envelope and its capability token.
#[derive(Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    pub(crate) token: MailboxToken,
    pub(crate) envelope: WireEnvelope,
}

impl MailboxRecord {
    pub fn new(token: MailboxToken, envelope: WireEnvelope) -> Result<Self, WireError> {
        if token != *envelope.mailbox_token() {
            return Err(WireError::InvalidEnvelopeComponent {
                field: "mailbox_token binding",
            });
        }
        Ok(Self { token, envelope })
    }

    pub fn token(&self) -> &MailboxToken {
        &self.token
    }

    pub fn envelope(&self) -> &WireEnvelope {
        &self.envelope
    }
}

/// The bytes returned by canonical encoding or AAD construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBytes(pub(crate) Vec<u8>);

impl EncodedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for EncodedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Encodes a supported wire value into the unique canonical byte form.
pub trait CanonicalEncode {
    fn encode(&self) -> Result<EncodedBytes, WireError>;
}

pub fn encode<T: CanonicalEncode>(value: &T) -> Result<EncodedBytes, WireError> {
    value.encode()
}
