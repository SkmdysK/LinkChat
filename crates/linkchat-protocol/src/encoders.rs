impl CanonicalEncode for WireApplicationMessage {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header_with_version(
            &mut output,
            TAG_APPLICATION_MESSAGE,
            self.protocol_version,
            FIELD_APPLICATION_MESSAGE,
        )?;
        push_u16_field(&mut output, self.cipher_suite.id())?;
        push_id_field(&mut output, self.session_id.get())?;
        push_id_field(&mut output, self.turn.get())?;
        push_u8_field(&mut output, self.direction as u8)?;
        push_id_field(&mut output, self.message_id.get())?;
        push_id_field(&mut output, self.receiver_key_id.get())?;
        push_fixed_field(&mut output, self.receiver_token.as_bytes())?;
        push_fixed_field(&mut output, self.payload.as_bytes())?;
        finish(output)
    }
}

impl WireApplicationMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let protocol_version =
            decoder.header(TAG_APPLICATION_MESSAGE, FIELD_APPLICATION_MESSAGE)?;
        let cipher_suite = read_cipher_suite(decoder.field("cipher_suite")?)?;
        let session_id = SessionId::new(read_id(decoder.field("session_id")?, "session_id")?);
        let turn = Turn::new(read_id(decoder.field("turn")?, "turn")?);
        let direction = Direction::from_byte(read_u8(decoder.field("direction")?, "direction")?)?;
        let message_id = MessageId::new(read_id(decoder.field("message_id")?, "message_id")?);
        let receiver_key_id = KeyId::new(read_id(
            decoder.field("receiver_key_id")?,
            "receiver_key_id",
        )?);
        let receiver_token = read_token(decoder.field("receiver_token")?)?;
        let payload = WireBytes::from_bytes(decoder.field("payload")?)?;
        decoder.finish()?;
        require_canonical(
            Self::new(
                protocol_version,
                cipher_suite,
                session_id,
                turn,
                direction,
                message_id,
                receiver_key_id,
                receiver_token,
                payload,
            ),
            bytes,
        )
    }
}

impl CanonicalEncode for WireReceiverPackage {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header_with_version(
            &mut output,
            TAG_RECEIVER_PACKAGE,
            self.protocol_version,
            FIELD_RECEIVER_PACKAGE,
        )?;
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
        push_fixed_field(&mut output, self.package_auth.as_bytes())?;
        finish(output)
    }
}

impl CanonicalEncode for WireHeader {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header_with_version(&mut output, TAG_HEADER, self.protocol_version, FIELD_HEADER)?;
        push_u16_field(&mut output, self.cipher_suite.id())?;
        push_id_field(&mut output, self.session_id.get())?;
        push_id_field(&mut output, self.turn.get())?;
        push_u8_field(&mut output, self.direction as u8)?;
        push_id_field(&mut output, self.message_id.get())?;
        push_id_field(&mut output, self.receiver_key_id.get())?;
        push_u8_field(&mut output, self.message_type as u8)?;
        push_fixed_field(&mut output, self.sender_package_hash.as_bytes())?;
        push_fixed_field(&mut output, self.receiver_package_hash.as_bytes())?;
        let package = self.return_receiver_package.encode()?;
        push_fixed_field(&mut output, package.as_bytes())?;
        if output.len() != WIRE_HEADER_LEN {
            return Err(WireError::InvalidFieldLength {
                field: "header",
                expected: WIRE_HEADER_LEN,
                actual: output.len(),
            });
        }
        Ok(EncodedBytes(output))
    }
}

impl WireHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let protocol_version = decoder.header(TAG_HEADER, FIELD_HEADER)?;
        let cipher_suite = read_cipher_suite(decoder.field("cipher_suite")?)?;
        let session_id = SessionId::new(read_id(decoder.field("session_id")?, "session_id")?);
        let turn = Turn::new(read_id(decoder.field("turn")?, "turn")?);
        let direction = Direction::from_byte(read_u8(decoder.field("direction")?, "direction")?)?;
        let message_id = MessageId::new(read_id(decoder.field("message_id")?, "message_id")?);
        let receiver_key_id = KeyId::new(read_id(
            decoder.field("receiver_key_id")?,
            "receiver_key_id",
        )?);
        let message_type =
            MessageType::from_byte(read_u8(decoder.field("message_type")?, "message_type")?)?;
        let sender_package_hash = read_package_hash(decoder.field("sender_package_hash")?)?;
        let receiver_package_hash = read_package_hash(decoder.field("receiver_package_hash")?)?;
        let package_bytes = decoder.field("return_receiver_package")?;
        if package_bytes.len() != WIRE_RECEIVER_PACKAGE_LEN {
            return Err(WireError::InvalidFieldLength {
                field: "return_receiver_package",
                expected: WIRE_RECEIVER_PACKAGE_LEN,
                actual: package_bytes.len(),
            });
        }
        let return_receiver_package = WireReceiverPackage::decode(package_bytes)?;
        decoder.finish()?;
        require_canonical(
            Self::new(
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
            )?,
            bytes,
        )
    }
}

impl WireReceiverPackage {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let protocol_version = decoder.header(TAG_RECEIVER_PACKAGE, FIELD_RECEIVER_PACKAGE)?;
        let cipher_suite = read_cipher_suite(decoder.field("cipher_suite")?)?;
        let session_id = SessionId::new(read_id(decoder.field("session_id")?, "session_id")?);
        let turn = Turn::new(read_id(decoder.field("turn")?, "turn")?);
        let generation =
            PackageGeneration::new(read_id(decoder.field("generation")?, "generation")?);
        let key_id = KeyId::new(read_id(decoder.field("key_id")?, "key_id")?);
        let x25519_public_key = read_x25519_public_key(decoder.field("x25519_public_key")?)?;
        let mlkem_public_key = WireBytes::from_bytes(decoder.field("mlkem_public_key")?)?;
        let mailbox_token = read_token(decoder.field("mailbox_token")?)?;
        let expiration = read_u64(decoder.field("expiration")?, "expiration")?;
        let previous_package_hash = read_package_hash(decoder.field("previous_package_hash")?)?;
        let package_auth = WireBytes::from_bytes(decoder.field("package_auth")?)?;
        decoder.finish()?;
        require_canonical(
            Self::new(
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
            )?,
            bytes,
        )
    }
}

impl CanonicalEncode for WireEnvelope {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        self.validate_components()?;
        let mut output = Vec::new();
        encode_header(&mut output, TAG_ENVELOPE, FIELD_ENVELOPE)?;
        push_fixed_field(&mut output, self.mailbox_token.as_bytes())?;
        push_fixed_field(&mut output, self.x25519_kem_ciphertext.as_bytes())?;
        push_fixed_field(&mut output, self.mlkem_ciphertext.as_bytes())?;
        push_fixed_field(&mut output, self.encrypted_header.as_bytes())?;
        push_fixed_field(&mut output, self.ciphertext.as_bytes())?;
        push_fixed_field(&mut output, self.padding.as_bytes())?;
        if output.len() != MAX_ENVELOPE_SIZE {
            return Err(WireError::InvalidEnvelopeLength {
                actual: output.len(),
            });
        }
        Ok(EncodedBytes(output))
    }
}

impl WireEnvelope {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != MAX_ENVELOPE_SIZE {
            return Err(WireError::InvalidEnvelopeLength {
                actual: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        let _version = decoder.header(TAG_ENVELOPE, FIELD_ENVELOPE)?;
        let mailbox_token = read_token(decoder.field("mailbox_token")?)?;
        let x25519_kem_ciphertext = WireBytes::from_bytes(decoder.field("x25519_kem_ciphertext")?)?;
        let mlkem_ciphertext = WireBytes::from_bytes(decoder.field("mlkem_ciphertext")?)?;
        let encrypted_header = WireBytes::from_bytes(decoder.field("encrypted_header")?)?;
        let ciphertext = WireBytes::from_bytes(decoder.field("ciphertext")?)?;
        let padding = WireBytes::from_bytes(decoder.field("padding")?)?;
        decoder.finish()?;
        require_canonical(
            Self::new(
                mailbox_token,
                x25519_kem_ciphertext,
                mlkem_ciphertext,
                encrypted_header,
                ciphertext,
                padding,
            )?,
            bytes,
        )
    }
}

impl CanonicalEncode for AckFrame {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header_with_version(&mut output, TAG_ACK, self.protocol_version, FIELD_ACK)?;
        push_u16_field(&mut output, self.cipher_suite.id())?;
        push_id_field(&mut output, self.session_id.get())?;
        push_id_field(&mut output, self.turn.get())?;
        push_u8_field(&mut output, self.direction as u8)?;
        push_id_field(&mut output, self.message_id.get())?;
        push_u8_field(&mut output, self.delivery_status as u8)?;
        finish(output)
    }
}

impl AckFrame {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let protocol_version = decoder.header(TAG_ACK, FIELD_ACK)?;
        let cipher_suite = read_cipher_suite(decoder.field("cipher_suite")?)?;
        let session_id = SessionId::new(read_id(decoder.field("session_id")?, "session_id")?);
        let turn = Turn::new(read_id(decoder.field("turn")?, "turn")?);
        let direction = Direction::from_byte(read_u8(decoder.field("direction")?, "direction")?)?;
        let message_id = MessageId::new(read_id(decoder.field("message_id")?, "message_id")?);
        let delivery_status = DeliveryStatus::from_byte(read_u8(
            decoder.field("delivery_status")?,
            "delivery_status",
        )?)?;
        decoder.finish()?;
        require_canonical(
            Self::new(
                protocol_version,
                cipher_suite,
                session_id,
                turn,
                direction,
                message_id,
                delivery_status,
            ),
            bytes,
        )
    }
}

impl CanonicalEncode for SackFrame {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header_with_version(&mut output, TAG_SACK, self.protocol_version, FIELD_SACK)?;
        push_u16_field(&mut output, self.cipher_suite.id())?;
        push_id_field(&mut output, self.session_id.get())?;
        push_id_field(&mut output, self.turn.get())?;
        push_u8_field(&mut output, self.direction as u8)?;
        push_id_field(&mut output, self.base.get())?;
        push_fixed_field(&mut output, self.bitmap.as_bytes())?;
        finish(output)
    }
}

impl SackFrame {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let protocol_version = decoder.header(TAG_SACK, FIELD_SACK)?;
        let cipher_suite = read_cipher_suite(decoder.field("cipher_suite")?)?;
        let session_id = SessionId::new(read_id(decoder.field("session_id")?, "session_id")?);
        let turn = Turn::new(read_id(decoder.field("turn")?, "turn")?);
        let direction = Direction::from_byte(read_u8(decoder.field("direction")?, "direction")?)?;
        let base = MessageId::new(read_id(decoder.field("base")?, "base")?);
        let bitmap = WireBytes::from_bytes(decoder.field("bitmap")?)?;
        decoder.finish()?;
        require_canonical(
            Self::new(
                protocol_version,
                cipher_suite,
                session_id,
                turn,
                direction,
                base,
                bitmap,
            )?,
            bytes,
        )
    }
}

impl CanonicalEncode for MailboxRecord {
    fn encode(&self) -> Result<EncodedBytes, WireError> {
        let mut output = Vec::new();
        encode_header(&mut output, TAG_MAILBOX_RECORD, FIELD_MAILBOX_RECORD)?;
        push_fixed_field(&mut output, self.token.as_bytes())?;
        let envelope = self.envelope.encode()?;
        push_fixed_field(&mut output, envelope.as_bytes())?;
        finish(output)
    }
}

impl MailboxRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let _version = decoder.header(TAG_MAILBOX_RECORD, FIELD_MAILBOX_RECORD)?;
        let token = read_token(decoder.field("token")?)?;
        let envelope_bytes = decoder.field("envelope")?;
        let nested = decoder.nested(envelope_bytes)?;
        let envelope = decode_envelope(nested.remaining())?;
        decoder.finish()?;
        require_canonical(Self::new(token, envelope)?, bytes)
    }
}
use crate::codec::{
    Decoder, encode_header, encode_header_with_version, finish, push_fixed_field, push_id_field,
    push_u8_field, push_u16_field, push_u64_field, read_cipher_suite, read_id, read_package_hash,
    read_token, read_u8, read_u64, read_x25519_public_key,
};
use crate::errors::WireError;
use crate::foundation::{
    FIELD_ACK, FIELD_APPLICATION_MESSAGE, FIELD_ENVELOPE, FIELD_HEADER, FIELD_MAILBOX_RECORD,
    FIELD_RECEIVER_PACKAGE, FIELD_SACK, MAX_ENVELOPE_SIZE, TAG_ACK, TAG_APPLICATION_MESSAGE,
    TAG_ENVELOPE, TAG_HEADER, TAG_MAILBOX_RECORD, TAG_RECEIVER_PACKAGE, TAG_SACK,
};
use crate::payload::decode_envelope;
use crate::wire_types::{
    AckFrame, CanonicalEncode, DeliveryStatus, Direction, EncodedBytes, MailboxRecord, MessageType,
    SackFrame, WireApplicationMessage, WireBytes, WireEnvelope, WireHeader, WireReceiverPackage,
};
use crate::{WIRE_HEADER_LEN, WIRE_RECEIVER_PACKAGE_LEN};
use linkchat_types::{KeyId, MessageId, PackageGeneration, SessionId, Turn};

fn require_canonical<T: CanonicalEncode>(value: T, input: &[u8]) -> Result<T, WireError> {
    let canonical = value.encode()?;
    if canonical.as_bytes() != input {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}
