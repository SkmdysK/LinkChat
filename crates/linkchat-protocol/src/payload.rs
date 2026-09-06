pub fn decode_application_message(bytes: &[u8]) -> Result<WireApplicationMessage, WireError> {
    WireApplicationMessage::decode(bytes)
}

pub fn decode_receiver_package(bytes: &[u8]) -> Result<WireReceiverPackage, WireError> {
    WireReceiverPackage::decode(bytes)
}

pub fn decode_header(bytes: &[u8]) -> Result<WireHeader, WireError> {
    WireHeader::decode(bytes)
}

pub fn decode_envelope(bytes: &[u8]) -> Result<WireEnvelope, WireError> {
    WireEnvelope::decode(bytes)
}

pub fn decode_ack(bytes: &[u8]) -> Result<AckFrame, WireError> {
    AckFrame::decode(bytes)
}

pub fn decode_sack(bytes: &[u8]) -> Result<SackFrame, WireError> {
    SackFrame::decode(bytes)
}

pub fn decode_mailbox_record(bytes: &[u8]) -> Result<MailboxRecord, WireError> {
    MailboxRecord::decode(bytes)
}

/// Canonically binds a domain label to one nested encoded value.
pub fn domain_input(domain: &[u8], value: &[u8]) -> Result<EncodedBytes, WireError> {
    let mut output = Vec::new();
    encode_header(&mut output, TAG_CONTEXT, 2)?;
    push_fixed_field(&mut output, domain)?;
    push_fixed_field(&mut output, value)?;
    Ok(EncodedBytes(output))
}

/// Encodes an application payload into the fixed-size v1 payload frame.
pub fn encode_payload_frame(payload: &[u8]) -> Result<EncodedBytes, WireError> {
    if payload.len() > MAX_APPLICATION_PAYLOAD_LEN {
        return Err(WireError::InvalidFieldLength {
            field: "application_payload",
            expected: MAX_APPLICATION_PAYLOAD_LEN,
            actual: payload.len(),
        });
    }
    let length = u16::try_from(payload.len()).map_err(|_| WireError::IntegerOverflow)?;
    let mut frame = Vec::with_capacity(PAYLOAD_FRAME_LEN);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.resize(PAYLOAD_FRAME_LEN, 0);
    Ok(EncodedBytes(frame))
}

/// Decodes and validates a fixed-size v1 payload frame.
pub fn decode_payload_frame(frame: &[u8]) -> Result<WireBytes, WireError> {
    if frame.len() != PAYLOAD_FRAME_LEN {
        return Err(WireError::InvalidFieldLength {
            field: "payload_frame",
            expected: PAYLOAD_FRAME_LEN,
            actual: frame.len(),
        });
    }
    let payload_len = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
    if payload_len > MAX_APPLICATION_PAYLOAD_LEN {
        return Err(WireError::InvalidFieldLength {
            field: "application_payload",
            expected: MAX_APPLICATION_PAYLOAD_LEN,
            actual: payload_len,
        });
    }
    if frame[2 + payload_len..].iter().any(|byte| *byte != 0) {
        return Err(WireError::InvalidHeaderComponent {
            field: "payload_frame padding",
        });
    }
    WireBytes::from_bytes(&frame[2..2 + payload_len])
}
use crate::codec::{encode_header, push_fixed_field};
use crate::errors::WireError;
use crate::foundation::{MAX_APPLICATION_PAYLOAD_LEN, PAYLOAD_FRAME_LEN, TAG_CONTEXT};
use crate::wire_types::{
    AckFrame, EncodedBytes, MailboxRecord, SackFrame, WireApplicationMessage, WireBytes,
    WireEnvelope, WireHeader, WireReceiverPackage,
};
