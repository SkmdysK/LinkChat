use crate::errors::WireError;
use crate::foundation::{
    CANONICAL_FORMAT_VERSION, FIELD_LENGTH_LEN, MAX_ENVELOPE_SIZE, MAX_FIELD_LEN,
    MAX_NESTING_DEPTH, TAG_ENVELOPE,
};
use crate::wire_types::EncodedBytes;
use linkchat_types::{
    CipherSuite, HASH_LEN, MAILBOX_TOKEN_LEN, MailboxToken, PackageHash, ProtocolVersion,
    X25519_PUBLIC_KEY_LEN, X25519PublicKey,
};

pub(crate) fn encode_header(output: &mut Vec<u8>, tag: u8, fields: usize) -> Result<(), WireError> {
    let fields = u16::try_from(fields).map_err(|_| WireError::IntegerOverflow)?;
    output.push(tag);
    output.extend_from_slice(&CANONICAL_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&ProtocolVersion::current().major().to_be_bytes());
    output.extend_from_slice(&ProtocolVersion::current().minor().to_be_bytes());
    output.extend_from_slice(&fields.to_be_bytes());
    Ok(())
}

pub(crate) fn encode_header_with_version(
    output: &mut Vec<u8>,
    tag: u8,
    version: ProtocolVersion,
    fields: usize,
) -> Result<(), WireError> {
    let fields = u16::try_from(fields).map_err(|_| WireError::IntegerOverflow)?;
    output.push(tag);
    output.extend_from_slice(&CANONICAL_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&version.major().to_be_bytes());
    output.extend_from_slice(&version.minor().to_be_bytes());
    output.extend_from_slice(&fields.to_be_bytes());
    Ok(())
}

pub(crate) fn push_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), WireError> {
    let length = u32::try_from(field.len()).map_err(|_| WireError::IntegerOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

pub(crate) fn push_u16_field(output: &mut Vec<u8>, value: u16) -> Result<(), WireError> {
    push_field(output, &value.to_be_bytes())
}

pub(crate) fn push_u64_field(output: &mut Vec<u8>, value: u64) -> Result<(), WireError> {
    push_field(output, &value.to_be_bytes())
}

pub(crate) fn push_u8_field(output: &mut Vec<u8>, value: u8) -> Result<(), WireError> {
    push_field(output, &[value])
}

pub(crate) fn push_id_field(output: &mut Vec<u8>, value: u64) -> Result<(), WireError> {
    push_u64_field(output, value)
}

pub(crate) fn push_fixed_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WireError> {
    push_field(output, value)
}

pub(crate) fn finish(output: Vec<u8>) -> Result<EncodedBytes, WireError> {
    if output.len() > MAX_ENVELOPE_SIZE && output.first() == Some(&TAG_ENVELOPE) {
        return Err(WireError::EnvelopeBudgetExceeded {
            actual: output.len(),
            maximum: MAX_ENVELOPE_SIZE,
        });
    }
    Ok(EncodedBytes(output))
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            depth: 0,
        }
    }

    fn with_depth(bytes: &'a [u8], depth: usize) -> Result<Self, WireError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(WireError::NestingDepthExceeded);
        }
        Ok(Self {
            bytes,
            offset: 0,
            depth,
        })
    }

    pub(crate) fn nested(&self, bytes: &'a [u8]) -> Result<Self, WireError> {
        Self::with_depth(bytes, self.depth + 1)
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::IntegerOverflow)?;
        if end > self.bytes.len() {
            return Err(WireError::Truncated {
                offset: self.offset,
                needed: length,
            });
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    pub(crate) fn header(
        &mut self,
        expected_tag: u8,
        expected_fields: usize,
    ) -> Result<ProtocolVersion, WireError> {
        let tag = self.take(1)?[0];
        if tag != expected_tag {
            return Err(WireError::InvalidTypeTag { actual: tag });
        }
        let format_version = read_u16(self.take(2)?, "format_version")?;
        if format_version != CANONICAL_FORMAT_VERSION {
            return Err(WireError::InvalidFormatVersion {
                actual: format_version,
            });
        }
        let major = read_u16(self.take(2)?, "protocol_major")?;
        let minor = read_u16(self.take(2)?, "protocol_minor")?;
        let version = ProtocolVersion::try_supported(major, minor)
            .map_err(|_| WireError::InvalidVersion { major, minor })?;
        let fields = read_u16(self.take(2)?, "field_count")? as usize;
        if fields != expected_fields {
            return Err(WireError::InvalidFieldCount {
                expected: expected_fields,
                actual: fields,
            });
        }
        Ok(version)
    }

    pub(crate) fn field(&mut self, name: &'static str) -> Result<&'a [u8], WireError> {
        let length = read_u32(self.take(FIELD_LENGTH_LEN)?, "field_length")? as usize;
        if length > MAX_FIELD_LEN {
            return Err(WireError::FieldTooLong {
                field: name,
                actual: length,
            });
        }
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), WireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes {
                offset: self.offset,
            })
        }
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

pub(crate) fn read_u8(bytes: &[u8], field: &'static str) -> Result<u8, WireError> {
    if bytes.len() != 1 {
        return Err(WireError::InvalidFieldLength {
            field,
            expected: 1,
            actual: bytes.len(),
        });
    }
    Ok(bytes[0])
}

pub(crate) fn read_u16(bytes: &[u8], field: &'static str) -> Result<u16, WireError> {
    let array = <[u8; 2]>::try_from(bytes).map_err(|_| WireError::InvalidFieldLength {
        field,
        expected: 2,
        actual: bytes.len(),
    })?;
    Ok(u16::from_be_bytes(array))
}

pub(crate) fn read_u32(bytes: &[u8], field: &'static str) -> Result<u32, WireError> {
    let array = <[u8; 4]>::try_from(bytes).map_err(|_| WireError::InvalidFieldLength {
        field,
        expected: 4,
        actual: bytes.len(),
    })?;
    Ok(u32::from_be_bytes(array))
}

pub(crate) fn read_u64(bytes: &[u8], field: &'static str) -> Result<u64, WireError> {
    let array = <[u8; 8]>::try_from(bytes).map_err(|_| WireError::InvalidFieldLength {
        field,
        expected: 8,
        actual: bytes.len(),
    })?;
    Ok(u64::from_be_bytes(array))
}

pub(crate) fn read_id(bytes: &[u8], field: &'static str) -> Result<u64, WireError> {
    read_u64(bytes, field)
}

pub(crate) fn read_fixed<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], WireError> {
    <[u8; N]>::try_from(bytes).map_err(|_| WireError::InvalidFieldLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

pub(crate) fn read_cipher_suite(bytes: &[u8]) -> Result<CipherSuite, WireError> {
    let id = read_u16(bytes, "cipher_suite")?;
    CipherSuite::try_from_id(id).map_err(|_| WireError::InvalidCipherSuite { id })
}

pub(crate) fn read_token(bytes: &[u8]) -> Result<MailboxToken, WireError> {
    Ok(MailboxToken::from_bytes(&read_fixed::<MAILBOX_TOKEN_LEN>(
        bytes,
        "mailbox_token",
    )?)?)
}

pub(crate) fn read_package_hash(bytes: &[u8]) -> Result<PackageHash, WireError> {
    Ok(PackageHash::from_bytes(&read_fixed::<HASH_LEN>(
        bytes,
        "package_hash",
    )?)?)
}

pub(crate) fn read_x25519_public_key(bytes: &[u8]) -> Result<X25519PublicKey, WireError> {
    Ok(X25519PublicKey::from_bytes(&read_fixed::<
        X25519_PUBLIC_KEY_LEN,
    >(
        bytes, "x25519_public_key"
    )?)?)
}
