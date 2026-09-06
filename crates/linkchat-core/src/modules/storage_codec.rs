//! Core-owned serialization for local durable state.
//!
//! The codec intentionally exposes only reader/writer operations. Storage
//! adapters can persist a complete state without receiving an API that returns
//! raw private-key bytes to ordinary callers.

use std::io::{self, Read, Write};

use crate::{PrivateReceiverPackage, PublicReceiverPackage, RefinedState, Session};
use linkchat_protocol::{WireReceiverPackage, decode_receiver_package, encode};
use linkchat_types::{CipherSuite, MessageId, ProtocolVersion, SessionId, Turn};

const MAGIC: &[u8; 4] = b"LCCS";
const VERSION: u16 = 1;
const MAX_CONSUMED_MESSAGE_IDS: usize = 65_536;
const X25519_SECRET_LEN: usize = 32;
const MLKEM_SECRET_LEN: usize = 64;

impl RefinedState {
    /// Writes the complete local state to a caller-supplied durable stream.
    ///
    /// This method is reserved for storage adapters. It never returns a raw
    /// private-key buffer, and callers must treat the resulting stream as
    /// secret endpoint state.
    pub fn write_storage_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(MAGIC)?;
        write_u16(writer, VERSION)?;
        let (session, turn, alice, bob, consumed) = self.storage_parts();
        write_u16(writer, session.protocol_version().major())?;
        write_u16(writer, session.protocol_version().minor())?;
        write_u16(writer, session.cipher_suite().id())?;
        write_u64(writer, session.session_id().get())?;
        write_u64(writer, turn.get())?;
        write_package(writer, alice)?;
        write_package(writer, bob)?;
        let count = u32::try_from(consumed.len()).map_err(invalid_input)?;
        write_u32(writer, count)?;
        for message_id in consumed {
            write_u64(writer, message_id.get())?;
        }
        Ok(())
    }

    /// Restores complete local state from a storage adapter stream.
    ///
    /// The decoder bounds all variable input, reconstructs public key
    /// projections from private material, and rejects mismatches before a
    /// state value is returned.
    pub fn read_storage_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut magic = [0; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC || read_u16(reader)? != VERSION {
            return Err(invalid_data("unsupported core storage record"));
        }
        let protocol_version = ProtocolVersion::try_supported(read_u16(reader)?, read_u16(reader)?)
            .map_err(invalid_input)?;
        let cipher_suite = CipherSuite::try_from_id(read_u16(reader)?).map_err(invalid_input)?;
        let session = Session::with_context(
            protocol_version,
            cipher_suite,
            SessionId::new(read_u64(reader)?),
        );
        let turn = Turn::new(read_u64(reader)?);
        let alice = read_package(reader)?;
        let bob = read_package(reader)?;
        let count = usize::try_from(read_u32(reader)?).map_err(invalid_input)?;
        if count > MAX_CONSUMED_MESSAGE_IDS {
            return Err(invalid_data("too many consumed message identifiers"));
        }
        let mut consumed = Vec::with_capacity(count);
        for _ in 0..count {
            consumed.push(MessageId::new(read_u64(reader)?));
        }
        let mut trailing = [0; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(invalid_data("trailing core storage bytes"));
        }
        RefinedState::with_turn(session, turn, alice, bob, consumed).map_err(invalid_input)
    }
}

fn write_package<W: Write>(writer: &mut W, package: &PrivateReceiverPackage) -> io::Result<()> {
    let wire = package
        .public_projection()
        .to_wire()
        .map_err(invalid_input)?;
    let encoded = encode(&wire).map_err(invalid_input)?;
    let encoded = encoded.as_bytes();
    write_u32(writer, u32::try_from(encoded.len()).map_err(invalid_input)?)?;
    writer.write_all(encoded)?;
    let (x25519_secret, mlkem_secret) = package.storage_secret_material();
    if x25519_secret.len() != X25519_SECRET_LEN || mlkem_secret.len() != MLKEM_SECRET_LEN {
        return Err(invalid_data("invalid private package length"));
    }
    writer.write_all(x25519_secret)?;
    writer.write_all(mlkem_secret)?;
    Ok(())
}

fn read_package<R: Read>(reader: &mut R) -> io::Result<PrivateReceiverPackage> {
    let wire_len = usize::try_from(read_u32(reader)?).map_err(invalid_input)?;
    if wire_len != linkchat_protocol::WIRE_RECEIVER_PACKAGE_LEN {
        return Err(invalid_data("invalid public package storage length"));
    }
    let mut wire_bytes = vec![0; wire_len];
    reader.read_exact(&mut wire_bytes)?;
    let wire: WireReceiverPackage = decode_receiver_package(&wire_bytes).map_err(invalid_input)?;
    let public = PublicReceiverPackage::from_wire(&wire).map_err(invalid_input)?;
    let mut x25519_secret = [0; X25519_SECRET_LEN];
    let mut mlkem_secret = [0; MLKEM_SECRET_LEN];
    reader.read_exact(&mut x25519_secret)?;
    reader.read_exact(&mut mlkem_secret)?;
    PrivateReceiverPackage::from_storage_secret_material(&x25519_secret, &mlkem_secret, public)
        .map_err(invalid_input)
}

fn write_u16<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn read_u16<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn invalid_input(_error: impl std::fmt::Display) -> io::Error {
    invalid_data("invalid core storage state")
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
