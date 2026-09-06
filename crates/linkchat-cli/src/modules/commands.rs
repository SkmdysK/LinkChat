use std::fs;

use linkchat_core::Session;
use linkchat_crypto::{CryptoBackend, OsCryptoBackend};
use linkchat_protocol::{
    WireApplicationMessage, WireBytes, WireError, WireReceiverPackage, decode_ack,
    decode_application_message, decode_envelope, decode_mailbox_record, decode_receiver_package,
    decode_sack, encode,
};
use linkchat_types::{
    CipherSuite, KeyId, MailboxToken, MessageId, PackageGeneration, PackageHash, ProtocolVersion,
    SessionId, Turn, X25519PublicKey,
};

use super::encoding::{hex_decode, hex_encode, parse_direction, parse_u64};
use super::errors::CliError;

const USAGE: &str =
    "usage: linkchat-cli <keygen|pair|inspect-package|encode|decode|verify|test-vector> ...";

pub(crate) fn encode_message(args: &[String]) -> Result<String, CliError> {
    if args.len() != 7 {
        return Err(CliError::Usage(
            "encode message <session> <turn> <direction> <message-id> <receiver-key-id> <token-hex> <payload-hex>",
        ));
    }
    let message = WireApplicationMessage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(parse_u64("session", &args[0])?),
        Turn::new(parse_u64("turn", &args[1])?),
        parse_direction(&args[2])?,
        MessageId::new(parse_u64("message-id", &args[3])?),
        KeyId::new(parse_u64("receiver-key-id", &args[4])?),
        MailboxToken::from_bytes(&hex_decode("token", &args[5], Some(MailboxToken::LEN))?)
            .map_err(|_| CliError::InvalidValue("token"))?,
        WireBytes::from_bytes(&hex_decode("payload", &args[6], None)?)?,
    );
    Ok(hex_encode(encode(&message)?.as_bytes()))
}

pub(crate) fn encode_package(args: &[String]) -> Result<String, CliError> {
    if args.len() != 10 {
        return Err(CliError::Usage(
            "encode package <session> <turn> <generation> <key-id> <x25519-hex> <mlkem-hex> <token-hex> <expiration> <previous-hash-hex> <package-auth-hex>",
        ));
    }
    let package = WireReceiverPackage::new(
        ProtocolVersion::V1_0,
        CipherSuite::current(),
        SessionId::new(parse_u64("session", &args[0])?),
        Turn::new(parse_u64("turn", &args[1])?),
        PackageGeneration::new(parse_u64("generation", &args[2])?),
        KeyId::new(parse_u64("key-id", &args[3])?),
        X25519PublicKey::from_bytes(&hex_decode("x25519", &args[4], Some(32))?)
            .map_err(|_| CliError::InvalidValue("x25519"))?,
        WireBytes::from_bytes(&hex_decode("mlkem", &args[5], Some(1184))?)?,
        MailboxToken::from_bytes(&hex_decode("token", &args[6], Some(MailboxToken::LEN))?)
            .map_err(|_| CliError::InvalidValue("token"))?,
        parse_u64("expiration", &args[7])?,
        PackageHash::from_bytes(&hex_decode("previous-hash", &args[8], Some(32))?)
            .map_err(|_| CliError::InvalidValue("previous-hash"))?,
        WireBytes::from_bytes(&hex_decode("package-auth", &args[9], Some(64))?)?,
    )?;
    Ok(hex_encode(encode(&package)?.as_bytes()))
}

pub(crate) fn keygen() -> Result<String, CliError> {
    let mut backend = OsCryptoBackend::new();
    let ed25519 = backend.generate_ed25519_keypair()?;
    let x25519 = backend.generate_x25519_keypair()?;
    let mlkem = backend.generate_mlkem768_keypair()?;
    Ok(format!(
        "ed25519_public_key={}\nx25519_public_key={}\nmlkem_public_key={}\n",
        hex_encode(ed25519.public_key.as_bytes()),
        hex_encode(x25519.public_key.as_bytes()),
        hex_encode(mlkem.public_key.as_bytes()),
    ))
}

pub(crate) fn pair(args: &[String]) -> Result<String, CliError> {
    if args.len() != 2 {
        return Err(CliError::Usage("pair <session-id>"));
    }
    let session = Session::new(SessionId::new(parse_u64("session-id", &args[1])?));
    Ok(format!(
        "protocol_version={}.{}\ncipher_suite={}\nsession_id={}\nendpoints=alice,bob\n",
        session.protocol_version().major(),
        session.protocol_version().minor(),
        session.cipher_suite().id(),
        session.session_id().get(),
    ))
}

fn package_summary(package: &WireReceiverPackage) -> String {
    format!(
        "type=receiver-package\nprotocol_version={}.{}\ncipher_suite={}\nsession_id={}\nturn={}\ngeneration={}\nkey_id={}\nx25519_public_key={}\nmlkem_public_key_len={}\nexpiration={}\nprevious_package_hash={}\npackage_auth_len={}\n",
        package.protocol_version().major(),
        package.protocol_version().minor(),
        package.cipher_suite().id(),
        package.session_id().get(),
        package.turn().get(),
        package.generation().get(),
        package.key_id().get(),
        hex_encode(package.x25519_public_key().as_bytes()),
        package.mlkem_public_key().len(),
        package.expiration(),
        hex_encode(package.previous_package_hash().as_bytes()),
        package.package_auth().len(),
    )
}

pub(crate) fn inspect_package(args: &[String]) -> Result<String, CliError> {
    if args.len() != 2 {
        return Err(CliError::Usage("inspect-package <canonical-package-hex>"));
    }
    let bytes = hex_decode("package", &args[1], None)?;
    let package = decode_receiver_package(&bytes)?;
    if encode(&package)?.as_bytes() != bytes.as_slice() {
        return Err(CliError::Wire(WireError::NonCanonical));
    }
    Ok(package_summary(&package))
}

fn decode_wire(kind: &str, bytes: &[u8]) -> Result<String, CliError> {
    match kind {
        "message" => {
            let value = decode_application_message(bytes)?;
            if encode(&value)?.as_bytes() != bytes {
                return Err(CliError::Wire(WireError::NonCanonical));
            }
            Ok(format!(
                "type=application-message\nsession_id={}\nturn={}\ndirection={:?}\nmessage_id={}\npayload_len={}\n",
                value.session_id().get(),
                value.turn().get(),
                value.direction(),
                value.message_id().get(),
                value.payload().len(),
            ))
        }
        "package" => inspect_package(&["inspect-package".to_string(), hex_encode(bytes)]),
        "envelope" => {
            let value = decode_envelope(bytes)?;
            if encode(&value)?.as_bytes() != bytes {
                return Err(CliError::Wire(WireError::NonCanonical));
            }
            Ok(format!(
                "type=envelope\nx25519_kem_ciphertext_len={}\nmlkem_ciphertext_len={}\nencrypted_header_len={}\nciphertext_len={}\npadding_len={}\n",
                value.x25519_kem_ciphertext().len(),
                value.mlkem_ciphertext().len(),
                value.encrypted_header().len(),
                value.ciphertext().len(),
                value.padding().len(),
            ))
        }
        "ack" => {
            let value = decode_ack(bytes)?;
            if encode(&value)?.as_bytes() != bytes {
                return Err(CliError::Wire(WireError::NonCanonical));
            }
            Ok("type=ack\nvalid-canonical-wire\n".to_string())
        }
        "sack" => {
            let value = decode_sack(bytes)?;
            if encode(&value)?.as_bytes() != bytes {
                return Err(CliError::Wire(WireError::NonCanonical));
            }
            Ok("type=sack\nvalid-canonical-wire\n".to_string())
        }
        "mailbox-record" => {
            let value = decode_mailbox_record(bytes)?;
            if encode(&value)?.as_bytes() != bytes {
                return Err(CliError::Wire(WireError::NonCanonical));
            }
            Ok(format!(
                "type=mailbox-record\nenvelope_len={}\n",
                value.envelope().encoded_len()?,
            ))
        }
        _ => Err(CliError::InvalidValue(
            "wire type; supported: message, package, envelope, ack, sack, mailbox-record",
        )),
    }
}

pub(crate) fn decode(args: &[String]) -> Result<String, CliError> {
    if args.len() != 3 {
        return Err(CliError::Usage(
            "decode <message|package|envelope|ack|sack|mailbox-record> <canonical-hex>",
        ));
    }
    decode_wire(&args[1], &hex_decode("wire input", &args[2], None)?)
}

pub(crate) fn verify(args: &[String]) -> Result<String, CliError> {
    if args.len() != 3 {
        return Err(CliError::Usage(
            "verify <message|package|envelope|ack|sack|mailbox-record> <canonical-hex>",
        ));
    }
    let bytes = hex_decode("wire input", &args[2], None)?;
    decode_wire(&args[1], &bytes)?;
    Ok("valid-canonical-wire\n".to_string())
}

pub(crate) fn test_vector(args: &[String]) -> Result<String, CliError> {
    if args.len() > 2 {
        return Err(CliError::Usage("test-vector [manifest-path]"));
    }
    let content = if let Some(path) = args.get(1) {
        fs::read_to_string(path).map_err(|_| CliError::Io)?
    } else {
        match fs::read_to_string("vectors/manifest.tsv") {
            Ok(content) => content,
            Err(_) => include_str!("../../../../vectors/manifest.tsv").to_string(),
        }
    };
    let rows = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        .saturating_sub(1);
    if rows == 0 {
        return Err(CliError::InvalidValue("empty vector manifest"));
    }
    Ok(format!("vector_manifest_rows={rows}\n"))
}

pub(crate) fn run(args: &[String]) -> Result<String, CliError> {
    let command = args.first().ok_or(CliError::Usage(USAGE))?;
    match command.as_str() {
        "keygen" if args.len() == 1 => keygen(),
        "pair" => pair(args),
        "inspect-package" => inspect_package(args),
        "encode" if args.get(1).map(String::as_str) == Some("message") => {
            encode_message(&args[2..])
        }
        "encode" if args.get(1).map(String::as_str) == Some("package") => {
            encode_package(&args[2..])
        }
        "decode" => decode(args),
        "verify" => verify(args),
        "test-vector" => test_vector(args),
        _ => Err(CliError::Usage(USAGE)),
    }
}
