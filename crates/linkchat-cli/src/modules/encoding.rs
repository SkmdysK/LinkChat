use linkchat_protocol::Direction;

use super::errors::CliError;

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn hex_decode(
    name: &'static str,
    value: &str,
    expected_len: Option<usize>,
) -> Result<Vec<u8>, CliError> {
    if !value.len().is_multiple_of(2) {
        return Err(CliError::InvalidHex(name));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(CliError::InvalidHex(name))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(CliError::InvalidHex(name))?;
        bytes.push(((high << 4) | low) as u8);
    }
    if let Some(expected) = expected_len
        && bytes.len() != expected
    {
        return Err(CliError::InvalidValue(name));
    }
    Ok(bytes)
}

pub(crate) fn parse_u64(name: &'static str, value: &str) -> Result<u64, CliError> {
    value.parse().map_err(|_| CliError::InvalidValue(name))
}

pub(crate) fn parse_direction(value: &str) -> Result<Direction, CliError> {
    match value {
        "alice" => Ok(Direction::Alice),
        "bob" => Ok(Direction::Bob),
        _ => Err(CliError::InvalidValue("direction")),
    }
}
