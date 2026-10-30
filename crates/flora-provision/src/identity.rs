//! Device credential helpers.
//!
//! The gateway id is derived from the device's public key, exactly as the
//! cloud and the firmware derive it — via `flora_protocol::device_id_bytes`
//! — so all three sides cannot disagree. Tokens are random and shown only
//! here; the cloud receives their SHA-256.

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

/// Derive the 32-hex-character gateway id from a hex-encoded public key.
pub fn device_id_from_public_key(public_key_hex: &str) -> Result<String> {
    let public_key = decode_hex::<32>(public_key_hex).context("aggregator public key")?;
    let id = flora_protocol::device_id_bytes(&public_key).context("derive gateway id")?;
    Ok(encode_hex(&id))
}

/// A fresh device token: 32 random bytes, hex-encoded.
pub fn generate_device_token() -> Result<String> {
    let mut token = [0u8; 32];
    getrandom::fill(&mut token)
        .map_err(|error| anyhow::anyhow!("operating-system RNG failed: {error:?}"))?;
    Ok(encode_hex(&token))
}

/// Decode a hex string of exactly `N` bytes.
pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "expected {N} hexadecimal bytes");
    let bytes = value.as_bytes();
    let mut decoded = [0u8; N];
    for (index, output_byte) in decoded.iter_mut().enumerate() {
        *output_byte = (hex_nibble(bytes[index * 2])? << 4) | hex_nibble(bytes[index * 2 + 1])?;
    }
    Ok(decoded)
}

/// Lowercase hex, matching what the cloud's `flora_auth::hex` produces.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// SHA-256 over the bytes a hex string denotes, hex-encoded.
///
/// The cloud stores hashes and compares them against `hash_token` of what
/// the device presents, so both sides must agree on exactly this
/// construction: digest the raw bytes, not the hex text.
pub fn hash_hex_secret(secret_hex: &str) -> Result<String> {
    let raw = decode_hex_any(secret_hex).context("secret is not valid hex")?;
    Ok(encode_hex(&Sha256::digest(&raw)))
}

/// Decode hex of any even length.
///
/// The fixed-size [`decode_hex`] is right where the width is a contract;
/// this is for values whose length is a runtime property, such as a secret
/// being hashed.
pub fn decode_hex_any(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len().is_multiple_of(2),
        "hex string has an odd number of characters"
    );
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => anyhow::bail!("invalid hexadecimal character"),
    }
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_matches_the_protocol_derivation() {
        let public_key = encode_hex(&(0u8..32).collect::<Vec<_>>());
        let key = decode_hex::<32>(&public_key).unwrap();
        let expected = encode_hex(&flora_protocol::device_id_bytes(&key).unwrap());
        assert_eq!(device_id_from_public_key(&public_key).unwrap(), expected);
        assert_eq!(device_id_from_public_key(&public_key).unwrap().len(), 32);
    }

    #[test]
    fn token_is_256_bit_and_hex() {
        let token = generate_device_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hashes_match_the_construction_the_cloud_verifies() {
        // SHA-256 over the raw bytes the hex denotes, not over the hex text.
        let secret = "00".repeat(32);
        let expected = encode_hex(&Sha256::digest([0u8; 32]));
        assert_eq!(hash_hex_secret(&secret).unwrap(), expected);
        assert_eq!(hash_hex_secret(&secret).unwrap().len(), 64);
    }

    #[test]
    fn a_short_secret_still_hashes_rather_than_panicking() {
        assert!(hash_hex_secret("abcd").is_ok());
        assert!(hash_hex_secret("not hex").is_err());
        assert!(hash_hex_secret("abc").is_err());
    }

    #[test]
    fn rejects_malformed_public_key() {
        assert!(device_id_from_public_key("abcd").is_err());
        assert!(device_id_from_public_key(&"zz".repeat(32)).is_err());
    }
}
