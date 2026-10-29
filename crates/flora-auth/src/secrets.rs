//! Secrets: token generation, hashing, and the provision API key.

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use password_hash::phc::PasswordHash;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Bytes of entropy in every opaque token (claim, device, refresh, invite).
pub const TOKEN_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("failed to generate random bytes")]
    Random,
    #[error("password hashing failed")]
    Hash,
    #[error("stored hash is malformed")]
    MalformedHash,
}

/// Generate an opaque token as raw bytes.
pub fn generate_token() -> Result<[u8; TOKEN_BYTES], SecretError> {
    let mut token = [0u8; TOKEN_BYTES];
    // The platform's CSPRNG. Token unpredictability is the only thing standing
    // between an unclaimed device and being paired by a stranger who guesses.
    getrandom::fill(&mut token).map_err(|_| SecretError::Random)?;
    Ok(token)
}

/// Generate a token and return it as lowercase hex.
pub fn generate_token_hex() -> Result<String, SecretError> {
    Ok(hex(&generate_token()?))
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

pub fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        out.push((nibble(bytes[index])? << 4) | nibble(bytes[index + 1])?);
    }
    Some(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Hash a token for storage.
///
/// These tokens are 256 bits of uniform randomness, so they cannot be guessed
/// and a fast digest is the right tool: there is no low-entropy secret here to
/// brute-force. A human-chosen password would need Argon2 instead.
pub fn hash_token(token: &[u8]) -> Vec<u8> {
    Sha256::digest(token).to_vec()
}

/// Constant-time comparison, so a token check does not leak its prefix.
pub fn tokens_match(candidate: &[u8], expected: &[u8]) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in candidate.iter().zip(expected) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Hash the provision API key for storage.
///
/// This one *is* a human-managed secret that may be short or reused across
/// environments, so it gets a memory-hard KDF rather than a plain digest.
pub fn hash_api_key(api_key: &str) -> Result<String, SecretError> {
    let salt = password_hash::generate_salt();
    Argon2::default()
        .hash_password_with_salt(api_key.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| SecretError::Hash)
}

/// Verify the provision API key against a stored Argon2 hash.
pub fn verify_api_key(api_key: &str, stored_hash: &str) -> Result<bool, SecretError> {
    let parsed = PasswordHash::new(stored_hash).map_err(|_| SecretError::MalformedHash)?;
    Ok(Argon2::default()
        .verify_password(api_key.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bit_and_unique() {
        let first = generate_token().unwrap();
        let second = generate_token().unwrap();
        assert_eq!(first.len(), TOKEN_BYTES);
        assert_ne!(first, second, "tokens must not repeat");
        assert_eq!(generate_token_hex().unwrap().len(), TOKEN_BYTES * 2);
    }

    #[test]
    fn token_hash_is_stable_and_not_the_token() {
        let token = generate_token().unwrap();
        let hash = hash_token(&token);
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, hash_token(&token));
        assert_ne!(hash, token.to_vec(), "storage must not reveal the token");
    }

    #[test]
    fn comparison_rejects_wrong_and_truncated_values() {
        let token = generate_token().unwrap();
        assert!(tokens_match(&token, &token));
        let mut altered = token;
        altered[0] ^= 0x01;
        assert!(!tokens_match(&altered, &token));
        assert!(
            !tokens_match(&token[..8], &token),
            "a prefix must not match"
        );
    }

    #[test]
    fn api_key_round_trips_through_argon2() {
        let hash = hash_api_key("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2"), "unescaped hash: {hash}");
        assert!(verify_api_key("correct horse battery staple", &hash).unwrap());
        assert!(!verify_api_key("wrong key", &hash).unwrap());
        assert!(matches!(
            verify_api_key("anything", "not-a-hash"),
            Err(SecretError::MalformedHash)
        ));
    }

    #[test]
    fn api_key_hashes_are_salted() {
        let first = hash_api_key("same-key").unwrap();
        let second = hash_api_key("same-key").unwrap();
        assert_ne!(first, second, "a shared salt would let one crack cover all");
        assert!(verify_api_key("same-key", &first).unwrap());
        assert!(verify_api_key("same-key", &second).unwrap());
    }

    #[test]
    fn hex_round_trips_and_rejects_odd_input() {
        let raw = generate_token().unwrap();
        let encoded = hex(&raw);
        assert_eq!(unhex(&encoded).unwrap(), raw.to_vec());
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
