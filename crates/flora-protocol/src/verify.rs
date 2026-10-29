//! Host-side Ed25519 signature verification.
//!
//! This module exists behind the `verify` feature: the server must
//! check app signatures against the same wire contract the aggregator
//! enforces, but dalek cannot link for thumbv6m, so the firmware path
//! uses `ed25519-compact` in `flora-device` instead. Both accept the
//! same signatures — the cross-implementation parity test in
//! `flora-device` proves the bytes agree.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::command::{PUBLIC_KEY_LEN, ProtocolError, SIGNATURE_LEN};

/// Verify a signature over any flow message (pair, auth, invite, or
/// canonical command).
///
/// `from_bytes` rejects non-canonical key encodings; `verify_strict`
/// additionally rejects low-order keys and non-canonical signatures,
/// which matters when the signed payload is the only thing standing
/// between a hostile cloud and a physical valve.
pub fn verify_command_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ProtocolError> {
    let key_bytes: [u8; PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| ProtocolError::PublicKeyLength)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| ProtocolError::PublicKeyEncoding)?;
    let signature_bytes: [u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| ProtocolError::SignatureLength)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(message, &signature)
        .map_err(|_| ProtocolError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    #[test]
    fn a_valid_signature_verifies() {
        let key = keypair();
        let message = b"flora-auth-v1\x01\x02\x03";
        let signature = key.sign(message);
        assert!(
            verify_command_signature(
                key.verifying_key().as_bytes(),
                message,
                &signature.to_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn wrong_key_tampered_message_and_bad_lengths_are_refused() {
        let key = keypair();
        let message = b"flora-pair-v1";
        let signature = key.sign(message);

        // Presented under a different key.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(
            verify_command_signature(
                other.verifying_key().as_bytes(),
                message,
                &signature.to_bytes()
            ),
            Err(ProtocolError::Signature)
        );
        // Message altered after signing.
        assert_eq!(
            verify_command_signature(
                key.verifying_key().as_bytes(),
                b"flora-pair-v2",
                &signature.to_bytes()
            ),
            Err(ProtocolError::Signature)
        );
        // Length violations are distinguished from signature failures.
        assert_eq!(
            verify_command_signature(&[0u8; 16], message, &signature.to_bytes()),
            Err(ProtocolError::PublicKeyLength)
        );
        assert_eq!(
            verify_command_signature(key.verifying_key().as_bytes(), message, &[0u8; 10]),
            Err(ProtocolError::SignatureLength)
        );
    }
}
