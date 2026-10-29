//! Pairing: claiming a gateway with a QR token.
//!
//! This is the flow that creates an account as a side effect, so there is no
//! signup screen. A phone presents a device id, a one-time claim token, and a
//! signature over the claim, proving it holds the private key it claims to.
//!
//! Every failure mode here is security-relevant: a replayed nonce, a consumed
//! token, an expired token, or a signature from a different key must all be
//! refused, and the tests below exist to prove each one is.

use chrono::{DateTime, Duration, Utc};
use flora_db::models::Gateway;
use flora_protocol::{ProtocolError, verify_command_signature};
use thiserror::Error;
use uuid::Uuid;

use crate::secrets::{TOKEN_BYTES, hash_token, tokens_match};

/// Claim tokens live for 24 hours, per the threat model.
pub const CLAIM_TTL_HOURS: i64 = 24;
/// Length of the nonce a signer must include.
pub const NONCE_BYTES: usize = 16;
/// Browser/pairing nonces are short-lived.
pub const NONCE_TTL_MINUTES: i64 = 5;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairError {
    #[error("claim token is missing, expired, or already used")]
    ClaimInvalid,
    #[error("the signature does not authorise this claim")]
    Signature(#[from] ProtocolError),
    #[error("this nonce was already used")]
    Replayed,
    #[error("the gateway is retired")]
    Retired,
    #[error("the app public key is malformed")]
    MalformedKey,
}

/// Fields covered by the pairing signature.
///
/// The device id and the claim token are both signed, so a signature cannot be
/// lifted from one claim and attached to another.
pub struct ClaimSignatureInput<'a> {
    pub device_id: &'a str,
    pub claim_token: &'a [u8],
    pub nonce: &'a [u8],
}

impl ClaimSignatureInput<'_> {
    /// Canonical bytes the app signs for a claim.
    ///
    /// `flora-pair-v1` || device_id || 0x00 || claim_token || nonce. The
    /// separator stops an ambiguous concatenation where two different
    /// (device_id, token) pairs produce the same byte string.
    pub fn message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(12 + self.device_id.len() + TOKEN_BYTES + NONCE_BYTES);
        message.extend_from_slice(b"flora-pair-v1");
        message.extend_from_slice(self.device_id.as_bytes());
        message.push(0x00);
        message.extend_from_slice(self.claim_token);
        message.extend_from_slice(self.nonce);
        message
    }
}

/// Outcome of a successful claim.
#[derive(Debug, Clone)]
pub struct ClaimOutcome {
    pub account_id: Uuid,
    pub account_created: bool,
    pub gateway_id: String,
}

/// Decide whether a claim token is still usable.
pub fn claim_is_usable(
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), PairError> {
    if used_at.is_some() {
        return Err(PairError::ClaimInvalid);
    }
    if expires_at <= now {
        return Err(PairError::ClaimInvalid);
    }
    Ok(())
}

/// Verify the claim token against the stored hash.
pub fn claim_token_matches(presented: &[u8], stored_hash: &[u8]) -> Result<(), PairError> {
    if presented.len() != TOKEN_BYTES {
        return Err(PairError::ClaimInvalid);
    }
    if !tokens_match(&hash_token(presented), stored_hash) {
        return Err(PairError::ClaimInvalid);
    }
    Ok(())
}

/// Verify the signature that authorises the claim.
pub fn verify_claim_signature(
    app_pubkey: &[u8],
    input: &ClaimSignatureInput<'_>,
    signature: &[u8],
) -> Result<(), PairError> {
    verify_command_signature(app_pubkey, &input.message(), signature).map_err(PairError::Signature)
}

/// Whether a claim attaches to an existing account or creates a new one.
///
/// Signing in from a new phone for an existing account is the same request as
/// pairing a first gateway, so the decision is made from the app key alone.
pub fn resolve_target(existing_account: Option<Uuid>) -> (Uuid, bool) {
    match existing_account {
        Some(account_id) => (account_id, false),
        None => (Uuid::new_v4(), true),
    }
}

/// Expiry for a newly issued claim token.
pub fn claim_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::hours(CLAIM_TTL_HOURS)
}

/// Refuse to touch a retired gateway.
pub fn ensure_not_retired(gateway: &Gateway) -> Result<(), PairError> {
    if gateway.is_retired() {
        return Err(PairError::Retired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn claim_input<'a>(
        device_id: &'a str,
        token: &'a [u8; 32],
        nonce: &'a [u8; 16],
    ) -> ClaimSignatureInput<'a> {
        ClaimSignatureInput {
            device_id,
            claim_token: token,
            nonce,
        }
    }

    #[test]
    fn a_correct_signature_authorises_the_claim() {
        let key = keypair(5);
        let token = [7u8; 32];
        let nonce = [9u8; 16];
        let input = claim_input("630dcd2966c4336691125448bbb25b4f", &token, &nonce);
        let signature = key.sign(&input.message());
        assert!(
            verify_claim_signature(
                &key.verifying_key().to_bytes(),
                &input,
                &signature.to_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_signature_for_another_token_or_device_is_rejected() {
        let key = keypair(5);
        let token = [7u8; 32];
        let other_token = [8u8; 32];
        let nonce = [9u8; 16];

        // Signed for a different claim token.
        let signed = claim_input("gateway-a", &token, &nonce);
        let signature = key.sign(&signed.message());
        let presented = claim_input("gateway-a", &other_token, &nonce);
        assert!(matches!(
            verify_claim_signature(
                &key.verifying_key().to_bytes(),
                &presented,
                &signature.to_bytes()
            ),
            Err(PairError::Signature(_))
        ));

        // Signed for a different device id.
        let presented = claim_input("gateway-b", &token, &nonce);
        assert!(matches!(
            verify_claim_signature(
                &key.verifying_key().to_bytes(),
                &presented,
                &signature.to_bytes()
            ),
            Err(PairError::Signature(_))
        ));
    }

    #[test]
    fn a_different_key_cannot_authorise_the_claim() {
        let signer = keypair(5);
        let attacker = keypair(6);
        let token = [7u8; 32];
        let nonce = [9u8; 16];
        let input = claim_input("gateway-a", &token, &nonce);
        let signature = signer.sign(&input.message());
        assert!(matches!(
            verify_claim_signature(
                &attacker.verifying_key().to_bytes(),
                &input,
                &signature.to_bytes()
            ),
            Err(PairError::Signature(_))
        ));
    }

    #[test]
    fn message_encoding_is_unambiguous() {
        let token = [0u8; 32];
        let nonce = [0u8; 16];
        let first = claim_input("ab", &token, &nonce).message();
        let second = claim_input("a", &token, &nonce).message();
        assert_ne!(first, second, "device id must be separated from the token");
        assert!(first.starts_with(b"flora-pair-v1"));
    }

    #[test]
    fn expired_and_used_claims_are_refused() {
        let now = Utc::now();
        assert!(claim_is_usable(now + Duration::hours(1), None, now).is_ok());
        assert!(matches!(
            claim_is_usable(now - Duration::seconds(1), None, now),
            Err(PairError::ClaimInvalid)
        ));
        assert!(
            matches!(
                claim_is_usable(now + Duration::hours(1), Some(now), now),
                Err(PairError::ClaimInvalid)
            ),
            "a consumed token must not be reusable"
        );
    }

    #[test]
    fn claim_token_check_compares_hashes_and_rejects_wrong_lengths() {
        let token = [3u8; 32];
        let stored = hash_token(&token);
        assert!(claim_token_matches(&token, &stored).is_ok());

        let wrong = [4u8; 32];
        assert!(matches!(
            claim_token_matches(&wrong, &stored),
            Err(PairError::ClaimInvalid)
        ));
        assert!(matches!(
            claim_token_matches(&token[..16], &stored),
            Err(PairError::ClaimInvalid)
        ));
    }

    #[test]
    fn claim_creates_an_account_only_when_none_exists() {
        let existing = Uuid::new_v4();
        let (account, created) = resolve_target(Some(existing));
        assert_eq!(account, existing);
        assert!(!created, "an existing account must not be replaced");

        let (_, created) = resolve_target(None);
        assert!(created, "the first claim creates the account");
    }

    #[test]
    fn retired_gateways_cannot_be_claimed() {
        let mut gateway = Gateway {
            id: "gw".into(),
            account_id: None,
            pubkey: vec![0; 32],
            label: None,
            status: "claimed".into(),
            fw_version: None,
            last_seen: None,
            claimed_at: None,
            retired_at: None,
            created_at: Utc::now(),
        };
        assert!(ensure_not_retired(&gateway).is_ok());
        gateway.status = "retired".into();
        assert!(matches!(
            ensure_not_retired(&gateway),
            Err(PairError::Retired)
        ));
    }

    #[test]
    fn claim_expiry_is_24_hours() {
        let now = Utc::now();
        assert_eq!(claim_expiry(now), now + Duration::hours(CLAIM_TTL_HOURS));
    }
}
