//! App-command signature verification.
//!
//! The cloud is a relay, not an authority: a compromised cloud must not
//! be able to open a valve. Every manual command carries an Ed25519
//! signature over the canonical byte encoding from `flora-protocol`, and
//! the aggregator verifies it against the account key before acting.

use ed25519_compact::{PublicKey, Signature};

/// Maximum tolerated signer clock skew ahead of the aggregator, seconds.
pub const SKEW_S: u32 = 300;
/// Maximum accepted age of a signed command, seconds.
pub const MAX_AGE_S: u32 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Public key is malformed, non-canonical, or low-order.
    InvalidPublicKey,
    /// Signature is not 64 bytes or is not a valid encoding.
    InvalidSignature,
    /// The signature does not match the message under this key.
    BadSignature,
    /// The nonce has already been seen; the command is a replay.
    Replayed,
    /// The signed timestamp is outside the accepted window.
    Stale,
}

/// Rolling cache of accepted nonces.
///
/// Bounded so a hostile cloud cannot exhaust memory: once full, the
/// oldest entry is evicted. Entries are additionally aged out by
/// timestamp so a long run does not accumulate stale nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceCache<const N: usize> {
    entries: [(u32, u32); N],
    len: usize,
    next: usize,
}

impl<const N: usize> Default for NonceCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NonceCache<N> {
    pub const fn new() -> Self {
        Self {
            entries: [(0, 0); N],
            len: 0,
            next: 0,
        }
    }

    /// True when `nonce` was accepted at or after `not_before`.
    pub fn contains(&self, nonce: u32, not_before: u32, now: u32) -> bool {
        self.entries[..self.len]
            .iter()
            .any(|(n, ts)| *n == nonce && timestamp_in_window(*ts, not_before, now))
    }

    /// Record a nonce. Returns `false` if it was already present in the
    /// window.
    pub fn insert(&mut self, nonce: u32, timestamp: u32) -> bool {
        if self.len == N {
            // Window is full: overwrite the oldest slot.
            self.entries[self.next] = (nonce, timestamp);
            self.next = (self.next + 1) % N;
            return true;
        }
        self.entries[self.len] = (nonce, timestamp);
        self.len += 1;
        true
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }
}

/// Accept anything at or after the window start, including future
/// timestamps skewed forward within the same wrapped window.
fn timestamp_in_window(stamp: u32, not_before: u32, now: u32) -> bool {
    stamp.wrapping_sub(not_before) as i32 >= 0 && now.wrapping_sub(stamp) as i32 >= -(SKEW_S as i32)
}

/// Verify a signed manual command.
///
/// Checks, in order: public-key validity, signature validity, freshness,
/// and replay. The nonce is only recorded on full success.
pub fn verify_command<const N: usize>(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    nonce: u32,
    timestamp: u32,
    cache: &mut NonceCache<N>,
    now: u32,
) -> Result<(), VerifyError> {
    let key = PublicKey::from_slice(public_key).map_err(|_| VerifyError::InvalidPublicKey)?;
    // Reject non-canonical or low-order keys explicitly.
    key.validate().map_err(|_| VerifyError::InvalidPublicKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| VerifyError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| VerifyError::BadSignature)?;

    // Reject stale commands so a captured-and-replayed payload expires.
    let age = now.wrapping_sub(timestamp);
    if age as i32 > MAX_AGE_S as i32 {
        return Err(VerifyError::Stale);
    }
    if timestamp.wrapping_sub(now) as i32 > SKEW_S as i32 {
        return Err(VerifyError::Stale);
    }

    let window_start = now.wrapping_sub(MAX_AGE_S);
    if cache.contains(nonce, window_start, now) {
        return Err(VerifyError::Replayed);
    }
    cache.insert(nonce, timestamp);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use ed25519_compact::{KeyPair, Seed};
    use flora_protocol::canonical_message;

    const N: usize = 8;

    fn keypair(seed_byte: u8) -> KeyPair {
        KeyPair::from_seed(Seed::new([seed_byte; 32]))
    }

    fn signed(
        keypair: &KeyPair,
        kind: u8,
        node_addr: u8,
        nonce: u32,
        timestamp: u32,
    ) -> ([u8; 31], Vec<u8>) {
        let message = canonical_message(
            kind,
            b"agg-0001agg-0001",
            node_addr,
            nonce,
            timestamp,
            &[0, 1, 2, 3],
        );
        let signature = keypair.sk.sign(message, None);
        (message, signature.to_vec())
    }

    #[test]
    fn accepts_a_correctly_signed_fresh_command() {
        let keypair = keypair(7);
        let (message, signature) = signed(&keypair, flora_protocol::KIND_SET_VALVE, 4, 1, 1_000);
        let mut cache = NonceCache::<N>::new();
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                &signature,
                &message,
                1,
                1_000,
                &mut cache,
                1_010
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        let signer = keypair(7);
        let attacker = keypair(9);
        let (message, signature) = signed(&signer, flora_protocol::KIND_SET_VALVE, 4, 1, 1_000);
        let mut cache = NonceCache::<N>::new();
        assert_eq!(
            verify_command(
                attacker.pk.as_ref(),
                &signature,
                &message,
                1,
                1_000,
                &mut cache,
                1_010
            ),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_a_tampered_message() {
        let keypair = keypair(7);
        let (mut message, signature) =
            signed(&keypair, flora_protocol::KIND_SET_VALVE, 4, 1, 1_000);
        // Flip the target node address after signing.
        message[18] = 9;
        let mut cache = NonceCache::<N>::new();
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                &signature,
                &message,
                1,
                1_000,
                &mut cache,
                1_010
            ),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_replay_of_an_accepted_command() {
        let keypair = keypair(7);
        let (message, signature) = signed(&keypair, flora_protocol::KIND_SET_VALVE, 4, 5, 1_000);
        let mut cache = NonceCache::<N>::new();
        assert!(
            verify_command(
                keypair.pk.as_ref(),
                &signature,
                &message,
                5,
                1_000,
                &mut cache,
                1_010
            )
            .is_ok()
        );
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                &signature,
                &message,
                5,
                1_000,
                &mut cache,
                1_011
            ),
            Err(VerifyError::Replayed)
        );
    }

    #[test]
    fn rejects_stale_and_far_future_commands() {
        let keypair = keypair(7);
        let (message, signature) = signed(&keypair, flora_protocol::KIND_SET_VALVE, 4, 1, 1_000);
        let mut cache = NonceCache::<N>::new();
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                &signature,
                &message,
                1,
                1_000,
                &mut cache,
                1_000 + MAX_AGE_S + 1
            ),
            Err(VerifyError::Stale)
        );

        let mut cache = NonceCache::<N>::new();
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                &signature,
                &message,
                1,
                100_000,
                &mut cache,
                1_000
            ),
            Err(VerifyError::Stale)
        );
    }

    #[test]
    fn rejects_malformed_keys_and_signatures() {
        let keypair = keypair(7);
        let (message, signature) = signed(&keypair, flora_protocol::KIND_SET_VALVE, 4, 1, 1_000);
        let mut cache = NonceCache::<N>::new();
        assert_eq!(
            verify_command(
                &[0u8; 31], &signature, &message, 1, 1_000, &mut cache, 1_010
            ),
            Err(VerifyError::InvalidPublicKey)
        );
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                &[0u8; 10],
                &message,
                1,
                1_000,
                &mut cache,
                1_010
            ),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn gateway_id_is_bound_so_commands_cannot_cross_gateways() {
        // Two aggregators whose ids differ only in their final byte.
        let first = *b"agg-0001agg-0001";
        let second = *b"agg-0001agg-0002";
        let keypair = keypair(7);
        let message = canonical_message(
            flora_protocol::KIND_SET_VALVE,
            &first,
            4,
            7,
            9,
            &[1, 0, 30, 0],
        );
        let signature = keypair.sk.sign(message, None);
        let other = canonical_message(
            flora_protocol::KIND_SET_VALVE,
            &second,
            4,
            7,
            9,
            &[1, 0, 30, 0],
        );
        let mut cache = NonceCache::<N>::new();
        assert_ne!(message, other, "the gateway id must change the bytes");
        assert_eq!(
            verify_command(
                keypair.pk.as_ref(),
                signature.as_ref(),
                &other,
                7,
                9,
                &mut cache,
                9
            ),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn nonce_cache_is_bounded_and_accepts_distinct_nonces() {
        let mut cache = NonceCache::<4>::new();
        for nonce in 0..4 {
            assert!(cache.insert(nonce, 1_000));
        }
        // Overwrites the oldest slot rather than growing without bound.
        assert!(cache.insert(99, 1_000));
        assert!(cache.contains(99, 0, 1_000));

        let mut fresh = NonceCache::<4>::new();
        fresh.insert(1, 1_000);
        assert!(fresh.contains(1, 0, 1_000));
        assert!(!fresh.contains(2, 0, 1_000));
    }
}

#[cfg(test)]
mod parity_tests {
    //! The cloud signs commands with `ed25519-dalek`; the aggregator
    //! verifies with `ed25519-compact`. A signature produced by one must
    //! verify under the other or a correct command is refused in the
    //! field.

    use super::*;
    use alloc::vec::Vec;
    use ed25519_dalek::Signer;

    const SECRET: [u8; 32] = [3u8; 32];

    #[test]
    fn a_dalek_signature_verifies_under_compact() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&SECRET);
        let message = flora_protocol::canonical_message(
            flora_protocol::KIND_SET_VALVE,
            b"agg-0001agg-0001",
            4,
            7,
            9,
            &[1, 0, 30, 0],
        );
        let signature: Vec<u8> = signing.sign(&message).to_bytes().to_vec();
        let mut cache = NonceCache::<8>::new();
        assert_eq!(
            verify_command(
                signing.verifying_key().as_bytes(),
                &signature,
                &message,
                7,
                9,
                &mut cache,
                9
            ),
            Ok(())
        );
    }
}
