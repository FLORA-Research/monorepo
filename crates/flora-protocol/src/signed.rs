//! Domain-separated signing messages for the account flows.
//!
//! Three flows exist — pairing, sign-in, invite acceptance — and a
//! signature made for one must not verify in another. Each message starts
//! with a distinct prefix, so the same key material cannot be tricked into
//! signing a different flow's meaning. The pairing and auth messages are
//! built by both the app and the cloud; the invite message by the app and
//! the API. All three are pinned here so no side invents its own layout.

use crate::command::{NONCE_LEN, PUBLIC_KEY_LEN, TOKEN_LEN};

/// Prefix of the pairing-claim message: `flora-pair-v1 || device_id ||
/// 0x00 || claim_token || nonce`.
///
/// The `0x00` separator stops an ambiguous concatenation where two
/// different (device_id, token) pairs produce the same byte string.
pub const PAIR_PREFIX: &[u8] = b"flora-pair-v1";

/// Prefix of the sign-in message: `flora-auth-v1 || pubkey || nonce`.
pub const AUTH_PREFIX: &[u8] = b"flora-auth-v1";

/// Prefix of the invite-acceptance message: `flora-invite-v1 || pubkey ||
/// invite_token || nonce`.
pub const INVITE_PREFIX: &[u8] = b"flora-invite-v1";

/// Message an app signs to claim a freshly provisioned aggregator.
///
/// `device_id` is the 32-byte lowercase-ASCII hex form of the 16-byte
/// device id. `claim_token` and `nonce` are raw bytes.
pub fn pair_message<'a>(
    device_id_hex: &[u8],
    claim_token: &[u8; TOKEN_LEN],
    nonce: &[u8; NONCE_LEN],
    out: &'a mut [u8],
) -> Option<&'a [u8]> {
    let len = PAIR_PREFIX.len() + device_id_hex.len() + 1 + TOKEN_LEN + NONCE_LEN;
    let out = out.get_mut(..len)?;
    let mut at = 0;
    out[..PAIR_PREFIX.len()].copy_from_slice(PAIR_PREFIX);
    at += PAIR_PREFIX.len();
    out[at..at + device_id_hex.len()].copy_from_slice(device_id_hex);
    at += device_id_hex.len();
    out[at] = 0x00;
    at += 1;
    out[at..at + TOKEN_LEN].copy_from_slice(claim_token);
    at += TOKEN_LEN;
    out[at..at + NONCE_LEN].copy_from_slice(nonce);
    Some(out)
}

/// Message an app signs to sign in: `flora-auth-v1 || pubkey || nonce`.
pub fn auth_message<'a>(
    public_key: &[u8; PUBLIC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    out: &'a mut [u8],
) -> Option<&'a [u8]> {
    let len = AUTH_PREFIX.len() + PUBLIC_KEY_LEN + NONCE_LEN;
    let out = out.get_mut(..len)?;
    out[..AUTH_PREFIX.len()].copy_from_slice(AUTH_PREFIX);
    let at = AUTH_PREFIX.len();
    out[at..at + PUBLIC_KEY_LEN].copy_from_slice(public_key);
    out[at + PUBLIC_KEY_LEN..].copy_from_slice(nonce);
    Some(out)
}

/// Message an app signs to accept an invite: `flora-invite-v1 || pubkey ||
/// invite_token || nonce`.
pub fn invite_message<'a>(
    public_key: &[u8; PUBLIC_KEY_LEN],
    invite_token: &[u8; TOKEN_LEN],
    nonce: &[u8; NONCE_LEN],
    out: &'a mut [u8],
) -> Option<&'a [u8]> {
    let len = INVITE_PREFIX.len() + PUBLIC_KEY_LEN + TOKEN_LEN + NONCE_LEN;
    let out = out.get_mut(..len)?;
    out[..INVITE_PREFIX.len()].copy_from_slice(INVITE_PREFIX);
    let mut at = INVITE_PREFIX.len();
    out[at..at + PUBLIC_KEY_LEN].copy_from_slice(public_key);
    at += PUBLIC_KEY_LEN;
    out[at..at + TOKEN_LEN].copy_from_slice(invite_token);
    at += TOKEN_LEN;
    out[at..at + NONCE_LEN].copy_from_slice(nonce);
    Some(out)
}

/// One hex character to its nibble, or `None`.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode a hex string into `out`, returning the decoded length.
///
/// Rejects odd lengths and non-hex characters rather than decoding a
/// prefix: a malformed token must fail loudly, not partially.
pub fn decode_hex_into(hex: &str, out: &mut [u8]) -> Option<usize> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let len = bytes.len() / 2;
    let out = out.get_mut(..len)?;
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(len)
}
