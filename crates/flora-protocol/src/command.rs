//! The canonical command encoding that apps sign and aggregators verify.
//!
//! Manual commands are relayed by the cloud, and the cloud is a relay, not
//! an authority: a compromised cloud must not be able to open a valve.
//! Every manual command therefore carries an Ed25519 signature over these
//! exact bytes, and the aggregator verifies it against the account key
//! before acting. Field order and widths are fixed here so the app, the
//! cloud, and the firmware agree without a shared JSON schema.
//!
//! `docs/commands.md` describes the same bytes in prose.

use sha2::Digest;

/// Length of the canonical command message.
///
/// Layout: `version(1) kind(1) gateway_id(16) node_addr(1) nonce(4)
/// timestamp(4) payload(4)`.
pub const CANONICAL_MESSAGE_LEN: usize = 31;

/// Version byte of the canonical encoding. Bumping it invalidates every
/// signature, so both sides must change together.
pub const CANONICAL_VERSION: u8 = 0x01;

/// Command kinds, mirrored from the aggregator. Kept numeric so the
/// canonical encoding is stable and independent of any JSON field ordering.
pub const KIND_SET_VALVE: u8 = 1;
pub const KIND_SET_THRESHOLD: u8 = 2;
pub const KIND_CALIBRATE: u8 = 3;

/// Bytes in a gateway identifier: the 16-byte `device_id`, matching the
/// provisioner's `SHA-256(pubkey)[..16]` derivation.
///
/// The full id is covered by the signature. Binding only a prefix would
/// let a command signed for one aggregator verify against another whose
/// id shares those bytes.
pub const GATEWAY_ID_LEN: usize = 16;

/// Bytes in an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Bytes in an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Bytes in a claim or invite token.
pub const TOKEN_LEN: usize = 32;
/// Bytes in a signature nonce.
pub const NONCE_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Public key is not [`PUBLIC_KEY_LEN`] bytes.
    PublicKeyLength,
    /// The output buffer is too small for the encoded result.
    OutputTooSmall,
    /// Public key is not a canonical Ed25519 point. Only produced by the
    /// `verify` feature; the firmware's `ed25519-compact` reports the
    /// same condition as a generic verify failure.
    PublicKeyEncoding,
    /// Signature is not [`SIGNATURE_LEN`] bytes.
    SignatureLength,
    /// Signature verification failed.
    Signature,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::PublicKeyLength => {
                write!(f, "public key must be {PUBLIC_KEY_LEN} bytes")
            }
            ProtocolError::OutputTooSmall => write!(f, "output buffer too small"),
            ProtocolError::PublicKeyEncoding => {
                write!(f, "public key is not a valid Ed25519 point")
            }
            ProtocolError::SignatureLength => {
                write!(f, "signature must be {SIGNATURE_LEN} bytes")
            }
            ProtocolError::Signature => write!(f, "signature verification failed"),
        }
    }
}

impl core::error::Error for ProtocolError {}

/// Encode the message an app signs for a manual command.
///
/// Byte-for-byte identical to the aggregator's encoder: `version(1)
/// kind(1) gateway_id(16) node_addr(1) nonce(4) timestamp(4) payload(4)`,
/// multi-byte fields big-endian.
pub fn canonical_message(
    kind: u8,
    gateway_id: &[u8; GATEWAY_ID_LEN],
    node_addr: u8,
    nonce: u32,
    timestamp: u32,
    payload: &[u8; 4],
) -> [u8; CANONICAL_MESSAGE_LEN] {
    let mut message = [0u8; CANONICAL_MESSAGE_LEN];
    message[0] = CANONICAL_VERSION;
    message[1] = kind;
    message[2..18].copy_from_slice(gateway_id);
    message[18] = node_addr;
    message[19..23].copy_from_slice(&nonce.to_be_bytes());
    message[23..27].copy_from_slice(&timestamp.to_be_bytes());
    message[27..31].copy_from_slice(payload);
    message
}

/// Derive the raw device identifier from an aggregator public key:
/// `SHA-256(pubkey)[..16]`.
///
/// Identical to the provisioner's derivation, so a device flashed by the
/// CLI is recognised by the cloud.
pub fn device_id_bytes(public_key: &[u8]) -> Result<[u8; GATEWAY_ID_LEN], ProtocolError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(ProtocolError::PublicKeyLength);
    }
    let digest = sha2::Sha256::digest(public_key);
    let mut id = [0u8; GATEWAY_ID_LEN];
    id.copy_from_slice(&digest[..GATEWAY_ID_LEN]);
    Ok(id)
}

/// Derive the device identifier as the 32-character lowercase hex string
/// used on the wire and in QR payloads.
///
/// Writes exactly `2 * GATEWAY_ID_LEN` ASCII bytes into `out` and returns
/// the count written.
pub fn device_id_hex(public_key: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
    let id = device_id_bytes(public_key)?;
    let out = out
        .get_mut(..2 * GATEWAY_ID_LEN)
        .ok_or(ProtocolError::OutputTooSmall)?;
    hex_lower(&id, out);
    Ok(out.len())
}

fn hex_lower(bytes: &[u8], out: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in bytes.iter().enumerate() {
        out[2 * i] = DIGITS[(byte >> 4) as usize];
        out[2 * i + 1] = DIGITS[(byte & 0x0F) as usize];
    }
}
