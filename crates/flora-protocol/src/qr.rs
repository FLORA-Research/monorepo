//! The `flora://pair` QR payload: what a phone scans to claim a
//! freshly provisioned aggregator.
//!
//! One shape, parsed by exactly one code path in the app. The builder is
//! allocation-free (writes into a caller buffer) because the provisioner
//! renders it under an embassy timeout and the cloud only needs the
//! string form once.

/// Prefix of the pairing QR payload.
pub const PAIR_SCHEME: &str = "flora://pair?v=1";

/// Build `flora://pair?v=1&id=..&ct=..&u=..` into `out`.
///
/// `device_id` is the 32-char hex gateway id, `claim_token` the 64-char
/// hex token the cloud issued, and `uuid` the 16-char hex aggregator
/// UUID. Returns the written slice, or `None` if the buffer is short.
pub fn pair_qr_payload<'a>(
    device_id: &str,
    claim_token: &str,
    uuid: &str,
    out: &'a mut [u8],
) -> Option<&'a [u8]> {
    let need = PAIR_SCHEME.len()
        + "&id=".len()
        + device_id.len()
        + "&ct=".len()
        + claim_token.len()
        + "&u=".len()
        + uuid.len();
    let out = out.get_mut(..need)?;
    let mut at = 0;
    for chunk in [
        PAIR_SCHEME.as_bytes(),
        b"&id=",
        device_id.as_bytes(),
        b"&ct=",
        claim_token.as_bytes(),
        b"&u=",
        uuid.as_bytes(),
    ] {
        out[at..at + chunk.len()].copy_from_slice(chunk);
        at += chunk.len();
    }
    Some(out)
}

/// Parse a `flora://pair` payload back into its parts.
///
/// The app side of the contract: returns `(device_id, claim_token, uuid)`
/// from the scanned string. Anything else — wrong scheme, missing
/// version, reordered fields — is a parse failure, not a best effort.
pub fn parse_pair_payload(payload: &str) -> Option<(&str, &str, &str)> {
    let rest = payload.strip_prefix(PAIR_SCHEME)?;
    let mut device_id = None;
    let mut claim_token = None;
    let mut uuid = None;
    for field in rest.split('&').skip(1) {
        let (key, value) = field.split_once('=')?;
        match key {
            "id" => device_id = Some(value),
            "ct" => claim_token = Some(value),
            "u" => uuid = Some(value),
            _ => return None,
        }
    }
    Some((device_id?, claim_token?, uuid?))
}
