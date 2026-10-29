//! The identity record: what the aggregator stores about itself and the
//! cloud.
//!
//! Split out from the flash driver so the encoding can be tested on a
//! host. The record is the one piece of this device that cannot be
//! recovered by re-flashing: the provisioner writes it once and the
//! operator's disk holds the only other copy. A format bug here is a
//! device that boots believing it was never provisioned, so the layout
//! is fixed offsets and a CRC rather than a serialized struct that a
//! dependency change could quietly redefine.

use core::str;

use flora_protocol::GATEWAY_ID_LEN;

/// Page size for a storage record.
///
/// Larger than the node's config page because an identity record carries
/// the cloud URL and the WiFi credentials as well as the device token.
/// It stays under one erase sector, which is what keeps a bank
/// independently erasable.
pub const RECORD_PAGE_SIZE: usize = 512;

/// Longest device token accepted, in hex characters. 32 bytes, matching
/// the provisioner's `generate_device_token`.
pub const DEVICE_TOKEN_HEX_LEN: usize = 64;
/// Longest device id accepted. The gateway id is 16 bytes, so 32 hex
/// characters.
pub const DEVICE_ID_LEN: usize = 32;
/// Longest cloud URL accepted, including scheme and a trailing slash.
pub const CLOUD_URL_LEN: usize = 96;
/// Longest WiFi SSID accepted. 32 is the 802.11 limit.
pub const WIFI_SSID_LEN: usize = 32;
/// Longest WiFi password accepted. 63 is the WPA2 passphrase limit.
pub const WIFI_PASSWORD_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    Flash,
    UnsupportedFlash,
    InvalidUniqueId,
    VerifyFailed,
    /// The record on flash is present but not decodable.
    Corrupt,
    /// A supplied string does not fit its field.
    TooLong,
}

/// Everything the cloud uplink needs, held in flash.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    pub gateway_id: [u8; GATEWAY_ID_LEN],
    device_id: [u8; DEVICE_ID_LEN],
    device_id_len: u8,
    device_token: [u8; DEVICE_TOKEN_HEX_LEN],
    device_token_len: u8,
    cloud_url: [u8; CLOUD_URL_LEN],
    cloud_url_len: u8,
    wifi_ssid: [u8; WIFI_SSID_LEN],
    wifi_ssid_len: u8,
    wifi_password: [u8; WIFI_PASSWORD_LEN],
    wifi_password_len: u8,
}

impl Identity {
    pub const EMPTY: Self = Self {
        gateway_id: [0; GATEWAY_ID_LEN],
        device_id: [0; DEVICE_ID_LEN],
        device_id_len: 0,
        device_token: [0; DEVICE_TOKEN_HEX_LEN],
        device_token_len: 0,
        cloud_url: [0; CLOUD_URL_LEN],
        cloud_url_len: 0,
        wifi_ssid: [0; WIFI_SSID_LEN],
        wifi_ssid_len: 0,
        wifi_password: [0; WIFI_PASSWORD_LEN],
        wifi_password_len: 0,
    };

    /// Whether commissioning has happened.
    pub fn is_provisioned(&self) -> bool {
        self.device_id_len > 0 && self.device_token_len > 0 && self.cloud_url_len > 0
    }

    pub fn device_id(&self) -> &str {
        str::from_utf8(&self.device_id[..self.device_id_len as usize]).unwrap_or("")
    }

    pub fn device_token(&self) -> &str {
        str::from_utf8(&self.device_token[..self.device_token_len as usize]).unwrap_or("")
    }

    pub fn cloud_url(&self) -> &str {
        str::from_utf8(&self.cloud_url[..self.cloud_url_len as usize]).unwrap_or("")
    }

    pub fn wifi_ssid(&self) -> &str {
        str::from_utf8(&self.wifi_ssid[..self.wifi_ssid_len as usize]).unwrap_or("")
    }

    pub fn wifi_password(&self) -> &str {
        str::from_utf8(&self.wifi_password[..self.wifi_password_len as usize]).unwrap_or("")
    }

    /// Build an identity from the strings handed over during
    /// commissioning.
    pub fn from_parts(
        gateway_id: [u8; GATEWAY_ID_LEN],
        device_id: &str,
        device_token: &str,
        cloud_url: &str,
        wifi_ssid: &str,
        wifi_password: &str,
    ) -> Result<Self, StorageError> {
        let mut identity = Self::EMPTY;
        identity.gateway_id = gateway_id;
        identity.device_id_len = copy_field(device_id, &mut identity.device_id)?;
        identity.device_token_len = copy_field(device_token, &mut identity.device_token)?;
        identity.cloud_url_len = copy_field(cloud_url, &mut identity.cloud_url)?;
        identity.wifi_ssid_len = copy_field(wifi_ssid, &mut identity.wifi_ssid)?;
        identity.wifi_password_len = copy_field(wifi_password, &mut identity.wifi_password)?;
        Ok(identity)
    }
}

/// Pick the newest valid record from two banks.
///
/// `None` for both means nothing has been written, which is not an
/// error: a fresh board boots with defaults and waits to be
/// commissioned.
pub fn select<T: Copy>(
    records: [Option<(u32, T)>; 2],
    banks: [usize; 2],
) -> Option<(usize, (u32, T))> {
    match (records[0], records[1]) {
        (Some(left), Some(right)) => {
            if generation_is_newer(left.0, right.0) {
                Some((banks[0], left))
            } else {
                Some((banks[1], right))
            }
        }
        (Some(left), None) => Some((banks[0], left)),
        (None, Some(right)) => Some((banks[1], right)),
        (None, None) => None,
    }
}

/// Compare generation counters that wrap at `u32::MAX`.
pub fn generation_is_newer(candidate: u32, current: u32) -> bool {
    candidate.wrapping_sub(current) < u32::MAX / 2
}

pub fn copy_field(value: &str, out: &mut [u8]) -> Result<u8, StorageError> {
    let bytes = value.as_bytes();
    if bytes.len() > out.len() {
        return Err(StorageError::TooLong);
    }
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len() as u8)
}

/// Identity record layout.
///
/// Fixed offsets rather than a serialized struct: the record must
/// survive a compiler or dependency change without becoming unreadable,
/// because a device in a field cannot be re-flashed to fix a format
/// drift.
///
/// ```text
///   0   magic "FLID" (4)
///   4   generation (4, big-endian)
///   8   gateway id (16)
///  24   device id len (1) | device token len (1) | cloud url len (1) | ssid len (1) | password len (1)
///  29   device id (32)
///  61   device token (64)
/// 125   cloud url (96)
/// 221   wifi ssid (32)
/// 253   wifi password (63)
/// 316   crc32 (4)
/// ```
const MAGIC: [u8; 4] = *b"FLID";
const OFF_GENERATION: usize = 4;
const OFF_GATEWAY_ID: usize = 8;
const OFF_LENGTHS: usize = 24;
const OFF_DEVICE_ID: usize = 29;
const OFF_DEVICE_TOKEN: usize = OFF_DEVICE_ID + DEVICE_ID_LEN;
const OFF_CLOUD_URL: usize = OFF_DEVICE_TOKEN + DEVICE_TOKEN_HEX_LEN;
const OFF_WIFI_SSID: usize = OFF_CLOUD_URL + CLOUD_URL_LEN;
const OFF_WIFI_PASSWORD: usize = OFF_WIFI_SSID + WIFI_SSID_LEN;
const OFF_CRC: usize = OFF_WIFI_PASSWORD + WIFI_PASSWORD_LEN;
const RECORD_END: usize = OFF_CRC + 4;

/// The record must fit one page, and a page must fit one erase sector.
const _: () = assert!(RECORD_END <= RECORD_PAGE_SIZE);

pub fn encode_identity(identity: &Identity, generation: u32, page: &mut [u8; RECORD_PAGE_SIZE]) {
    page.fill(0xFF);
    page[..4].copy_from_slice(&MAGIC);
    page[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&generation.to_be_bytes());
    page[OFF_GATEWAY_ID..OFF_GATEWAY_ID + GATEWAY_ID_LEN].copy_from_slice(&identity.gateway_id);
    page[OFF_LENGTHS] = identity.device_id_len;
    page[OFF_LENGTHS + 1] = identity.device_token_len;
    page[OFF_LENGTHS + 2] = identity.cloud_url_len;
    page[OFF_LENGTHS + 3] = identity.wifi_ssid_len;
    page[OFF_LENGTHS + 4] = identity.wifi_password_len;
    page[OFF_DEVICE_ID..OFF_DEVICE_ID + DEVICE_ID_LEN].copy_from_slice(&identity.device_id);
    page[OFF_DEVICE_TOKEN..OFF_DEVICE_TOKEN + DEVICE_TOKEN_HEX_LEN]
        .copy_from_slice(&identity.device_token);
    page[OFF_CLOUD_URL..OFF_CLOUD_URL + CLOUD_URL_LEN].copy_from_slice(&identity.cloud_url);
    page[OFF_WIFI_SSID..OFF_WIFI_SSID + WIFI_SSID_LEN].copy_from_slice(&identity.wifi_ssid);
    page[OFF_WIFI_PASSWORD..OFF_WIFI_PASSWORD + WIFI_PASSWORD_LEN]
        .copy_from_slice(&identity.wifi_password);
    let crc = crc32(&page[..OFF_CRC]);
    page[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_be_bytes());
}

pub fn decode_identity(page: &[u8; RECORD_PAGE_SIZE]) -> Option<(u32, Identity)> {
    if page[..4] != MAGIC {
        return None;
    }
    let stored = u32::from_be_bytes(page[OFF_CRC..OFF_CRC + 4].try_into().ok()?);
    if crc32(&page[..OFF_CRC]) != stored {
        return None;
    }

    let mut identity = Identity::EMPTY;
    identity
        .gateway_id
        .copy_from_slice(&page[OFF_GATEWAY_ID..OFF_GATEWAY_ID + GATEWAY_ID_LEN]);
    identity.device_id_len = bounded(page[OFF_LENGTHS], DEVICE_ID_LEN)?;
    identity.device_token_len = bounded(page[OFF_LENGTHS + 1], DEVICE_TOKEN_HEX_LEN)?;
    identity.cloud_url_len = bounded(page[OFF_LENGTHS + 2], CLOUD_URL_LEN)?;
    identity.wifi_ssid_len = bounded(page[OFF_LENGTHS + 3], WIFI_SSID_LEN)?;
    identity.wifi_password_len = bounded(page[OFF_LENGTHS + 4], WIFI_PASSWORD_LEN)?;

    identity.device_id[..DEVICE_ID_LEN]
        .copy_from_slice(&page[OFF_DEVICE_ID..OFF_DEVICE_ID + DEVICE_ID_LEN]);
    identity.device_token[..DEVICE_TOKEN_HEX_LEN]
        .copy_from_slice(&page[OFF_DEVICE_TOKEN..OFF_DEVICE_TOKEN + DEVICE_TOKEN_HEX_LEN]);
    identity.cloud_url[..CLOUD_URL_LEN]
        .copy_from_slice(&page[OFF_CLOUD_URL..OFF_CLOUD_URL + CLOUD_URL_LEN]);
    identity.wifi_ssid[..WIFI_SSID_LEN]
        .copy_from_slice(&page[OFF_WIFI_SSID..OFF_WIFI_SSID + WIFI_SSID_LEN]);
    identity.wifi_password[..WIFI_PASSWORD_LEN]
        .copy_from_slice(&page[OFF_WIFI_PASSWORD..OFF_WIFI_PASSWORD + WIFI_PASSWORD_LEN]);

    // Every stored string must be valid UTF-8, or the accessors would
    // silently return empty and the device would look unprovisioned
    // while holding data.
    for value in [
        identity.device_id(),
        identity.device_token(),
        identity.cloud_url(),
        identity.wifi_ssid(),
        identity.wifi_password(),
    ] {
        str::from_utf8(value.as_bytes()).ok()?;
    }

    let generation = u32::from_be_bytes(page[OFF_GENERATION..OFF_GENERATION + 4].try_into().ok()?);
    Some((generation, identity))
}

fn bounded(value: u8, limit: usize) -> Option<u8> {
    if value as usize > limit {
        None
    } else {
        Some(value)
    }
}

/// CRC-32 (IEEE), the same polynomial the protocol uses.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The record's generation counter, used to pick between two banks.
pub fn config_generation(page: &[u8; RECORD_PAGE_SIZE]) -> Option<u32> {
    if page[..4] != MAGIC {
        return None;
    }
    Some(u32::from_be_bytes(
        page[OFF_GENERATION..OFF_GENERATION + 4].try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> Identity {
        Identity::from_parts(
            [7u8; GATEWAY_ID_LEN],
            "9a2db2e23f1504cd056606553ac049c5",
            &"ab".repeat(32),
            "https://flora-api.onrender.com",
            "plot-north",
            "correct horse battery",
        )
        .unwrap()
    }

    #[test]
    fn identity_round_trips_through_a_page() {
        let identity = sample_identity();
        let mut page = [0xFFu8; RECORD_PAGE_SIZE];
        encode_identity(&identity, 3, &mut page);
        let (generation, decoded) = decode_identity(&page).expect("decodes");
        assert_eq!(generation, 3);
        assert_eq!(decoded.gateway_id, identity.gateway_id);
        assert_eq!(decoded.device_id(), "9a2db2e23f1504cd056606553ac049c5");
        assert_eq!(decoded.device_token(), "ab".repeat(32));
        assert_eq!(decoded.cloud_url(), "https://flora-api.onrender.com");
        assert_eq!(decoded.wifi_ssid(), "plot-north");
        assert_eq!(decoded.wifi_password(), "correct horse battery");
    }

    #[test]
    fn an_erased_page_is_not_an_identity() {
        // A blank flash reads as all ones and must be distinguishable from
        // a record that happens to be there.
        let page = [0xFFu8; RECORD_PAGE_SIZE];
        assert!(decode_identity(&page).is_none());
    }

    #[test]
    fn a_single_flipped_bit_invalidates_the_record() {
        let identity = sample_identity();
        let mut page = [0xFFu8; RECORD_PAGE_SIZE];
        encode_identity(&identity, 1, &mut page);
        page[OFF_DEVICE_ID] ^= 0x01;
        assert!(
            decode_identity(&page).is_none(),
            "a corrupt record must not decode to a plausible identity"
        );
    }

    #[test]
    fn a_length_beyond_its_field_is_rejected() {
        let identity = sample_identity();
        let mut page = [0xFFu8; RECORD_PAGE_SIZE];
        encode_identity(&identity, 1, &mut page);
        // Claim a device id longer than its field. The CRC is recomputed
        // so this exercises the bound rather than the checksum.
        page[OFF_LENGTHS] = (DEVICE_ID_LEN + 1) as u8;
        let crc = crc32(&page[..OFF_CRC]);
        page[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_be_bytes());
        assert!(decode_identity(&page).is_none());
    }

    #[test]
    fn an_overlong_field_is_refused_rather_than_truncated() {
        let mut out = [0u8; 4];
        assert_eq!(copy_field("abcd", &mut out), Ok(4));
        assert_eq!(copy_field("abcde", &mut out), Err(StorageError::TooLong));
    }

    #[test]
    fn a_field_exactly_filling_its_limit_is_accepted() {
        let identity = Identity::from_parts(
            [1u8; GATEWAY_ID_LEN],
            &"a".repeat(DEVICE_ID_LEN),
            &"b".repeat(DEVICE_TOKEN_HEX_LEN),
            &"c".repeat(CLOUD_URL_LEN),
            &"d".repeat(WIFI_SSID_LEN),
            &"e".repeat(WIFI_PASSWORD_LEN),
        )
        .expect("exactly the limit must fit");
        let mut page = [0xFFu8; RECORD_PAGE_SIZE];
        encode_identity(&identity, 1, &mut page);
        let (_, decoded) = decode_identity(&page).expect("decodes");
        assert_eq!(decoded.device_id().len(), DEVICE_ID_LEN);
        assert_eq!(decoded.wifi_password().len(), WIFI_PASSWORD_LEN);
    }

    #[test]
    fn an_empty_identity_is_not_provisioned() {
        assert!(!Identity::EMPTY.is_provisioned());
        assert!(sample_identity().is_provisioned());
    }

    #[test]
    fn a_partial_identity_is_not_provisioned() {
        // A record written without a token would otherwise authenticate
        // as an empty bearer, which the server would reject on every
        // uplink.
        let identity = Identity::from_parts(
            [1u8; GATEWAY_ID_LEN],
            "9a2db2e23f1504cd056606553ac049c5",
            "",
            "https://flora-api.onrender.com",
            "ssid",
            "password",
        )
        .unwrap();
        assert!(!identity.is_provisioned());
    }

    #[test]
    fn generations_wrap_without_losing_the_newer_record() {
        assert!(generation_is_newer(2, 1));
        assert!(!generation_is_newer(1, 2));
        // Just after the counter wraps, the new record must still win.
        assert!(generation_is_newer(0, u32::MAX));
        assert!(!generation_is_newer(u32::MAX, 0));
    }

    #[test]
    fn the_newer_bank_wins_and_a_blank_bank_loses() {
        let left = Some((5u32, 1u8));
        let right = Some((9u32, 2u8));
        assert_eq!(select([left, right], [0, 1]), Some((1, (9, 2))));
        assert_eq!(select([right, left], [0, 1]), Some((0, (9, 2))));
        assert_eq!(select([left, None], [0, 1]), Some((0, (5, 1))));
        assert_eq!(select::<u8>([None, None], [0, 1]), None);
    }

    #[test]
    fn config_generation_reads_the_counter_without_full_decoding() {
        let identity = sample_identity();
        let mut page = [0xFFu8; RECORD_PAGE_SIZE];
        encode_identity(&identity, 42, &mut page);
        assert_eq!(config_generation(&page), Some(42));
        // Flipping a payload byte still decodes the generation: the
        // caller uses it to decide which bank to trust, and must see the
        // counter even when the rest of the record fails its CRC.
        page[OFF_DEVICE_ID] ^= 0x80;
        assert_eq!(config_generation(&page), Some(42));
    }
}
