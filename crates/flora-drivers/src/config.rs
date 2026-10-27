//! Runtime configuration of a field node, and its flash record format.
//!
//! Thresholds and ADC references persist across reboots in a fixed-offset
//! record with a CRC. Fields hardware cannot observe use the sentinel
//! rather than a fabricated value.

use flora_protocol::UNAVAILABLE_U16;
use flora_protocol::crc16_ccitt_false;

/// Packed firmware version reported over the bus. Per-crate semver: the
/// firmware bins bump this with their own versions.
pub const FW_PACKED: u16 = 0x0100;
/// Human-readable firmware version, also used by the provisioning greeting.
pub const FIRMWARE_VERSION: &str = "0.1.0";

/// One flash page holds one config record.
pub const CONFIG_PAGE_SIZE: usize = 256;

const RECORD_MAGIC: [u8; 4] = *b"FLRN";
const RECORD_VERSION: u8 = 1;
const RECORD_BODY_LEN: usize = 22;
const RECORD_LEN: usize = RECORD_BODY_LEN + 2;

/// Runtime configuration of a field node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeConfig {
    /// RS-485 address. `0` means uncommissioned; valid nodes are `0x02..=0xFE`.
    pub address: u8,
    /// ADC count in air, captured by `CALIBRATE` mode 0.
    pub soil_dry_adc: u16,
    /// ADC count in water, captured by `CALIBRATE` mode 1.
    pub soil_wet_adc: u16,
    /// Moisture at or below which irrigation starts, per mille.
    pub dry_threshold: u16,
    /// Moisture at or above which irrigation stops, per mille.
    pub wet_threshold: u16,
    /// Hard cap on a single run, seconds.
    pub max_runtime_s: u16,
    /// Minimum rest between runs, seconds.
    pub min_off_s: u16,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            address: 0,
            soil_dry_adc: UNAVAILABLE_U16,
            soil_wet_adc: UNAVAILABLE_U16,
            dry_threshold: 300,
            wet_threshold: 600,
            max_runtime_s: 300,
            min_off_s: 600,
        }
    }
}

impl NodeConfig {
    /// Whether the moisture probe has usable references.
    pub fn soil_calibrated(&self) -> bool {
        self.soil_dry_adc != UNAVAILABLE_U16
            && self.soil_wet_adc != UNAVAILABLE_U16
            && self.soil_dry_adc != self.soil_wet_adc
    }

    /// Reject configurations that would make the node unsafe or unusable.
    pub fn validate(&self) -> bool {
        if !(0x02..=0xFE).contains(&self.address) {
            return false;
        }
        for reference in [self.soil_dry_adc, self.soil_wet_adc] {
            if reference != UNAVAILABLE_U16 && reference > 4095 {
                return false;
            }
        }
        // Either probe polarity is valid: `to_per_mille` handles both, mapping
        // the dry reference to 0 and the wet reference to 1000. Only identical
        // references are unusable, because they define no scale.
        let both_present =
            self.soil_dry_adc != UNAVAILABLE_U16 && self.soil_wet_adc != UNAVAILABLE_U16;
        if both_present && self.soil_dry_adc == self.soil_wet_adc {
            return false;
        }
        if self.dry_threshold > 1000 || self.wet_threshold > 1000 {
            return false;
        }
        if self.wet_threshold <= self.dry_threshold {
            return false;
        }
        if self.max_runtime_s == 0 {
            return false;
        }
        true
    }

    /// Serialize the record into the head of `page`. The remainder is left
    /// untouched so the caller can pre-fill it with `0xFF`.
    pub fn encode_record(&self, generation: u32, page: &mut [u8]) {
        debug_assert!(page.len() >= RECORD_LEN);
        let mut body = [0u8; RECORD_BODY_LEN];
        body[0..4].copy_from_slice(&RECORD_MAGIC);
        body[4] = RECORD_VERSION;
        body[5] = self.address;
        body[6..8].copy_from_slice(&self.soil_dry_adc.to_be_bytes());
        body[8..10].copy_from_slice(&self.soil_wet_adc.to_be_bytes());
        body[10..12].copy_from_slice(&self.dry_threshold.to_be_bytes());
        body[12..14].copy_from_slice(&self.wet_threshold.to_be_bytes());
        body[14..16].copy_from_slice(&self.max_runtime_s.to_be_bytes());
        body[16..18].copy_from_slice(&self.min_off_s.to_be_bytes());
        body[18..22].copy_from_slice(&generation.to_be_bytes());

        page[..RECORD_BODY_LEN].copy_from_slice(&body);
        let checksum = crc16_ccitt_false(&body);
        page[RECORD_BODY_LEN..RECORD_LEN].copy_from_slice(&checksum.to_be_bytes());
    }

    /// Parse and validate a record. Returns `None` for erased, corrupt, or
    /// invalid pages so callers fall back to their previous configuration.
    pub fn decode_record(page: &[u8]) -> Option<(u32, Self)> {
        if page.len() < RECORD_LEN {
            return None;
        }
        let body = &page[..RECORD_BODY_LEN];
        if body[0..4] != RECORD_MAGIC || body[4] != RECORD_VERSION {
            return None;
        }
        let stored = u16::from_be_bytes([page[RECORD_BODY_LEN], page[RECORD_BODY_LEN + 1]]);
        if crc16_ccitt_false(body) != stored {
            return None;
        }
        let config = Self {
            address: body[5],
            soil_dry_adc: u16::from_be_bytes([body[6], body[7]]),
            soil_wet_adc: u16::from_be_bytes([body[8], body[9]]),
            dry_threshold: u16::from_be_bytes([body[10], body[11]]),
            wet_threshold: u16::from_be_bytes([body[12], body[13]]),
            max_runtime_s: u16::from_be_bytes([body[14], body[15]]),
            min_off_s: u16::from_be_bytes([body[16], body[17]]),
        };
        let generation = u32::from_be_bytes([body[18], body[19], body[20], body[21]]);
        if !config.validate() {
            return None;
        }
        Some((generation, config))
    }
}
