//! Soil moisture conversion: ADC counts to per mille, from captured
//! dry/wet references.

use crate::config::NodeConfig;
use flora_protocol::UNAVAILABLE_U16;

/// Convert an ADC sample to per-mille moisture using captured dry/wet
/// references.
///
/// Either probe polarity works: the dry reference maps to 0 and the wet
/// reference to 1000. Uncalibrated or out-of-range inputs return `None`
/// rather than a fabricated number — an uncalibrated node reports
/// "unavailable", which the wire encoding preserves.
pub fn to_per_mille(raw: u16, dry_reference: u16, wet_reference: u16) -> Option<u16> {
    if dry_reference == UNAVAILABLE_U16
        || wet_reference == UNAVAILABLE_U16
        || dry_reference > 4095
        || wet_reference > 4095
        || dry_reference == wet_reference
        || raw > 4095
    {
        return None;
    }

    let numerator = (i32::from(raw) - i32::from(dry_reference)) * 1000;
    let denominator = i32::from(wet_reference) - i32::from(dry_reference);
    Some((numerator / denominator).clamp(0, 1000) as u16)
}

/// Convert a sample against a configuration's references. `None` when the
/// probe is not calibrated or the sample is invalid.
pub fn sample_per_mille(raw: u16, config: &NodeConfig) -> Option<u16> {
    to_per_mille(raw, config.soil_dry_adc, config.soil_wet_adc)
}
