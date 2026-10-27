//! DHT22 temperature/humidity decode.
//!
//! The 40-bit payload is RH high/low, temperature high/low, checksum. The
//! checksum is the wrapping sum of the first four bytes. Temperature is
//! signed via bit 15 of the high byte — the sensor's own encoding, not a
//! device convention.

/// One decoded DHT22 sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub temperature_deci_c: i16,
    pub humidity_per_mille: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Checksum,
    OutOfRange,
}

/// Decode the 40-bit DHT22 payload: RH high/low, temperature high/low,
/// checksum.
///
/// Out-of-range values are rejected rather than clamped: a sensor that
/// reports 150% RH has failed, and storing its number would read as data.
pub fn decode(bytes: [u8; 5]) -> Result<Reading, Error> {
    let checksum = bytes[0]
        .wrapping_add(bytes[1])
        .wrapping_add(bytes[2])
        .wrapping_add(bytes[3]);
    if checksum != bytes[4] {
        return Err(Error::Checksum);
    }

    let humidity = u16::from_be_bytes([bytes[0], bytes[1]]);
    let temperature_raw = u16::from_be_bytes([bytes[2] & 0x7F, bytes[3]]) as i16;
    let temperature_deci_c = if bytes[2] & 0x80 == 0 {
        temperature_raw
    } else {
        -temperature_raw
    };
    if humidity > 1000 || !(-400..=800).contains(&temperature_deci_c) {
        return Err(Error::OutOfRange);
    }

    Ok(Reading {
        temperature_deci_c,
        humidity_per_mille: humidity,
    })
}
