//! Payload layouts carried inside RS-485 frames.
//!
//! The `DATA` body is 27 bytes in a fixed field order; `INFO` is 11. Both
//! are hand-rolled — they are binary layouts, not JSON-shaped models, and
//! the field order is the contract. A value this build cannot measure is
//! encoded as its sentinel, never as a plausible number.

use crate::frame::{UNAVAILABLE_I16, UNAVAILABLE_U16};

// The fixed field order of a `DATA` body:
//
//   0-7   node UUID
//   8-9   firmware version, packed (major<<8 | minor)
//  10-11  moisture, per mille, big-endian
//  12-13  temperature, tenths of a degree C, big-endian, signed
//  14-15  humidity, per mille, big-endian
//  16     valve state, 0 or 1
//  17-18  reserved, sent as 0xFFFF
//  19-22  sample sequence
//

/// Bytes in a `DATA` payload (the `SensorFrame` body).
pub const DATA_PAYLOAD_LEN: usize = 27;
/// Bytes in an `INFO` payload.
pub const INFO_PAYLOAD_LEN: usize = 11;

/// One sensor sample as the node sees it, before wire encoding.
///
/// Fields are optional because this build cannot always measure them: the
/// soil probe is unavailable until calibrated, the DHT22 read can fail its
/// checksum, and there is no battery monitor at all. `None` goes on the
/// wire as the documented sentinel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SensorReading {
    /// Raw ADC count from the soil probe; used when capturing calibration.
    pub soil_raw: u16,
    /// Soil moisture in per mille, once the probe is calibrated.
    pub moisture_per_mille: Option<u16>,
    /// Air temperature in tenths of a degree Celsius.
    pub temperature_deci_c: Option<i16>,
    /// Relative humidity in per mille.
    pub humidity_per_mille: Option<u16>,
    /// Monotonic sample counter, reported to the coordinator.
    pub sequence: u32,
}

/// Encode the 27-byte `DATA` body in wire field order.
pub fn data_payload(
    node_uuid: &[u8; 8],
    fw_ver: u16,
    reading: SensorReading,
    valve_open: bool,
    uptime_s: u32,
) -> [u8; DATA_PAYLOAD_LEN] {
    let mut payload = [0u8; DATA_PAYLOAD_LEN];
    payload[0..8].copy_from_slice(node_uuid);
    payload[8..10].copy_from_slice(&fw_ver.to_be_bytes());
    payload[10..12].copy_from_slice(
        &reading
            .moisture_per_mille
            .unwrap_or(UNAVAILABLE_U16)
            .to_be_bytes(),
    );
    payload[12..14].copy_from_slice(
        &reading
            .temperature_deci_c
            .unwrap_or(UNAVAILABLE_I16)
            .to_be_bytes(),
    );
    payload[14..16].copy_from_slice(
        &reading
            .humidity_per_mille
            .unwrap_or(UNAVAILABLE_U16)
            .to_be_bytes(),
    );
    payload[16] = u8::from(valve_open);
    payload[17..19].copy_from_slice(&UNAVAILABLE_U16.to_be_bytes());
    payload[19..23].copy_from_slice(&reading.sequence.to_be_bytes());
    payload[23..27].copy_from_slice(&uptime_s.to_be_bytes());
    payload
}

/// A decoded `DATA` body: wire values with sentinels preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorFrame {
    pub node_uuid: [u8; 8],
    pub fw_ver: u16,
    /// `None` when the node sent the unavailable sentinel.
    pub moisture_per_mille: Option<u16>,
    /// `None` when the node sent the unavailable sentinel.
    pub temperature_deci_c: Option<i16>,
    /// `None` when the node sent the unavailable sentinel.
    pub humidity_per_mille: Option<u16>,
    pub valve_open: bool,
    pub sequence: u32,
    pub uptime_s: u32,
}

/// Decode a 27-byte `DATA` body. A wrong length is rejected rather than
/// read out of bounds.
pub fn decode_data(payload: &[u8]) -> Option<SensorFrame> {
    if payload.len() != DATA_PAYLOAD_LEN {
        return None;
    }
    let mut node_uuid = [0u8; 8];
    node_uuid.copy_from_slice(&payload[0..8]);
    let moisture_raw = u16::from_be_bytes([payload[10], payload[11]]);
    let temperature_raw = i16::from_be_bytes([payload[12], payload[13]]);
    let humidity_raw = u16::from_be_bytes([payload[14], payload[15]]);
    Some(SensorFrame {
        node_uuid,
        fw_ver: u16::from_be_bytes([payload[8], payload[9]]),
        moisture_per_mille: (moisture_raw != UNAVAILABLE_U16).then_some(moisture_raw),
        temperature_deci_c: (temperature_raw != UNAVAILABLE_I16).then_some(temperature_raw),
        humidity_per_mille: (humidity_raw != UNAVAILABLE_U16).then_some(humidity_raw),
        valve_open: payload[16] != 0,
        sequence: u32::from_be_bytes([payload[19], payload[20], payload[21], payload[22]]),
        uptime_s: u32::from_be_bytes([payload[23], payload[24], payload[25], payload[26]]),
    })
}

/// Encode the 11-byte `INFO` body: UUID, address, packed firmware version.
pub fn info_payload(node_uuid: &[u8; 8], addr: u8, fw_ver: u16) -> [u8; INFO_PAYLOAD_LEN] {
    let mut payload = [0u8; INFO_PAYLOAD_LEN];
    payload[0..8].copy_from_slice(node_uuid);
    payload[8] = addr;
    payload[9..11].copy_from_slice(&fw_ver.to_be_bytes());
    payload
}

/// A decoded `INFO` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_uuid: [u8; 8],
    pub address: u8,
    pub fw_ver: u16,
}

/// Decode an 11-byte `INFO` body.
pub fn decode_info(payload: &[u8]) -> Option<NodeInfo> {
    if payload.len() != INFO_PAYLOAD_LEN {
        return None;
    }
    let mut node_uuid = [0u8; 8];
    node_uuid.copy_from_slice(&payload[0..8]);
    Some(NodeInfo {
        node_uuid,
        address: payload[8],
        fw_ver: u16::from_be_bytes([payload[9], payload[10]]),
    })
}
