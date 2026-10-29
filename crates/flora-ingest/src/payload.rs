//! Telemetry batch decoding.
//!
//! The aggregator publishes one JSON batch per uplink. This module turns
//! those bytes into rows, and it is where the two conversions that
//! matter happen:
//!
//! * **Units.** The wire carries moisture and humidity in per mille and
//!   temperature in deci-degrees. The database stores SI. Getting this
//!   wrong does not raise an error, it silently scales every MAE
//!   calculation.
//! * **Sentinels.** The firmware reports `65535` and `-32768` for
//!   "unavailable" (uncalibrated probe, failed read, no sensor this
//!   build carries). Those become SQL `NULL`. Storing them as numbers
//!   would let analytics average a sentinel and report a temperature
//!   of -3276.8 °C.
//!
//! The wire structs live in `flora-protocol` and are shared with the
//! firmware's encoder tests, so this module only owns the conversions
//! from wire values to database rows. Both conversions are pinned with
//! the exact payload the aggregator emits.

use chrono::{DateTime, TimeZone, Utc};
use flora_db::models::NewReading;
use flora_protocol::{GATEWAY_ID_LEN, UNAVAILABLE_I16, UNAVAILABLE_U16, WireBatch};

/// Largest accepted batch, matching the aggregator's `MAX_BATCH_NODES`.
pub const MAX_NODES_PER_BATCH: usize = 8;

/// Tolerance for a device clock that has not yet been synced, in
/// seconds.
///
/// An aggregator that boots without NTP can be badly wrong about the
/// wall clock. Trusting its timestamp would place readings at the wrong
/// time, which corrupts time-series queries and the MAE window. A batch
/// outside this window is timestamped by the server instead.
pub const CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("batch is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timestamp {0} is outside the representable range")]
    Timestamp(i64),
    #[error("batch carries {found} nodes, above the {MAX_NODES_PER_BATCH} limit")]
    TooManyNodes { found: usize },
    #[error("node uuid {0:?} is not 8 bytes")]
    NodeUuid(Vec<u8>),
    #[error("gateway id must be 16 bytes")]
    GatewayId,
}

/// One node as reported in a batch.
///
/// This is the discovery map the plan describes: an aggregator reports
/// which nodes answered and at which address, so the cloud never needs
/// a fixed node count and does not have to be told about a node
/// separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveredNode {
    pub node_uuid: [u8; 8],
    pub addr: u8,
    pub fw_ver: u16,
}

/// A decoded batch ready to be written.
#[derive(Debug, Clone)]
pub struct DecodedBatch {
    pub gateway_id: String,
    pub ts: DateTime<Utc>,
    pub dropped: u32,
    pub readings: Vec<NewReading>,
    /// Nodes this batch proves exist, with the address each answered at.
    pub nodes: Vec<DiscoveredNode>,
}

/// Convert a wire metric to per mille as a percentage, or `None` when
/// the firmware reported it unavailable.
///
/// Per mille to percent is a divide by ten. The value is kept as `f32`
/// because the database column is `REAL`.
pub fn permille_to_percent(value: u16) -> Option<f32> {
    if value == UNAVAILABLE_U16 {
        return None;
    }
    Some(f32::from(value) / 10.0)
}

/// Convert a wire temperature to degrees Celsius, or `None` when
/// unavailable.
pub fn deci_to_celsius(value: i16) -> Option<f32> {
    if value == UNAVAILABLE_I16 {
        return None;
    }
    Some(f32::from(value) / 10.0)
}

/// Valve state, rejecting anything outside the documented range.
pub fn valve_state(value: u8) -> Option<i16> {
    match value {
        0 | 1 => Some(i16::from(value)),
        _ => None,
    }
}

/// Resolve the timestamp a batch should be stored under.
///
/// A device's clock is only trusted when it is plausibly right. An
/// unsynced aggregator would otherwise scatter readings across the
/// timeline.
pub fn resolve_timestamp(device_ts: i64, now: i64) -> DateTime<Utc> {
    if (device_ts - now).abs() <= CLOCK_SKEW_SECONDS {
        Utc.timestamp_opt(device_ts, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(now, 0).single().expect("valid now"))
    } else {
        Utc.timestamp_opt(now, 0).single().expect("valid now")
    }
}

/// Decode a batch into database rows, resolving the timestamp against
/// `now`.
pub fn decode_batch_at(bytes: &[u8], now: i64) -> Result<DecodedBatch, DecodeError> {
    let mut batch = decode_batch(bytes)?;
    batch.ts = resolve_timestamp(batch.ts.timestamp(), now);
    for reading in batch.readings.iter_mut() {
        reading.ts = batch.ts;
    }
    Ok(batch)
}

/// Decode a batch into database rows, trusting the batch timestamp.
pub fn decode_batch(bytes: &[u8]) -> Result<DecodedBatch, DecodeError> {
    let wire: WireBatch = serde_json::from_slice(bytes)?;
    if wire.nodes.len() > MAX_NODES_PER_BATCH {
        return Err(DecodeError::TooManyNodes {
            found: wire.nodes.len(),
        });
    }

    let gateway_id = wire.gw_id.to_lowercase();
    if gateway_id.len() != GATEWAY_ID_LEN * 2 {
        return Err(DecodeError::GatewayId);
    }

    let seconds = wire
        .ts
        .checked_mul(1)
        .and_then(|_| Utc.timestamp_opt(wire.ts, 0).single())
        .ok_or(DecodeError::Timestamp(wire.ts))?;

    let mut readings = Vec::with_capacity(wire.nodes.len());
    let mut nodes = Vec::with_capacity(wire.nodes.len());
    for node in &wire.nodes {
        let uuid = hex::decode(&node.uuid)
            .map_err(|_| DecodeError::NodeUuid(node.uuid.clone().into_bytes()))?;
        if uuid.len() != 8 {
            return Err(DecodeError::NodeUuid(uuid));
        }
        let mut node_uuid = [0u8; 8];
        node_uuid.copy_from_slice(&uuid);
        nodes.push(DiscoveredNode {
            node_uuid,
            addr: node.addr,
            fw_ver: node.fw_ver,
        });
        readings.push(NewReading {
            ts: seconds,
            gateway_id: gateway_id.clone(),
            node_uuid: uuid,
            moisture: permille_to_percent(node.moist),
            temperature: deci_to_celsius(node.temp),
            humidity: permille_to_percent(node.hum),
            valve_state: valve_state(node.valve),
            seq: Some(i64::from(node.seq)),
        });
    }

    Ok(DecodedBatch {
        gateway_id,
        ts: seconds,
        dropped: wire.dropped.unwrap_or(0),
        readings,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact payload the aggregator's encoder produces, byte for
    /// byte.
    const AGGREGATOR_BATCH: &[u8] = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"nodes":[{"uuid":"0202020202020202","addr":2,"moist":312,"temp":284,"hum":710,"valve":0,"seq":1042,"fw_ver":256},{"uuid":"0303030303030303","addr":3,"moist":187,"temp":284,"hum":710,"valve":0,"seq":1042,"fw_ver":256}]}"#;

    #[test]
    fn decodes_the_aggregator_payload_and_converts_units() {
        let batch = decode_batch(AGGREGATOR_BATCH).unwrap();
        assert_eq!(batch.gateway_id, "6167672d303030316167672d30303031");
        assert_eq!(batch.ts.timestamp(), 1_717_000_000);
        assert_eq!(batch.readings.len(), 2);

        let first = &batch.readings[0];
        // 312 per mille is 31.2 percent, not 312.
        assert_eq!(first.moisture, Some(31.2));
        // 284 deci-degrees is 28.4 degrees, not 284.
        assert_eq!(first.temperature, Some(28.4));
        assert_eq!(first.humidity, Some(71.0));
        assert_eq!(first.valve_state, Some(0));
        assert_eq!(first.seq, Some(1042));
        assert_eq!(first.node_uuid, vec![2u8; 8]);
        assert_eq!(batch.nodes[0].addr, 2);
        assert_eq!(batch.nodes[0].fw_ver, 256);
    }

    #[test]
    fn unavailable_sentinels_become_null_rather_than_numbers() {
        // Matches the aggregator's own unavailable shape: uncalibrated
        // probe, failed DHT22 read, no sensor this build carries.
        let payload = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"nodes":[{"uuid":"0202020202020202","addr":2,"moist":65535,"temp":-32768,"hum":65535,"valve":0,"seq":1043,"fw_ver":256}]}"#;
        let batch = decode_batch(payload).unwrap();
        let reading = &batch.readings[0];
        assert_eq!(
            reading.moisture, None,
            "65535 must not become 6553.5 percent"
        );
        assert_eq!(
            reading.temperature, None,
            "-32768 must not become -3276.8 degrees"
        );
        assert_eq!(reading.humidity, None);
    }

    #[test]
    fn dropped_count_is_carried_through() {
        let payload = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"dropped":3,"nodes":[{"uuid":"0202020202020202","addr":2,"moist":100,"temp":200,"hum":300,"valve":0,"seq":1,"fw_ver":256}]}"#;
        let batch = decode_batch(payload).unwrap();
        assert_eq!(batch.dropped, 3);

        let without = decode_batch(AGGREGATOR_BATCH).unwrap();
        assert_eq!(
            without.dropped, 0,
            "an absent field means nothing was dropped"
        );
    }

    #[test]
    fn an_empty_batch_is_valid() {
        let payload = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"nodes":[]}"#;
        let batch = decode_batch(payload).unwrap();
        assert!(batch.readings.is_empty());
    }

    #[test]
    fn oversized_batches_are_refused() {
        let node = r#"{"uuid":"0202020202020202","addr":2,"moist":1,"temp":2,"hum":3,"valve":0,"seq":5,"fw_ver":256}"#;
        let nodes = std::iter::repeat_n(node, MAX_NODES_PER_BATCH + 1)
            .collect::<Vec<_>>()
            .join(",");
        let payload =
            format!(r#"{{"gw_id":"6167672d303030316167672d30303031","ts":1,"nodes":[{nodes}]}}"#);
        assert!(matches!(
            decode_batch(payload.as_bytes()),
            Err(DecodeError::TooManyNodes { .. })
        ));
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        assert!(decode_batch(b"not json").is_err());
        assert!(decode_batch(b"{}").is_err());
        // Short gateway id.
        assert!(decode_batch(br#"{"gw_id":"ab","ts":1,"nodes":[]}"#).is_err());
        // Non-hex node uuid.
        assert!(
            decode_batch(
                br#"{"gw_id":"6167672d303030316167672d30303031","ts":1,"nodes":[{"uuid":"zz","addr":2,"moist":1,"temp":2,"hum":3,"valve":0,"seq":5,"fw_ver":256}]}"#
            )
            .is_err()
        );
        // Out-of-range timestamp.
        assert!(matches!(
            decode_batch(
                br#"{"gw_id":"6167672d303030316167672d30303031","ts":99999999999999,"nodes":[]}"#
            ),
            Err(DecodeError::Timestamp(_))
        ));
    }

    #[test]
    fn a_plausible_device_clock_is_trusted_and_a_wild_one_is_not() {
        let now = 1_717_000_000i64;
        let body = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"nodes":[]}"#;

        // Within tolerance: the device timestamp is kept.
        let batch = decode_batch_at(body, now + 60).unwrap();
        assert_eq!(batch.ts.timestamp(), now);

        // Far in the past, as an unsynced clock would be: the server
        // wins.
        let old = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1000000000,"nodes":[]}"#;
        let batch = decode_batch_at(old, now).unwrap();
        assert_eq!(
            batch.ts.timestamp(),
            now,
            "an unsynced device must not place readings years in the past"
        );

        // Far in the future, likewise.
        let future = br#"{"gw_id":"6167672d303030316167672d30303031","ts":9999999999,"nodes":[]}"#;
        let batch = decode_batch_at(future, now).unwrap();
        assert_eq!(batch.ts.timestamp(), now);
    }

    #[test]
    fn resolved_timestamp_applies_to_every_reading() {
        let now = 1_717_000_000i64;
        let batch = decode_batch_at(AGGREGATOR_BATCH, now).unwrap();
        assert!(batch.readings.iter().all(|r| r.ts == batch.ts));
    }

    #[test]
    fn unit_helpers_are_explicit_about_unavailable() {
        assert_eq!(permille_to_percent(0), Some(0.0));
        assert_eq!(permille_to_percent(1000), Some(100.0));
        assert_eq!(permille_to_percent(UNAVAILABLE_U16), None);
        assert_eq!(deci_to_celsius(0), Some(0.0));
        assert_eq!(deci_to_celsius(-100), Some(-10.0));
        assert_eq!(deci_to_celsius(UNAVAILABLE_I16), None);
        // An out-of-range valve value is not a valve state.
        assert_eq!(valve_state(2), None);
    }
}
