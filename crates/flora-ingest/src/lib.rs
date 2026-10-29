//! Telemetry ingest: accepting an aggregator's batch and persisting it.
//!
//! Transport is an authenticated HTTPS POST to the public API. An
//! embedded MQTT broker was implemented first and removed: Render's free
//! plan states that "free web services can send private network
//! requests, but they can't receive them", and private services are not
//! free, so a broker inside this process would have been reachable by
//! nothing. A single POST over the surface that already exists is also
//! far cheaper on an RP2040 than an MQTT-over-TLS client, and it
//! survives the platform's request/proxy model without extra machinery.
//!
//! What this module owns is the part that matters for correctness: how
//! a device authenticates, which gateway its data may be attributed to,
//! and how a batch becomes rows without duplicating when a retry
//! arrives.

pub mod payload;

pub use payload::{
    CLOCK_SKEW_SECONDS, DecodeError, DecodedBatch, DiscoveredNode, decode_batch, decode_batch_at,
    permille_to_percent, resolve_timestamp,
};

use chrono::{DateTime, Utc};
use flora_db::models::NewReading;
use sqlx::PgPool;

/// Largest accepted batch body, matching the aggregator's buffer size.
pub const MAX_BATCH_BYTES: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("device {0} submitted a batch for another gateway")]
    GatewayMismatch(String),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Whether an authenticated device may submit a batch for `gateway_id`.
///
/// A device submits only its own readings. The identity comes from the
/// credential, never from the body, so one plot cannot write another's
/// data.
pub fn submission_authorized(device_id: &str, gateway_id: &str) -> bool {
    !device_id.is_empty() && device_id == gateway_id
}

/// One decoded batch plus the gateway it belongs to.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub gateway_id: String,
    pub ts: DateTime<Utc>,
    pub dropped: u32,
    pub readings: Vec<NewReading>,
    pub nodes: Vec<DiscoveredNode>,
}

/// Decode a submitted batch, attributing it to the authenticated device.
pub fn accept_batch(device_id: &str, bytes: &[u8], now: i64) -> Result<Incoming, IngestError> {
    let mut batch = decode_batch_at(bytes, now)?;
    // The authenticated identity wins over the body's claim, so a
    // device cannot attribute readings to another gateway even if it
    // names one.
    if !submission_authorized(device_id, &batch.gateway_id) {
        return Err(IngestError::GatewayMismatch(device_id.to_owned()));
    }
    batch.gateway_id = device_id.to_owned();
    for reading in batch.readings.iter_mut() {
        reading.gateway_id = device_id.to_owned();
    }

    Ok(Incoming {
        gateway_id: batch.gateway_id,
        ts: batch.ts,
        dropped: batch.dropped,
        readings: batch.readings,
        nodes: batch.nodes,
    })
}

/// Persist a batch, ignoring duplicates.
///
/// A device retries after a timeout or a dropped response, so the same
/// batch can legitimately arrive more than once. The primary key is
/// `(ts, gateway_id, node_uuid)` and the insert ignores conflicts, which
/// makes ingest idempotent rather than duplicating a reading on every
/// retry.
pub async fn store(pool: &PgPool, incoming: &Incoming) -> Result<u64, IngestError> {
    // Record the nodes this batch proves exist, with the address each
    // answered at. This is the discovery map: the cloud is never told
    // about a node separately, and a node that moves address updates
    // rather than duplicating because the identity is
    // (gateway_id, node_uuid).
    for node in &incoming.nodes {
        sqlx::query(
            "INSERT INTO nodes (gateway_id, node_uuid, addr, fw_version, last_seen)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (gateway_id, node_uuid) DO UPDATE
               SET addr = EXCLUDED.addr,
                   fw_version = EXCLUDED.fw_version,
                   last_seen = EXCLUDED.last_seen",
        )
        .bind(&incoming.gateway_id)
        .bind(node.node_uuid.to_vec())
        .bind(i16::from(node.addr))
        .bind(format!("{}.{}.{}", node.fw_ver >> 8, node.fw_ver & 0xFF, 0))
        .bind(incoming.ts)
        .execute(pool)
        .await?;
    }

    let mut inserted = 0u64;
    for reading in &incoming.readings {
        let result = sqlx::query(
            "INSERT INTO readings (ts, gateway_id, node_uuid, moisture, temperature,
                                   humidity, valve_state, seq)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (ts, gateway_id, node_uuid) DO NOTHING",
        )
        .bind(reading.ts)
        .bind(&reading.gateway_id)
        .bind(&reading.node_uuid)
        .bind(reading.moisture)
        .bind(reading.temperature)
        .bind(reading.humidity)
        .bind(reading.valve_state)
        .bind(reading.seq)
        .execute(pool)
        .await?;
        inserted += result.rows_affected();
    }

    // Every batch proves the gateway is alive, even one carrying no node
    // rows.
    sqlx::query("UPDATE gateways SET last_seen = $2 WHERE id = $1")
        .bind(&incoming.gateway_id)
        .bind(incoming.ts)
        .execute(pool)
        .await?;

    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: &str = "6167672d303030316167672d30303031";
    const BATCH: &[u8] = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"nodes":[{"uuid":"0202020202020202","addr":2,"moist":312,"temp":284,"hum":710,"valve":0,"seq":1042,"fw_ver":256}]}"#;

    #[test]
    fn a_device_may_only_submit_its_own_gateway() {
        assert!(submission_authorized(GATEWAY, GATEWAY));
        assert!(!submission_authorized(
            GATEWAY,
            "6167672d303030326167672d30303032"
        ));
        assert!(!submission_authorized("", GATEWAY));
        assert!(!submission_authorized(GATEWAY, ""));
    }

    #[test]
    fn a_batch_from_the_authenticated_device_is_accepted() {
        let incoming = accept_batch(GATEWAY, BATCH, 1_717_000_000).unwrap();
        assert_eq!(incoming.gateway_id, GATEWAY);
        assert_eq!(incoming.readings.len(), 1);
        assert_eq!(incoming.readings[0].moisture, Some(31.2));
    }

    #[test]
    fn a_batch_naming_another_gateway_is_refused() {
        let error =
            accept_batch("6167672d303030326167672d30303032", BATCH, 1_717_000_000).unwrap_err();
        assert!(matches!(error, IngestError::GatewayMismatch(_)), "{error}");
    }

    #[test]
    fn the_authenticated_identity_overrides_the_body_claim() {
        // A body naming a different gateway is refused outright rather
        // than silently rewritten, so a misconfigured device is visible.
        let forged = br#"{"gw_id":"6167672d303030326167672d30303032","ts":1717000000,"nodes":[]}"#;
        assert!(accept_batch(GATEWAY, forged, 1_717_000_000).is_err());
    }

    #[test]
    fn malformed_bodies_are_rejected_without_panicking() {
        assert!(accept_batch(GATEWAY, b"not json", 0).is_err());
        assert!(accept_batch(GATEWAY, b"{}", 0).is_err());
        assert!(accept_batch(GATEWAY, b"", 0).is_err());
    }
}
