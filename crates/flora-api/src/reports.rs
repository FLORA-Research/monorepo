//! `/account/reports/*`: the Chapter 4 outputs.
//!
//! Each report fetches rows scoped to the caller's account and then hands them
//! to `flora-analytics`, so the arithmetic lives in tested functions rather than
//! in SQL that a reader cannot check against the methodology.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use flora_analytics::{
    FleetEntry, FleetHealth, MaeReport, PairedSample, WaterSavings, WaterUse, fleet_health,
    mae_report, pair_with_reference, valve_open_minutes, water_savings,
};

use crate::account::authenticate;
use crate::state::{ApiError, AppState};

/// The paper's data-collection window.
const COLLECTION_WINDOW_DAYS: i64 = 45;
/// How far a reference measurement may be from a reading to be paired with it.
const REFERENCE_TOLERANCE_MINUTES: i64 = 5;
/// Valve state is sampled per uplink, so an open reading implies at most this
/// much watering before the next sighting.
const MAX_OPEN_GAP_MINUTES: i64 = 10;
/// A gateway is offline after three missed uplink periods.
const OFFLINE_AFTER_MINUTES: i64 = 15;

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    pub gateway_id: Option<String>,
    pub node_uuid: Option<String>,
    pub days: Option<i64>,
    /// Baseline watering minutes per day, for the savings comparison.
    pub baseline_minutes_per_day: Option<f64>,
    /// Flow rate in litres per minute, to convert open time into volume.
    pub litres_per_minute: Option<f64>,
}

/// Valve samples for one node, in time order.
type NodeSamples = (Vec<u8>, Vec<(DateTime<Utc>, Option<i16>)>);

/// A gateway's health row: id, label, status, firmware, last sighting.
type FleetRow = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
);

/// A reference row: time plus the three measured references.
type ReferenceRow = (DateTime<Utc>, Option<f32>, Option<f32>, Option<f32>);

/// A reading row: time plus the three sensor metrics.
type ReadingRow = (DateTime<Utc>, Option<f32>, Option<f32>, Option<f32>);

#[derive(Debug, Serialize)]
pub struct MaeResponse {
    pub gateways: Vec<MaeReport>,
}

/// `GET /account/reports/mae`
///
/// Compares each node metric against the independent reference measurements
/// recorded during the validation procedure.
pub async fn mae(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReportQuery>,
) -> Result<Json<MaeResponse>, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let days = query.days.unwrap_or(COLLECTION_WINDOW_DAYS).clamp(1, 365);
    let since = Utc::now() - Duration::days(days);

    // Scoped to the account: the join on gateways is what enforces ownership.
    let gateways = selected_gateways(&state, claims.sub, query.gateway_id.as_deref()).await?;
    let mut reports = Vec::new();

    for gateway_id in gateways {
        let references: Vec<ReferenceRow> = sqlx::query_as(
            "SELECT ts, moisture_ref, temperature_ref, humidity_ref
                 FROM reference_measurements
                 WHERE gateway_id = $1 AND ts >= $2
                 ORDER BY ts",
        )
        .bind(&gateway_id)
        .bind(since)
        .fetch_all(&state.pool)
        .await?;

        let readings: Vec<ReadingRow> = sqlx::query_as(
            "SELECT ts, moisture, temperature, humidity FROM readings
                 WHERE gateway_id = $1 AND ts >= $2
                   AND ($3::bytea IS NULL OR node_uuid = $3)
                 ORDER BY ts",
        )
        .bind(&gateway_id)
        .bind(since)
        .bind(query_node_uuid(&query)?)
        .fetch_all(&state.pool)
        .await?;

        for (index, metric) in flora_analytics::METRICS.iter().enumerate() {
            let reading_pairs: Vec<(DateTime<Utc>, Option<f32>)> = readings
                .iter()
                .map(|(ts, a, b, c)| {
                    let value = match index {
                        0 => *a,
                        1 => *b,
                        _ => *c,
                    };
                    (*ts, value)
                })
                .collect();
            let reference_pairs: Vec<(DateTime<Utc>, Option<f32>)> = references
                .iter()
                .map(|(ts, a, b, c)| {
                    let value = match index {
                        0 => *a,
                        1 => *b,
                        _ => *c,
                    };
                    (*ts, value)
                })
                .collect();

            let pairs = pair_with_reference(
                &reading_pairs,
                &reference_pairs,
                Duration::minutes(REFERENCE_TOLERANCE_MINUTES),
            );
            let paired = pairs.len();
            let unpaired = reading_pairs
                .iter()
                .filter(|(_, value)| value.is_some())
                .count()
                .saturating_sub(paired);

            let mut report = mae_report(metric, &pairs, unpaired, days);
            // Name the gateway so a multi-aggregator account can tell which
            // plot a number belongs to.
            report.metric = format!("{gateway_id}:{metric}");
            reports.push(report);
        }
    }

    Ok(Json(MaeResponse { gateways: reports }))
}

#[derive(Debug, Serialize)]
pub struct WaterSavingsResponse {
    pub gateways: Vec<GatewayWater>,
}

#[derive(Debug, Serialize)]
pub struct GatewayWater {
    pub gateway_id: String,
    pub nodes: Vec<WaterUse>,
    pub totals: WaterSavings,
}

/// `GET /account/reports/water-savings`
pub async fn water_savings_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReportQuery>,
) -> Result<Json<WaterSavingsResponse>, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let days = query.days.unwrap_or(COLLECTION_WINDOW_DAYS).clamp(1, 365);
    let since = Utc::now() - Duration::days(days);
    let gateways = selected_gateways(&state, claims.sub, query.gateway_id.as_deref()).await?;

    let mut per_gateway = Vec::new();
    for gateway_id in gateways {
        let rows: Vec<(Vec<u8>, DateTime<Utc>, Option<i16>)> = sqlx::query_as(
            "SELECT node_uuid, ts, valve_state FROM readings
             WHERE gateway_id = $1 AND ts >= $2
             ORDER BY node_uuid, ts",
        )
        .bind(&gateway_id)
        .bind(since)
        .fetch_all(&state.pool)
        .await?;

        // Group by node, because valve time is per node.
        let mut by_node: Vec<NodeSamples> = Vec::new();
        for (uuid, ts, valve) in rows {
            match by_node.last_mut() {
                Some((existing, samples)) if *existing == uuid => samples.push((ts, valve)),
                _ => by_node.push((uuid, vec![(ts, valve)])),
            }
        }

        let mut nodes = Vec::new();
        let mut automated_total = 0.0;
        for (uuid, samples) in by_node {
            let minutes = valve_open_minutes(&samples, Duration::minutes(MAX_OPEN_GAP_MINUTES));
            automated_total += minutes;
            nodes.push(WaterUse {
                node_uuid: flora_auth::hex(&uuid),
                open_minutes: minutes,
                litres: query.litres_per_minute.map(|rate| minutes * rate),
            });
        }

        let baseline_per_day = query.baseline_minutes_per_day.unwrap_or(0.0);
        let baseline_total = baseline_per_day * days as f64;
        per_gateway.push(GatewayWater {
            gateway_id,
            nodes,
            totals: water_savings(automated_total, baseline_total),
        });
    }

    Ok(Json(WaterSavingsResponse {
        gateways: per_gateway,
    }))
}

/// `GET /account/reports/fleet-health`
pub async fn fleet(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FleetHealth>, ApiError> {
    let claims = authenticate(&state, &headers)?;

    let rows: Vec<FleetRow> = sqlx::query_as(
        "SELECT id, label, status, fw_version, last_seen
         FROM gateways WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(claims.sub)
    .fetch_all(&state.pool)
    .await?;

    let now = Utc::now();
    let mut entries = Vec::with_capacity(rows.len());
    for (gateway_id, label, status, fw_version, last_seen) in rows {
        // One query now that the battery column is gone: the second count only
        // ever asked "how many nodes lack a battery figure", and with no
        // monitor fitted that was every node, which is noise rather than a
        // finding.
        let node_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM nodes WHERE gateway_id = $1")
                .bind(&gateway_id)
                .fetch_one(&state.pool)
                .await?;

        entries.push(FleetEntry {
            gateway_id,
            label,
            status,
            fw_version,
            last_seen,
            minutes_since_seen: last_seen.map(|seen| (now - seen).num_minutes()),
            nodes: node_count,
        });
    }

    Ok(Json(fleet_health(entries, OFFLINE_AFTER_MINUTES)))
}

/// The account's gateways, optionally narrowed to one.
///
/// A `gateway_id` the caller does not own yields nothing rather than an error,
/// so the report does not confirm whether that gateway exists.
async fn selected_gateways(
    state: &AppState,
    account_id: uuid::Uuid,
    requested: Option<&str>,
) -> Result<Vec<String>, ApiError> {
    match requested {
        Some(gateway_id) => {
            let gateway = flora_db::queries::gateway_by_id(&state.pool, gateway_id)
                .await?
                .ok_or(ApiError::NotFound)?;
            if !gateway.owned_by(account_id) {
                return Err(ApiError::Forbidden);
            }
            Ok(vec![gateway.id])
        }
        None => Ok(
            flora_db::queries::gateways_for_account(&state.pool, account_id)
                .await?
                .into_iter()
                .map(|gateway| gateway.id)
                .collect(),
        ),
    }
}

fn query_node_uuid(query: &ReportQuery) -> Result<Option<Vec<u8>>, ApiError> {
    match query.node_uuid.as_deref() {
        None => Ok(None),
        Some(value) => {
            let bytes = flora_auth::unhex(value)
                .filter(|bytes| bytes.len() == 8)
                .ok_or_else(|| ApiError::BadRequest("node_uuid must be 8 bytes of hex".into()))?;
            Ok(Some(bytes))
        }
    }
}

/// A paired sample is exposed so a report consumer can see the raw pairs.
#[derive(Debug, Serialize)]
pub struct PairView {
    pub sensor: f32,
    pub reference: f32,
}

impl From<PairedSample> for PairView {
    fn from(pair: PairedSample) -> Self {
        Self {
            sensor: pair.sensor,
            reference: pair.reference,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_uuid_filter_is_validated() {
        let ok = ReportQuery {
            gateway_id: None,
            node_uuid: Some("0202020202020202".into()),
            days: None,
            baseline_minutes_per_day: None,
            litres_per_minute: None,
        };
        assert_eq!(query_node_uuid(&ok).unwrap().unwrap().len(), 8);

        let short = ReportQuery {
            node_uuid: Some("0202".into()),
            ..ok
        };
        assert!(query_node_uuid(&short).is_err());

        let none = ReportQuery {
            node_uuid: None,
            ..ReportQuery {
                gateway_id: None,
                node_uuid: None,
                days: None,
                baseline_minutes_per_day: None,
                litres_per_minute: None,
            }
        };
        assert_eq!(query_node_uuid(&none).unwrap(), None);
    }

    #[test]
    fn the_default_window_is_the_collection_period() {
        // The paper specifies 45 days, so the default must match or a report
        // silently covers less data than the methodology claims.
        assert_eq!(COLLECTION_WINDOW_DAYS, 45);
    }
}
