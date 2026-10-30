//! Read-only gateway data for the app: nodes, readings, and history.
//!
//! Every handler funnels through one ownership check, so a per-handler habit
//! cannot become an authorisation gap. The check is on the gateway's
//! `account_id`, never on anything in the request.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::account::authenticate;
use crate::state::{ApiError, AppState};

/// Default history window when the caller does not specify one.
const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Hard cap on returned rows, so one request cannot pull the whole dataset.
const MAX_ROWS: i64 = 2_000;

/// A node row: uuid, address, label, firmware, first and last sighting.
type NodeRow = (
    Vec<u8>,
    i16,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

/// A reading row, in the column order the queries select.
type ReadingRow = (
    DateTime<Utc>,
    Vec<u8>,
    Option<f32>,
    Option<f32>,
    Option<f32>,
    Option<i16>,
    Option<i64>,
);

#[derive(Debug, Serialize)]
pub struct NodeView {
    pub node_uuid: String,
    pub addr: u8,
    pub label: Option<String>,
    pub fw_version: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Whether the node answered recently enough to be considered online.
    pub online: bool,
}

/// A node is considered offline once this much time passes without a reading.
///
/// Three uplink periods, so one missed batch does not flip the indicator.
const OFFLINE_AFTER_MINUTES: i64 = 15;

#[derive(Debug, Serialize)]
pub struct ReadingView {
    pub ts: DateTime<Utc>,
    pub node_uuid: String,
    /// Percent, or `null` when the firmware reported the value unavailable.
    pub moisture: Option<f32>,
    /// Degrees Celsius, or `null` when unavailable.
    pub temperature: Option<f32>,
    pub humidity: Option<f32>,
    pub valve_state: Option<i16>,
    pub seq: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub node_uuid: Option<String>,
    /// One of `moisture`, `temperature`, `humidity`.
    pub metric: Option<String>,
    pub limit: Option<i64>,
}

/// Confirm the gateway exists and belongs to the caller's account.
async fn owned_gateway(
    state: &AppState,
    headers: &HeaderMap,
    gateway_id: &str,
) -> Result<uuid::Uuid, ApiError> {
    let claims = authenticate(state, headers)?;
    let gateway = flora_db::queries::gateway_by_id(&state.pool, gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !gateway.owned_by(claims.sub) {
        return Err(ApiError::Forbidden);
    }
    Ok(claims.sub)
}

/// `GET /gateways/{id}/nodes`
pub async fn nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Result<Json<Vec<NodeView>>, ApiError> {
    owned_gateway(&state, &headers, &gateway_id).await?;

    let rows: Vec<NodeRow> = sqlx::query_as(
        "SELECT node_uuid, addr, label, fw_version, first_seen, last_seen
             FROM nodes WHERE gateway_id = $1 ORDER BY addr",
    )
    .bind(&gateway_id)
    .fetch_all(&state.pool)
    .await?;

    let cutoff = Utc::now() - Duration::minutes(OFFLINE_AFTER_MINUTES);
    Ok(Json(
        rows.into_iter()
            .map(
                |(uuid, addr, label, fw_version, first_seen, last_seen)| NodeView {
                    node_uuid: flora_auth::hex(&uuid),
                    addr: addr as u8,
                    label,
                    fw_version,
                    first_seen,
                    online: last_seen.is_some_and(|seen| seen > cutoff),
                    last_seen,
                },
            )
            .collect(),
    ))
}

/// `GET /gateways/{id}/readings/latest`
///
/// The newest reading per node, which is what a dashboard shows.
pub async fn latest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Result<Json<Vec<ReadingView>>, ApiError> {
    owned_gateway(&state, &headers, &gateway_id).await?;

    let rows: Vec<ReadingRow> = sqlx::query_as(
        // `DISTINCT ON` with a matching ORDER BY picks the newest row per node
        // in one pass, rather than a correlated subquery per node.
        "SELECT DISTINCT ON (node_uuid)
                ts, node_uuid, moisture, temperature, humidity, valve_state, seq
         FROM readings
         WHERE gateway_id = $1
         ORDER BY node_uuid, ts DESC",
    )
    .bind(&gateway_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(ts, uuid, moisture, temperature, humidity, valve_state, seq)| ReadingView {
                    ts,
                    node_uuid: flora_auth::hex(&uuid),
                    moisture,
                    temperature,
                    humidity,
                    valve_state,
                    seq,
                },
            )
            .collect(),
    ))
}

/// `GET /gateways/{id}/readings?from&to&node_uuid&metric&limit`
pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<ReadingView>>, ApiError> {
    owned_gateway(&state, &headers, &gateway_id).await?;

    let now = Utc::now();
    let from = match query.from.as_deref() {
        Some(value) => parse_time(value)?,
        None => now - Duration::hours(DEFAULT_WINDOW_HOURS),
    };
    let to = match query.to.as_deref() {
        Some(value) => parse_time(value)?,
        None => now,
    };
    if to <= from {
        return Err(ApiError::BadRequest("`to` must be after `from`".into()));
    }

    let node_uuid = match query.node_uuid.as_deref() {
        Some(value) => Some(
            flora_auth::unhex(value)
                .filter(|bytes| bytes.len() == 8)
                .ok_or_else(|| ApiError::BadRequest("node_uuid must be 8 bytes of hex".into()))?,
        ),
        None => None,
    };

    // `metric` selects the column, so it must map to a fixed literal rather
    // than being interpolated into the statement.
    let metric = match query.metric.as_deref() {
        None => "all",
        Some("moisture") => "moisture",
        Some("temperature") => "temperature",
        Some("humidity") => "humidity",
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown metric {other}; expected moisture, temperature, or humidity"
            )));
        }
    };

    let limit = query.limit.unwrap_or(MAX_ROWS).clamp(1, MAX_ROWS);

    let rows: Vec<ReadingRow> = sqlx::query_as(
        "SELECT ts, node_uuid, moisture, temperature, humidity, valve_state, seq
         FROM readings
         WHERE gateway_id = $1
           AND ts >= $2 AND ts <= $3
           AND ($4::bytea IS NULL OR node_uuid = $4)
         ORDER BY ts DESC
         LIMIT $5",
    )
    .bind(&gateway_id)
    .bind(from)
    .bind(to)
    .bind(node_uuid)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(ts, uuid, moisture, temperature, humidity, valve_state, seq)| {
                    ReadingView {
                        ts,
                        node_uuid: flora_auth::hex(&uuid),
                        // A metric filter blanks the others so a chart never plots a
                        // column the caller did not ask for.
                        moisture: if matches!(metric, "all" | "moisture") {
                            moisture
                        } else {
                            None
                        },
                        temperature: if matches!(metric, "all" | "temperature") {
                            temperature
                        } else {
                            None
                        },
                        humidity: if matches!(metric, "all" | "humidity") {
                            humidity
                        } else {
                            None
                        },
                        valve_state,
                        seq,
                    }
                },
            )
            .collect(),
    ))
}

/// Parse an RFC 3339 timestamp or a Unix epoch second.
fn parse_time(value: &str) -> Result<DateTime<Utc>, ApiError> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(parsed.with_timezone(&Utc));
    }
    if let Ok(seconds) = value.parse::<i64>() {
        return DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| ApiError::BadRequest("timestamp is out of range".into()));
    }
    Err(ApiError::BadRequest(
        "expected an RFC 3339 timestamp or a Unix epoch second".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_accept_both_documented_forms() {
        let rfc = parse_time("2026-10-02T12:00:00Z").unwrap();
        let epoch = parse_time("1791024000").unwrap();
        assert_eq!(epoch.timestamp(), 1_791_024_000);
        assert!(rfc.timestamp() > 0);
        assert!(parse_time("not a time").is_err());
        assert!(parse_time("").is_err());
    }

    #[test]
    fn out_of_range_epochs_are_rejected() {
        assert!(parse_time("999999999999999999").is_err());
    }

    #[test]
    fn offline_threshold_matches_three_uplink_periods() {
        // The aggregator uplinks every five minutes, so three missed batches
        // is the point at which a node is genuinely gone rather than unlucky.
        assert_eq!(OFFLINE_AFTER_MINUTES, 15);
    }

    #[test]
    fn history_limit_is_clamped() {
        // Guards the same expression the handler uses.
        assert_eq!(5_000i64.clamp(1, MAX_ROWS), MAX_ROWS);
        assert_eq!(0i64.clamp(1, MAX_ROWS), 1);
        assert_eq!((-5i64).clamp(1, MAX_ROWS), 1);
    }
}
