//! Reference measurements: the ground truth a sensor is judged against.
//!
//! `reports::mae` compares these against what the node reported, and until now
//! nothing ever wrote them, so every MAE came back null. This is the writer.
//!
//! References are taken by hand with a calibrated meter, so they are sparse,
//! arrive out of band, and often arrive late: a student walks the plots in the
//! afternoon and types the numbers in that evening. Nothing here assumes a
//! reference arrives before or near its reading; the tolerance window is
//! applied when the report pairs them, not when they are stored.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::account::authenticate;
use crate::state::{ApiError, AppState};

/// Longest method string kept. Methods are free text (`"oven-dry"`,
/// `"TDR probe"`), so this is a sanity bound, not a vocabulary.
const MAX_METHOD_LEN: usize = 64;

#[derive(Debug, Deserialize)]
pub struct ReferenceRequest {
    pub ts: DateTime<Utc>,
    /// Hex-encoded 8-byte node UUID.
    pub node_uuid: String,
    /// Whichever of these were measured. A reference that measured nothing is
    /// rejected rather than stored as a row of nulls, because a null row would
    /// count as a reference and silently widen the pairing window.
    pub moisture_ref: Option<f32>,
    pub temperature_ref: Option<f32>,
    pub humidity_ref: Option<f32>,
    pub method: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReferenceResponse {
    pub ts: DateTime<Utc>,
    pub node_uuid: String,
    /// `inserted` or `replaced`; replacing is the normal case when a reading is
    /// corrected after the fact.
    pub status: &'static str,
}

/// Store a reference measurement.
///
/// The primary key is `(ts, gateway_id, node_uuid)`, so re-submitting the same
/// triple is a correction, not a duplicate. That is deliberate: a transcription
/// typo is far likelier than two genuinely different references taken at the
/// same instant for the same node, and an upsert lets the mistake be fixed
/// without a delete path.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
    Json(request): Json<ReferenceRequest>,
) -> Result<(StatusCode, Json<ReferenceResponse>), ApiError> {
    owned_gateway(&state, &headers, &gateway_id).await?;

    let node_uuid = flora_auth::unhex(&request.node_uuid)
        .filter(|bytes| bytes.len() == 8)
        .ok_or_else(|| ApiError::BadRequest("node_uuid must be 8 bytes of hex".into()))?;

    // A reference whose values are all absent carries no information and would
    // still occupy a row, so it is refused instead of stored.
    if request.moisture_ref.is_none()
        && request.temperature_ref.is_none()
        && request.humidity_ref.is_none()
    {
        return Err(ApiError::BadRequest(
            "at least one of moisture_ref, temperature_ref, humidity_ref is required".into(),
        ));
    }

    if let Some(method) = &request.method
        && method.len() > MAX_METHOD_LEN
    {
        return Err(ApiError::BadRequest(format!(
            "method must be at most {MAX_METHOD_LEN} characters"
        )));
    }

    // Every value must be finite: NaN and infinities are representable in JSON
    // only as non-standard literals, and a NaN would poison the MAE sum rather
    // than fail loudly.
    for (name, value) in [
        ("moisture_ref", request.moisture_ref),
        ("temperature_ref", request.temperature_ref),
        ("humidity_ref", request.humidity_ref),
    ] {
        if let Some(value) = value
            && !value.is_finite()
        {
            return Err(ApiError::BadRequest(format!("{name} must be finite")));
        }
    }

    let inserted = sqlx::query_scalar::<_, bool>(
        "INSERT INTO reference_measurements
             (ts, gateway_id, node_uuid, moisture_ref, temperature_ref, humidity_ref, method)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (ts, gateway_id, node_uuid) DO UPDATE
             SET moisture_ref = EXCLUDED.moisture_ref,
                 temperature_ref = EXCLUDED.temperature_ref,
                 humidity_ref = EXCLUDED.humidity_ref,
                 method = EXCLUDED.method
         RETURNING (xmax = 0) AS inserted",
    )
    .bind(request.ts)
    .bind(&gateway_id)
    .bind(&node_uuid)
    .bind(request.moisture_ref)
    .bind(request.temperature_ref)
    .bind(request.humidity_ref)
    .bind(request.method.as_deref())
    .fetch_one(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ReferenceResponse {
            ts: request.ts,
            node_uuid: request.node_uuid,
            status: if inserted { "inserted" } else { "replaced" },
        }),
    ))
}

/// Same ownership rule as every other gateway-scoped route: the gateway must
/// exist and belong to the caller. A missing gateway and someone else's gateway
/// are both 404, so the API does not confirm that a device id is in use.
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
        return Err(ApiError::NotFound);
    }
    Ok(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_request_accepts_a_partial_measurement() {
        let request: ReferenceRequest = serde_json::from_str(
            r#"{"ts":"2026-01-01T00:00:00Z","node_uuid":"0102030405060708","moisture_ref":31.5}"#,
        )
        .unwrap();
        assert_eq!(request.moisture_ref, Some(31.5));
        assert!(request.temperature_ref.is_none());
        assert!(request.method.is_none());
    }

    #[test]
    fn reference_request_requires_a_timestamp_and_uuid() {
        assert!(
            serde_json::from_str::<ReferenceRequest>(r#"{"node_uuid":"0102030405060708"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ReferenceRequest>(r#"{"ts":"2026-01-01T00:00:00Z"}"#).is_err()
        );
    }
}
