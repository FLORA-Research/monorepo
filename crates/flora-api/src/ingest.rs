//! Device-facing ingest endpoint.
//!
//! `POST /ingest/batch` is how an aggregator delivers everything it collected:
//! its own plot's readings, and the readings of every node it polled. One
//! request carries both, because the aggregator already assembles them into a
//! single batch for storage.
//!
//! Authentication is `username = device_id`, `password = device_token`, the
//! same credentials the device was provisioned with. The token is compared
//! against a stored hash and the device id in the credential must match the
//! batch, so a valid device still cannot write another plot's data.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;

use flora_auth::{hash_token, tokens_match, unhex};

use crate::state::{ApiError, AppState};
use crate::stream::{ReadingEvent, publish_telemetry};

/// Message returned on success, reporting how many rows were new.
#[derive(Debug, serde::Serialize)]
pub struct IngestResponse {
    pub accepted: usize,
    pub stored: u64,
    pub dropped: u32,
    /// Server-assigned timestamp when the device clock was not trusted.
    pub ts: chrono::DateTime<Utc>,
}

/// Parse device credentials from the `Authorization` header.
///
/// `Authorization: Device <device_id>:<device_token_hex>`. A dedicated scheme
/// keeps device credentials from being confused with the organisation key used
/// by `/provision/*` or a user's bearer JWT.
pub(crate) fn device_credentials(headers: &HeaderMap) -> Result<(String, Vec<u8>), ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Device "))
        .ok_or(ApiError::Unauthorized)?;

    // The device id is hex and has no colon, so the first colon separates the
    // two fields unambiguously.
    let (device_id, token_hex) = value.split_once(':').ok_or(ApiError::Unauthorized)?;
    if device_id.is_empty() {
        return Err(ApiError::Unauthorized);
    }
    let token = unhex(token_hex).ok_or(ApiError::Unauthorized)?;
    if token.len() != flora_auth::secrets::TOKEN_BYTES {
        return Err(ApiError::Unauthorized);
    }
    Ok((device_id.to_owned(), token))
}

/// Verify a device token against its stored hash.
///
/// The lookup is by device id, then the hash is compared in constant time, so a
/// timing signal cannot be used to probe for a valid token.
pub(crate) async fn authorize_device(
    state: &AppState,
    device_id: &str,
    token: &[u8],
) -> Result<(), ApiError> {
    let stored: Option<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT t.token_hash, g.status
         FROM device_tokens t
         JOIN gateways g ON g.id = t.device_id
         WHERE t.device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((stored_hash, status)) = stored else {
        // Unknown device and wrong token are reported identically, so the
        // endpoint does not confirm which device ids exist.
        return Err(ApiError::Unauthorized);
    };
    if status == "retired" {
        // A revoked device must stop being able to write data.
        return Err(ApiError::Forbidden);
    }
    if !tokens_match(&hash_token(token), &stored_hash) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// `POST /ingest/batch`
pub async fn batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<IngestResponse>), ApiError> {
    let (device_id, token) = device_credentials(&headers)?;

    if body.len() > flora_ingest::MAX_BATCH_BYTES {
        return Err(ApiError::BadRequest("batch is too large".into()));
    }

    authorize_device(&state, &device_id, &token).await?;

    let now = Utc::now().timestamp();
    let incoming = flora_ingest::accept_batch(&device_id, &body, now)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let stored = flora_ingest::store(&state.pool, &incoming)
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?;

    // Notify subscribed apps. The account is needed to route the event, and an
    // unclaimed gateway has none, so it simply notifies nobody.
    let account_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT account_id FROM gateways WHERE id = $1")
            .bind(&device_id)
            .fetch_optional(&state.pool)
            .await?
            .flatten();

    let addresses: std::collections::HashMap<[u8; 8], u8> = incoming
        .nodes
        .iter()
        .map(|node| (node.node_uuid, node.addr))
        .collect();
    let readings = incoming
        .readings
        .iter()
        .map(|reading| {
            let uuid: [u8; 8] = reading.node_uuid.as_slice().try_into().unwrap_or([0u8; 8]);
            ReadingEvent {
                node_uuid: flora_auth::hex(&reading.node_uuid),
                addr: addresses.get(&uuid).copied().unwrap_or(0),
                moisture: reading.moisture,
                temperature: reading.temperature,
                humidity: reading.humidity,
                valve_state: reading.valve_state,
            }
        })
        .collect();
    publish_telemetry(&state.events, account_id, &device_id, readings);

    tracing::debug!(
        %device_id,
        accepted = incoming.readings.len(),
        stored,
        dropped = incoming.dropped,
        "batch ingested"
    );

    Ok((
        StatusCode::OK,
        Json(IngestResponse {
            accepted: incoming.readings.len(),
            stored,
            dropped: incoming.dropped,
            ts: incoming.ts,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn device_credentials_parse_the_device_scheme() {
        let token = "ab".repeat(32);
        let (device_id, parsed) =
            device_credentials(&headers_with(&format!("Device gw123:{token}"))).unwrap();
        assert_eq!(device_id, "gw123");
        assert_eq!(parsed.len(), 32);
    }

    #[test]
    fn other_authorization_schemes_are_not_device_credentials() {
        // A bearer JWT or the provision key must not authenticate a device.
        assert!(device_credentials(&headers_with("Bearer sometoken")).is_err());
        assert!(device_credentials(&headers_with("Basic abc")).is_err());
        assert!(device_credentials(&HeaderMap::new()).is_err());
    }

    #[test]
    fn malformed_device_credentials_are_rejected() {
        assert!(device_credentials(&headers_with("Device gw123")).is_err());
        assert!(device_credentials(&headers_with("Device :aabb")).is_err());
        // Non-hex token.
        assert!(device_credentials(&headers_with("Device gw123:zzzz")).is_err());
        // Wrong token length.
        assert!(device_credentials(&headers_with("Device gw123:aabb")).is_err());
    }
}
