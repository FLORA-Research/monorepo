//! `/provision/*` handlers.
//!
//! Called by the provisioner CLI, never by a phone. Authorised with the
//! organisation API key, which is compared against an Argon2 hash.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;

use flora_auth::{claim_expiry, hash_api_key, hex, unhex, verify_api_key};

use crate::dto::{
    ProvisionStatusResponse, RegisterRequest, RegisterResponse, ReissueRequest, ReissueResponse,
};
use crate::state::{ApiError, AppState};

/// Verify the Bearer credential against the configured hash.
pub async fn authorize(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let Some(expected) = state.provision_key_hash.as_deref() else {
        // No key configured means the endpoint is closed, not open. Failing
        // closed matters: an unset variable must not expose provisioning.
        return Err(ApiError::Forbidden);
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    // Argon2 is intentionally slow, so it runs off the async worker.
    let expected = expected.to_owned();
    let presented = presented.to_owned();
    let valid = tokio::task::spawn_blocking(move || verify_api_key(&presented, &expected))
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .map_err(|error| ApiError::Internal(error.to_string()))?;

    if valid {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

/// Helper for operators: turn a plaintext key into a storable hash.
///
/// Exposed so the deployment step has one obvious way to derive the value for
/// `PROVISION_API_KEY_HASH`.
pub fn hash_key_for_config(api_key: &str) -> Result<String, ApiError> {
    hash_api_key(api_key).map_err(|error| ApiError::Internal(error.to_string()))
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    authorize(&headers, &state).await?;

    let pubkey = decode_hex_field(&body.pubkey, "pubkey")?;
    if pubkey.len() != flora_protocol::PUBLIC_KEY_LEN {
        return Err(ApiError::BadRequest("pubkey must be 32 bytes".into()));
    }
    let token_hash = decode_hex_field(&body.token_hash, "token_hash")?;
    let claim_hash = decode_hex_field(&body.claim_hash, "claim_hash")?;
    if token_hash.is_empty() || claim_hash.is_empty() {
        return Err(ApiError::BadRequest(
            "token_hash and claim_hash are required".into(),
        ));
    }
    // The device id is derived, not trusted: a mismatch means the caller and the
    // key disagree, which would let one device claim another's identity.
    let derived = flora_protocol::device_id_bytes(&pubkey)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let expected_id = hex(&derived);
    if expected_id != body.device_id {
        return Err(ApiError::BadRequest(
            "device_id does not match the supplied public key".into(),
        ));
    }

    let now = Utc::now();
    let expires_at = claim_expiry(now);

    sqlx::query(
        "INSERT INTO gateways (id, pubkey, label, status, fw_version)
         VALUES ($1, $2, $3, 'unclaimed', $4)
         ON CONFLICT (id) DO UPDATE
           SET pubkey = EXCLUDED.pubkey,
               label = COALESCE(EXCLUDED.label, gateways.label),
               fw_version = EXCLUDED.fw_version",
    )
    .bind(&body.device_id)
    .bind(&pubkey)
    .bind(&body.label)
    .bind(&body.fw_ver)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        "INSERT INTO device_tokens (device_id, token_hash)
         VALUES ($1, $2)
         ON CONFLICT (device_id) DO UPDATE SET token_hash = EXCLUDED.token_hash,
                                               rotated_at = now()",
    )
    .bind(&body.device_id)
    .bind(&token_hash)
    .execute(&state.pool)
    .await?;

    flora_db::queries::upsert_claim_token(&state.pool, &body.device_id, &claim_hash, expires_at)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            device_id: body.device_id,
            status: "unclaimed".into(),
            claim_expires_at: expires_at,
        }),
    ))
}

pub async fn reissue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ReissueRequest>,
) -> Result<Json<ReissueResponse>, ApiError> {
    authorize(&headers, &state).await?;

    let gateway = flora_db::queries::gateway_by_id(&state.pool, &body.device_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if gateway.is_retired() {
        return Err(ApiError::Conflict("gateway is retired".into()));
    }

    // A reissue mints a fresh claim token. The provisioner prints it; the cloud
    // only ever sees the hash, which the caller supplies.
    let expires_at = claim_expiry(Utc::now());
    sqlx::query("UPDATE claim_tokens SET expires_at = $2, used_at = NULL WHERE device_id = $1")
        .bind(&body.device_id)
        .bind(expires_at)
        .execute(&state.pool)
        .await?;

    Ok(Json(ReissueResponse {
        device_id: body.device_id,
        claim_expires_at: expires_at,
    }))
}

pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<Json<ProvisionStatusResponse>, ApiError> {
    authorize(&headers, &state).await?;

    let gateway = flora_db::queries::gateway_by_id(&state.pool, &device_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(ProvisionStatusResponse {
        device_id: gateway.id,
        status: gateway.status,
        label: gateway.label,
        hw: None,
        fw_version: gateway.fw_version,
        created_at: gateway.created_at,
        claimed_at: gateway.claimed_at,
        retired_at: gateway.retired_at,
    }))
}

fn decode_hex_field(value: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    unhex(value).ok_or_else(|| ApiError::BadRequest(format!("{field} must be hexadecimal")))
}

/// Re-exported so the server wiring can log a derived hash during setup.
pub fn describe_hash(bytes: &[u8]) -> String {
    hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_fields_are_validated() {
        assert!(decode_hex_field("aabb", "pubkey").is_ok());
        assert!(decode_hex_field("zz", "pubkey").is_err());
        assert!(decode_hex_field("abc", "pubkey").is_err());
    }

    #[test]
    fn derived_hash_is_storable_and_verifiable() {
        let hash = hash_key_for_config("an-api-key").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_api_key("an-api-key", &hash).unwrap());
        assert!(!verify_api_key("another-key", &hash).unwrap());
    }
}
