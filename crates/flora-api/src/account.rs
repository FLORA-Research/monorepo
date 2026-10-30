//! Authenticated account and device handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use uuid::Uuid;

use crate::dto::{AccountResponse, GatewaySummary};
use crate::state::{ApiError, AppState};

/// Extract and verify the bearer JWT, returning the account and device.
pub fn authenticate(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<flora_auth::Claims, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    flora_auth::verify_access_token(&state.jwt_secret, token).map_err(|_| ApiError::Unauthorized)
}

/// `GET /account/me`
pub async fn me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AccountResponse>, ApiError> {
    let claims = authenticate(&state, &headers)?;

    let account = sqlx::query_as::<_, (Uuid, chrono::DateTime<Utc>)>(
        "SELECT id, created_at FROM accounts WHERE id = $1",
    )
    .bind(claims.sub)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    let gateways = flora_db::queries::gateways_for_account(&state.pool, claims.sub)
        .await?
        .into_iter()
        .map(GatewaySummary::from)
        .collect();

    Ok(Json(AccountResponse {
        account_id: account.0,
        created_at: account.1,
        gateways,
    }))
}

/// `GET /account/gateways`
pub async fn gateways(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<GatewaySummary>>, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let gateways = flora_db::queries::gateways_for_account(&state.pool, claims.sub)
        .await?
        .into_iter()
        .map(GatewaySummary::from)
        .collect();
    Ok(Json(gateways))
}

/// `POST /account/app-devices/:id/revoke`
///
/// Revoking the device that is calling is allowed: that is the "I lost my
/// other phone" path, and the caller will simply need to sign in again.
pub async fn revoke_app_device(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let claims = authenticate(&state, &headers)?;

    // Scoped by account_id as well as id, so one account cannot revoke another's
    // device by guessing a UUID.
    let result = sqlx::query(
        "UPDATE app_devices SET revoked_at = $3
         WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(claims.sub)
    .bind(Utc::now())
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    // Revoking a device also kills its refresh tokens, so a stolen phone cannot
    // keep minting access tokens.
    sqlx::query(
        "UPDATE refresh_tokens SET used_at = now() WHERE device_id = $1 AND used_at IS NULL",
    )
    .bind(device_id)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
