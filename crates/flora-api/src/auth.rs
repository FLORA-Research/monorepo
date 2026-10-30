//! `/auth/*` handlers: challenge, verify, and refresh.
//!
//! Sign-in is a signature over a server nonce. There is nothing to type, and
//! nothing secret is transmitted: the app proves possession of a private key it
//! holds locally, and recovery happens by re-deriving that key from the phrase
//! rather than by sending the phrase here.

use axum::Json;
use axum::extract::State;
use chrono::{Duration, Utc};

use flora_auth::pairing::NONCE_TTL_MINUTES;
use flora_auth::{generate_token, hash_token, hex, refresh_expiry, tokens_match, unhex};

use crate::dto::{
    ChallengeRequest, ChallengeResponse, RefreshRequest, TokenPair, VerifyRequest, VerifyResponse,
};
use crate::pairing::issue_tokens;
use crate::state::{ApiError, AppState};

/// Message an app signs to sign in. Domain-separated from pairing and commands.
pub const AUTH_PREFIX: &[u8] = b"flora-auth-v1";

pub fn auth_message(pubkey: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(AUTH_PREFIX.len() + pubkey.len() + nonce.len());
    message.extend_from_slice(AUTH_PREFIX);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(nonce);
    message
}

/// Issue a nonce for the app to sign.
pub async fn challenge(
    State(state): State<AppState>,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let now = Utc::now();
    let pubkey = unhex(&body.app_pubkey)
        .ok_or_else(|| ApiError::BadRequest("app_pubkey must be hexadecimal".into()))?;
    if pubkey.len() != flora_protocol::PUBLIC_KEY_LEN {
        return Err(ApiError::BadRequest("app_pubkey must be 32 bytes".into()));
    }
    if !state
        .auth_limiter
        .check(&format!("challenge:{}", body.app_pubkey), now.timestamp())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    let nonce = generate_token().map_err(|error| ApiError::Internal(error.to_string()))?;
    let expires_at = now + Duration::minutes(NONCE_TTL_MINUTES);
    flora_db::queries::prune_nonces(&state.pool, now).await?;
    flora_db::queries::record_nonce(&state.pool, &nonce, "auth", expires_at).await?;

    Ok(Json(ChallengeResponse {
        nonce: hex(&nonce),
        expires_at,
    }))
}

/// Verify a signed challenge and issue tokens.
pub async fn verify(
    State(state): State<AppState>,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let now = Utc::now();
    let pubkey = unhex(&body.app_pubkey)
        .ok_or_else(|| ApiError::BadRequest("app_pubkey must be hexadecimal".into()))?;
    let nonce = unhex(&body.nonce)
        .ok_or_else(|| ApiError::BadRequest("nonce must be hexadecimal".into()))?;
    let signature = unhex(&body.signature)
        .ok_or_else(|| ApiError::BadRequest("signature must be hexadecimal".into()))?;

    if !state
        .auth_limiter
        .check(&format!("verify:{}", body.app_pubkey), now.timestamp())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    // The nonce must be one we issued, unused, and unexpired. Delete-and-return
    // makes single use atomic: a replayed nonce finds no row.
    let consumed: Option<(Vec<u8>,)> = sqlx::query_as(
        "DELETE FROM auth_nonces
         WHERE nonce = $1 AND scope = 'auth' AND expires_at > $2
         RETURNING nonce",
    )
    .bind(&nonce)
    .bind(now)
    .fetch_optional(&state.pool)
    .await?;
    if consumed.is_none() {
        return Err(ApiError::Unauthorized);
    }

    flora_protocol::verify_command_signature(&pubkey, &auth_message(&pubkey, &nonce), &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    let device = flora_db::queries::live_app_device_by_pubkey(&state.pool, &pubkey)
        .await?
        .ok_or(ApiError::NotFound)?;

    sqlx::query("UPDATE app_devices SET last_seen = $2 WHERE id = $1")
        .bind(device.id)
        .bind(now)
        .execute(&state.pool)
        .await?;

    let (access, refresh) = issue_tokens(&state, device.account_id, device.id, now).await?;
    Ok(Json(VerifyResponse {
        access_token: access,
        refresh_token: refresh,
        expires_in: flora_auth::ACCESS_TTL_MINUTES * 60,
        account_id: device.account_id,
    }))
}

/// Exchange a refresh token for a new pair, rotating the old one.
pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, ApiError> {
    let now = Utc::now();
    let presented = unhex(&body.refresh_token)
        .ok_or_else(|| ApiError::BadRequest("refresh_token must be hexadecimal".into()))?;
    let hash = hash_token(&presented);

    let row: Option<(uuid::Uuid, uuid::Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, device_id, token_hash FROM refresh_tokens
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(&hash)
    .bind(now)
    .fetch_optional(&state.pool)
    .await?;
    let (token_id, device_id, stored_hash) = row.ok_or(ApiError::Unauthorized)?;
    if !tokens_match(&hash, &stored_hash) {
        return Err(ApiError::Unauthorized);
    }

    // Rotate: mark used first, so two concurrent refreshes cannot both succeed.
    let rotated =
        sqlx::query("UPDATE refresh_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL")
            .bind(token_id)
            .bind(now)
            .execute(&state.pool)
            .await?;
    if rotated.rows_affected() != 1 {
        return Err(ApiError::Unauthorized);
    }

    let device = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT account_id FROM app_devices WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    let account_id = device.0;
    let (access, refresh) = issue_tokens(&state, account_id, device_id, now).await?;
    Ok(Json(TokenPair {
        access_token: access,
        refresh_token: refresh,
        expires_in: flora_auth::ACCESS_TTL_MINUTES * 60,
        account_id,
        account_created: false,
        gateway_id: String::new(),
    }))
}

/// Expiry used when storing a refresh token.
pub fn refresh_expiry_for(now: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    refresh_expiry(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_message_is_domain_separated_from_other_flows() {
        let pubkey = [1u8; 32];
        let nonce = [2u8; 16];
        let message = auth_message(&pubkey, &nonce);
        assert!(message.starts_with(AUTH_PREFIX));
        // Distinct from the pairing prefix, so a signature made for one flow
        // cannot be replayed into the other.
        let pairing_prefix = b"flora-pair-v1";
        assert_ne!(AUTH_PREFIX, pairing_prefix.as_slice());
        assert_eq!(message.len(), AUTH_PREFIX.len() + 32 + 16);
        assert_eq!(message[AUTH_PREFIX.len()..AUTH_PREFIX.len() + 32], pubkey);
        assert_eq!(&message[AUTH_PREFIX.len() + 32..], &nonce);
    }
}
