//! `/pair/*` handlers: claiming a gateway, which creates the account.
//!
//! Unauthenticated by design. The claim token plus a signature over the claim is
//! the credential, so there is no login step and no password to forget.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{Duration, Utc};

use flora_auth::pairing::{
    ClaimSignatureInput, NONCE_TTL_MINUTES, claim_is_usable, claim_token_matches,
    ensure_not_retired, resolve_target, verify_claim_signature,
};
use flora_auth::{generate_token, hash_token, hex, refresh_expiry, unhex};

use crate::dto::{ClaimRequest, TokenPair};
use crate::state::{ApiError, AppState};

/// Claim a gateway, creating the account if this key has none.
pub async fn claim(
    State(state): State<AppState>,
    Json(body): Json<ClaimRequest>,
) -> Result<(StatusCode, Json<TokenPair>), ApiError> {
    let now = Utc::now();

    // Rate limit per device id and per claimed address before any crypto, so a
    // flood cannot turn into CPU work.
    let device_key = format!("device:{}", body.device_id);
    if !state
        .claim_limiter
        .check(&device_key, now.timestamp())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    let app_pubkey = unhex(&body.app_pubkey)
        .ok_or_else(|| ApiError::BadRequest("app_pubkey must be hexadecimal".into()))?;
    if app_pubkey.len() != flora_protocol::PUBLIC_KEY_LEN {
        return Err(ApiError::BadRequest("app_pubkey must be 32 bytes".into()));
    }
    let claim_token = unhex(&body.claim_token)
        .ok_or_else(|| ApiError::BadRequest("claim_token must be hexadecimal".into()))?;
    let nonce = unhex(&body.nonce)
        .ok_or_else(|| ApiError::BadRequest("nonce must be hexadecimal".into()))?;
    let signature = unhex(&body.signature)
        .ok_or_else(|| ApiError::BadRequest("signature must be hexadecimal".into()))?;

    // The signature is checked before the database is touched: an unauthorised
    // caller should not be able to make us read a row or consume a token.
    let input = ClaimSignatureInput {
        device_id: &body.device_id,
        claim_token: &claim_token,
        nonce: &nonce,
    };
    verify_claim_signature(&app_pubkey, &input, &signature).map_err(|_| ApiError::Unauthorized)?;

    // Nonce replay: insert first, and treat a conflict as a replay.
    let nonce_expires = now + Duration::minutes(NONCE_TTL_MINUTES);
    flora_db::queries::prune_nonces(&state.pool, now).await?;
    let fresh = flora_db::queries::record_nonce(&state.pool, &nonce, "pair", nonce_expires).await?;
    if !fresh {
        return Err(ApiError::Conflict("nonce already used".into()));
    }

    let gateway = flora_db::queries::gateway_by_id(&state.pool, &body.device_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    ensure_not_retired(&gateway).map_err(|_| ApiError::Conflict("gateway is retired".into()))?;

    // Fetch and check the claim token.
    /// Stored claim: token hash, expiry, and consumption time.
    type StoredClaim = (
        Vec<u8>,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
    );

    let stored: Option<StoredClaim> = sqlx::query_as(
        "SELECT token_hash, expires_at, used_at FROM claim_tokens WHERE device_id = $1",
    )
    .bind(&body.device_id)
    .fetch_optional(&state.pool)
    .await?;
    let (stored_hash, expires_at, used_at) = stored.ok_or(ApiError::NotFound)?;
    claim_is_usable(expires_at, used_at, now)
        .map_err(|_| ApiError::Conflict("claim token is expired or already used".into()))?;
    claim_token_matches(&claim_token, &stored_hash).map_err(|_| ApiError::Unauthorized)?;

    // Consume atomically. A concurrent claim with the same token finds nothing.
    let consumed =
        flora_db::queries::consume_claim_token(&state.pool, &body.device_id, &stored_hash, now)
            .await?;
    if consumed.is_none() {
        return Err(ApiError::Conflict("claim token was already used".into()));
    }

    // Attach to an existing account, or create one. This is the only place an
    // account comes into existence, which is why there is no signup screen.
    let existing = flora_db::queries::live_app_device_by_pubkey(&state.pool, &app_pubkey).await?;
    let existing_account = match &existing {
        Some(device) => Some(device.account_id),
        None => {
            // The account is keyed by the app key on first contact.
            let account = flora_db::queries::account_by_pubkey(&state.pool, &app_pubkey).await?;
            account.map(|account| account.id)
        }
    };
    let (account_id, account_created) = resolve_target(existing_account);

    if account_created {
        sqlx::query("INSERT INTO accounts (id, owner_pubkey) VALUES ($1, $2)")
            .bind(account_id)
            .bind(&app_pubkey)
            .execute(&state.pool)
            .await?;
    }

    let device_id = match existing {
        Some(device) => device.id,
        None => {
            let row: (uuid::Uuid,) = sqlx::query_as(
                "INSERT INTO app_devices (account_id, pubkey, label)
                 VALUES ($1, $2, $3) RETURNING id",
            )
            .bind(account_id)
            .bind(&app_pubkey)
            .bind(&body.label)
            .fetch_one(&state.pool)
            .await?;
            row.0
        }
    };

    sqlx::query(
        "UPDATE gateways SET account_id = $2, status = 'claimed', claimed_at = $3,
                             label = COALESCE($4, label)
         WHERE id = $1",
    )
    .bind(&body.device_id)
    .bind(account_id)
    .bind(now)
    .bind(&body.label)
    .execute(&state.pool)
    .await?;
    sqlx::query("UPDATE app_devices SET last_seen = $2 WHERE id = $1")
        .bind(device_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

    let tokens = issue_tokens(&state, account_id, device_id, now).await?;
    Ok((
        StatusCode::CREATED,
        Json(TokenPair {
            access_token: tokens.0,
            refresh_token: tokens.1,
            expires_in: flora_auth::ACCESS_TTL_MINUTES * 60,
            account_id,
            account_created,
            gateway_id: body.device_id,
        }),
    ))
}

/// Mint an access token and a stored refresh token.
pub(crate) async fn issue_tokens(
    state: &AppState,
    account_id: uuid::Uuid,
    device_id: uuid::Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(String, String), ApiError> {
    let access = flora_auth::issue_access_token(&state.jwt_secret, account_id, device_id, now)
        .map_err(|error| ApiError::Internal(error.to_string()))?;

    let raw = generate_token().map_err(|error| ApiError::Internal(error.to_string()))?;
    let hash = hash_token(&raw);
    sqlx::query(
        "INSERT INTO refresh_tokens (account_id, device_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(account_id)
    .bind(device_id)
    .bind(&hash)
    .bind(refresh_expiry(now))
    .execute(&state.pool)
    .await?;

    Ok((access, hex(&raw)))
}
