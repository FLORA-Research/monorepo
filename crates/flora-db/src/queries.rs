//! Typed queries.
//!
//! These use runtime-checked `sqlx::query_as` rather than the
//! compile-time macros. The macros need a live database at build time,
//! which would break the "fresh machine builds with no setup" goal that
//! this workspace exists to support.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{Account, AppDevice, Gateway};

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("not found")]
    NotFound,
}

/// Find an account by its owner public key.
pub async fn account_by_pubkey(
    pool: &PgPool,
    pubkey: &[u8],
) -> Result<Option<Account>, QueryError> {
    let account = sqlx::query_as::<_, Account>(
        "SELECT id, owner_pubkey, created_at FROM accounts WHERE owner_pubkey = $1",
    )
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;
    Ok(account)
}

/// Find an app device by its public key, ignoring revoked rows.
pub async fn live_app_device_by_pubkey(
    pool: &PgPool,
    pubkey: &[u8],
) -> Result<Option<AppDevice>, QueryError> {
    let device = sqlx::query_as::<_, AppDevice>(
        "SELECT id, account_id, pubkey, label, revoked_at, last_seen, created_at
         FROM app_devices
         WHERE pubkey = $1 AND revoked_at IS NULL",
    )
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;
    Ok(device)
}

pub async fn gateway_by_id(pool: &PgPool, device_id: &str) -> Result<Option<Gateway>, QueryError> {
    let gateway = sqlx::query_as::<_, Gateway>(
        "SELECT id, account_id, pubkey, label, status, fw_version,
                last_seen, claimed_at, retired_at, created_at
         FROM gateways WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    Ok(gateway)
}

/// Gateways belonging to an account, newest first.
pub async fn gateways_for_account(
    pool: &PgPool,
    account_id: Uuid,
) -> Result<Vec<Gateway>, QueryError> {
    let gateways = sqlx::query_as::<_, Gateway>(
        "SELECT id, account_id, pubkey, label, status, fw_version,
                last_seen, claimed_at, retired_at, created_at
         FROM gateways WHERE account_id = $1 ORDER BY created_at DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(gateways)
}

/// Record a claim token, replacing any previous unused one for the
/// gateway.
pub async fn upsert_claim_token(
    pool: &PgPool,
    device_id: &str,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), QueryError> {
    sqlx::query(
        "INSERT INTO claim_tokens (device_id, token_hash, expires_at, used_at)
         VALUES ($1, $2, $3, NULL)
         ON CONFLICT (device_id) DO UPDATE
           SET token_hash = EXCLUDED.token_hash,
               expires_at = EXCLUDED.expires_at,
               used_at = NULL",
    )
    .bind(device_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Consume a claim token atomically.
///
/// The `used_at IS NULL` predicate and the `expires_at` comparison are
/// part of the UPDATE, so two concurrent claims cannot both succeed:
/// the second finds no matching row. Returns the gateway id on success.
pub async fn consume_claim_token(
    pool: &PgPool,
    device_id: &str,
    token_hash: &[u8],
    now: DateTime<Utc>,
) -> Result<Option<String>, QueryError> {
    let row = sqlx::query_as::<_, (String,)>(
        "UPDATE claim_tokens
         SET used_at = $3
         WHERE device_id = $1 AND token_hash = $2 AND used_at IS NULL AND expires_at > $3
         RETURNING device_id",
    )
    .bind(device_id)
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// Delete expired nonces. Called before inserting a new one so the
/// table stays proportional to the replay window rather than growing
/// forever.
pub async fn prune_nonces(pool: &PgPool, now: DateTime<Utc>) -> Result<u64, QueryError> {
    let result = sqlx::query("DELETE FROM auth_nonces WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Record a nonce. Returns `false` when it was already present, which
/// means the request is a replay.
pub async fn record_nonce(
    pool: &PgPool,
    nonce: &[u8],
    scope: &str,
    expires_at: DateTime<Utc>,
) -> Result<bool, QueryError> {
    let result = sqlx::query(
        "INSERT INTO auth_nonces (nonce, scope, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (nonce) DO NOTHING",
    )
    .bind(nonce)
    .bind(scope)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    // Query behaviour against a live database is covered by the
    // integration tests in `tests/`, which skip when TEST_DATABASE_URL
    // is absent.
}
