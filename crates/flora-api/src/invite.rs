//! Invites: letting a second phone join an account with no email.
//!
//! The plan describes it as "generate an invite QR, scan on the second phone,
//! join the same account". That requires two halves, and only one existed: the
//! table was created and never written to.
//!
//! ```text
//! Inviter phone --POST /account/invite--> API mints a single-use token
//! Inviter shows a QR encoding flora://invite?v=1&a=<account>&t=<token>
//! Second phone scans, signs, POSTs /pair/invite
//! API attaches a new app device to the same account and issues a session
//! ```
//!
//! The token is short-lived and single-use. It is also the only thing a scanner
//! needs, so it is deliberately not reusable and expires quickly: an invite
//! photographed off a screen should stop working within minutes.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use flora_auth::{generate_token, hash_token, hex, unhex};

use crate::account::authenticate;
use crate::dto::TokenPair;
use crate::pairing::issue_tokens;
use crate::state::{ApiError, AppState};

/// How long an invite stays valid.
///
/// Short on purpose. An invite is shown on screen and may be photographed, so
/// the window is minutes rather than the 24 hours a printed device code gets.
pub const INVITE_TTL_MINUTES: i64 = 15;

/// Invites an account may have outstanding at once.
///
/// Without a cap, a signed-in device could mint unbounded rows; with one, a
/// mistake by the caller cannot fill the table.
pub const MAX_LIVE_INVITES: i64 = 5;

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    /// The payload to encode in a QR.
    pub payload: String,
    /// The raw token, shown once and never stored in the clear.
    pub token: String,
    pub account_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RedeemInviteRequest {
    /// Hex-encoded invite token from the QR.
    pub invite_token: String,
    /// Hex-encoded Ed25519 public key of the phone joining.
    pub app_pubkey: String,
    /// Hex-encoded single-use nonce.
    pub nonce: String,
    /// Hex-encoded signature over the invite signing input.
    pub signature: String,
    pub label: Option<String>,
}

/// The message a phone signs to accept an invite.
///
/// Domain-separated from claiming and from signing in, so a signature made for
/// one flow cannot be replayed into another.
pub fn invite_message(pubkey: &[u8], invite_token: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(14 + pubkey.len() + invite_token.len() + nonce.len());
    message.extend_from_slice(b"flora-invite-v1");
    message.extend_from_slice(pubkey);
    message.extend_from_slice(invite_token);
    message.extend_from_slice(nonce);
    message
}

/// Build the QR payload for an invite.
pub fn invite_qr_payload(account_id: Uuid, token_hex: &str) -> String {
    format!("flora://invite?v=1&a={account_id}&t={token_hex}")
}

/// `POST /account/invite`
pub async fn create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<InviteResponse>), ApiError> {
    let claims = authenticate(&state, &headers)?;
    let now = Utc::now();

    // Expire stale invites first, so the cap counts only live ones.
    sqlx::query("UPDATE invite_tokens SET used_at = now() WHERE account_id = $1 AND used_at IS NULL AND expires_at <= $2")
        .bind(claims.sub)
        .bind(now)
        .execute(&state.pool)
        .await?;

    let live: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM invite_tokens WHERE account_id = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(claims.sub)
    .bind(now)
    .fetch_one(&state.pool)
    .await?;
    if live.0 >= MAX_LIVE_INVITES {
        return Err(ApiError::Conflict(
            "you already have several invites waiting. Use one or wait for them to expire.".into(),
        ));
    }

    // The inviting device must exist and not be revoked, or an invite could be
    // minted with a device that can no longer sign in.
    let inviter: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM app_devices WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
    )
    .bind(claims.dev)
    .bind(claims.sub)
    .fetch_optional(&state.pool)
    .await?;
    let inviter_id = inviter.ok_or(ApiError::Unauthorized)?.0;

    let token = generate_token().map_err(|error| ApiError::Internal(error.to_string()))?;
    let expires_at = now + Duration::minutes(INVITE_TTL_MINUTES);

    sqlx::query(
        "INSERT INTO invite_tokens (account_id, token_hash, inviter_device_id, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(claims.sub)
    .bind(hash_token(&token))
    .bind(inviter_id)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    let token_hex = hex(&token);
    tracing::info!(account = %claims.sub, "invite created");

    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            payload: invite_qr_payload(claims.sub, &token_hex),
            // Shown once. Only the hash is stored, so it cannot be recovered.
            token: token_hex,
            account_id: claims.sub,
            expires_at,
        }),
    ))
}

/// `POST /pair/invite`
///
/// Unauthenticated: the invite token plus a signature is the credential, which
/// is what lets a phone join without an email address.
pub async fn redeem_invite(
    State(state): State<AppState>,
    Json(body): Json<RedeemInviteRequest>,
) -> Result<(StatusCode, Json<TokenPair>), ApiError> {
    let now = Utc::now();

    let pubkey = unhex(&body.app_pubkey)
        .ok_or_else(|| ApiError::BadRequest("app_pubkey must be hexadecimal".into()))?;
    if pubkey.len() != flora_protocol::PUBLIC_KEY_LEN {
        return Err(ApiError::BadRequest("app_pubkey must be 32 bytes".into()));
    }
    let invite_token = unhex(&body.invite_token)
        .ok_or_else(|| ApiError::BadRequest("invite_token must be hexadecimal".into()))?;
    if invite_token.len() != flora_auth::secrets::TOKEN_BYTES {
        return Err(ApiError::BadRequest("invite_token must be 32 bytes".into()));
    }
    let nonce = unhex(&body.nonce)
        .ok_or_else(|| ApiError::BadRequest("nonce must be hexadecimal".into()))?;
    let signature = unhex(&body.signature)
        .ok_or_else(|| ApiError::BadRequest("signature must be hexadecimal".into()))?;

    // Rate limited before any database work, so a flood cannot become queries.
    if !state
        .claim_limiter
        .check(&format!("invite:{}", body.app_pubkey), now.timestamp())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    // Signature first: an unauthorised caller must not be able to consume a
    // token, which would lock out the person the invite was meant for.
    flora_protocol::verify_command_signature(
        &pubkey,
        &invite_message(&pubkey, &invite_token, &nonce),
        &signature,
    )
    .map_err(|_| ApiError::Unauthorized)?;

    // Nonce replay, same rule as the other unauthenticated routes.
    let nonce_expires = now + Duration::minutes(5);
    flora_db::queries::prune_nonces(&state.pool, now).await?;
    let fresh =
        flora_db::queries::record_nonce(&state.pool, &nonce, "invite", nonce_expires).await?;
    if !fresh {
        return Err(ApiError::Conflict("nonce already used".into()));
    }

    // Consume atomically, so two phones racing the same invite cannot both join.
    let claimed: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE invite_tokens SET used_at = $2
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
         RETURNING account_id",
    )
    .bind(hash_token(&invite_token))
    .bind(now)
    .fetch_optional(&state.pool)
    .await?;
    let account_id = claimed.ok_or(ApiError::Unauthorized)?.0;

    // If this key already belongs to a live device, it is the same phone pairing
    // again rather than a new one: reuse the row instead of duplicating.
    let existing = flora_db::queries::live_app_device_by_pubkey(&state.pool, &pubkey).await?;
    let device_id = match existing {
        Some(device) if device.account_id == account_id => {
            sqlx::query("UPDATE app_devices SET last_seen = $2 WHERE id = $1")
                .bind(device.id)
                .bind(now)
                .execute(&state.pool)
                .await?;
            device.id
        }
        Some(_) => {
            // The key belongs to a different account. Attaching it here would
            // let one phone read two farms' data with one identity.
            return Err(ApiError::Conflict(
                "this phone is already part of another account".into(),
            ));
        }
        None => {
            let row: (Uuid,) = sqlx::query_as(
                "INSERT INTO app_devices (account_id, pubkey, label)
                 VALUES ($1, $2, $3) RETURNING id",
            )
            .bind(account_id)
            .bind(&pubkey)
            .bind(&body.label)
            .fetch_one(&state.pool)
            .await?;
            row.0
        }
    };

    let (access, refresh) = issue_tokens(&state, account_id, device_id, now).await?;
    tracing::info!(account = %account_id, "invite redeemed");

    Ok((
        StatusCode::CREATED,
        Json(TokenPair {
            access_token: access,
            refresh_token: refresh,
            expires_in: flora_auth::ACCESS_TTL_MINUTES * 60,
            account_id,
            account_created: false,
            // An invite attaches a phone, not a gateway, so there is no gateway
            // to report.
            gateway_id: String::new(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn the_invite_message_is_domain_separated() {
        let pubkey = [1u8; 32];
        let token = [2u8; 32];
        let nonce = [3u8; 16];
        let message = invite_message(&pubkey, &token, &nonce);

        assert!(message.starts_with(b"flora-invite-v1"));
        assert_eq!(message.len(), 15 + 32 + 32 + 16);
        // Distinct from the pairing and auth prefixes, so a signature cannot be
        // replayed across flows.
        assert!(!message.starts_with(b"flora-pair-v1"));
        assert!(!message.starts_with(b"flora-auth-v1"));
    }

    #[test]
    fn a_signature_over_the_invite_input_verifies() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let token = [2u8; 32];
        let nonce = [3u8; 16];
        let message = invite_message(key.verifying_key().as_bytes(), &token, &nonce);
        let signature = key.sign(&message);

        assert_eq!(
            flora_protocol::verify_command_signature(
                key.verifying_key().as_bytes(),
                &message,
                &signature.to_bytes(),
            ),
            Ok(())
        );
    }

    #[test]
    fn a_signature_for_a_different_token_is_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = invite_message(key.verifying_key().as_bytes(), &[2u8; 32], &[3u8; 16]);
        let other = invite_message(key.verifying_key().as_bytes(), &[9u8; 32], &[3u8; 16]);
        let signature = key.sign(&signed);
        assert!(
            flora_protocol::verify_command_signature(
                key.verifying_key().as_bytes(),
                &other,
                &signature.to_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn the_qr_payload_carries_the_account_and_token() {
        let payload = invite_qr_payload(Uuid::nil(), "aabbccdd");
        assert_eq!(
            payload,
            "flora://invite?v=1&a=00000000-0000-0000-0000-000000000000&t=aabbccdd"
        );
    }
}
