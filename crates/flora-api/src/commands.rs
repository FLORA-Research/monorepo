//! Manual commands: App → API → verify → queue → aggregator.
//!
//! The path, and why it has a queue in the middle:
//!
//! ```text
//! App  --POST /gateways/:id/commands-->  API
//! API  --verify signature, audit, queue-->  device_commands
//! Aggregator  --GET /device/commands-->  API   (polls)
//! Aggregator  --verify signature again-->  acts
//! ```
//!
//! The API verifies the signature to reject garbage early and to keep an audit
//! trail. The aggregator verifies it **again** before a valve moves. That
//! second check is the point: a compromised cloud must not be able to open a
//! valve, so the aggregator's own verification is what actually authorises the
//! action, and the cloud is only a relay.
//!
//! The queue exists because the cloud cannot reach the device. Commands are
//! collected by the aggregator when it next polls, which is also why a command
//! has a freshness window rather than being acted on hours later.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration, Utc};
use uuid::Uuid;

use flora_protocol::{KIND_CALIBRATE, KIND_SET_THRESHOLD, KIND_SET_VALVE};

use crate::account::authenticate;
use crate::dto::{
    AckCommandRequest, CommandRequest, CommandResponse, PendingCommand, PendingCommandsResponse,
};
use crate::ingest::device_credentials;
use crate::state::{ApiError, AppState};
use crate::stream::StreamEvent;

/// How long a queued command stays valid.
///
/// An irrigation command that arrives hours late is worse than no command: the
/// plot may already be wet. Beyond this window the aggregator refuses it, and
/// the audit row records that it expired rather than pretending it was applied.
pub const COMMAND_TTL_MINUTES: i64 = 15;

/// Commands allowed per account per minute, per the plan's rate limits.
pub const COMMANDS_PER_MINUTE: u32 = 30;

/// Human name for a command kind, for the audit row and the API response.
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_SET_VALVE => "set_valve",
        KIND_SET_THRESHOLD => "set_threshold",
        KIND_CALIBRATE => "calibrate",
        _ => "unknown",
    }
}

/// Parse a kind name back to its numeric value.
pub fn kind_from_name(name: &str) -> Option<u8> {
    match name {
        "set_valve" => Some(KIND_SET_VALVE),
        "set_threshold" => Some(KIND_SET_THRESHOLD),
        "calibrate" => Some(KIND_CALIBRATE),
        _ => None,
    }
}

/// Payload bytes a command kind requires.
pub fn expected_payload_len(kind: u8) -> Option<usize> {
    match kind {
        KIND_SET_VALVE => Some(4),
        KIND_SET_THRESHOLD => Some(4),
        KIND_CALIBRATE => Some(4),
        _ => None,
    }
}

/// Validate a command's kind and payload before it is queued.
///
/// Rejecting here means a malformed command never reaches a device and never
/// occupies the audit log as if it were actionable.
pub fn validate_command(kind: u8, payload: &[u8]) -> Result<[u8; 4], ApiError> {
    if expected_payload_len(kind).is_none() {
        return Err(ApiError::BadRequest(format!("unknown command kind {kind}")));
    }
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| ApiError::BadRequest(format!("kind {kind} needs a 4-byte payload")))?;

    match kind {
        KIND_SET_VALVE => {
            if bytes[0] > 1 {
                return Err(ApiError::BadRequest("valve state must be 0 or 1".into()));
            }
        }
        KIND_SET_THRESHOLD => {
            let dry = u16::from_be_bytes([bytes[0], bytes[1]]);
            let wet = u16::from_be_bytes([bytes[2], bytes[3]]);
            if dry > 1000 || wet > 1000 {
                return Err(ApiError::BadRequest(
                    "thresholds are per mille, so at most 1000".into(),
                ));
            }
            if wet <= dry {
                return Err(ApiError::BadRequest(
                    "the wet threshold must be above the dry threshold".into(),
                ));
            }
        }
        KIND_CALIBRATE => {
            if bytes[0] > 1 {
                return Err(ApiError::BadRequest(
                    "calibration mode is 0 (dry) or 1 (wet)".into(),
                ));
            }
        }
        _ => unreachable!("kind was checked above"),
    }
    Ok(bytes)
}

/// `POST /gateways/{id}/commands`
///
/// The app has already signed the canonical message. The API checks ownership,
/// verifies the signature, validates the payload, and queues the command.
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
    Json(body): Json<CommandRequest>,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let claims = authenticate(&state, &headers)?;
    let now = Utc::now();

    if !state
        .command_limiter
        .check(&format!("commands:{}", claims.sub), now.timestamp())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    // Ownership comes from the database, never from the request body.
    let gateway = flora_db::queries::gateway_by_id(&state.pool, &gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !gateway.owned_by(claims.sub) {
        return Err(ApiError::Forbidden);
    }

    let kind = kind_from_name(&body.kind)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown command kind {}", body.kind)))?;
    let payload = decode_hex_4(&body.payload)?;
    validate_command(kind, &payload)?;

    let app_pubkey = hex_field(&body.app_pubkey)?;
    if app_pubkey.len() != flora_protocol::PUBLIC_KEY_LEN {
        return Err(ApiError::BadRequest("app_pubkey must be 32 bytes".into()));
    }
    let signature = hex_field(&body.signature)?;

    // The signing key must belong to this account. Without this check any
    // account could sign a command for any gateway and have it queued.
    ensure_key_in_account(&state, claims.sub, &app_pubkey).await?;

    // The signature covers the full gateway id, the target node, the nonce, the
    // timestamp, and the payload, so nothing here can be altered in transit.
    let gateway_bytes = decode_gateway_id(&gateway_id)?;
    let message = flora_protocol::canonical_message(
        kind,
        &gateway_bytes,
        body.node_addr,
        body.nonce,
        body.ts,
        &payload,
    );
    flora_protocol::verify_command_signature(&app_pubkey, &message, &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    // A command already past its window would only be refused by the device.
    let signed_at = chrono::DateTime::from_timestamp(i64::from(body.ts), 0)
        .ok_or_else(|| ApiError::BadRequest("ts is not a valid Unix timestamp".into()))?;

    let id = Uuid::new_v4();
    let expires_at = now + Duration::minutes(COMMAND_TTL_MINUTES);
    sqlx::query(
        "INSERT INTO device_commands
           (id, account_id, gateway_id, node_addr, kind, payload, app_pubkey,
            app_signature, nonce, signed_at, expires_at, result)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending')",
    )
    .bind(id)
    .bind(claims.sub)
    .bind(&gateway_id)
    .bind(i16::from(body.node_addr))
    .bind(kind_name(kind))
    .bind(serde_json::json!({
        "bytes": flora_auth::hex(&payload),
        "duration_s": if kind == KIND_SET_VALVE {
            Some(u16::from_be_bytes([payload[1], payload[2]]))
        } else { None },
    }))
    .bind(&app_pubkey)
    .bind(&signature)
    .bind(i64::from(body.nonce))
    .bind(signed_at)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    tracing::info!(
        command = %id,
        %gateway_id,
        node_addr = body.node_addr,
        kind = kind_name(kind),
        "command queued"
    );
    state.events.publish(
        claims.sub,
        StreamEvent::Command {
            gateway_id: gateway_id.clone(),
            command_id: id,
            status: "pending".into(),
        },
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(CommandResponse {
            id,
            kind: kind_name(kind).to_owned(),
            node_addr: body.node_addr,
            status: "pending".into(),
            expires_at,
        }),
    ))
}

/// `GET /device/commands`
///
/// The aggregator polls this. Claiming and returning are one statement, so two
/// concurrent polls cannot both deliver the same command to a device.
pub async fn poll_device_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PendingCommandsResponse>, ApiError> {
    let (device_id, token) = device_credentials(&headers)?;
    crate::ingest::authorize_device(&state, &device_id, &token).await?;

    let now = Utc::now();
    // Expiry is applied on read: a command whose window closed while it sat in
    // the queue is marked expired rather than handed over for the device to
    // reject.
    sqlx::query(
        "UPDATE device_commands SET result = 'expired'
         WHERE gateway_id = $1 AND result = 'pending' AND expires_at <= $2",
    )
    .bind(&device_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    /// A queued command as stored: id, node, kind, payload, public key,
    /// signature, nonce, and the time it was signed.
    type CommandRow = (
        Uuid,
        i16,
        String,
        serde_json::Value,
        Vec<u8>,
        Vec<u8>,
        i64,
        chrono::DateTime<Utc>,
    );

    let rows: Vec<CommandRow> = sqlx::query_as(
        "UPDATE device_commands
             SET dispatched_at = $2, result = 'dispatched'
             WHERE id IN (
                 SELECT id FROM device_commands
                 WHERE gateway_id = $1 AND result = 'pending' AND expires_at > $2
                 ORDER BY ts
                 LIMIT 16
             )
             RETURNING id, node_addr, kind, payload, app_pubkey, app_signature, nonce, signed_at",
    )
    .bind(&device_id)
    .bind(now)
    .fetch_all(&state.pool)
    .await?;

    let mut commands = Vec::with_capacity(rows.len());
    for (id, node_addr, kind, payload, pubkey, signature, nonce, signed_at) in rows {
        let kind_code = kind_from_name(&kind).unwrap_or_default();
        let bytes = payload
            .get("bytes")
            .and_then(|value| value.as_str())
            .and_then(flora_auth::unhex)
            .unwrap_or_default();
        commands.push(PendingCommand {
            id,
            kind: kind_code,
            node_addr: node_addr as u8,
            payload: flora_auth::hex(&bytes),
            app_pubkey: flora_auth::hex(&pubkey),
            signature: flora_auth::hex(&signature),
            nonce: nonce as u32,
            ts: signed_at.timestamp() as u32,
        });
    }

    Ok(Json(PendingCommandsResponse { commands }))
}

/// `POST /device/commands/{id}/ack`
///
/// The device reports what it did, including a refusal.
pub async fn ack_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<Uuid>,
    Json(body): Json<AckCommandRequest>,
) -> Result<StatusCode, ApiError> {
    let (device_id, token) = device_credentials(&headers)?;
    crate::ingest::authorize_device(&state, &device_id, &token).await?;

    // Scoped by gateway, so a device cannot ack another device's command.
    let updated = sqlx::query(
        "UPDATE device_commands
         SET acked_at = now(), result = $3
         WHERE id = $1 AND gateway_id = $2",
    )
    .bind(command_id)
    .bind(&device_id)
    .bind(&body.result)
    .execute(&state.pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    // Tell the app the outcome, including a refusal.
    let account_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT account_id FROM gateways WHERE id = $1")
            .bind(&device_id)
            .fetch_optional(&state.pool)
            .await?
            .flatten();
    if let Some(account_id) = account_id {
        state.events.publish(
            account_id,
            StreamEvent::Command {
                gateway_id: device_id.clone(),
                command_id,
                status: body.result.clone(),
            },
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /gateways/{id}/commands`
///
/// The audit trail, so a farmer can see what was requested and what happened.
pub async fn list_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Result<Json<Vec<CommandResponse>>, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let gateway = flora_db::queries::gateway_by_id(&state.pool, &gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !gateway.owned_by(claims.sub) {
        return Err(ApiError::Forbidden);
    }

    let rows: Vec<(Uuid, i16, String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, node_addr, kind, result, expires_at FROM device_commands
         WHERE gateway_id = $1 ORDER BY ts DESC LIMIT 50",
    )
    .bind(&gateway_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, node_addr, kind, status, expires_at)| CommandResponse {
                    id,
                    kind,
                    node_addr: node_addr as u8,
                    status,
                    expires_at,
                },
            )
            .collect(),
    ))
}

/// Confirm the signing key belongs to the account.
async fn ensure_key_in_account(
    state: &AppState,
    account_id: Uuid,
    pubkey: &[u8],
) -> Result<(), ApiError> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM accounts WHERE id = $1 AND owner_pubkey = $2
         UNION ALL
         SELECT 1 FROM app_devices
           WHERE account_id = $1 AND pubkey = $2 AND revoked_at IS NULL
         LIMIT 1",
    )
    .bind(account_id)
    .bind(pubkey)
    .fetch_optional(&state.pool)
    .await?;

    // A revoked phone's key must stop working here as well as at sign-in.
    found.map(|_| ()).ok_or(ApiError::Forbidden)
}

fn decode_gateway_id(gateway_id: &str) -> Result<[u8; flora_protocol::GATEWAY_ID_LEN], ApiError> {
    let bytes = flora_auth::unhex(gateway_id)
        .ok_or_else(|| ApiError::BadRequest("gateway id must be hexadecimal".into()))?;
    bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("gateway id must be 16 bytes".into()))
}

fn hex_field(value: &str) -> Result<Vec<u8>, ApiError> {
    flora_auth::unhex(value).ok_or_else(|| ApiError::BadRequest("expected hexadecimal".into()))
}

fn decode_hex_4(value: &str) -> Result<[u8; 4], ApiError> {
    let bytes = hex_field(value)?;
    bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("payload must be 4 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_map_both_directions() {
        for (code, name) in [
            (KIND_SET_VALVE, "set_valve"),
            (KIND_SET_THRESHOLD, "set_threshold"),
            (KIND_CALIBRATE, "calibrate"),
        ] {
            assert_eq!(kind_name(code), name);
            assert_eq!(kind_from_name(name), Some(code));
        }
        assert_eq!(kind_from_name("reboot"), None);
        assert_eq!(kind_name(99), "unknown");
    }

    #[test]
    fn valve_payload_accepts_only_open_or_closed() {
        assert_eq!(
            validate_command(KIND_SET_VALVE, &[0, 0, 0, 0]).unwrap(),
            [0, 0, 0, 0]
        );
        assert_eq!(
            validate_command(KIND_SET_VALVE, &[1, 0, 30, 0]).unwrap(),
            [1, 0, 30, 0]
        );
        assert!(validate_command(KIND_SET_VALVE, &[2, 0, 0, 0]).is_err());
    }

    #[test]
    fn threshold_payload_must_be_a_valid_band() {
        // dry 200, wet 700.
        assert!(validate_command(KIND_SET_THRESHOLD, &[0, 200, 2, 188]).is_ok());
        // Inverted band: the device would reject it anyway, but rejecting here
        // keeps the audit log free of commands that could never apply.
        assert!(validate_command(KIND_SET_THRESHOLD, &[2, 188, 0, 200]).is_err());
        assert!(validate_command(KIND_SET_THRESHOLD, &[0, 200, 0, 200]).is_err());
        // Above the per-mille ceiling.
        assert!(validate_command(KIND_SET_THRESHOLD, &[0, 200, 3, 233]).is_err());
    }

    #[test]
    fn calibration_mode_is_bounded() {
        assert!(validate_command(KIND_CALIBRATE, &[0, 0, 0, 0]).is_ok());
        assert!(validate_command(KIND_CALIBRATE, &[1, 0, 0, 0]).is_ok());
        assert!(validate_command(KIND_CALIBRATE, &[2, 0, 0, 0]).is_err());
    }

    #[test]
    fn unknown_kinds_and_wrong_lengths_are_rejected() {
        assert!(validate_command(99, &[0, 0, 0, 0]).is_err());
        assert!(validate_command(KIND_SET_VALVE, &[1, 0]).is_err());
        assert!(validate_command(KIND_SET_VALVE, &[]).is_err());
    }

    #[test]
    fn gateway_ids_must_be_sixteen_bytes_of_hex() {
        assert!(decode_gateway_id("6167672d303030316167672d30303031").is_ok());
        assert_eq!(
            decode_gateway_id("6167672d303030316167672d30303031").unwrap(),
            *b"agg-0001agg-0001"
        );
        // Eight bytes is the old width; it must now be refused.
        assert!(decode_gateway_id("6167672d30303031").is_err());
        assert!(decode_gateway_id("zzzz").is_err());
    }
}
