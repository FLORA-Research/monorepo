//! Request and response bodies.
//!
//! Wire types are separate from database rows on purpose: renaming a column
//! must not silently change an API response.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use flora_db::models::Gateway;

// ---- Provisioning ----

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub device_id: String,
    /// Hex-encoded aggregator Ed25519 public key.
    pub pubkey: String,
    /// Hex-encoded SHA-256 of the device token. The token itself never arrives.
    pub token_hash: String,
    /// Hex-encoded SHA-256 of the claim token.
    pub claim_hash: String,
    pub hw: String,
    pub fw_ver: String,
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub device_id: String,
    pub status: String,
    pub claim_expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ReissueRequest {
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct ReissueResponse {
    pub device_id: String,
    pub claim_expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ProvisionStatusResponse {
    pub device_id: String,
    pub status: String,
    pub label: Option<String>,
    pub hw: Option<String>,
    pub fw_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
}

// ---- Pairing ----

#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    pub device_id: String,
    /// Hex-encoded claim token, as printed in the QR.
    pub claim_token: String,
    /// Hex-encoded app Ed25519 public key.
    pub app_pubkey: String,
    /// Hex-encoded single-use nonce.
    pub nonce: String,
    /// Hex-encoded Ed25519 signature over the canonical claim message.
    pub signature: String,
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub account_id: Uuid,
    pub account_created: bool,
    pub gateway_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// ---- Auth ----

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub app_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// Hex-encoded nonce to be signed.
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub app_pubkey: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub account_id: Uuid,
}

// ---- Devices ----

#[derive(Debug, Serialize)]
pub struct GatewaySummary {
    pub id: String,
    pub label: Option<String>,
    pub status: String,
    pub fw_version: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
}

impl From<Gateway> for GatewaySummary {
    fn from(gateway: Gateway) -> Self {
        Self {
            id: gateway.id,
            label: gateway.label,
            status: gateway.status,
            fw_version: gateway.fw_version,
            last_seen: gateway.last_seen,
            claimed_at: gateway.claimed_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub account_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub gateways: Vec<GatewaySummary>,
}

// ---- Manual commands ----

#[derive(Debug, Deserialize)]
pub struct CommandRequest {
    pub node_addr: u8,
    /// Command kind name, e.g. `set_valve`.
    pub kind: String,
    /// Hex-encoded 4-byte payload.
    pub payload: String,
    /// Hex-encoded app Ed25519 public key that signed this command.
    pub app_pubkey: String,
    pub nonce: u32,
    pub ts: u32,
    /// Hex-encoded Ed25519 signature over the canonical command message.
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct CommandResponse {
    pub id: Uuid,
    pub kind: String,
    pub node_addr: u8,
    /// `pending`, `dispatched`, `applied`, `refused`, or `expired`.
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

/// One queued command as handed to an aggregator.
///
/// Carries the signature again, because the aggregator verifies it
/// independently: the cloud is a relay, not an authority on whether a valve
/// may open.
#[derive(Debug, Serialize)]
pub struct PendingCommand {
    pub id: Uuid,
    pub kind: u8,
    pub node_addr: u8,
    pub payload: String,
    pub app_pubkey: String,
    pub signature: String,
    pub nonce: u32,
    pub ts: u32,
}

#[derive(Debug, Serialize)]
pub struct PendingCommandsResponse {
    pub commands: Vec<PendingCommand>,
}

#[derive(Debug, Deserialize)]
pub struct AckCommandRequest {
    /// Outcome as reported by the device: `applied` or `refused`.
    pub result: String,
}

// ---- Errors ----

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

impl ErrorBody {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}
