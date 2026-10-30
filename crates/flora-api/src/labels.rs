//! Renaming gateways and nodes.
//!
//! The plan lists `PATCH /gateways/:id/label`, and the app needs it: a farmer
//! names plots and nodes, and without an endpoint those edits would live only
//! on the phone and vanish on reinstall.
//!
//! Labelling a node additionally requires the gateway to be owned, because a
//! node is scoped to its gateway rather than to the account directly.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde::Deserialize;

use crate::account::authenticate;
use crate::dto::GatewaySummary;
use crate::state::{ApiError, AppState};

/// Longest accepted label.
///
/// A name is shown in a list row and a card title, so an unbounded string would
/// break the layout and let a client store something absurd.
pub const MAX_LABEL_LENGTH: usize = 64;

#[derive(Debug, Deserialize)]
pub struct LabelRequest {
    /// The new label. `null` or an empty string clears it, falling back to the
    /// generated display name.
    pub label: Option<String>,
}

/// Normalise a label: trim, reject control characters, and cap the length.
///
/// Returns `None` for "clear the label". Rejecting rather than truncating keeps
/// a silent data change out of the database.
pub fn normalise_label(label: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(raw) = label else { return Ok(None) };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_LABEL_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "a label may be at most {MAX_LABEL_LENGTH} characters"
        )));
    }
    // Newlines and tabs would corrupt a list row or a log line.
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest(
            "a label may not contain control characters".into(),
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

/// `PATCH /gateways/{gateway_id}/label`
pub async fn rename_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
    Json(body): Json<LabelRequest>,
) -> Result<Json<GatewaySummary>, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let label = normalise_label(body.label.as_deref())?;

    let gateway = flora_db::queries::gateway_by_id(&state.pool, &gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !gateway.owned_by(claims.sub) {
        return Err(ApiError::Forbidden);
    }

    // Scoped by account as well as id, so a guessed id cannot rename another
    // account's gateway.
    sqlx::query("UPDATE gateways SET label = $3 WHERE id = $1 AND account_id = $2")
        .bind(&gateway_id)
        .bind(claims.sub)
        .bind(&label)
        .execute(&state.pool)
        .await?;

    // Read back rather than echoing the request, so the response is what a
    // subsequent list call would show.
    let updated = flora_db::queries::gateway_by_id(&state.pool, &gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(GatewaySummary::from(updated)))
}

/// `PATCH /gateways/{gateway_id}/nodes/{node_uuid}/label`
pub async fn rename_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((gateway_id, node_uuid)): Path<(String, String)>,
    Json(body): Json<LabelRequest>,
) -> Result<StatusCode, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let label = normalise_label(body.label.as_deref())?;

    let gateway = flora_db::queries::gateway_by_id(&state.pool, &gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !gateway.owned_by(claims.sub) {
        return Err(ApiError::Forbidden);
    }

    let uuid = flora_auth::unhex(&node_uuid)
        .filter(|bytes| bytes.len() == 8)
        .ok_or_else(|| ApiError::BadRequest("node_uuid must be 8 bytes of hex".into()))?;

    // The gateway is already known to belong to this account, so matching on it
    // is sufficient here.
    let result =
        sqlx::query("UPDATE nodes SET label = $3 WHERE gateway_id = $1 AND node_uuid = $2")
            .bind(&gateway_id)
            .bind(&uuid)
            .bind(&label)
            .execute(&state.pool)
            .await?;

    if result.rows_affected() == 0 {
        // Either the node is unknown or the label was already that value; both
        // are "nothing to report" rather than an error the app must handle.
        let exists: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM nodes WHERE gateway_id = $1 AND node_uuid = $2")
                .bind(&gateway_id)
                .bind(&uuid)
                .fetch_optional(&state.pool)
                .await?;
        if exists.is_none() {
            return Err(ApiError::NotFound);
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /gateways/{gateway_id}/retire`
///
/// Retiring is how a farmer removes a gateway they no longer use. It is a soft
/// delete: the rows remain so the collected data stays attributable, which the
/// paper needs, but the device stops being able to collect commands or ingest.
pub async fn retire_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let claims = authenticate(&state, &headers)?;

    let gateway = flora_db::queries::gateway_by_id(&state.pool, &gateway_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    // A retired gateway is no longer actionable, so `owned_by` would refuse it;
    // check ownership directly so retiring twice is idempotent rather than a
    // confusing 403.
    if gateway.account_id != Some(claims.sub) {
        return Err(ApiError::Forbidden);
    }
    if gateway.is_retired() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let now = Utc::now();
    sqlx::query(
        "UPDATE gateways SET status = 'retired', retired_at = $3 WHERE id = $1 AND account_id = $2",
    )
    .bind(&gateway_id)
    .bind(claims.sub)
    .bind(now)
    .execute(&state.pool)
    .await?;

    // Rotating the device token on retire stops the device from collecting
    // commands or ingesting, independent of the status check.
    sqlx::query("UPDATE device_tokens SET rotated_at = $2 WHERE device_id = $1")
        .bind(&gateway_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

    tracing::info!(%gateway_id, "gateway retired");
    Ok(StatusCode::NO_CONTENT)
}

/// Whether a device id is well formed, used by the app before it calls.
pub fn is_gateway_id(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Re-exported so the app's node path is documented in one place.
pub fn node_label_path(gateway_id: &str, node_uuid: &str) -> String {
    format!("/gateways/{gateway_id}/nodes/{node_uuid}/label")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_trimmed_and_empties_clear() {
        assert_eq!(
            normalise_label(Some("  plot-north ")).unwrap(),
            Some("plot-north".into())
        );
        assert_eq!(normalise_label(Some("")).unwrap(), None);
        assert_eq!(normalise_label(Some("   ")).unwrap(), None);
        assert_eq!(normalise_label(None).unwrap(), None);
    }

    #[test]
    fn overlong_and_control_character_labels_are_refused() {
        let long = "a".repeat(MAX_LABEL_LENGTH + 1);
        assert!(normalise_label(Some(&long)).is_err());
        // Exactly at the limit is fine.
        let exact = "a".repeat(MAX_LABEL_LENGTH);
        assert!(normalise_label(Some(&exact)).is_ok());
        // A newline would break a list row; a tab too.
        assert!(normalise_label(Some("plot\nnorth")).is_err());
        assert!(normalise_label(Some("plot\tnorth")).is_err());
        // Non-ASCII is allowed: names are not restricted to English.
        assert!(normalise_label(Some("plot·north")).is_ok());
    }

    #[test]
    fn gateway_ids_are_thirty_two_hex_characters() {
        assert!(is_gateway_id("fe812c12f3ab4ce6ac5db69ac352f906"));
        assert!(
            !is_gateway_id("fe812c12"),
            "a short id is the old 8-byte width"
        );
        assert!(!is_gateway_id("zz812c12f3ab4ce6ac5db69ac352f906"));
        assert!(!is_gateway_id(""));
    }

    #[test]
    fn the_node_label_path_is_well_formed() {
        assert_eq!(
            node_label_path("fe812c12f3ab4ce6ac5db69ac352f906", "0202020202020202"),
            "/gateways/fe812c12f3ab4ce6ac5db69ac352f906/nodes/0202020202020202/label"
        );
    }
}
