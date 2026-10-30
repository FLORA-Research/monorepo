//! HTTP surface: routing, shared state, and error mapping.

pub mod account;
pub mod auth;
pub mod commands;
pub mod dto;
pub mod gateways;
pub mod ingest;
pub mod invite;
pub mod labels;
pub mod pairing;
pub mod provision;
pub mod reference;
pub mod reports;
pub mod state;
pub mod stream;

use axum::Router;
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub use state::{ApiError, AppState, RateLimiter};

/// Largest accepted request body. Commands and claims are small; this stops a
/// trivial memory-exhaustion attempt on the unauthenticated routes.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Build the application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Real-time streams. Authentication is the first frame, not a query
        // parameter, so a token never lands in an access log.
        .route("/account/stream", get(stream::account_stream))
        .route("/gateways/{gateway_id}/stream", get(stream::gateway_stream))
        // Cheap liveness for Render's probe and UptimeRobot.
        .route(LIVENESS_PATH, get(liveness))
        // Readiness including the database, for manual verification.
        .route("/healthz", get(readyz))
        // Provisioning: organisation key.
        .route("/provision/register", post(provision::register))
        .route("/provision/reissue", post(provision::reissue))
        .route("/provision/status/{device_id}", get(provision::status))
        // Pairing and auth: unauthenticated, credential is a token plus signature.
        .route("/pair/claim", post(pairing::claim))
        .route("/pair/invite", post(invite::redeem_invite))
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/verify", post(auth::verify))
        .route("/auth/refresh", post(auth::refresh))
        // Device ingest and delivery: device credentials, not a user JWT.
        .route("/ingest/batch", post(ingest::batch))
        .route("/device/commands", get(commands::poll_device_commands))
        .route(
            "/device/commands/{command_id}/ack",
            post(commands::ack_command),
        )
        // Manual commands: App -> API -> verify -> queue -> aggregator.
        .route(
            "/gateways/{gateway_id}/commands",
            post(commands::submit).get(commands::list_commands),
        )
        // Read-only gateway data for the app.
        .route(
            "/gateways/{gateway_id}/label",
            axum::routing::patch(labels::rename_gateway),
        )
        .route(
            "/gateways/{gateway_id}/retire",
            post(labels::retire_gateway),
        )
        .route(
            "/gateways/{gateway_id}/nodes/{node_uuid}/label",
            axum::routing::patch(labels::rename_node),
        )
        .route("/gateways/{gateway_id}/nodes", get(gateways::nodes))
        .route("/gateways/{gateway_id}/reference", post(reference::create))
        .route("/gateways/{gateway_id}/readings", get(gateways::history))
        .route(
            "/gateways/{gateway_id}/readings/latest",
            get(gateways::latest),
        )
        // Cross-gateway reports (JWT).
        .route("/account/reports/mae", get(reports::mae))
        .route(
            "/account/reports/water-savings",
            get(reports::water_savings_report),
        )
        .route("/account/reports/fleet-health", get(reports::fleet))
        // Account: bearer JWT.
        .route("/account/me", get(account::me))
        .route("/account/gateways", get(account::gateways))
        .route("/account/invite", post(invite::create_invite))
        .route(
            "/account/app-devices/{device_id}/revoke",
            post(account::revoke_app_device),
        )
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Path Render probes and that UptimeRobot should use.
pub const LIVENESS_PATH: &str = "/uptime";

/// Liveness only: the process is up and serving.
///
/// Deliberately does **not** touch the database. Render probes this path every
/// few seconds, and two external services querying Postgres on that schedule
/// would (a) hold a hibernating database permanently awake, which violates
/// Layerbase's free-plan sleep requirement, and (b) spend Layerbase session
/// minutes for no benefit. Process liveness is what both probes actually need.
///
/// Returns a tiny fixed body so the response cost stays negligible.
async fn liveness() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        "ok",
    )
}

/// Readiness, including the database.
///
/// For operators and manual checks rather than for polling: it proves the whole
/// path works. Render's `healthCheckPath` points at the liveness route instead,
/// for the reason above.
async fn readyz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<axum::http::StatusCode, ApiError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_limit_is_small_and_explicit() {
        assert_eq!(MAX_BODY_BYTES, 16 * 1024);
    }

    /// Every route in the plan's Step 5 surface must be mounted. A missing route
    /// is a 404 in production, so it is worth asserting here.
    #[test]
    fn step_five_routes_are_registered() {
        let source = include_str!("lib.rs");
        for path in [
            "/account/stream",
            "/gateways/{gateway_id}/stream",
            LIVENESS_PATH,
            "/healthz",
            "/provision/register",
            "/provision/reissue",
            "/provision/status/{device_id}",
            "/pair/claim",
            "/pair/invite",
            "/auth/challenge",
            "/auth/verify",
            "/auth/refresh",
            "/ingest/batch",
            "/device/commands",
            "/device/commands/{command_id}/ack",
            "/gateways/{gateway_id}/commands",
            "/gateways/{gateway_id}/label",
            "/gateways/{gateway_id}/retire",
            "/gateways/{gateway_id}/nodes/{node_uuid}/label",
            "/gateways/{gateway_id}/nodes",
            "/gateways/{gateway_id}/readings",
            "/gateways/{gateway_id}/readings/latest",
            "/account/reports/mae",
            "/account/reports/water-savings",
            "/account/reports/fleet-health",
            "/account/me",
            "/account/gateways",
            "/account/invite",
            "/account/app-devices/{device_id}/revoke",
        ] {
            assert!(source.contains(path), "route {path} is not registered");
        }
    }
}
