//! Shared application state and error mapping.

use std::sync::Arc;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::PgPool;

use crate::dto::ErrorBody;

/// A fixed-window counter, enough for the limits in the plan.
///
/// Kept in memory: a restarted instance resets its counters, which is
/// acceptable for brute-force damping and avoids a database round trip on the
/// unauthenticated paths that most need limiting.
#[derive(Debug)]
pub struct RateLimiter {
    window_secs: i64,
    max: u32,
    hits: tokio::sync::Mutex<std::collections::HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    pub fn new(window_secs: i64, max: u32) -> Self {
        Self {
            window_secs,
            max,
            hits: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record an attempt. Returns `false` when the caller is over the limit.
    pub async fn check(&self, key: &str, now_epoch: i64) -> bool {
        let mut hits = self.hits.lock().await;
        // Opportunistic cleanup so a long-running process does not accumulate
        // an entry per client address forever.
        if hits.len() > 10_000 {
            let window = self.window_secs;
            hits.retain(|_, (start, _)| now_epoch - *start < window);
        }
        let entry = hits.entry(key.to_owned()).or_insert((now_epoch, 0));
        if now_epoch - entry.0 >= self.window_secs {
            *entry = (now_epoch, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// Fan-out for WebSocket subscribers.
    pub events: Arc<crate::stream::EventHub>,
    pub jwt_secret: Arc<[u8]>,
    /// Argon2 hash of the provision API key; the key itself is never stored.
    pub provision_key_hash: Option<Arc<str>>,
    pub claim_limiter: Arc<RateLimiter>,
    pub auth_limiter: Arc<RateLimiter>,
    pub command_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(pool: PgPool, jwt_secret: Vec<u8>, provision_key_hash: Option<String>) -> Self {
        Self {
            pool,
            events: Arc::new(crate::stream::EventHub::new()),
            jwt_secret: Arc::from(jwt_secret),
            provision_key_hash: provision_key_hash.map(Arc::from),
            // 5/min per device id and 20/min per address, per the plan.
            claim_limiter: Arc::new(RateLimiter::new(60, 20)),
            auth_limiter: Arc::new(RateLimiter::new(60, 10)),
            // 30 commands per account per minute, per the plan.
            command_limiter: Arc::new(RateLimiter::new(60, crate::commands::COMMANDS_PER_MINUTE)),
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    NotFound,
    Unauthorized,
    Forbidden,
    BadRequest(String),
    Conflict(String),
    TooManyRequests,
    /// An upstream or internal failure. The detail is logged, never returned.
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn public_message(&self) -> String {
        match self {
            ApiError::NotFound => "not found".into(),
            ApiError::Unauthorized => "unauthorized".into(),
            ApiError::Forbidden => "forbidden".into(),
            ApiError::BadRequest(detail) => detail.clone(),
            ApiError::Conflict(detail) => detail.clone(),
            ApiError::TooManyRequests => "too many requests".into(),
            // Deliberately opaque: internal detail must not reach a client.
            ApiError::Internal(_) => "internal error".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(detail) = &self {
            // Logged with the request context the tracing layer attaches.
            tracing::error!(error = %detail, "request failed");
        }
        (self.status(), Json(ErrorBody::new(self.public_message()))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => ApiError::NotFound,
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl From<flora_db::queries::QueryError> for ApiError {
    fn from(error: flora_db::queries::QueryError) -> Self {
        match error {
            flora_db::queries::QueryError::NotFound => ApiError::NotFound,
            flora_db::queries::QueryError::Database(inner) => ApiError::from(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_allows_up_to_the_limit_then_refuses() {
        let limiter = RateLimiter::new(60, 3);
        for _ in 0..3 {
            assert!(limiter.check("client", 1_000).await);
        }
        assert!(
            !limiter.check("client", 1_000).await,
            "fourth attempt is over the limit"
        );
    }

    #[tokio::test]
    async fn rate_limiter_resets_after_the_window() {
        let limiter = RateLimiter::new(60, 1);
        assert!(limiter.check("client", 1_000).await);
        assert!(!limiter.check("client", 1_030).await);
        assert!(limiter.check("client", 1_060).await, "a new window starts");
    }

    #[tokio::test]
    async fn rate_limiter_isolates_clients() {
        let limiter = RateLimiter::new(60, 1);
        assert!(limiter.check("first", 1_000).await);
        assert!(limiter.check("second", 1_000).await, "limits are per key");
    }

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let error = ApiError::Internal("connection string with password".into());
        assert_eq!(error.public_message(), "internal error");
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn deliberate_errors_are_surfaced() {
        assert_eq!(
            ApiError::BadRequest("bad nonce".into()).public_message(),
            "bad nonce"
        );
        assert_eq!(ApiError::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::TooManyRequests.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
