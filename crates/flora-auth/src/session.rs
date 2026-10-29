//! Session tokens: short-lived access JWTs and rotating refresh tokens.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Access token lifetime. Short, because it is carried in memory only.
pub const ACCESS_TTL_MINUTES: i64 = 60;
/// Refresh token lifetime. Long, because it is the thing that keeps a phone
/// logged in without a password.
pub const REFRESH_TTL_DAYS: i64 = 30;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("token encoding failed")]
    Encode,
    #[error("token is invalid or expired")]
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the account id.
    pub sub: Uuid,
    /// The app device that authenticated, so a single phone can be revoked.
    pub dev: Uuid,
    pub exp: i64,
    pub iat: i64,
}

/// Build an access token for an account and device.
pub fn issue_access_token(
    secret: &[u8],
    account_id: Uuid,
    device_id: Uuid,
    now: DateTime<Utc>,
) -> Result<String, SessionError> {
    let claims = Claims {
        sub: account_id,
        dev: device_id,
        iat: now.timestamp(),
        exp: (now + Duration::minutes(ACCESS_TTL_MINUTES)).timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|_| SessionError::Encode)
}

/// Verify an access token and return its claims.
pub fn verify_access_token(secret: &[u8], token: &str) -> Result<Claims, SessionError> {
    let validation = Validation::default();
    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|data| data.claims)
        .map_err(|_| SessionError::Invalid)
}

/// Expiry instant for a freshly issued refresh token.
pub fn refresh_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::days(REFRESH_TTL_DAYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-not-used-in-production";

    #[test]
    fn access_token_round_trips_with_both_identifiers() {
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let token = issue_access_token(SECRET, account, device, Utc::now()).unwrap();
        let claims = verify_access_token(SECRET, &token).unwrap();
        assert_eq!(claims.sub, account);
        assert_eq!(
            claims.dev, device,
            "the device claim is what revocation checks"
        );
    }

    #[test]
    fn a_token_from_another_secret_is_rejected() {
        let token = issue_access_token(SECRET, Uuid::new_v4(), Uuid::new_v4(), Utc::now()).unwrap();
        assert!(matches!(
            verify_access_token(b"a-different-secret", &token),
            Err(SessionError::Invalid)
        ));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(verify_access_token(SECRET, "not.a.jwt").is_err());
        assert!(verify_access_token(SECRET, "").is_err());
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let past = Utc::now() - Duration::hours(3);
        let token = issue_access_token(SECRET, Uuid::new_v4(), Uuid::new_v4(), past).unwrap();
        assert!(matches!(
            verify_access_token(SECRET, &token),
            Err(SessionError::Invalid)
        ));
    }

    #[test]
    fn refresh_expiry_is_in_the_future() {
        let now = Utc::now();
        assert!(refresh_expiry(now) > now);
    }
}
