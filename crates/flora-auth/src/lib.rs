//! Authentication, pairing, and session handling.
//!
//! The rule that shapes this crate: the cloud is never trusted to
//! authorise an irrigation command on its own. It verifies what it can
//! here, records what it did, and the aggregator verifies again before
//! a valve moves.

pub mod pairing;
pub mod secrets;
pub mod session;

pub use pairing::{
    CLAIM_TTL_HOURS, ClaimOutcome, ClaimSignatureInput, NONCE_BYTES, NONCE_TTL_MINUTES, PairError,
    claim_expiry, claim_is_usable, claim_token_matches, ensure_not_retired, resolve_target,
    verify_claim_signature,
};
pub use secrets::{
    SecretError, generate_token, generate_token_hex, hash_api_key, hash_token, hex, tokens_match,
    unhex, verify_api_key,
};
pub use session::{
    ACCESS_TTL_MINUTES, Claims, REFRESH_TTL_DAYS, SessionError, issue_access_token, refresh_expiry,
    verify_access_token,
};
