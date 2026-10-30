//! The invite flow end to end against a real database.
//!
//! A second phone joins an existing account with no email, which is the plan's
//! requirement and the half that was missing: the table existed and nothing
//! wrote to it.
//!
//! Proves the happy path and each refusal: a replayed nonce, a consumed token,
//! an expired token, a forged signature, and a key already bound to another
//! account.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use flora_api::{AppState, router, state::RateLimiter};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &[u8] = b"test-secret-long-enough-for-hs256-signing";
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Derive the gateway id from a public key, as the v2 protocol defines it.
fn derive_device_id(pubkey: &[u8]) -> String {
    hex::encode(flora_protocol::device_id_bytes(pubkey).unwrap())
}

async fn state() -> AppState {
    let url = database_url().expect("checked by caller");
    let pool = flora_db::connect_and_migrate(&url).await.expect("migrate");
    sqlx::raw_sql(
        "DELETE FROM device_commands; DELETE FROM readings; DELETE FROM nodes;
         DELETE FROM invite_tokens; DELETE FROM auth_nonces; DELETE FROM refresh_tokens;
         DELETE FROM claim_tokens; DELETE FROM device_tokens; DELETE FROM gateways;
         DELETE FROM app_devices; DELETE FROM accounts;",
    )
    .execute(&pool)
    .await
    .expect("clear tables");
    AppState {
        pool,
        jwt_secret: Arc::from(JWT_SECRET),
        provision_key_hash: Some(Arc::from(
            flora_auth::hash_api_key("test-provision-key").unwrap(),
        )),
        claim_limiter: Arc::new(RateLimiter::new(60, 1000)),
        auth_limiter: Arc::new(RateLimiter::new(60, 1000)),
        command_limiter: Arc::new(RateLimiter::new(60, 1000)),
        events: Arc::new(flora_api::stream::EventHub::new()),
    }
}

async fn call(
    state: &AppState,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(json) => builder
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// Create an account by claiming a gateway, returning the first phone's session.
async fn make_account(state: &AppState, seed: u8) -> (String, SigningKey, Uuid) {
    let aggregator = SigningKey::from_bytes(&[seed; 32]);
    let device_id = derive_device_id(aggregator.verifying_key().as_bytes());
    let claim_token = flora_auth::generate_token().unwrap();

    let (status, _) = call(
        state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": device_id,
            "pubkey": hex::encode(aggregator.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&[seed.wrapping_add(1); 32])),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0"
        })),
        Some("test-provision-key"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let phone = SigningKey::from_bytes(&[seed.wrapping_add(2); 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let input = flora_auth::ClaimSignatureInput {
        device_id: &device_id,
        claim_token: &claim_token,
        nonce: &nonce,
    };
    let signature = phone.sign(&input.message());
    let (status, body) = call(
        state,
        "POST",
        "/pair/claim",
        Some(serde_json::json!({
            "device_id": device_id,
            "claim_token": hex::encode(claim_token),
            "app_pubkey": hex::encode(phone.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(signature.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        body["access_token"].as_str().unwrap().to_string(),
        phone,
        Uuid::parse_str(body["account_id"].as_str().unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn a_second_phone_joins_with_an_invite_and_no_email() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let (first_access, _first_phone, account_id) = make_account(&state, 41).await;

    // ---- 1. The inviter mints an invite ----
    let (status, body) = call(&state, "POST", "/account/invite", None, Some(&first_access)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let invite_token = body["token"].as_str().unwrap().to_string();
    let payload = body["payload"].as_str().unwrap();
    assert!(payload.starts_with("flora://invite?v=1&a="), "{payload}");
    assert!(payload.contains(&account_id.to_string()));
    // The raw token is returned once; only its hash is stored.
    assert_eq!(invite_token.len(), 64);

    // ---- 2. The second phone scans, signs, and joins ----
    let second_phone = SigningKey::from_bytes(&[77u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let signature = second_phone.sign(&flora_api::invite::invite_message(
        second_phone.verifying_key().as_bytes(),
        &Canonical::hex_decode(&invite_token),
        &nonce,
    ));

    let (status, body) = call(
        &state,
        "POST",
        "/pair/invite",
        Some(serde_json::json!({
            "invite_token": invite_token,
            "app_pubkey": hex::encode(second_phone.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(signature.to_bytes()),
            "label": "second phone"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["account_id"].as_str().unwrap(),
        account_id.to_string(),
        "the second phone joins the same account"
    );
    assert_eq!(
        body["account_created"], false,
        "an invite never creates an account"
    );
    let second_access = body["access_token"].as_str().unwrap().to_string();

    // ---- 3. Both phones see the same plots ----
    let (status, first_view) = call(
        &state,
        "GET",
        "/account/gateways",
        None,
        Some(&first_access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, second_view) = call(
        &state,
        "GET",
        "/account/gateways",
        None,
        Some(&second_access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first_view.as_array().unwrap().len(), 1);
    assert_eq!(
        first_view, second_view,
        "both phones must see the same account contents"
    );

    // ---- 4. The invite is single use ----
    let nonce2 = flora_auth::generate_token().unwrap();
    let signature2 = second_phone.sign(&flora_api::invite::invite_message(
        second_phone.verifying_key().as_bytes(),
        &Canonical::hex_decode(&invite_token),
        &nonce2,
    ));
    let (status, _) = call(
        &state,
        "POST",
        "/pair/invite",
        Some(serde_json::json!({
            "invite_token": invite_token,
            "app_pubkey": hex::encode(second_phone.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce2),
            "signature": hex::encode(signature2.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a consumed invite must not work again"
    );
}

#[tokio::test]
async fn the_invite_refusals_hold() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let (access, _phone, _account) = make_account(&state, 51).await;

    // A forged signature must not consume the invite, or it would lock out the
    // person the invite was meant for.
    let (_, invite) = call(&state, "POST", "/account/invite", None, Some(&access)).await;
    let token = invite["token"].as_str().unwrap().to_string();
    let token_bytes = Canonical::hex_decode(&token);
    let stranger = SigningKey::from_bytes(&[88u8; 32]);
    let attacker = SigningKey::from_bytes(&[89u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let forged = attacker.sign(&flora_api::invite::invite_message(
        stranger.verifying_key().as_bytes(),
        &token_bytes,
        &nonce,
    ));
    let (status, _) = call(
        &state,
        "POST",
        "/pair/invite",
        Some(serde_json::json!({
            "invite_token": token,
            "app_pubkey": hex::encode(stranger.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(forged.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a forged signature must not join"
    );

    // The invite survives the forgery attempt, proving the signature is checked
    // before the token is consumed.
    let legitimate = SigningKey::from_bytes(&[90u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let signature = legitimate.sign(&flora_api::invite::invite_message(
        legitimate.verifying_key().as_bytes(),
        &token_bytes,
        &nonce,
    ));
    let (status, _) = call(
        &state,
        "POST",
        "/pair/invite",
        Some(serde_json::json!({
            "invite_token": token,
            "app_pubkey": hex::encode(legitimate.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(signature.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the genuine invite still works"
    );

    // A replayed nonce is refused.
    let (_, invite) = call(&state, "POST", "/account/invite", None, Some(&access)).await;
    let token2 = invite["token"].as_str().unwrap().to_string();
    let token2_bytes = Canonical::hex_decode(&token2);
    let newest = SigningKey::from_bytes(&[91u8; 32]);
    let reused_nonce = flora_auth::generate_token().unwrap();
    let signature = newest.sign(&flora_api::invite::invite_message(
        newest.verifying_key().as_bytes(),
        &token2_bytes,
        &reused_nonce,
    ));
    let body = serde_json::json!({
        "invite_token": token2,
        "app_pubkey": hex::encode(newest.verifying_key().as_bytes()),
        "nonce": hex::encode(reused_nonce),
        "signature": hex::encode(signature.to_bytes())
    });

    let (status, _) = call(&state, "POST", "/pair/invite", Some(body.clone()), None).await;
    assert_eq!(status, StatusCode::CREATED);
    // The same nonce against a fresh invite is refused, because nonces are
    // global rather than per invite. The signature must cover the new token,
    // or the request would fail verification before reaching the nonce check
    // and the test would be asserting the wrong refusal.
    let (_, invite3) = call(&state, "POST", "/account/invite", None, Some(&access)).await;
    let token3 = invite3["token"].as_str().unwrap().to_string();
    let replay_signature = newest.sign(&flora_api::invite::invite_message(
        newest.verifying_key().as_bytes(),
        &Canonical::hex_decode(&token3),
        &reused_nonce,
    ));
    let body3 = serde_json::json!({
        "invite_token": token3,
        "app_pubkey": hex::encode(newest.verifying_key().as_bytes()),
        "nonce": hex::encode(reused_nonce),
        "signature": hex::encode(replay_signature.to_bytes())
    });
    let (status, body3_response) = call(&state, "POST", "/pair/invite", Some(body3), None).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a nonce is single use: {body3_response}"
    );

    // An expired invite is refused.
    let (_, invite4) = call(&state, "POST", "/account/invite", None, Some(&access)).await;
    let expired_token = invite4["token"].as_str().unwrap().to_string();
    sqlx::query("UPDATE invite_tokens SET expires_at = now() - interval '1 minute'")
        .execute(&state.pool)
        .await
        .unwrap();
    let late = SigningKey::from_bytes(&[92u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let signature = late.sign(&flora_api::invite::invite_message(
        late.verifying_key().as_bytes(),
        &Canonical::hex_decode(&expired_token),
        &nonce,
    ));
    let (status, _) = call(
        &state,
        "POST",
        "/pair/invite",
        Some(serde_json::json!({
            "invite_token": expired_token,
            "app_pubkey": hex::encode(late.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(signature.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an expired invite must not work"
    );
}

#[tokio::test]
async fn a_key_bound_to_another_account_cannot_join() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;

    // Two separate accounts, each with its own phone.
    let (first_access, first_phone, _) = make_account(&state, 61).await;
    let (second_access, _second_phone, _) = make_account(&state, 71).await;

    // The first account invites. The already-bound key tries to use it.
    let (_, invite) = call(
        &state,
        "POST",
        "/account/invite",
        None,
        Some(&second_access),
    )
    .await;
    let token = invite["token"].as_str().unwrap().to_string();
    let nonce = flora_auth::generate_token().unwrap();
    let signature = first_phone.sign(&flora_api::invite::invite_message(
        first_phone.verifying_key().as_bytes(),
        &Canonical::hex_decode(&token),
        &nonce,
    ));
    let (status, body) = call(
        &state,
        "POST",
        "/pair/invite",
        Some(serde_json::json!({
            "invite_token": token,
            "app_pubkey": hex::encode(first_phone.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(signature.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a key already in another account must not join a second one: {body}"
    );

    // And the first phone still reads only its own account.
    let (status, view) = call(
        &state,
        "GET",
        "/account/gateways",
        None,
        Some(&first_access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view.as_array().unwrap().len(), 1);
}

/// Hex decoding for the test's signing inputs.
///
/// Delegates to the crate rather than hand-rolling it, so the test cannot
/// disagree with the server about what a hex string means.
struct Canonical;

impl Canonical {
    fn hex_decode(value: &str) -> Vec<u8> {
        flora_auth::unhex(value).expect("valid hex")
    }
}
