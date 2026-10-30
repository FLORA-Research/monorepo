//! End-to-end flow against a real Postgres.
//!
//! Skipped unless `TEST_DATABASE_URL` is set, so the workspace still builds and
//! tests on a machine with no database. When it is set, this drives the whole
//! provisioning and pairing path through the HTTP router, which is the only way
//! to catch a mistake that unit tests cannot see: a migration that does not
//! apply, a column that does not exist, a route that is not mounted.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use flora_api::{AppState, router, state::RateLimiter};
use std::sync::Arc;
use tower::ServiceExt;

const JWT_SECRET: &[u8] = b"test-secret-long-enough-for-hs256-signing";

fn database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Serialises tests within this binary, because they share one database.
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn state() -> AppState {
    let url = database_url().expect("checked by caller");
    let pool = flora_db::connect_and_migrate(&url).await.expect("migrate");
    // Start from a clean slate. Order respects foreign keys.
    // Individual literal statements: a prepared statement cannot carry several
    // commands, and `TRUNCATE ... CASCADE` cannot be used because the schema is
    // also exercised by the migration test.
    sqlx::raw_sql(
        "DELETE FROM device_commands; DELETE FROM reference_measurements;
         DELETE FROM readings; DELETE FROM nodes; DELETE FROM invite_tokens;
         DELETE FROM auth_nonces; DELETE FROM refresh_tokens; DELETE FROM claim_tokens;
         DELETE FROM device_tokens; DELETE FROM gateways; DELETE FROM app_devices;
         DELETE FROM accounts;",
    )
    .execute(&pool)
    .await
    .expect("clear tables");
    AppState {
        pool,
        jwt_secret: Arc::from(JWT_SECRET),
        // Argon2 hash of "test-provision-key".
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

#[tokio::test]
async fn full_provision_claim_and_authenticate_flow() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping end-to-end flow");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;

    // ---- 1. Provisioner registers an aggregator ----
    let aggregator_key = SigningKey::from_bytes(&[7u8; 32]);
    let device_id =
        flora_protocol::derive_device_id(aggregator_key.verifying_key().as_bytes()).unwrap();
    let device_token = flora_auth::generate_token().unwrap();
    let claim_token = flora_auth::generate_token().unwrap();

    let (status, body) = call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": device_id,
            "pubkey": hex::encode(aggregator_key.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&device_token)),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0",
            "label": "plot-north"
        })),
        Some("test-provision-key"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "unclaimed");

    // The device id must match the key, or provisioning is refused.
    let (status, _) = call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": "00000000000000000000000000000000",
            "pubkey": hex::encode(aggregator_key.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&device_token)),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0"
        })),
        Some("test-provision-key"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "device id must be derived from the key"
    );

    // Provisioning without the key is refused.
    let (status, _) = call(
        &state,
        "GET",
        &format!("/provision/status/{device_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ---- 2. First phone claims the gateway: the account is created here ----
    let phone_key = SigningKey::from_bytes(&[3u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let input = flora_auth::ClaimSignatureInput {
        device_id: &device_id,
        claim_token: &claim_token,
        nonce: &nonce,
    };
    let signature = phone_key.sign(&input.message());

    let claim_body = serde_json::json!({
        "device_id": device_id,
        "claim_token": hex::encode(claim_token),
        "app_pubkey": hex::encode(phone_key.verifying_key().as_bytes()),
        "nonce": hex::encode(nonce),
        "signature": hex::encode(signature.to_bytes()),
        "label": "plot-north"
    });
    let (status, body) = call(
        &state,
        "POST",
        "/pair/claim",
        Some(claim_body.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["account_created"], true,
        "the first claim creates the account"
    );
    let account_id = body["account_id"].as_str().unwrap().to_string();
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    // ---- 3. The account now sees its gateway ----
    let (status, body) = call(&state, "GET", "/account/gateways", None, Some(&access)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let gateways = body.as_array().unwrap();
    assert_eq!(gateways.len(), 1);
    assert_eq!(gateways[0]["id"], device_id);
    assert_eq!(gateways[0]["status"], "claimed");

    // ---- 4. The claim token is one-time ----
    let replay_nonce = flora_auth::generate_token().unwrap();
    let replay_input = flora_auth::ClaimSignatureInput {
        device_id: &device_id,
        claim_token: &claim_token,
        nonce: &replay_nonce,
    };
    let replay_sig = phone_key.sign(&replay_input.message());
    let (status, _) = call(
        &state,
        "POST",
        "/pair/claim",
        Some(serde_json::json!({
            "device_id": device_id,
            "claim_token": hex::encode(claim_token),
            "app_pubkey": hex::encode(phone_key.verifying_key().as_bytes()),
            "nonce": hex::encode(replay_nonce),
            "signature": hex::encode(replay_sig.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a consumed claim token must not work again"
    );

    // ---- 5. A signature from the wrong key cannot claim ----
    let stranger = SigningKey::from_bytes(&[9u8; 32]);
    let device_id_b =
        flora_protocol::derive_device_id(stranger.verifying_key().as_bytes()).unwrap();
    let token_b = flora_auth::generate_token().unwrap();
    let hash_b = flora_auth::hash_token(&token_b);
    let (status, _) = call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": device_id_b,
            "pubkey": hex::encode(stranger.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&device_token)),
            "claim_hash": hex::encode(hash_b),
            "hw": "pico_w",
            "fw_ver": "0.1.0"
        })),
        Some("test-provision-key"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let forged_nonce = flora_auth::generate_token().unwrap();
    let forged_input = flora_auth::ClaimSignatureInput {
        device_id: &device_id_b,
        claim_token: &token_b,
        nonce: &forged_nonce,
    };
    // Signed by an unrelated key rather than the one being presented.
    let forged_sig = SigningKey::from_bytes(&[11u8; 32]).sign(&forged_input.message());
    let (status, _) = call(
        &state,
        "POST",
        "/pair/claim",
        Some(serde_json::json!({
            "device_id": device_id_b,
            "claim_token": hex::encode(token_b),
            "app_pubkey": hex::encode(stranger.verifying_key().as_bytes()),
            "nonce": hex::encode(forged_nonce),
            "signature": hex::encode(forged_sig.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a forged signature must not claim"
    );

    // ---- 6. Re-authentication by signing a challenge ----
    let (status, body) = call(
        &state,
        "POST",
        "/auth/challenge",
        Some(serde_json::json!({
            "app_pubkey": hex::encode(phone_key.verifying_key().as_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge = hex::decode(body["nonce"].as_str().unwrap()).unwrap();
    let auth_sig = phone_key.sign(&flora_api::auth::auth_message(
        phone_key.verifying_key().as_bytes(),
        &challenge,
    ));
    let (status, body) = call(
        &state,
        "POST",
        "/auth/verify",
        Some(serde_json::json!({
            "app_pubkey": hex::encode(phone_key.verifying_key().as_bytes()),
            "nonce": hex::encode(&challenge),
            "signature": hex::encode(auth_sig.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["account_id"].as_str().unwrap(), account_id);

    // The same nonce cannot be used twice.
    let (status, _) = call(
        &state,
        "POST",
        "/auth/verify",
        Some(serde_json::json!({
            "app_pubkey": hex::encode(phone_key.verifying_key().as_bytes()),
            "nonce": hex::encode(&challenge),
            "signature": hex::encode(auth_sig.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a nonce is single use");

    // ---- 7. Refresh rotation ----
    let (status, body) = call(
        &state,
        "POST",
        "/auth/refresh",
        Some(serde_json::json!({ "refresh_token": refresh })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rotated = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rotated, refresh, "refresh tokens must rotate");

    let (status, _) = call(
        &state,
        "POST",
        "/auth/refresh",
        Some(serde_json::json!({ "refresh_token": refresh })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a used refresh token must be refused"
    );
}

#[tokio::test]
async fn revoked_device_loses_access() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping revocation test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;

    // Provision and claim, reusing the flow above in miniature.
    let aggregator = SigningKey::from_bytes(&[21u8; 32]);
    let device_id =
        flora_protocol::derive_device_id(aggregator.verifying_key().as_bytes()).unwrap();
    let claim_token = flora_auth::generate_token().unwrap();
    call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": device_id,
            "pubkey": hex::encode(aggregator.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&[1u8; 32])),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0"
        })),
        Some("test-provision-key"),
    )
    .await;

    let phone = SigningKey::from_bytes(&[22u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let input = flora_auth::ClaimSignatureInput {
        device_id: &device_id,
        claim_token: &claim_token,
        nonce: &nonce,
    };
    let signature = phone.sign(&input.message());
    let (status, body) = call(
        &state,
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
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    // Find the device id via the account token, then revoke it.
    let pool = &state.pool;
    let (device_row,): (uuid::Uuid,) =
        sqlx::query_as("SELECT id FROM app_devices WHERE pubkey = $1")
            .bind(phone.verifying_key().as_bytes().to_vec())
            .fetch_one(pool)
            .await
            .unwrap();

    let (status, _) = call(
        &state,
        "POST",
        &format!("/account/app-devices/{device_row}/revoke"),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The refresh token issued to that device must stop working.
    let (status, _) = call(
        &state,
        "POST",
        "/auth/refresh",
        Some(serde_json::json!({ "refresh_token": refresh })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoking a phone must invalidate its refresh tokens"
    );

    // And it can no longer sign in from scratch.
    let (status, body) = call(
        &state,
        "POST",
        "/auth/challenge",
        Some(serde_json::json!({
            "app_pubkey": hex::encode(phone.verifying_key().as_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge = hex::decode(body["nonce"].as_str().unwrap()).unwrap();
    let sig = phone.sign(&flora_api::auth::auth_message(
        phone.verifying_key().as_bytes(),
        &challenge,
    ));
    let (status, _) = call(
        &state,
        "POST",
        "/auth/verify",
        Some(serde_json::json!({
            "app_pubkey": hex::encode(phone.verifying_key().as_bytes()),
            "nonce": hex::encode(&challenge),
            "signature": hex::encode(sig.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a revoked device is not a live device"
    );
}

#[tokio::test]
async fn health_check_reports_database_reachability() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping health test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let (status, _) = call(&state, "GET", "/healthz", None, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// The read surface and the Chapter 4 reports, against real data.
#[tokio::test]
async fn read_surface_and_reports_return_ingested_data() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;

    // Provision and claim a gateway.
    let aggregator = SigningKey::from_bytes(&[31u8; 32]);
    let device_id =
        flora_protocol::derive_device_id(aggregator.verifying_key().as_bytes()).unwrap();
    let device_token = flora_auth::generate_token().unwrap();
    let claim_token = flora_auth::generate_token().unwrap();
    // Assert the registration, so a failure here does not surface later as a
    // confusing not-found on the claim.
    let (registered, register_body) = call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": device_id,
            "pubkey": hex::encode(aggregator.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&device_token)),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0",
            "label": "plot-south"
        })),
        Some("test-provision-key"),
    )
    .await;
    assert_eq!(registered, StatusCode::CREATED, "register: {register_body}");

    let phone = SigningKey::from_bytes(&[32u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let input = flora_auth::ClaimSignatureInput {
        device_id: &device_id,
        claim_token: &claim_token,
        nonce: &nonce,
    };
    let signature = phone.sign(&input.message());
    let (status, body) = call(
        &state,
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
    let access = body["access_token"].as_str().unwrap().to_string();
    let device_auth = format!("Device {device_id}:{}", hex::encode(device_token));

    // A batch carrying two nodes: one fully readable, one with sentinels.
    let now = chrono::Utc::now().timestamp();
    let batch = serde_json::json!({
        "gw_id": device_id,
        "ts": now,
        "nodes": [
            {"uuid":"0202020202020202","addr":2,"moist":312,"temp":284,"hum":710,
             "valve":0,"seq":1042,"fw_ver":256},
            {"uuid":"0303030303030303","addr":3,"moist":65535,"temp":-32768,"hum":65535,
             "valve":1,"seq":1,"fw_ver":256}
        ]
    });
    let request = Request::builder()
        .method("POST")
        .uri("/ingest/batch")
        .header("authorization", &device_auth)
        .header("content-type", "application/json")
        .body(Body::from(batch.to_string()))
        .unwrap();
    let response = router(state.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // ---- Nodes are discovered from the batch, not told to us separately ----
    let (status, nodes) = call(
        &state,
        "GET",
        &format!("/gateways/{device_id}/nodes"),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{nodes}");
    let nodes = nodes.as_array().unwrap();
    assert_eq!(
        nodes.len(),
        2,
        "both nodes must be discovered from telemetry"
    );
    assert_eq!(nodes[0]["addr"], 2);
    assert_eq!(nodes[1]["addr"], 3);
    assert_eq!(nodes[0]["online"], true);

    // ---- Latest reading per node, with sentinels preserved as null ----
    let (status, latest) = call(
        &state,
        "GET",
        &format!("/gateways/{device_id}/readings/latest"),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{latest}");
    let latest = latest.as_array().unwrap();
    assert_eq!(latest.len(), 2);
    let readable = latest
        .iter()
        .find(|row| row["node_uuid"].as_str().unwrap() == "0202020202020202")
        .unwrap();
    assert_eq!(readable["moisture"], 31.2);
    assert_eq!(readable["temperature"], 28.4);
    let unavailable = latest
        .iter()
        .find(|row| row["node_uuid"].as_str().unwrap() == "0303030303030303")
        .unwrap();
    assert_eq!(
        unavailable["moisture"],
        serde_json::Value::Null,
        "a sentinel must surface as null, never as 6553.5 percent"
    );

    // ---- History with a node filter ----
    let (status, history) = call(
        &state,
        "GET",
        &format!("/gateways/{device_id}/readings?node_uuid=0202020202020202"),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert_eq!(history.as_array().unwrap().len(), 1);

    // An unknown metric is refused rather than silently returning everything.
    let (status, _) = call(
        &state,
        "GET",
        &format!("/gateways/{device_id}/readings?metric=pressure"),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // ---- Reports ----
    let (status, mae) = call(&state, "GET", "/account/reports/mae", None, Some(&access)).await;
    assert_eq!(status, StatusCode::OK, "{mae}");
    let reports = mae["gateways"].as_array().unwrap();
    assert_eq!(reports.len(), 3, "one report per metric");
    // No reference measurements were recorded, so MAE is null, not zero.
    for report in reports {
        assert_eq!(
            report["mae"],
            serde_json::Value::Null,
            "absent reference data must not read as perfect agreement"
        );
    }

    let (status, savings) = call(
        &state,
        "GET",
        "/account/reports/water-savings?baseline_minutes_per_day=30",
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{savings}");
    let gateways = savings["gateways"].as_array().unwrap();
    assert_eq!(gateways.len(), 1);
    assert_eq!(gateways[0]["nodes"].as_array().unwrap().len(), 2);

    let (status, fleet) = call(
        &state,
        "GET",
        "/account/reports/fleet-health",
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fleet}");
    assert_eq!(fleet["provisioned"], 1);
    assert_eq!(fleet["claimed"], 1);
    assert_eq!(fleet["online"], 1);
    assert_eq!(fleet["gateways"][0]["nodes"], 2);

    // ---- Ownership: another account sees nothing ----
    let stranger = SigningKey::from_bytes(&[33u8; 32]);
    let other_id = flora_protocol::derive_device_id(stranger.verifying_key().as_bytes()).unwrap();
    let other_claim = flora_auth::generate_token().unwrap();
    call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": other_id,
            "pubkey": hex::encode(stranger.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&[2u8; 32])),
            "claim_hash": hex::encode(flora_auth::hash_token(&other_claim)),
            "hw": "pico_w",
            "fw_ver": "0.1.0"
        })),
        Some("test-provision-key"),
    )
    .await;
    let other_phone = SigningKey::from_bytes(&[34u8; 32]);
    let other_nonce = flora_auth::generate_token().unwrap();
    let other_input = flora_auth::ClaimSignatureInput {
        device_id: &other_id,
        claim_token: &other_claim,
        nonce: &other_nonce,
    };
    let other_sig = other_phone.sign(&other_input.message());
    let (status, other_body) = call(
        &state,
        "POST",
        "/pair/claim",
        Some(serde_json::json!({
            "device_id": other_id,
            "claim_token": hex::encode(other_claim),
            "app_pubkey": hex::encode(other_phone.verifying_key().as_bytes()),
            "nonce": hex::encode(other_nonce),
            "signature": hex::encode(other_sig.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{other_body}");
    let other_access = other_body["access_token"].as_str().unwrap().to_string();

    let (status, _) = call(
        &state,
        "GET",
        &format!("/gateways/{device_id}/nodes"),
        None,
        Some(&other_access),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another account must not read this gateway"
    );

    let (status, _) = call(
        &state,
        "GET",
        "/account/reports/mae",
        None,
        Some(&other_access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The other account has its own gateway but no readings for it.
    let (_, other_mae) = call(
        &state,
        "GET",
        "/account/reports/mae",
        None,
        Some(&other_access),
    )
    .await;
    let other_reports = other_mae["gateways"].as_array().unwrap();
    assert!(
        other_reports
            .iter()
            .all(|r| !r["metric"].as_str().unwrap().starts_with(&device_id)),
        "a report must never include another account's gateway"
    );
}
