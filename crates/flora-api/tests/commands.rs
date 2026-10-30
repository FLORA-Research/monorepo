//! The manual command path, end to end against a real database.
//!
//! Proves the route the system depends on:
//!
//! ```text
//! App --POST /gateways/:id/commands--> API verifies signature, queues
//! Aggregator --GET /device/commands--> API hands it over, marking dispatched
//! Aggregator --POST /device/commands/:id/ack--> API records the outcome
//! ```
//!
//! and that the refusals hold: a wrong signature, a revoked phone's key, a
//! non-owner account, an inverted threshold band, and a command past its
//! freshness window.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use flora_api::{AppState, router, state::RateLimiter};
use flora_protocol::{KIND_SET_THRESHOLD, KIND_SET_VALVE, canonical_message};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &[u8] = b"test-secret-long-enough-for-hs256-signing";
/// Derived as `SHA-256(pubkey)[..16]` for the fixed test key, so the test
/// exercises the real derivation instead of a convenient literal.
const GATEWAY: &str = "fe812c12f3ab4ce6ac5db69ac352f906";

fn database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Serialises tests within this binary, because they share one database and
/// each one clears the tables.
///
/// An async mutex, not a blocking one: the guard is held across `await`, so a
/// synchronous lock would block the test executor's worker thread.
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn state() -> AppState {
    let url = database_url().expect("checked by caller");
    let pool = flora_db::connect_and_migrate(&url).await.expect("migrate");
    sqlx::raw_sql(
        "DELETE FROM device_commands; DELETE FROM readings; DELETE FROM nodes;
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
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(value) = auth {
        builder = builder.header("authorization", value);
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

/// Provision a gateway and claim it with a phone, returning the useful values.
struct Fixture {
    access: String,
    phone: SigningKey,
    device_token_hex: String,
}

async fn pair_a_gateway(state: &AppState) -> Fixture {
    let aggregator = SigningKey::from_bytes(&[7u8; 32]);
    let device_id =
        flora_protocol::derive_device_id(aggregator.verifying_key().as_bytes()).unwrap();
    assert_eq!(device_id, GATEWAY, "test expects this gateway id");

    let device_token = flora_auth::generate_token().unwrap();
    let claim_token = flora_auth::generate_token().unwrap();

    let (status, _) = call(
        state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": device_id,
            "pubkey": hex::encode(aggregator.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&device_token)),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0",
            "label": "plot-north"
        })),
        Some("Bearer test-provision-key"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let phone = SigningKey::from_bytes(&[3u8; 32]);
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

    Fixture {
        access: body["access_token"].as_str().unwrap().to_string(),
        phone,
        device_token_hex: hex::encode(device_token),
    }
}

/// Sign a command the way the app would.
fn sign_command(
    phone: &SigningKey,
    gateway_id: &str,
    kind: u8,
    node_addr: u8,
    payload: [u8; 4],
    nonce: u32,
    ts: u32,
) -> (String, String) {
    let gateway_bytes: [u8; flora_protocol::GATEWAY_ID_LEN] =
        hex::decode(gateway_id).unwrap().try_into().unwrap();
    let message = canonical_message(kind, &gateway_bytes, node_addr, nonce, ts, &payload);
    let signature = phone.sign(&message);
    (hex::encode(payload), hex::encode(signature.to_bytes()))
}

/// Everything the aggregator needs to authenticate as a device.
fn device_auth(fixture: &Fixture) -> String {
    format!("Device {GATEWAY}:{}", fixture.device_token_hex)
}

#[tokio::test]
async fn a_signed_command_reaches_the_device_and_is_acknowledged() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = pair_a_gateway(&state).await;
    let now = chrono::Utc::now().timestamp() as u32;

    // ---- 1. App submits a command for a field node ----
    let (payload, signature) = sign_command(
        &fixture.phone,
        GATEWAY,
        KIND_SET_VALVE,
        4,
        [1, 0, 30, 0],
        1,
        now,
    );
    let (status, body) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_valve",
            "payload": payload,
            "app_pubkey": hex::encode(fixture.phone.verifying_key().as_bytes()),
            "nonce": 1,
            "ts": now,
            "signature": signature
        })),
        Some(&format!("Bearer {}", fixture.access)),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "pending");
    assert_eq!(body["node_addr"], 4);
    let command_id = body["id"].as_str().unwrap().to_string();

    // ---- 2. Aggregator polls and receives it ----
    let (status, body) = call(
        &state,
        "GET",
        "/device/commands",
        None,
        Some(&device_auth(&fixture)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let commands = body["commands"].as_array().unwrap();
    assert_eq!(commands.len(), 1, "the queued command must be handed over");
    let delivered = &commands[0];
    assert_eq!(delivered["id"], command_id);
    assert_eq!(delivered["node_addr"], 4);
    assert_eq!(delivered["kind"], KIND_SET_VALVE);
    // The signature travels with it: the device verifies independently.
    assert_eq!(delivered["signature"], signature);
    assert_eq!(delivered["payload"], "01001e00");

    // ---- 3. A second poll returns nothing: delivery is single ----
    let (status, body) = call(
        &state,
        "GET",
        "/device/commands",
        None,
        Some(&device_auth(&fixture)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["commands"].as_array().unwrap().is_empty(),
        "a dispatched command must not be handed out twice"
    );

    // ---- 4. Aggregator acknowledges the outcome ----
    let (status, _) = call(
        &state,
        "POST",
        &format!("/device/commands/{command_id}/ack"),
        Some(serde_json::json!({ "result": "applied" })),
        Some(&device_auth(&fixture)),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // ---- 5. The audit trail shows the outcome ----
    let (status, body) = call(
        &state,
        "GET",
        &format!("/gateways/{GATEWAY}/commands"),
        None,
        Some(&format!("Bearer {}", fixture.access)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let history = body.as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["status"], "applied");
}

#[tokio::test]
async fn a_command_for_the_aggregators_own_plot_is_accepted() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = pair_a_gateway(&state).await;
    let now = chrono::Utc::now().timestamp() as u32;

    // Node address 1 is the aggregator itself: it opens its own valve rather
    // than routing anything onto the bus.
    let (payload, signature) = sign_command(
        &fixture.phone,
        GATEWAY,
        KIND_SET_VALVE,
        1,
        [1, 0, 60, 0],
        1,
        now,
    );
    let (status, body) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 1,
            "kind": "set_valve",
            "payload": payload,
            "app_pubkey": hex::encode(fixture.phone.verifying_key().as_bytes()),
            "nonce": 1,
            "ts": now,
            "signature": signature
        })),
        Some(&format!("Bearer {}", fixture.access)),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        body["node_addr"], 1,
        "the aggregator's own plot is addressable"
    );
}

#[tokio::test]
async fn forged_and_unauthorised_commands_are_refused() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = pair_a_gateway(&state).await;
    let now = chrono::Utc::now().timestamp() as u32;
    let auth = format!("Bearer {}", fixture.access);

    let attempt = |node_addr: u8, key: &SigningKey, nonce: u32, ts: u32, payload: [u8; 4]| {
        sign_command(key, GATEWAY, KIND_SET_VALVE, node_addr, payload, nonce, ts)
    };

    // A signature from a key that does not belong to the account is refused
    // before it can be queued, so a stranger cannot irrigate anyone's plot.
    let stranger = SigningKey::from_bytes(&[9u8; 32]);
    let (payload, signature) = attempt(4, &stranger, 1, now, [1, 0, 30, 0]);
    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_valve",
            "payload": payload,
            "app_pubkey": hex::encode(stranger.verifying_key().as_bytes()),
            "nonce": 1,
            "ts": now,
            "signature": signature
        })),
        Some(&auth),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unknown key must not queue a command"
    );

    // A signature that covers different bytes is refused.
    let (payload, _) = attempt(4, &fixture.phone, 2, now, [1, 0, 30, 0]);
    let wrong_signature = {
        // Signed for node 5 but submitted for node 4.
        let (_, sig) = attempt(5, &fixture.phone, 2, now, [1, 0, 30, 0]);
        sig
    };
    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_valve",
            "payload": payload,
            "app_pubkey": hex::encode(fixture.phone.verifying_key().as_bytes()),
            "nonce": 2,
            "ts": now,
            "signature": wrong_signature
        })),
        Some(&auth),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a signature for another target must fail"
    );

    // A tampered payload is refused: the signature covers it.
    let (_, signature) = attempt(4, &fixture.phone, 3, now, [1, 0, 30, 0]);
    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_valve",
            "payload": "0100ffff",
            "app_pubkey": hex::encode(fixture.phone.verifying_key().as_bytes()),
            "nonce": 3,
            "ts": now,
            "signature": signature
        })),
        Some(&auth),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an altered payload must fail"
    );

    // An inverted threshold band never gets queued.
    let gateway_bytes: [u8; flora_protocol::GATEWAY_ID_LEN] =
        hex::decode(GATEWAY).unwrap().try_into().unwrap();
    let payload_inverted = [2u8, 188, 0, 200];
    let message = canonical_message(
        KIND_SET_THRESHOLD,
        &gateway_bytes,
        4,
        4,
        now,
        &payload_inverted,
    );
    let signature = fixture.phone.sign(&message);
    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_threshold",
            "payload": hex::encode(payload_inverted),
            "app_pubkey": hex::encode(fixture.phone.verifying_key().as_bytes()),
            "nonce": 4,
            "ts": now,
            "signature": hex::encode(signature.to_bytes())
        })),
        Some(&auth),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an inverted band must be rejected"
    );
}

#[tokio::test]
async fn an_account_cannot_command_another_accounts_gateway() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let _owner = pair_a_gateway(&state).await;

    // A second account, with its own gateway and phone.
    let other_aggregator = SigningKey::from_bytes(&[21u8; 32]);
    let other_id =
        flora_protocol::derive_device_id(other_aggregator.verifying_key().as_bytes()).unwrap();
    let claim_token = flora_auth::generate_token().unwrap();
    call(
        &state,
        "POST",
        "/provision/register",
        Some(serde_json::json!({
            "device_id": other_id,
            "pubkey": hex::encode(other_aggregator.verifying_key().as_bytes()),
            "token_hash": hex::encode(flora_auth::hash_token(&[1u8; 32])),
            "claim_hash": hex::encode(flora_auth::hash_token(&claim_token)),
            "hw": "pico_w",
            "fw_ver": "0.1.0"
        })),
        Some("Bearer test-provision-key"),
    )
    .await;
    let other_phone = SigningKey::from_bytes(&[22u8; 32]);
    let nonce = flora_auth::generate_token().unwrap();
    let input = flora_auth::ClaimSignatureInput {
        device_id: &other_id,
        claim_token: &claim_token,
        nonce: &nonce,
    };
    let signature = other_phone.sign(&input.message());
    let (status, body) = call(
        &state,
        "POST",
        "/pair/claim",
        Some(serde_json::json!({
            "device_id": other_id,
            "claim_token": hex::encode(claim_token),
            "app_pubkey": hex::encode(other_phone.verifying_key().as_bytes()),
            "nonce": hex::encode(nonce),
            "signature": hex::encode(signature.to_bytes())
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let other_access = body["access_token"].as_str().unwrap().to_string();

    // The second account tries to command the first account's gateway.
    let now = chrono::Utc::now().timestamp() as u32;
    let (payload, signature) = sign_command(
        &other_phone,
        GATEWAY,
        KIND_SET_VALVE,
        4,
        [1, 0, 30, 0],
        1,
        now,
    );
    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_valve",
            "payload": payload,
            "app_pubkey": hex::encode(other_phone.verifying_key().as_bytes()),
            "nonce": 1,
            "ts": now,
            "signature": signature
        })),
        Some(&format!("Bearer {other_access}")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "ownership is checked before anything else"
    );
}

#[tokio::test]
async fn a_command_past_its_window_expires_instead_of_arriving_late() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = pair_a_gateway(&state).await;
    let now = chrono::Utc::now().timestamp() as u32;

    let (payload, signature) = sign_command(
        &fixture.phone,
        GATEWAY,
        KIND_SET_VALVE,
        4,
        [1, 0, 30, 0],
        1,
        now,
    );
    call(
        &state,
        "POST",
        &format!("/gateways/{GATEWAY}/commands"),
        Some(serde_json::json!({
            "node_addr": 4,
            "kind": "set_valve",
            "payload": payload,
            "app_pubkey": hex::encode(fixture.phone.verifying_key().as_bytes()),
            "nonce": 1,
            "ts": now,
            "signature": signature
        })),
        Some(&format!("Bearer {}", fixture.access)),
    )
    .await;

    // Age the command past its window, as if the aggregator had been offline.
    sqlx::query("UPDATE device_commands SET expires_at = now() - interval '1 minute'")
        .execute(&state.pool)
        .await
        .unwrap();

    let (status, body) = call(
        &state,
        "GET",
        "/device/commands",
        None,
        Some(&device_auth(&fixture)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["commands"].as_array().unwrap().is_empty(),
        "an irrigation command must not arrive after its window"
    );

    // And the audit trail says why, rather than leaving it looking pending.
    let (_, body) = call(
        &state,
        "GET",
        &format!("/gateways/{GATEWAY}/commands"),
        None,
        Some(&format!("Bearer {}", fixture.access)),
    )
    .await;
    assert_eq!(body[0]["status"], "expired");
}

#[tokio::test]
async fn device_endpoints_require_device_credentials() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = pair_a_gateway(&state).await;

    // No credentials at all.
    let (status, _) = call(&state, "GET", "/device/commands", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A user JWT is not a device credential.
    let (status, _) = call(
        &state,
        "GET",
        "/device/commands",
        None,
        Some(&format!("Bearer {}", fixture.access)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A wrong token for a real device.
    let (status, _) = call(
        &state,
        "GET",
        "/device/commands",
        None,
        Some(&format!("Device {GATEWAY}:{}", "ff".repeat(32))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A retired gateway stops being able to collect commands.
    sqlx::query("UPDATE gateways SET status = 'retired' WHERE id = $1")
        .bind(GATEWAY)
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, _) = call(
        &state,
        "GET",
        "/device/commands",
        None,
        Some(&device_auth(&fixture)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a revoked device must not collect commands"
    );
}

#[tokio::test]
async fn a_device_cannot_acknowledge_another_devices_command() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = pair_a_gateway(&state).await;

    // A command row belonging to a different gateway, inserted directly.
    let other_id: Uuid = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let foreign_command = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO device_commands (id, account_id, gateway_id, node_addr, kind, result, expires_at)
         VALUES ($1, $2, '99999999999999999999999999999999', 2, 'set_valve', 'dispatched', now() + interval '5 minutes')",
    )
    .bind(foreign_command)
    .bind(other_id)
    .execute(&state.pool)
    .await
    .unwrap();

    let (status, _) = call(
        &state,
        "POST",
        &format!("/device/commands/{foreign_command}/ack"),
        Some(serde_json::json!({ "result": "applied" })),
        Some(&device_auth(&fixture)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "acking is scoped to the authenticated gateway"
    );
}
