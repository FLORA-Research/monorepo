//! Reference measurements feeding the MAE report.
//!
//! Skipped unless `TEST_DATABASE_URL` is set.
//!
//! The report path existed before the writer, so every MAE came back null and
//! nothing noticed: a null MAE is indistinguishable from a perfect one at a
//! glance. These tests pin the whole chain, because the failure mode of the
//! missing half was silence rather than an error.

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

/// Derive the gateway id from a public key, as the v2 protocol defines it.
fn derive_device_id(pubkey: &[u8]) -> String {
    hex::encode(flora_protocol::device_id_bytes(pubkey).unwrap())
}

static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn state() -> AppState {
    let url = database_url().expect("checked by caller");
    let pool = flora_db::connect_and_migrate(&url).await.expect("migrate");
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

/// A claimed gateway plus the access token and device credential for it.
struct Fixture {
    device_id: String,
    access: String,
    device_auth: String,
}

/// Provision, claim, and return the credentials needed to ingest and to read.
///
/// The seed keeps each test on its own key, so a device id collision cannot
/// make two tests interfere.
async fn claimed_gateway(state: &AppState, seed: u8) -> Fixture {
    let aggregator = SigningKey::from_bytes(&[seed; 32]);
    let device_id = derive_device_id(aggregator.verifying_key().as_bytes());
    let device_token = flora_auth::generate_token().unwrap();
    let claim_token = flora_auth::generate_token().unwrap();

    let (status, body) = call(
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
            "label": "plot-mae"
        })),
        Some("test-provision-key"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");

    let phone = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
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
    assert_eq!(status, StatusCode::CREATED, "claim: {body}");

    Fixture {
        access: body["access_token"].as_str().unwrap().to_string(),
        device_auth: format!("Device {device_id}:{}", hex::encode(device_token)),
        device_id,
    }
}

/// Push one node's telemetry at a given timestamp.
async fn ingest(
    state: &AppState,
    fixture: &Fixture,
    ts: i64,
    uuid: &str,
    moist: u16,
    temp: i16,
    hum: u16,
) {
    let batch = serde_json::json!({
        "gw_id": fixture.device_id,
        "ts": ts,
        "nodes": [
            {"uuid": uuid, "addr": 2, "moist": moist, "temp": temp, "hum": hum,
             "valve": 0, "seq": 7, "fw_ver": 256}
        ]
    });
    let request = Request::builder()
        .method("POST")
        .uri("/ingest/batch")
        .header("authorization", &fixture.device_auth)
        .header("content-type", "application/json")
        .body(Body::from(batch.to_string()))
        .unwrap();
    let response = router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "ingest: {}",
        String::from_utf8_lossy(&body)
    );
}

fn mae_for<'a>(body: &'a serde_json::Value, suffix: &str) -> &'a serde_json::Value {
    body["gateways"]
        .as_array()
        .expect("gateways array")
        .iter()
        .find(|entry| {
            entry["metric"]
                .as_str()
                .is_some_and(|metric| metric.ends_with(suffix))
        })
        .unwrap_or_else(|| panic!("no metric ending in {suffix}: {body}"))
}

#[tokio::test]
async fn reference_measurements_produce_a_non_null_mae() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping MAE test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = claimed_gateway(&state, 61).await;

    // Sensor says 31.0 percent; the meter says 30.0. Moisture is stored in
    // tenths of a percent, so 312 deci-percent is 31.2 percent.
    let now = chrono::Utc::now();
    let ts = now.timestamp();
    ingest(&state, &fixture, ts, "0202020202020202", 312, 284, 710).await;

    // A reference within the tolerance window of the reading.
    let (status, body) = call(
        &state,
        "POST",
        &format!("/gateways/{}/reference", fixture.device_id),
        Some(serde_json::json!({
            "ts": now.to_rfc3339(),
            "node_uuid": "0202020202020202",
            "moisture_ref": 30.0,
            "method": "oven-dry"
        })),
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "inserted");

    // The report must now carry a real number, not null.
    let (status, body) = call(
        &state,
        "GET",
        "/account/reports/mae",
        None,
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let moisture = mae_for(&body, ":moisture");
    assert!(
        !moisture["mae"].is_null(),
        "a stored reference must yield a non-null MAE: {body}"
    );
    assert_eq!(
        moisture["samples"], 1,
        "the reference must pair with the reading: {body}"
    );

    // |31.2 - 30.0| = 1.2 percent. The pairing tolerance is on time, not value,
    // so the whole gap counts.
    let mae = moisture["mae"].as_f64().expect("numeric mae");
    assert!(
        (mae - 1.2).abs() < 0.05,
        "expected an MAE near 1.2, got {mae}: {body}"
    );

    // Metrics with no reference stay null rather than reporting zero, which
    // would read as a perfect match.
    assert!(
        mae_for(&body, ":temperature")["mae"].is_null(),
        "unmeasured metrics must stay null: {body}"
    );
}

#[tokio::test]
async fn a_reference_outside_the_window_does_not_pair() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping window test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = claimed_gateway(&state, 71).await;

    let now = chrono::Utc::now();
    ingest(
        &state,
        &fixture,
        now.timestamp(),
        "0202020202020202",
        312,
        284,
        710,
    )
    .await;

    // Half an hour later, well outside the five-minute tolerance.
    let late = now + chrono::Duration::minutes(30);
    let (status, body) = call(
        &state,
        "POST",
        &format!("/gateways/{}/reference", fixture.device_id),
        Some(serde_json::json!({
            "ts": late.to_rfc3339(),
            "node_uuid": "0202020202020202",
            "moisture_ref": 30.0
        })),
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (_, body) = call(
        &state,
        "GET",
        "/account/reports/mae",
        None,
        Some(&fixture.access),
    )
    .await;
    let moisture = mae_for(&body, ":moisture");
    assert_eq!(
        moisture["samples"], 0,
        "a reference outside the window must not pair: {body}"
    );
    assert!(
        moisture["mae"].is_null(),
        "no pairs means no MAE, not zero: {body}"
    );
}

#[tokio::test]
async fn resubmitting_a_reference_corrects_it_in_place() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping upsert test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = claimed_gateway(&state, 81).await;

    let now = chrono::Utc::now();
    ingest(
        &state,
        &fixture,
        now.timestamp(),
        "0202020202020202",
        312,
        284,
        710,
    )
    .await;

    let reference = |value: f32| {
        serde_json::json!({
            "ts": now.to_rfc3339(),
            "node_uuid": "0202020202020202",
            "moisture_ref": value
        })
    };

    let path = format!("/gateways/{}/reference", fixture.device_id);
    let (status, body) = call(
        &state,
        "POST",
        &path,
        Some(reference(99.0)),
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "inserted");

    // A transcription error is corrected by sending the same instant again.
    let (status, body) = call(
        &state,
        "POST",
        &path,
        Some(reference(30.0)),
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["status"], "replaced",
        "same key must replace, not duplicate"
    );

    let (_, body) = call(
        &state,
        "GET",
        "/account/reports/mae",
        None,
        Some(&fixture.access),
    )
    .await;
    let moisture = mae_for(&body, ":moisture");
    assert_eq!(
        moisture["samples"], 1,
        "a correction must leave exactly one reference: {body}"
    );
    let mae = moisture["mae"].as_f64().expect("numeric mae");
    assert!(
        (mae - 1.2).abs() < 0.05,
        "the corrected value must be the one measured, got {mae}: {body}"
    );
}

#[tokio::test]
async fn a_reference_that_measured_nothing_is_refused() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping empty reference test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let fixture = claimed_gateway(&state, 91).await;

    let (status, body) = call(
        &state,
        "POST",
        &format!("/gateways/{}/reference", fixture.device_id),
        Some(serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "node_uuid": "0202020202020202"
        })),
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A malformed uuid is rejected before it reaches the database.
    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{}/reference", fixture.device_id),
        Some(serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "node_uuid": "0202",
            "moisture_ref": 30.0
        })),
        Some(&fixture.access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn another_account_cannot_write_a_reference() {
    let Some(_) = database_url() else {
        eprintln!("TEST_DATABASE_URL unset; skipping ownership test");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let state = state().await;
    let owner = claimed_gateway(&state, 101).await;
    let stranger = claimed_gateway(&state, 111).await;

    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{}/reference", owner.device_id),
        Some(serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "node_uuid": "0202020202020202",
            "moisture_ref": 30.0
        })),
        Some(&stranger.access),
    )
    .await;
    // Not-found rather than forbidden: the API does not confirm that someone
    // else's device id exists.
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(
        &state,
        "POST",
        &format!("/gateways/{}/reference", owner.device_id),
        Some(serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "node_uuid": "0202020202020202",
            "moisture_ref": 30.0
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no token must not write");
}
