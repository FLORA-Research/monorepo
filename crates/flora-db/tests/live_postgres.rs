//! Integration tests against a real Postgres.
//!
//! They exercise the actual schema: constraints, upserts, and the
//! atomic claim-token consume. A mock cannot catch a wrong CHECK
//! constraint or a missing index, and this is the layer where those
//! live.
//!
//! Skipped when `TEST_DATABASE_URL` is unset, so `cargo test` works on
//! a machine with no database. CI sets the variable and fails the job if
//! these were skipped (see rust.yml).

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use flora_db::{connect_and_migrate, queries};

async fn pool() -> PgPool {
    let url = match std::env::var("TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("TEST_DATABASE_URL unset; skipping");
            std::process::exit(0);
        }
    };
    connect_and_migrate(&url)
        .await
        .expect("connect and migrate")
}

/// Insert an account and gateway row the test can reference. The key
/// is randomised per call so tests that run in parallel cannot collide
/// on the unique `owner_pubkey` constraint.
async fn seed_gateway(pool: &PgPool) -> (Uuid, String) {
    let account_id = Uuid::new_v4();
    let mut owner_key = [0u8; 32];
    owner_key[..16].copy_from_slice(&account_id.as_u128().to_le_bytes());
    sqlx::query("INSERT INTO accounts (id, owner_pubkey) VALUES ($1, $2)")
        .bind(account_id)
        .bind(owner_key.to_vec())
        .execute(pool)
        .await
        .expect("seed account");
    let gateway_id = format!("{:032x}", account_id.as_u128() & 0xFFFF_FFFF);
    sqlx::query(
        "INSERT INTO gateways (id, account_id, pubkey, status) VALUES ($1, $2, $3, 'claimed')",
    )
    .bind(&gateway_id)
    .bind(account_id)
    .bind(vec![0x22u8; 32])
    .execute(pool)
    .await
    .expect("seed gateway");
    (account_id, gateway_id)
}
#[tokio::test]
async fn migrations_create_the_expected_schema() {
    let pool = pool().await;
    // A too-short key violates the length CHECK: the constraint this
    // codebase relies on is present and enforced.
    let short = sqlx::query("INSERT INTO accounts (owner_pubkey) VALUES ($1)")
        .bind(vec![1u8; 16])
        .execute(&pool)
        .await;
    assert!(short.is_err(), "pubkey length must be constrained");
}

#[tokio::test]
async fn account_lookup_round_trips() {
    let pool = pool().await;
    let (account_id, _) = seed_gateway(&pool).await;
    // The seed key is derived from the account id, so the lookup proves
    // the exact row that was inserted is the one found.
    let mut seeded_key = [0u8; 32];
    seeded_key[..16].copy_from_slice(&account_id.as_u128().to_le_bytes());
    let account = queries::account_by_pubkey(&pool, &seeded_key)
        .await
        .expect("query")
        .expect("seeded account is found");
    assert_eq!(account.id, account_id);
    assert!(
        queries::account_by_pubkey(&pool, &[0x99u8; 32])
            .await
            .expect("query")
            .is_none(),
        "unknown key finds nothing"
    );
}

#[tokio::test]
async fn claim_token_upsert_replaces_and_consume_is_atomic() {
    let pool = pool().await;
    let (_, gateway_id) = seed_gateway(&pool).await;
    let now = Utc::now();

    queries::upsert_claim_token(&pool, &gateway_id, &[1u8; 32], now + Duration::hours(1))
        .await
        .expect("upsert");
    // A re-issued token replaces the first and resets used_at.
    queries::upsert_claim_token(&pool, &gateway_id, &[2u8; 32], now + Duration::hours(1))
        .await
        .expect("re-upsert");

    // The superseded token no longer matches.
    assert!(
        queries::consume_claim_token(&pool, &gateway_id, &[1u8; 32], now)
            .await
            .expect("consume")
            .is_none()
    );
    // The current token consumes exactly once.
    assert_eq!(
        queries::consume_claim_token(&pool, &gateway_id, &[2u8; 32], now)
            .await
            .expect("consume"),
        Some(gateway_id.clone())
    );
    assert!(
        queries::consume_claim_token(&pool, &gateway_id, &[2u8; 32], now)
            .await
            .expect("replay")
            .is_none(),
        "a consumed token must not be reusable"
    );
}

#[tokio::test]
async fn an_expired_claim_token_is_refused() {
    let pool = pool().await;
    let (_, gateway_id) = seed_gateway(&pool).await;
    let now = Utc::now();
    queries::upsert_claim_token(&pool, &gateway_id, &[3u8; 32], now - Duration::seconds(1))
        .await
        .expect("upsert");
    assert!(
        queries::consume_claim_token(&pool, &gateway_id, &[3u8; 32], now)
            .await
            .expect("consume")
            .is_none(),
        "expiry is enforced inside the UPDATE"
    );
}
#[tokio::test]
async fn nonces_are_unique_and_prunable() {
    let pool = pool().await;
    let now = Utc::now();
    // A fresh nonce per run: the table is shared with previous test runs,
    // and the first assertion must observe a genuine insert.
    let nonce = Uuid::new_v4().as_u128().to_be_bytes();
    queries::prune_nonces(&pool, now).await.expect("prune");

    assert!(
        queries::record_nonce(&pool, &nonce, "auth", now + Duration::minutes(5))
            .await
            .expect("record")
    );
    assert!(
        !queries::record_nonce(&pool, &nonce, "auth", now + Duration::minutes(5))
            .await
            .expect("record"),
        "the same nonce is a replay"
    );
    // A different scope does not bypass uniqueness: one nonce, one use.
    assert!(
        !queries::record_nonce(&pool, &nonce, "pair", now + Duration::minutes(5))
            .await
            .expect("record"),
        "scope must not widen a nonce's use"
    );

    // Pruning removes expired rows so the next use of the nonce is
    // fresh again — the replay window is bounded, not permanent.
    queries::prune_nonces(&pool, now + Duration::minutes(6))
        .await
        .expect("prune");
    assert!(
        queries::record_nonce(&pool, &nonce, "auth", now + Duration::minutes(30))
            .await
            .expect("record")
    );
}

#[tokio::test]
async fn gateway_lookup_and_ownership() {
    let pool = pool().await;
    let (account_id, gateway_id) = seed_gateway(&pool).await;
    let gateway = queries::gateway_by_id(&pool, &gateway_id)
        .await
        .expect("query")
        .expect("seeded gateway");
    assert!(gateway.is_claimed());
    assert!(gateway.owned_by(account_id));
    assert!(!gateway.owned_by(Uuid::new_v4()));

    let listed = queries::gateways_for_account(&pool, account_id)
        .await
        .expect("query");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, gateway_id);
}

#[tokio::test]
async fn readings_reject_invalid_valve_states_and_duplicate_rows() {
    let pool = pool().await;
    let (_, gateway_id) = seed_gateway(&pool).await;
    let ts = Utc::now();

    // The CHECK constraint is part of the data contract.
    let bad = sqlx::query(
        "INSERT INTO readings (ts, gateway_id, node_uuid, valve_state)
         VALUES ($1, $2, $3, 7)",
    )
    .bind(ts)
    .bind(&gateway_id)
    .bind(vec![2u8; 8])
    .execute(&pool)
    .await;
    assert!(bad.is_err(), "valve_state must be constrained");

    sqlx::query(
        "INSERT INTO readings (ts, gateway_id, node_uuid, moisture)
         VALUES ($1, $2, $3, 31.2)",
    )
    .bind(ts)
    .bind(&gateway_id)
    .bind(vec![2u8; 8])
    .execute(&pool)
    .await
    .expect("insert");

    let duplicate = sqlx::query(
        "INSERT INTO readings (ts, gateway_id, node_uuid, humidity)
         VALUES ($1, $2, $3, 71.0)
         ON CONFLICT (ts, gateway_id, node_uuid) DO NOTHING",
    )
    .bind(ts)
    .bind(&gateway_id)
    .bind(vec![2u8; 8])
    .execute(&pool)
    .await
    .expect("idempotent insert");
    assert_eq!(duplicate.rows_affected(), 0, "retries must not duplicate");
}
