//! Postgres access, connection setup, and automatic migrations.
//!
//! Migrations run on every boot. A fresh machine and a fresh database
//! therefore come up working with no manual step, which is what makes a
//! single deployment target viable across Render, Layerbase, or a local
//! container.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use thiserror::Error;

pub mod models;
pub mod queries;

/// Embedded migrations, compiled into the binary.
///
/// The directory lives inside the crate, not at the repository root: the
/// Docker build copies only `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
/// and `crates/`, and `sqlx::migrate!` resolves its path against the crate
/// manifest dir at compile time. An out-of-crate path (`../../migrations`)
/// points outside everything the image build copies and fails there, though
/// it compiles fine on a full checkout. The `./` prefix is required: sqlx
/// rejects bare single-component relative paths.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database connection failed: {0}")]
    Connect(#[from] sqlx::Error),
    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("DATABASE_URL is not set")]
    MissingUrl,
}

/// How long to wait for a pooled connection before giving up.
///
/// A hibernated database (Layerbase free tier, or a stopped container)
/// can take several seconds to wake, so this is deliberately longer
/// than the usual default. Waking is transparent to the caller: the
/// first connection simply takes longer.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect and bring the schema up to date.
///
/// Safe to call on every boot: `sqlx` records applied migrations and
/// skips the rest. Also safe against two instances starting at once,
/// because sqlx takes an advisory lock while migrating.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool, DbError> {
    let pool = connect(database_url).await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

/// Create a pool without touching the schema.
pub async fn connect(database_url: &str) -> Result<PgPool, DbError> {
    if database_url.trim().is_empty() {
        return Err(DbError::MissingUrl);
    }

    let options: PgConnectOptions = database_url.parse().map_err(DbError::Connect)?;
    // Keep TLS as the URL specifies. Layerbase requires `sslmode=require`;
    // the `tls-rustls-ring-webpki` backend in the workspace dependency
    // supplies the trust roots, so no system trust store is needed on a
    // slim build image.
    let options = options
        .log_statements(tracing::log::LevelFilter::Trace)
        .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_millis(500));

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .min_connections(0)
        // Idle connections are dropped so a hibernating database is
        // allowed to sleep rather than being held awake by our own pool.
        .idle_timeout(Some(Duration::from_secs(300)))
        .acquire_timeout(ACQUIRE_TIMEOUT)
        // Recycle before the platform does, so a wake-up is handled by
        // the pool rather than surfacing as a statement error.
        .max_lifetime(Some(Duration::from_secs(1_800)))
        .test_before_acquire(true)
        .connect_with(options)
        .await
        .map_err(DbError::Connect)?;

    Ok(pool)
}

/// Run migrations against an existing pool.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migrations_are_present_and_ordered() {
        let migrations: Vec<_> = MIGRATOR.iter().collect();
        assert!(
            !migrations.is_empty(),
            "at least one migration must be embedded"
        );
        // sqlx sorts by version; confirm the first migration is our schema.
        let first = migrations.first().unwrap();
        assert_eq!(first.version, 1);
        assert!(first.description.contains("init"), "{}", first.description);
    }

    #[tokio::test]
    async fn missing_url_is_a_clear_error() {
        assert!(matches!(connect("").await, Err(DbError::MissingUrl)));
        assert!(matches!(connect("   ").await, Err(DbError::MissingUrl)));
    }

    #[tokio::test]
    async fn malformed_url_is_rejected_before_connecting() {
        assert!(matches!(
            connect("not-a-url").await,
            Err(DbError::Connect(_))
        ));
    }
}
