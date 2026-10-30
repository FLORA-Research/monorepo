//! FLORA cloud server: configuration, wiring, and startup.
//!
//! Startup order matters. The schema is brought up to date before the listener
//! opens, so a freshly provisioned machine and database pair come up working
//! with no manual migration step and no window where the API serves against a
//! schema it does not expect.

use anyhow::{Context, Result};
use flora_api::{AppState, router};
use std::net::SocketAddr;
use std::time::Duration;

/// Load configuration from the environment, falling back to `.env` locally.
///
/// Render and Layerbase both inject real environment variables; `.env` exists so
/// the same binary runs unchanged on a workstation.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub jwt_secret: Vec<u8>,
    pub provision_key_hash: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .context("DATABASE_URL is required (set it in the environment or .env)")?;

        // Render supplies PORT and expects the server on 0.0.0.0.
        let bind_addr =
            std::env::var("BIND_ADDR").unwrap_or_else(|_| match std::env::var("PORT") {
                Ok(port) => format!("0.0.0.0:{port}"),
                Err(_) => "127.0.0.1:8080".to_string(),
            });

        let jwt_secret = std::env::var("JWT_SECRET")
            .context("JWT_SECRET is required")?
            .into_bytes();
        if jwt_secret.len() < 32 {
            anyhow::bail!("JWT_SECRET must be at least 32 bytes");
        }

        // Optional so the API can run before provisioning is set up. When it is
        // absent the /provision/* routes refuse every caller rather than
        // allowing them: an unset secret must never mean "open".
        let provision_key_hash = std::env::var("PROVISION_API_KEY_HASH")
            .ok()
            .filter(|v| !v.is_empty());

        Ok(Self {
            database_url,
            bind_addr,
            jwt_secret,
            provision_key_hash,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // `.env` is optional; a deployed environment has real variables.
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "flora_server=info,tower_http=info,sqlx=warn".into()),
        )
        .init();

    let config = Config::from_env()?;

    if config.provision_key_hash.is_none() {
        tracing::warn!("PROVISION_API_KEY_HASH is unset; /provision/* will refuse all requests");
    }

    // Connect with retries: a hibernating database takes a few seconds to wake,
    // and failing the whole deploy because of that would be wrong.
    let pool = connect_with_retry(&config.database_url).await?;
    tracing::info!("database ready and migrations applied");

    let state = AppState::new(pool, config.jwt_secret, config.provision_key_hash);
    let app = router(state);

    let addr: SocketAddr = config.bind_addr.parse().with_context(|| {
        format!(
            "BIND_ADDR is not a valid socket address: {}",
            config.bind_addr
        )
    })?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

/// Connect and migrate, retrying a transient failure.
///
/// A cold database can refuse the first connections while it resumes, so this
/// distinguishes "not ready yet" from "misconfigured" by giving up only after
/// the retry budget is spent.
async fn connect_with_retry(database_url: &str) -> Result<sqlx::PgPool> {
    const ATTEMPTS: u32 = 5;
    let mut last_error = None;
    for attempt in 1..=ATTEMPTS {
        match flora_db::connect_and_migrate(database_url).await {
            Ok(pool) => return Ok(pool),
            Err(error) => {
                tracing::warn!(attempt, %error, "database not ready; retrying");
                last_error = Some(error);
                tokio::time::sleep(Duration::from_secs(2 * u64::from(attempt))).await;
            }
        }
    }
    Err(anyhow::anyhow!(
        "could not reach the database after {ATTEMPTS} attempts: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_default()
    ))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests manipulate process environment variables, which are global,
    /// so they are serialised through one lock.
    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn clear() {
        for key in [
            "DATABASE_URL",
            "JWT_SECRET",
            "BIND_ADDR",
            "PORT",
            "PROVISION_API_KEY_HASH",
        ] {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn missing_database_url_is_reported_clearly() {
        let _guard = ENV_LOCK.lock();
        clear();
        unsafe { std::env::set_var("JWT_SECRET", "x".repeat(40)) };
        let error = Config::from_env().unwrap_err().to_string();
        assert!(error.contains("DATABASE_URL"), "{error}");
        clear();
    }

    #[test]
    fn short_jwt_secret_is_rejected() {
        let _guard = ENV_LOCK.lock();
        clear();
        unsafe {
            std::env::set_var("DATABASE_URL", "postgres://example/db");
            std::env::set_var("JWT_SECRET", "too-short");
        }
        let error = Config::from_env().unwrap_err().to_string();
        assert!(error.contains("JWT_SECRET"), "{error}");
        clear();
    }

    #[test]
    fn render_port_variable_drives_the_bind_address() {
        let _guard = ENV_LOCK.lock();
        clear();
        unsafe {
            std::env::set_var("DATABASE_URL", "postgres://example/db");
            std::env::set_var("JWT_SECRET", "x".repeat(40));
            std::env::set_var("PORT", "10000");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(
            config.bind_addr, "0.0.0.0:10000",
            "Render requires binding 0.0.0.0 on the injected port"
        );
        clear();
    }

    #[test]
    fn explicit_bind_address_wins_over_port() {
        let _guard = ENV_LOCK.lock();
        clear();
        unsafe {
            std::env::set_var("DATABASE_URL", "postgres://example/db");
            std::env::set_var("JWT_SECRET", "x".repeat(40));
            std::env::set_var("PORT", "10000");
            std::env::set_var("BIND_ADDR", "127.0.0.1:9999");
        }
        assert_eq!(Config::from_env().unwrap().bind_addr, "127.0.0.1:9999");
        clear();
    }

    #[test]
    fn unset_provision_key_stays_unset_rather_than_empty() {
        let _guard = ENV_LOCK.lock();
        clear();
        unsafe {
            std::env::set_var("DATABASE_URL", "postgres://example/db");
            std::env::set_var("JWT_SECRET", "x".repeat(40));
        }
        assert!(Config::from_env().unwrap().provision_key_hash.is_none());

        unsafe { std::env::set_var("PROVISION_API_KEY_HASH", "") };
        assert!(
            Config::from_env().unwrap().provision_key_hash.is_none(),
            "an empty value must not enable provisioning"
        );
        clear();
    }
}
