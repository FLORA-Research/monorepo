//! Row types returned by the database layer.
//!
//! These are deliberately separate from API DTOs: the wire shape is a
//! product decision, while these mirror columns. Keeping them apart
//! means a schema rename does not silently change an API response.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct Account {
    pub id: Uuid,
    pub owner_pubkey: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AppDevice {
    pub id: Uuid,
    pub account_id: Uuid,
    pub pubkey: Vec<u8>,
    pub label: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Gateway {
    pub id: String,
    pub account_id: Option<Uuid>,
    pub pubkey: Vec<u8>,
    pub label: Option<String>,
    pub status: String,
    pub fw_version: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Gateway {
    pub fn is_claimed(&self) -> bool {
        self.status == "claimed"
    }

    pub fn is_retired(&self) -> bool {
        self.status == "retired"
    }

    /// Whether `account_id` may act on this gateway.
    ///
    /// Every `/gateways/:id/*` route funnels through this, so an
    /// ownership bug is a single place rather than a per-handler habit.
    pub fn owned_by(&self, account_id: Uuid) -> bool {
        self.account_id == Some(account_id) && !self.is_retired()
    }
}

/// A telemetry row ready to insert.
#[derive(Debug, Clone)]
pub struct NewReading {
    pub ts: DateTime<Utc>,
    pub gateway_id: String,
    pub node_uuid: Vec<u8>,
    pub moisture: Option<f32>,
    pub temperature: Option<f32>,
    pub humidity: Option<f32>,
    pub valve_state: Option<i16>,
    pub seq: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(account: Option<Uuid>, status: &str) -> Gateway {
        Gateway {
            id: "gw".into(),
            account_id: account,
            pubkey: vec![0; 32],
            label: None,
            status: status.into(),
            fw_version: None,
            last_seen: None,
            claimed_at: None,
            retired_at: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn ownership_requires_a_match_and_a_live_gateway() {
        let account = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(gateway(Some(account), "claimed").owned_by(account));
        assert!(!gateway(Some(account), "claimed").owned_by(other));
        assert!(!gateway(None, "unclaimed").owned_by(account));
        assert!(
            !gateway(Some(account), "retired").owned_by(account),
            "retired is not actionable"
        );
    }
}
