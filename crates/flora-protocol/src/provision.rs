//! USB-CDC provisioning handshake: the JSON lines a device and the
//! provisioner exchange over the commissioning serial link.
//!
//! In v1 these shapes lived on both sides as private structs, and they
//! drifted: the provisioner sent `{cmd, device_id, token}` while the
//! aggregator parsed `{gateway_id, device_id, device_token, cloud_url,
//! wifi_ssid, wifi_password}` with `#[serde(default)]` — so missing fields
//! silently provisioned a device with empty Wi-Fi credentials. Here one
//! struct per message is shared by the firmware (serde-json-core) and the
//! CLI (serde_json), so a missing field is a compile error on the side
//! that forgets it.
//!
//! The aggregator's WiFi credentials are *not* part of this handshake: the
//! radio's access-point dictionary is compiled in from `wifi.toml`, so a
//! deployment edits one file rather than re-provisioning every device.
//!
//! All strings are borrowed: neither side allocates to parse or emit.
//! The firmware writes these with its own small formatter; the shapes are
//! pinned here by tests so the bytes agree.

use serde::{Deserialize, Serialize};

/// Version of the provisioning handshake. Bumping it invalidates both
/// sides together.
pub const HANDSHAKE_VERSION: u8 = 1;

/// Greeting a node sends when the provisioner connects.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NodeHello<'a> {
    pub flora_prov: u8,
    pub hw: &'a str,
    pub fw: &'a str,
    /// Hex-encoded 8-byte node UUID.
    pub uuid: &'a str,
}

/// Greeting an aggregator sends when the provisioner connects.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AggregatorHello<'a> {
    pub flora_prov: u8,
    pub hw: &'a str,
    pub fw: &'a str,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub pubkey: &'a str,
    /// Hex-encoded 8-byte aggregator UUID.
    pub uuid: &'a str,
}
/// Provisioning request for a node: assign its RS-485 address.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SetNodeAddress<'a> {
    pub cmd: &'a str,
    pub address: u8,
}

/// Provisioning request for an aggregator: install its identity and the
/// cloud it uplinks to. Every field is required on both sides — a default
/// would provision a device that cannot reach the cloud.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SetIdentity<'a> {
    pub cmd: &'a str,
    /// Hex-encoded 16-byte gateway id, `SHA-256(pubkey)[..16]`.
    pub gateway_id: &'a str,
    /// The same hex string, as the cloud knows the device.
    pub device_id: &'a str,
    pub device_token: &'a str,
    /// Scheme, host, and optional port; the firmware appends its paths.
    pub cloud_url: &'a str,
}

impl SetNodeAddress<'_> {
    pub const CMD: &'static str = "set_node_address";
}

impl SetIdentity<'_> {
    pub const CMD: &'static str = "set_identity";
}

/// Acknowledgement a device sends for a provisioning request.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Ack<'a> {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
}
/// The greeting a node emits, as a fixed wire shape.
pub const NODE_HW: &str = "pico";
/// The greeting an aggregator emits, as a fixed wire shape.
pub const AGGREGATOR_HW: &str = "pico_w";
