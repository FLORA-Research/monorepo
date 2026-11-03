#![no_std]

//! Firmware library for the Pico W aggregator: a node plus radio, uplink,
//! and command verification. Embassy entry point and hardware bindings
//! live in `src/bin/firmware.rs`, behind the `firmware` feature; everything
//! testable lives here and in `flora-device` and is tested on the host.

// Tests run on the host, where `String`/`format!` exist; the crate itself
// never allocates.
#[cfg(test)]
extern crate alloc;

pub mod commands;
#[cfg(feature = "firmware")]
pub mod storage;
pub mod uplink;
pub mod wifi;

/// Board-level constants shared by the firmware binary.
pub mod board {
    /// Address the aggregator answers to on its own RS-485 bus.
    pub const LOCAL_ADDR: u8 = 1;
    /// How often the local plot is sampled, in seconds.
    pub const SAMPLE_INTERVAL_S: u64 = 60;
    /// How often a batch is queued and the uplink attempted, in seconds.
    pub const UPLINK_INTERVAL_S: u64 = 300;
    /// How long a polled node is given to answer before it is skipped.
    pub const POLL_TIMEOUT_MS: u64 = 200;
    /// RS-485 baud rate, matching the nodes.
    pub const RS485_BAUD: u32 = 115_200;
}

/// The compiled-in WiFi dictionary, in join order.
///
/// `crates/flora-aggregator/wifi.toml` is the single place a deployment
/// edits to say which access points exist, what protects them (open,
/// WPA, WPA2, WPA3, or mixed), and which to prefer. The file is baked in
/// at build time because the firmware has neither an allocator nor a
/// filesystem worth running before the radio is up.
///
/// A file that does not parse is a compile error via the unit tests in
/// [`wifi`], not a device that boots offline.
pub fn wifi_networks() -> heapless::Vec<wifi::WifiNetwork, { wifi::MAX_NETWORKS }> {
    // `expect` in a const-context function that the firmware calls once at
    // boot: a malformed dictionary must be fixed before flashing, and the
    // host tests catch it first.
    match wifi::parse_dictionary(include_str!("../wifi.toml")) {
        Ok(networks) => networks,
        // Distinguish the failure modes so the panic message names the fix.
        Err(wifi::DictionaryError::TooManyNetworks) => {
            panic!("wifi.toml: too many networks")
        }
        Err(wifi::DictionaryError::DuplicateSsid) => panic!("wifi.toml: duplicate ssid"),
        Err(wifi::DictionaryError::InvalidField(what)) => panic!("wifi.toml: {what}"),
        Err(wifi::DictionaryError::Malformed(what)) => panic!("wifi.toml: {what}"),
    }
}
