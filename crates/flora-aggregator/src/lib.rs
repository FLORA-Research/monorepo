#![no_std]

//! Firmware library for the Pico W aggregator: a node plus radio, uplink,
//! and command verification. Embassy entry point and hardware bindings
//! live in `src/bin/firmware.rs`, behind the `firmware` feature; everything
//! testable lives here and in `flora-device` and is tested on the host.

pub mod wifi;

/// The compiled-in WiFi dictionary, in join order.
///
/// `wifi.toml` at the repository root is the single place a deployment
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
    match wifi::parse_dictionary(include_str!("../../../wifi.toml")) {
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
