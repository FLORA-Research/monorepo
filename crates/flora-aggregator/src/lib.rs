#![no_std]

/// Firmware library for the Pico W aggregator: a node plus radio, uplink,
/// and command verification. Embassy entry point and hardware bindings
/// live in `src/bin/firmware.rs`, behind the `firmware` feature; everything
/// testable lives in `flora-device` and is tested on the host.
pub fn hello() -> &'static str {
    "flora-aggregator"
}
