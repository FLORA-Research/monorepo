#![no_std]

/// Firmware library for the plain Pico field node. Embassy entry point and
/// hardware bindings live in `src/bin/firmware.rs`, behind the `firmware`
/// feature; everything testable lives in `flora-device` and is tested on
/// the host.
pub fn hello() -> &'static str {
    "flora-node"
}
