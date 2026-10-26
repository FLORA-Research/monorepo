#![no_std]

/// Device logic shared by the node and the aggregator roles: sensing
/// schedule, irrigation limits, RS-485 answers, and bus coordination.
///
/// A node and an aggregator are the same device; the aggregator adds radio,
/// uplink, and command verification. Both roles are tested on the host, so
/// the firmware binaries stay thin embassy entry points.
pub fn hello() -> &'static str {
    "flora-device"
}
