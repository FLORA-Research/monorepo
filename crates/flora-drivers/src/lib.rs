#![no_std]

/// Sensors and actuators, generic over `embedded-hal`.
///
/// The decode and calibration math is plain code and is tested on the host;
/// the hardware bindings live in the firmware crates, which own pins and
/// peripherals. Nothing here may reference a board.
pub fn hello() -> &'static str {
    "flora-drivers"
}
