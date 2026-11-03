#![no_std]

//! Firmware library for the plain Pico field node. Embassy entry point and
//! hardware bindings live in `src/bin/firmware.rs`, behind the `firmware`
//! feature; the bus command processor, drivers, and identity codecs live
//! in `flora-device`/`flora-drivers` and are tested on the host.

/// Flash-backed configuration and the chip's unique id.
///
/// Only compiled where the flash peripheral exists: the crate builds on
/// the host for its tests, and `embassy-rp` is firmware-only.
#[cfg(feature = "firmware")]
pub mod storage;

/// The pins the field node uses, from the wiring diagram.
pub mod board {
    pub const SOIL_MOISTURE_ADC_GPIO: u8 = 26;
    pub const DHT22_DATA_GPIO: u8 = 16;
    pub const VALVE_DRIVER_GPIO: u8 = 15;
    pub const RS485_UART0_TX_GPIO: u8 = 0;
    pub const RS485_UART0_RX_GPIO: u8 = 1;
    pub const RS485_DE_RE_GPIO: u8 = 2;
    pub const RS485_BAUD: u32 = 115_200;
    /// Before commissioning the address is zero, which is also the bus
    /// broadcast address, so an uncommissioned node never answers.
    pub const UNCOMMISSIONED_ADDRESS: u8 = 0;
}
