#![no_std]

//! Sensors and actuators, generic over `embedded-hal`.
//!
//! The decode, calibration, and control math is plain code and is tested
//! on the host; the hardware bindings live in the firmware bins, which
//! own pins and peripherals. Nothing here references a board.
//!
//! Layout:
//! * [`config`] — node configuration and its flash record codec.
//! * [`soil_moisture`] — ADC counts to per mille via captured references.
//! * [`dht22`] — temperature/humidity decode with range checks.
//! * [`irrigation`] — the valve state machine and its safety caps.

pub mod config;
pub mod dht22;
pub mod irrigation;
pub mod soil_moisture;

pub use config::{CONFIG_PAGE_SIZE, FIRMWARE_VERSION, FW_PACKED, NodeConfig};
pub use dht22::{Error as Dht22Error, Reading as Dht22Reading};
pub use irrigation::{IrrigationController, ManualError};
pub use soil_moisture::{sample_per_mille, to_per_mille};
