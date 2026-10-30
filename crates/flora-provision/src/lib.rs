//! Provisioner CLI: flash a UF2, commission a device over USB, register it
//! with the cloud, write credentials and the pairing QR.

pub mod artifacts;
pub mod bundle;
pub mod cloud;
pub mod handshake;
pub mod identity;
pub mod provision;
pub mod qr;
pub mod uf2;

pub use cli::{Cli, run};
mod cli;
