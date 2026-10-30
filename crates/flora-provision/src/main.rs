//! Provisioner CLI: flash a UF2, commission a device over USB, register it
//! with the cloud, write credentials and the pairing QR.

use clap::Parser;
use flora_provision::{Cli, run};

fn main() -> anyhow::Result<()> {
    run(Cli::parse())
}
