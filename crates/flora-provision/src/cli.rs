//! The `flora-provision` command line: two subcommands, one per device kind.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serialport::SerialPort;

use crate::provision;
use crate::uf2::flash_uf2;

const SERIAL_BAUD: u32 = 115_200;
const SERIAL_READ_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Parser)]
#[command(
    name = "flora-provision",
    version,
    about = "Provision FLORA Pico devices"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Provision a Pico W aggregator over USB serial.
    Aggregator(AggregatorArgs),
    /// Assign an RS-485 address to a regular Pico node over USB serial.
    Node(NodeArgs),
}

#[derive(Debug, Args)]
struct AggregatorArgs {
    #[arg(long, value_name = "PORT")]
    port: PathBuf,
    #[arg(long)]
    label: String,
    #[arg(long, value_name = "UF2")]
    firmware: Option<PathBuf>,
    #[arg(long, value_name = "MOUNT")]
    bootsel_mount: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    output_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout_secs: u64,
    /// Register the device with the cloud and write the pairing QR.
    ///
    /// Without this the device is flashed and given credentials but the cloud
    /// never learns about it, so no phone can claim it.
    #[arg(long, value_name = "URL")]
    cloud_url: Option<String>,
    /// The provisioning API key.
    ///
    /// Defaults to `FLORA_PROVISION_API_KEY`, so a key does not have to be
    /// pasted into shell history.
    #[arg(long, value_name = "KEY")]
    cloud_key: Option<String>,
}

#[derive(Debug, Args)]
struct NodeArgs {
    #[arg(long, value_name = "PORT")]
    port: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u8).range(2..=254))]
    address: u8,
    #[arg(long, value_name = "UF2")]
    firmware: Option<PathBuf>,
    #[arg(long, value_name = "MOUNT")]
    bootsel_mount: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout_secs: u64,
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Aggregator(args) => run_aggregator(args),
        Command::Node(args) => run_node(args),
    }
}

fn run_aggregator(args: AggregatorArgs) -> Result<()> {
    flash_if_requested(args.firmware.as_deref(), args.bootsel_mount.as_deref())?;
    let timeout = Duration::from_secs(args.timeout_secs);
    let mut port = open_serial(&args.port, timeout)?;
    let output_root = output_root(args.output_dir.as_deref())?;

    // A URL without a key would register nothing, so the pair is required
    // together rather than silently skipping registration.
    let cloud_target = match (&args.cloud_url, &args.cloud_key) {
        (Some(url), Some(key)) => Some(provision::CloudTarget {
            base_url: url.clone(),
            api_key: key.clone(),
        }),
        (Some(_), None) => {
            // Fall back to the environment so a key need not appear in shell
            // history, but say so when neither is present.
            match std::env::var("FLORA_PROVISION_API_KEY") {
                Ok(key) if !key.trim().is_empty() => Some(provision::CloudTarget {
                    base_url: args.cloud_url.clone().expect("checked above"),
                    api_key: key,
                }),
                _ => anyhow::bail!("--cloud-url needs --cloud-key, or FLORA_PROVISION_API_KEY set"),
            }
        }
        (None, Some(_)) => {
            anyhow::bail!("--cloud-key was given without --cloud-url")
        }
        (None, None) => None,
    };

    let result = provision::provision_aggregator_with_cloud(
        &mut port,
        &args.label,
        &output_root,
        timeout,
        cloud_target.as_ref(),
        args.firmware.as_deref(),
    )?;
    println!(
        "Aggregator {} provisioned (firmware {}, UUID {}). Credentials: {}",
        result.device_id,
        result.fw,
        result.uuid,
        result.credentials_path.display()
    );
    if let Some(qr) = &result.qr_path {
        println!("Pairing code: {}", qr.display());
    }
    if let Some(bundle) = &result.bundle_path {
        println!("Bundle: {}", bundle.display());
    }
    if let Some(status) = &result.cloud_status {
        println!("Cloud: {status}");
    }
    Ok(())
}

fn run_node(args: NodeArgs) -> Result<()> {
    flash_if_requested(args.firmware.as_deref(), args.bootsel_mount.as_deref())?;
    let timeout = Duration::from_secs(args.timeout_secs);
    let mut port = open_serial(&args.port, timeout)?;
    let result = provision::provision_node(&mut port, args.address, timeout)?;
    println!(
        "Node {} assigned address {} (firmware {}).",
        result.uuid, result.address, result.fw
    );
    Ok(())
}

fn flash_if_requested(firmware: Option<&Path>, mount: Option<&Path>) -> Result<()> {
    match (firmware, mount) {
        (None, None) => Ok(()),
        (Some(firmware), Some(mount)) => {
            let destination = flash_uf2(firmware, mount)?;
            println!("Flashed UF2 to {}.", destination.display());
            Ok(())
        }
        _ => anyhow::bail!("--firmware and --bootsel-mount must be supplied together"),
    }
}

fn open_serial(path: &Path, timeout: Duration) -> Result<Box<dyn SerialPort>> {
    let name = path
        .to_str()
        .with_context(|| format!("serial port path is not valid UTF-8: {}", path.display()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match serialport::new(name, SERIAL_BAUD)
            .timeout(SERIAL_READ_TIMEOUT)
            .open()
        {
            Ok(port) => return Ok(port),
            Err(error) if Instant::now() >= deadline => {
                return Err(error).with_context(|| {
                    format!(
                        "could not open serial port {} before timeout",
                        path.display()
                    )
                });
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn output_root(argument: Option<&Path>) -> Result<PathBuf> {
    match argument {
        None => Ok(home_directory()?.join(".flora").join("provisioned")),
        Some(path) if path == Path::new("~") => home_directory(),
        Some(path) if path.starts_with("~/") => {
            Ok(home_directory()?.join(path.strip_prefix("~/")?))
        }
        Some(path) => Ok(path.to_path_buf()),
    }
}

fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("HOME or USERPROFILE is not set")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flashing_requires_both_firmware_and_bootsel_mount() {
        assert!(flash_if_requested(None, None).is_ok());
        assert!(flash_if_requested(Some(Path::new("app.uf2")), None).is_err());
        assert!(flash_if_requested(None, Some(Path::new("/media/RPI-RP2"))).is_err());
    }

    #[test]
    fn default_artifact_directory_is_under_home() {
        let home = home_directory().unwrap();
        assert_eq!(
            output_root(None).unwrap(),
            home.join(".flora").join("provisioned")
        );
    }

    #[test]
    fn a_tilde_prefix_expands() {
        let home = home_directory().unwrap();
        assert_eq!(output_root(Some(Path::new("~"))).unwrap(), home);
        assert_eq!(
            output_root(Some(Path::new("~/flora-out"))).unwrap(),
            home.join("flora-out")
        );
    }
}
