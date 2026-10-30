//! The per-device provisioning bundle.
//!
//! On a successful provision the CLI packages everything an operator needs
//! to bring the board back or hand the pairing code over, into one zip
//! beside the credentials:
//!
//! * `credentials.json` — the device id, token, and claim secret (0600 on
//!   disk; the zip inherits the operator's umask, so it should be handled
//!   with the same care);
//! * `pair.svg` — the QR a phone scans to claim the device;
//! * `firmware.uf2` — when the run flashed the device, the exact image
//!   bytes that were written, so a re-flash reproduces the same build.
//!
//! One file per device is the difference between "downloaded the folder"
//! and "can restore the site".

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

/// The archive name: `<device-id>.zip` in the device directory.
pub fn bundle_path(device_dir: &Path, device_id: &str) -> PathBuf {
    device_dir.join(format!("{device_id}.zip"))
}

/// Write the bundle, returning its path.
///
/// `firmware` is optional: a commission-only run (no `--firmware`) has no
/// image to back up and the bundle simply omits it. Existing archives are
/// replaced, because the bundle reflects the latest successful run.
pub fn write_bundle(
    device_dir: &Path,
    device_id: &str,
    credentials_path: &Path,
    qr_path: &Path,
    firmware: Option<&Path>,
) -> Result<PathBuf> {
    let path = bundle_path(device_dir, device_id);
    let file = File::create(&path)
        .with_context(|| format!("create provisioning bundle {}", path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    add_file(&mut zip, options, "credentials.json", credentials_path)?;
    add_file(&mut zip, options, "pair.svg", qr_path)?;
    if let Some(firmware) = firmware {
        let name = firmware
            .file_name()
            .and_then(|name| name.to_str())
            .context("firmware path has no usable filename")?
            .to_owned();
        add_file(&mut zip, options, &name, firmware)?;
    }

    zip.finish()
        .with_context(|| format!("finish provisioning bundle {}", path.display()))?;
    Ok(path)
}

/// Sanity check a bundle: it must exist and unzip to the members that were
/// added. Used by the CLI's self-check after writing, so a truncated copy
/// on a flaky mount is caught at provision time rather than restore time.
pub fn verify_bundle(path: &Path, expect_firmware: bool) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("read provisioning bundle {}", path.display()))?;
    ensure!(
        archive.by_name("credentials.json").is_ok(),
        "bundle is missing credentials.json"
    );
    ensure!(
        archive.by_name("pair.svg").is_ok(),
        "bundle is missing pair.svg"
    );
    if expect_firmware {
        ensure!(
            archive.file_names().any(|name| name.ends_with(".uf2")),
            "bundle is missing the firmware backup"
        );
    }
    Ok(())
}

fn add_file<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    options: zip::write::SimpleFileOptions,
    name: &str,
    source: &Path,
) -> Result<()> {
    let bytes =
        fs::read(source).with_context(|| format!("read {} for the bundle", source.display()))?;
    zip.start_file(name, options)
        .with_context(|| format!("add {name} to the bundle"))?;
    zip.write_all(&bytes)
        .with_context(|| format!("write {name} into the bundle"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn bundles_credentials_qr_and_firmware() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        fs::write(
            dir.join("credentials.json"),
            b"{\"status\":\"provisioned\"}",
        )
        .unwrap();
        fs::write(dir.join("pair.svg"), b"<svg></svg>").unwrap();
        let firmware = dir.join("flora-aggregator.uf2");
        fs::write(&firmware, b"UF2BYTES").unwrap();

        let path = write_bundle(
            dir,
            "abcd",
            &dir.join("credentials.json"),
            &dir.join("pair.svg"),
            Some(&firmware),
        )
        .unwrap();
        assert_eq!(path, dir.join("abcd.zip"));
        verify_bundle(&path, true).unwrap();

        let file = File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_owned())
            .collect();
        assert!(names.contains(&"credentials.json".to_owned()));
        assert!(names.contains(&"pair.svg".to_owned()));
        assert!(names.contains(&"flora-aggregator.uf2".to_owned()));
        let mut contents = String::new();
        archive
            .by_name("credentials.json")
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "{\"status\":\"provisioned\"}");
    }

    #[test]
    fn a_commission_only_bundle_omits_firmware() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        fs::write(dir.join("credentials.json"), b"{}").unwrap();
        fs::write(dir.join("pair.svg"), b"<svg/>").unwrap();

        let path = write_bundle(
            dir,
            "abcd",
            &dir.join("credentials.json"),
            &dir.join("pair.svg"),
            None,
        )
        .unwrap();
        verify_bundle(&path, false).unwrap();
        assert!(verify_bundle(&path, true).is_err());
    }
}
