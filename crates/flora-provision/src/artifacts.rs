//! On-disk credential artifacts, one directory per device.
//!
//! Layout under the output root:
//!
//! ```text
//! <root>/<gateway-id>/credentials.json   0600, atomically replaced
//! <root>/<gateway-id>/pair.svg           the QR a phone scans
//! ```
//!
//! Two properties matter. The credentials file is written `create_new` at
//! 0600 and only ever replaced by an atomic rename, so a crash mid-run
//! cannot truncate it and another user cannot read it in between. And a
//! re-run against the same board resumes: the existing artifact is loaded
//! and checked against the greeting, so the device token never changes
//! underneath a device that already learned it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::handshake::AggregatorHello;
use crate::identity;

const ARTIFACT_VERSION: u8 = 1;
const CREDENTIALS_FILE: &str = "credentials.json";

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Pending,
    Provisioned,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct GatewayArtifact {
    pub format_version: u8,
    pub status: ArtifactStatus,
    pub device_id: String,
    pub device_token: String,
    pub device_pubkey: String,
    pub uuid: String,
    pub hw: String,
    pub fw: String,
    pub label: String,
    /// The secret a phone presents to claim this device.
    ///
    /// Stored here because the QR can only be shown once: the cloud keeps only
    /// its hash, so a lost claim token means provisioning again.
    #[serde(default)]
    pub claim_token: Option<String>,
    /// Where the QR was written, relative to the artifact directory.
    #[serde(default)]
    pub qr_path: Option<String>,
    /// How the cloud answered, or why it could not be reached.
    #[serde(default)]
    pub cloud_status: Option<String>,
}

impl GatewayArtifact {
    fn matches_hello(&self, hello: &AggregatorHello, label: &str, device_id: &str) -> Result<()> {
        ensure!(
            self.format_version == ARTIFACT_VERSION,
            "unsupported credential artifact version"
        );
        ensure!(
            self.device_id == device_id,
            "credential artifact device ID does not match firmware"
        );
        ensure!(
            self.device_pubkey == hello.pubkey,
            "credential artifact public key does not match firmware"
        );
        ensure!(
            self.uuid == hello.uuid,
            "credential artifact UUID does not match firmware"
        );
        ensure!(
            self.hw == hello.hw,
            "credential artifact hardware does not match firmware"
        );
        ensure!(
            self.fw == hello.fw,
            "credential artifact firmware version does not match firmware"
        );
        ensure!(
            self.label == label,
            "credential artifact label differs; use the original label to resume"
        );
        identity::decode_hex::<32>(&self.device_token)
            .context("credential artifact device token")?;
        Ok(())
    }
}

/// Create (or resume) the pending artifact for one device.
///
/// The device id is derived from the key the firmware reported, so the
/// directory name is the identity the cloud will use too.
pub fn prepare_pending(
    output_root: &Path,
    hello: &AggregatorHello,
    label: &str,
) -> Result<(GatewayArtifact, PathBuf)> {
    ensure!(
        !label.trim().is_empty(),
        "aggregator label must not be empty"
    );
    ensure!(label.len() <= 128, "aggregator label exceeds 128 bytes");

    let device_id = identity::device_id_from_public_key(&hello.pubkey)?;
    fs::create_dir_all(output_root).with_context(|| {
        format!(
            "create provisioning output directory {}",
            output_root.display()
        )
    })?;
    let device_dir = output_root.join(&device_id);
    create_private_device_dir(&device_dir)?;
    let credentials_path = device_dir.join(CREDENTIALS_FILE);

    if path_exists_without_following(&credentials_path)? {
        let artifact = read_existing(&credentials_path)?;
        artifact.matches_hello(hello, label, &device_id)?;
        return Ok((artifact, device_dir));
    }

    let artifact = GatewayArtifact {
        format_version: ARTIFACT_VERSION,
        status: ArtifactStatus::Pending,
        device_id: device_id.clone(),
        device_token: identity::generate_device_token()?,
        device_pubkey: hello.pubkey.clone(),
        uuid: hello.uuid.clone(),
        hw: hello.hw.clone(),
        fw: hello.fw.clone(),
        label: label.to_owned(),
        claim_token: None,
        qr_path: None,
        cloud_status: None,
    };

    match write_new_private(&credentials_path, &artifact) {
        Ok(()) => Ok((artifact, device_dir)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_existing(&credentials_path)?;
            existing.matches_hello(hello, label, &artifact.device_id)?;
            Ok((existing, device_dir))
        }
        Err(error) => Err(error).with_context(|| format!("write {}", credentials_path.display())),
    }
}

/// Flip the artifact to `provisioned` atomically, returning its path.
pub fn mark_provisioned(device_dir: &Path, artifact: &mut GatewayArtifact) -> Result<PathBuf> {
    let path = device_dir.join(CREDENTIALS_FILE);
    let mut completed = artifact.clone();
    completed.status = ArtifactStatus::Provisioned;
    replace_private(&path, &completed)?;
    *artifact = completed;
    Ok(path)
}

fn read_existing(path: &Path) -> Result<GatewayArtifact> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect credential artifact {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "refusing non-regular credential artifact"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "credential artifact permissions must be 0600 or stricter"
        );
    }

    let mut file =
        File::open(path).with_context(|| format!("read credential artifact {}", path.display()))?;
    let mut json = String::new();
    file.read_to_string(&mut json)?;
    let artifact: GatewayArtifact = serde_json::from_str(&json)
        .with_context(|| format!("parse credential artifact {}", path.display()))?;
    Ok(artifact)
}

fn path_exists_without_following(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "refusing non-regular credential artifact"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn create_private_device_dir(path: &Path) -> Result<()> {
    match create_private_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.file_type().is_dir(),
                "refusing non-directory credential path"
            );
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("create credential directory {}", path.display()))
        }
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn write_new_private(path: &Path, artifact: &GatewayArtifact) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(artifact).map_err(std::io::Error::other)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(&json).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn replace_private(path: &Path, artifact: &GatewayArtifact) -> Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos();
    let temp = path.with_file_name(format!(
        "credentials.json.tmp-{}-{nonce}",
        std::process::id()
    ));
    let json = serde_json::to_vec_pretty(artifact)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .with_context(|| format!("create temporary credential artifact {}", temp.display()))?;
    if let Err(error) = file.write_all(&json).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(error)
            .with_context(|| format!("write temporary credential artifact {}", temp.display()));
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error)
            .with_context(|| format!("replace credential artifact {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> (AggregatorHello, String) {
        let key = identity::encode_hex(&[9u8; 32]);
        (
            AggregatorHello {
                fw: "0.2.0".into(),
                hw: "pico_w".into(),
                pubkey: key.clone(),
                uuid: "a1b2c3d4e5f60708".into(),
            },
            key,
        )
    }

    #[test]
    fn prepares_pending_then_resumes_with_the_same_token() {
        let temp = tempfile::tempdir().unwrap();
        let (hello, _) = hello();

        let (first, dir) = prepare_pending(temp.path(), &hello, "plot-north").unwrap();
        assert_eq!(first.status, ArtifactStatus::Pending);
        assert!(first.device_id.len() == 32);

        let (second, dir2) = prepare_pending(temp.path(), &hello, "plot-north").unwrap();
        assert_eq!(dir, dir2);
        assert_eq!(
            second.device_token, first.device_token,
            "resume keeps the token"
        );
    }

    #[test]
    fn a_label_change_is_refused_on_resume() {
        let temp = tempfile::tempdir().unwrap();
        let (hello, _) = hello();
        prepare_pending(temp.path(), &hello, "plot-north").unwrap();
        assert!(prepare_pending(temp.path(), &hello, "plot-south").is_err());
    }

    #[test]
    fn credentials_are_0600_in_a_0700_directory() {
        let temp = tempfile::tempdir().unwrap();
        let (hello, _) = hello();
        let (artifact, dir) = prepare_pending(temp.path(), &hello, "x").unwrap();
        let path = mark_provisioned(&dir, &mut artifact.clone()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn an_insecure_existing_artifact_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let (hello, _) = hello();
        let device_id = identity::device_id_from_public_key(&hello.pubkey).unwrap();
        let dir = temp.path().join(&device_id);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CREDENTIALS_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&path, "{}").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(prepare_pending(temp.path(), &hello, "x").is_err());
    }
}
