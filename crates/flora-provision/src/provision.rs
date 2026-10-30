//! Provisioning flows: node address assignment and aggregator commissioning.
//!
//! The node path is one exchange: read the greeting, send the address,
//! confirm the acknowledgement. The aggregator path is longer because the
//! cloud is involved: greet, persist credentials *before* writing them to
//! the device (a crash then means a retry, not a bricked board), write the
//! identity, mint the claim token, draw the QR, optionally register with
//! the cloud, and only then mark the artifact provisioned.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, ensure};

use crate::artifacts;
use crate::cloud;
use crate::handshake::{self, AggregatorHello};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedNode {
    pub address: u8,
    pub fw: String,
    pub uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedAggregator {
    pub device_id: String,
    pub fw: String,
    pub uuid: String,
    pub credentials_path: PathBuf,
    /// Where the QR a phone scans was written.
    pub qr_path: Option<PathBuf>,
    /// How the cloud answered, or why it was not contacted.
    pub cloud_status: Option<String>,
}

/// Assign an RS-485 address to a node.
pub fn provision_node<R: Read + Write>(
    serial: &mut R,
    address: u8,
    timeout: Duration,
) -> Result<ProvisionedNode> {
    ensure!(
        (0x02..=0xFE).contains(&address),
        "node address must be in 0x02..=0xFE"
    );
    let hello = handshake::read_node_hello(serial, timeout)?;
    handshake::set_node_address(serial, address, timeout)?;
    Ok(ProvisionedNode {
        address,
        fw: hello.fw,
        uuid: hello.uuid,
    })
}

/// Commission an aggregator without a cloud registration.
pub fn provision_aggregator<R: Read + Write>(
    serial: &mut R,
    label: &str,
    output_root: &Path,
    timeout: Duration,
) -> Result<ProvisionedAggregator> {
    provision_aggregator_with_cloud(serial, label, output_root, timeout, None)
}

/// Where the cloud lives and how to authenticate to it.
#[derive(Debug, Clone)]
pub struct CloudTarget {
    pub base_url: String,
    pub api_key: String,
}

/// Provision a device and, when a cloud target is given, register it and write
/// the QR a phone scans.
///
/// Registration is optional because the two halves are useful apart: bringing up
/// a board on a bench needs no server, and a device already flashed should not
/// be re-flashed just because the cloud moved.
pub fn provision_aggregator_with_cloud<R: Read + Write>(
    serial: &mut R,
    label: &str,
    output_root: &Path,
    timeout: Duration,
    cloud_target: Option<&CloudTarget>,
) -> Result<ProvisionedAggregator> {
    let hello: AggregatorHello = handshake::read_aggregator_hello(serial, timeout)?;
    let (mut artifact, device_dir) = artifacts::prepare_pending(output_root, &hello, label)?;
    handshake::set_aggregator_identity(
        serial,
        &artifact.device_id,
        &artifact.device_token,
        timeout,
    )?;

    // The claim token is generated before registration, because the cloud stores
    // its hash: losing it means the QR can never be shown again.
    let claim_token = cloud::generate_claim_token()?;
    artifact.claim_token = Some(claim_token.clone());

    let payload = cloud::qr_payload(&artifact.device_id, &claim_token, &artifact.uuid)?;
    let qr_name = "pair.svg";
    crate::qr::write_svg(&device_dir.join(qr_name), &payload)?;
    artifact.qr_path = Some(qr_name.to_owned());

    if let Some(target) = cloud_target {
        let registration = cloud::Registration {
            device_id: artifact.device_id.clone(),
            pubkey: artifact.device_pubkey.clone(),
            token_hash: crate::identity::hash_hex_secret(&artifact.device_token)?,
            claim_hash: crate::identity::hash_hex_secret(&claim_token)?,
            hw: artifact.hw.clone(),
            fw: artifact.fw.clone(),
            label: artifact.label.clone(),
        };
        // A cloud failure must not lose the work already done: the device is
        // flashed and its credentials are on disk, so the status is recorded and
        // the caller can retry registration without touching the hardware.
        artifact.cloud_status = Some(
            match cloud::register(
                &target.base_url,
                &target.api_key,
                &registration,
                timeout.max(Duration::from_secs(10)),
            ) {
                Ok(body) => format!("registered: {body}"),
                Err(error) => format!("not registered: {error}"),
            },
        );
    } else {
        artifact.cloud_status = Some("skipped: no cloud target given".to_owned());
    }

    let credentials_path = artifacts::mark_provisioned(&device_dir, &mut artifact)?;

    Ok(ProvisionedAggregator {
        device_id: artifact.device_id,
        fw: artifact.fw,
        uuid: artifact.uuid,
        credentials_path,
        qr_path: Some(device_dir.join(qr_name)),
        cloud_status: artifact.cloud_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{ArtifactStatus, GatewayArtifact};
    use crate::identity;
    use serde_json::Value;
    use std::collections::VecDeque;
    use std::io;

    struct FirmwareStub {
        input: VecDeque<u8>,
        current_line: Vec<u8>,
        requests: Vec<Value>,
        acknowledge: bool,
    }

    impl FirmwareStub {
        fn new(greeting: &str, acknowledge: bool) -> Self {
            Self {
                input: greeting.bytes().collect(),
                current_line: Vec::new(),
                requests: Vec::new(),
                acknowledge,
            }
        }
    }

    impl Read for FirmwareStub {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.input.is_empty() {
                return Ok(0);
            }
            let count = output.len().min(self.input.len());
            for slot in &mut output[..count] {
                *slot = self.input.pop_front().unwrap();
            }
            Ok(count)
        }
    }

    impl Write for FirmwareStub {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for byte in bytes {
                self.current_line.push(*byte);
                if *byte == b'\n' {
                    let request: Value =
                        serde_json::from_slice(&self.current_line).map_err(io::Error::other)?;
                    match request["cmd"].as_str() {
                        Some("set_node_address") => {
                            let address = request["address"].as_u64().unwrap_or_default();
                            if !(2..=254).contains(&address) {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid node address",
                                ));
                            }
                        }
                        Some("set_identity") => {
                            let device_id = request["device_id"].as_str().unwrap_or_default();
                            let token = request["token"].as_str().unwrap_or_default();
                            if device_id.len() != 32 || token.len() != 64 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid identity fields",
                                ));
                            }
                        }
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unknown provisioning command",
                            ));
                        }
                    }
                    self.requests.push(request);
                    self.current_line.clear();
                    let ack: &[u8] = if self.acknowledge {
                        b"{\"ok\":true}\n"
                    } else {
                        b"{\"ok\":false}\n"
                    };
                    self.input.extend(ack.iter().copied());
                }
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn node_greeting() -> &'static str {
        "{\"flora_prov\":1,\"hw\":\"pico\",\"fw\":\"0.1.0\",\"uuid\":\"a1b2c3d4e5f60708\"}\n"
    }

    fn aggregator_greeting() -> String {
        let pubkey = identity::encode_hex(&(0u8..32).collect::<Vec<_>>());
        format!(
            "{{\"flora_prov\":1,\"pubkey\":\"{pubkey}\",\"hw\":\"pico_w\",\"fw\":\"0.1.0\",\"uuid\":\"a1b2c3d4e5f60708\"}}\n"
        )
    }

    #[test]
    fn provisions_node_address_and_requires_positive_ack() {
        let mut firmware = FirmwareStub::new(node_greeting(), true);
        let node = provision_node(&mut firmware, 2, Duration::from_secs(1)).unwrap();
        assert_eq!(node.address, 2);
        assert_eq!(node.uuid, "a1b2c3d4e5f60708");
        assert_eq!(firmware.requests[0]["cmd"], "set_node_address");
        assert_eq!(firmware.requests[0]["address"], 2);

        let mut rejected = FirmwareStub::new(node_greeting(), false);
        assert!(provision_node(&mut rejected, 3, Duration::from_secs(1)).is_err());
        let mut invalid_address = FirmwareStub::new(node_greeting(), true);
        assert!(provision_node(&mut invalid_address, 1, Duration::from_secs(1)).is_err());
        assert!(invalid_address.requests.is_empty());
    }

    #[test]
    fn aggregator_identity_is_persisted_before_write_and_resumes_after_nack() {
        let temp = tempfile::tempdir().unwrap();
        let greeting = aggregator_greeting();
        let mut first = FirmwareStub::new(&greeting, false);
        assert!(
            provision_aggregator(
                &mut first,
                "plot-north",
                temp.path(),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert_eq!(first.requests.len(), 1);
        let first_token = first.requests[0]["token"].as_str().unwrap().to_owned();
        let device_id = first.requests[0]["device_id"].as_str().unwrap().to_owned();
        let credentials_path = temp.path().join(&device_id).join("credentials.json");
        let pending: GatewayArtifact =
            serde_json::from_slice(&std::fs::read(&credentials_path).unwrap()).unwrap();
        assert_eq!(pending.status, ArtifactStatus::Pending);
        assert_eq!(pending.device_token, first_token);

        let mut retry = FirmwareStub::new(&greeting, true);
        let completed = provision_aggregator(
            &mut retry,
            "plot-north",
            temp.path(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(completed.device_id, device_id);
        assert_eq!(
            retry.requests[0]["token"].as_str(),
            Some(first_token.as_str())
        );
        let saved: GatewayArtifact =
            serde_json::from_slice(&std::fs::read(&completed.credentials_path).unwrap()).unwrap();
        assert_eq!(saved.status, ArtifactStatus::Provisioned);
        assert_eq!(saved.device_token, first_token);
        assert!(saved.claim_token.is_some());
        assert_eq!(
            saved.cloud_status.as_deref(),
            Some("skipped: no cloud target given")
        );
        assert!(completed.qr_path.is_some_and(|path| path.is_file()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&completed.credentials_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
