//! Serial handshake with the FLORA firmware, over any byte stream.
//!
//! The link is line-delimited JSON: the device introduces itself with one
//! line, the provisioner answers with one line per field, and every line
//! ends with an `ok` acknowledgement. Generic over `Read`/`Write`, so the
//! tests drive it with in-memory stubs and the CLI points it at a real
//! USB serial port.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::identity;

pub const HANDSHAKE_VERSION: u8 = 1;
const MAX_JSON_LINE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHello {
    pub fw: String,
    pub uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatorHello {
    pub fw: String,
    pub hw: String,
    pub pubkey: String,
    pub uuid: String,
}

#[derive(Deserialize)]
struct NodeHelloWire {
    flora_prov: u8,
    hw: String,
    fw: String,
    uuid: String,
}

#[derive(Deserialize)]
struct AggregatorHelloWire {
    flora_prov: u8,
    hw: String,
    fw: String,
    pubkey: String,
    uuid: String,
}

#[derive(Serialize)]
struct SetNodeAddress {
    cmd: &'static str,
    address: u8,
}

#[derive(Serialize)]
struct SetIdentity<'a> {
    cmd: &'static str,
    device_id: &'a str,
    token: &'a str,
}

#[derive(Deserialize)]
struct Ack {
    ok: bool,
}

pub fn read_node_hello<R: Read>(reader: &mut R, timeout: Duration) -> Result<NodeHello> {
    let line = read_json_line(reader, timeout).context("read node provisioning greeting")?;
    let wire: NodeHelloWire =
        serde_json::from_str(&line).context("parse node provisioning greeting")?;
    ensure!(
        wire.flora_prov == HANDSHAKE_VERSION,
        "unsupported node provisioning protocol version"
    );
    ensure!(
        wire.hw == "pico",
        "expected a standard Pico node, got hardware {:?}",
        wire.hw
    );
    validate_firmware(&wire.fw)?;
    let uuid = identity::encode_hex(&identity::decode_hex::<8>(&wire.uuid).context("node UUID")?);
    Ok(NodeHello { fw: wire.fw, uuid })
}

pub fn read_aggregator_hello<R: Read>(
    reader: &mut R,
    timeout: Duration,
) -> Result<AggregatorHello> {
    let line = read_json_line(reader, timeout).context("read aggregator provisioning greeting")?;
    let wire: AggregatorHelloWire =
        serde_json::from_str(&line).context("parse aggregator provisioning greeting")?;
    ensure!(
        wire.flora_prov == HANDSHAKE_VERSION,
        "unsupported aggregator provisioning protocol version"
    );
    ensure!(
        wire.hw == "pico_w",
        "expected a Pico W aggregator, got hardware {:?}",
        wire.hw
    );
    validate_firmware(&wire.fw)?;
    let pubkey = identity::encode_hex(
        &identity::decode_hex::<32>(&wire.pubkey).context("aggregator public key")?,
    );
    let uuid =
        identity::encode_hex(&identity::decode_hex::<8>(&wire.uuid).context("aggregator UUID")?);
    Ok(AggregatorHello {
        fw: wire.fw,
        hw: wire.hw,
        pubkey,
        uuid,
    })
}

pub fn set_node_address<R: Read + Write>(
    stream: &mut R,
    address: u8,
    timeout: Duration,
) -> Result<()> {
    ensure!(
        (0x02..=0xFE).contains(&address),
        "node address must be in 0x02..=0xFE"
    );
    write_json_line(
        stream,
        &SetNodeAddress {
            cmd: "set_node_address",
            address,
        },
    )?;
    read_ack(stream, timeout).context("node rejected address provisioning")
}

pub fn set_aggregator_identity<R: Read + Write>(
    stream: &mut R,
    device_id: &str,
    token: &str,
    timeout: Duration,
) -> Result<()> {
    write_json_line(
        stream,
        &SetIdentity {
            cmd: "set_identity",
            device_id,
            token,
        },
    )?;
    read_ack(stream, timeout).context("aggregator rejected identity provisioning")
}

fn validate_firmware(version: &str) -> Result<()> {
    ensure!(
        !version.is_empty() && version.len() <= 32,
        "firmware version must be 1..=32 bytes"
    );
    ensure!(
        version.bytes().all(|byte| byte.is_ascii_graphic()),
        "firmware version contains whitespace or control characters"
    );
    Ok(())
}

fn write_json_line<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).context("serialize provisioning request")?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .context("write provisioning request")?;
    writer.flush().context("flush provisioning request")?;
    Ok(())
}

fn read_ack<R: Read>(reader: &mut R, timeout: Duration) -> Result<()> {
    let line = read_json_line(reader, timeout).context("read provisioning acknowledgement")?;
    let ack: Ack = serde_json::from_str(&line).context("parse provisioning acknowledgement")?;
    ensure!(ack.ok, "firmware returned ok=false");
    Ok(())
}

fn read_json_line<R: Read>(reader: &mut R, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let mut line = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        let read_result = reader.read(&mut byte);
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for provisioning line"
        );
        match read_result {
            Ok(0) => anyhow::bail!("serial stream closed before newline"),
            Ok(_) if byte[0] == b'\n' => {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return String::from_utf8(line).context("provisioning line is not UTF-8");
            }
            Ok(_) => {
                ensure!(
                    line.len() < MAX_JSON_LINE,
                    "provisioning line exceeds {MAX_JSON_LINE} bytes"
                );
                line.push(byte[0]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) && Instant::now() < deadline => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                anyhow::bail!("timed out waiting for provisioning line")
            }
            Err(error) => return Err(error).context("read provisioning serial stream"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_versioned_node_greeting_and_normalizes_uuid() {
        let mut greeting = Cursor::new(
            b"{\"flora_prov\":1,\"hw\":\"pico\",\"fw\":\"0.1.0\",\"uuid\":\"A1B2C3D4E5F60708\"}\r\n",
        );
        let parsed = read_node_hello(&mut greeting, Duration::from_secs(1)).unwrap();
        assert_eq!(parsed.fw, "0.1.0");
        assert_eq!(parsed.uuid, "a1b2c3d4e5f60708");
    }

    #[test]
    fn rejects_wrong_board_and_invalid_uuid() {
        let mut wrong_board = Cursor::new(
            b"{\"flora_prov\":1,\"hw\":\"pico_w\",\"fw\":\"0.1.0\",\"uuid\":\"a1b2c3d4e5f60708\"}\n",
        );
        assert!(read_node_hello(&mut wrong_board, Duration::from_secs(1)).is_err());

        let mut invalid_uuid = Cursor::new(
            b"{\"flora_prov\":1,\"hw\":\"pico\",\"fw\":\"0.1.0\",\"uuid\":\"invalid\"}\n",
        );
        assert!(read_node_hello(&mut invalid_uuid, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn aggregator_greeting_carries_a_32_byte_key() {
        let pubkey = identity::encode_hex(&[7u8; 32]);
        let mut greeting = Cursor::new(
            format!(
                "{{\"flora_prov\":1,\"hw\":\"pico_w\",\"fw\":\"0.1.0\",\"pubkey\":\"{pubkey}\",\"uuid\":\"a1b2c3d4e5f60708\"}}\n"
            )
            .into_bytes(),
        );
        let parsed = read_aggregator_hello(&mut greeting, Duration::from_secs(1)).unwrap();
        assert_eq!(parsed.hw, "pico_w");
        assert_eq!(parsed.pubkey, pubkey);
    }

    #[test]
    fn a_nack_is_an_error() {
        let pubkey = identity::encode_hex(&[7u8; 32]);
        let mut stream = EchoAckStub::new(b"{\"ok\":false}\n");
        stream.push_greeting(
            format!(
                "{{\"flora_prov\":1,\"hw\":\"pico_w\",\"fw\":\"0.1.0\",\"pubkey\":\"{pubkey}\",\"uuid\":\"a1b2c3d4e5f60708\"}}\n"
            )
            .into_bytes(),
        );
        assert!(
            set_aggregator_identity(
                &mut stream,
                &"a".repeat(32),
                &"b".repeat(64),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    /// Answers any written line with a canned reply, so the write path is
    /// exercised without a serial port.
    struct EchoAckStub {
        pending: Vec<u8>,
        reply: Vec<u8>,
    }

    impl EchoAckStub {
        fn new(reply: &[u8]) -> Self {
            Self {
                pending: Vec::new(),
                reply: reply.to_vec(),
            }
        }

        fn push_greeting(&mut self, bytes: Vec<u8>) {
            self.pending = bytes;
        }
    }

    impl Read for EchoAckStub {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let source = if self.pending.is_empty() {
                &self.reply
            } else {
                &self.pending
            };
            let count = output.len().min(source.len());
            output[..count].copy_from_slice(&source[..count]);
            if self.pending.is_empty() {
                self.reply.clear();
            } else {
                self.pending.clear();
            }
            Ok(count)
        }
    }

    impl Write for EchoAckStub {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
