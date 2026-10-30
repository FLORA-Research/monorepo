//! Registration with the cloud.
//!
//! The firmware learns its identity over the serial link; the cloud needs
//! the *hashes* of the same secrets plus the public key, so it can
//! recognise the device when it uplinks and can hand the device to whoever
//! scans the QR.
//!
//! Nothing here sends a secret. The device token is sent as its SHA-256
//! hash and the claim token likewise, so a compromised server or a logged
//! request cannot yield a credential that works on the serial link.
//!
//! The HTTP client is hand-rolled over `std::net::TcpStream` rather than
//! pulled in as a dependency: the provisioner is a synchronous,
//! single-request CLI, and a TLS stack would be by far its largest
//! dependency for one POST.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};

use crate::identity;

/// The path the cloud exposes for device registration.
pub const REGISTER_PATH: &str = "/provision/register";

/// Longest response body accepted, so a hostile or broken peer cannot exhaust
/// memory.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// What the cloud needs to know about a freshly provisioned aggregator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub device_id: String,
    /// Hex Ed25519 public key, as the firmware reported it.
    pub pubkey: String,
    /// Hex SHA-256 of the device token.
    pub token_hash: String,
    /// Hex SHA-256 of the claim token.
    pub claim_hash: String,
    pub hw: String,
    pub fw: String,
    pub label: String,
}

impl Registration {
    /// Build the request body.
    ///
    /// Field names match the cloud's `RegisterRequest` exactly; a mismatch here
    /// is a 400 that says nothing useful, so the pairing is pinned by a test.
    pub fn body(&self) -> String {
        serde_json::json!({
            "device_id": self.device_id,
            "pubkey": self.pubkey,
            "token_hash": self.token_hash,
            "claim_hash": self.claim_hash,
            "hw": self.hw,
            "fw_ver": self.fw,
            "label": self.label,
        })
        .to_string()
    }
}

/// Register a device with the cloud.
///
/// `api_key` is the provisioning API key, which authorises the act of
/// registering. It is deliberately a separate credential from the device token:
/// one admits an operator, the other identifies a device.
pub fn register(
    base_url: &str,
    api_key: &str,
    registration: &Registration,
    timeout: Duration,
) -> Result<String> {
    ensure!(!api_key.trim().is_empty(), "provisioning API key is empty");
    let (host, port, secure) = split_base_url(base_url)?;
    if secure {
        bail!(
            "cloud base URL is https, which this build cannot reach: the provisioner \
             has no TLS stack. Point it at the local server over http, or register \
             from a tool that has one"
        );
    }

    let body = registration.body();
    let request = format!(
        "POST {REGISTER_PATH} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Authorization: Bearer {api_key}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         User-Agent: flora-provision/{version}\r\n\
         \r\n\
         {body}",
        len = body.len(),
        version = env!("CARGO_PKG_VERSION"),
    );

    let address = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&address)
        .with_context(|| format!("cannot reach the cloud at {address}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream
        .write_all(request.as_bytes())
        .context("sending the registration request")?;
    stream.flush()?;

    let response = read_response(&mut stream)?;
    let status = parse_status(&response)?;
    let payload = response_body(&response);
    match status {
        200 | 201 => Ok(payload.to_string()),
        401 | 403 => bail!(
            "the cloud rejected the provisioning key (HTTP {status}). Check \
             FLORA_PROVISION_API_KEY against the server's PROVISION_API_KEY_HASH"
        ),
        _ => bail!("the cloud refused registration (HTTP {status}): {payload}"),
    }
}

/// Split `scheme://host[:port]` into its parts, defaulting the port by scheme.
fn split_base_url(base_url: &str) -> Result<(String, u16, bool)> {
    let trimmed = base_url.trim().trim_end_matches('/');
    let (secure, rest) = if let Some(rest) = trimmed.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("cloud URL must start with http:// or https://");
    };
    ensure!(!rest.is_empty(), "cloud URL has no host");
    // A path component is not expected, but tolerate one rather than failing.
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().context("cloud URL port is not a number")?;
            Ok((host.to_string(), port, secure))
        }
        None => Ok((authority.to_string(), if secure { 443 } else { 80 }, secure)),
    }
}

/// Read the whole response, bounded so a broken peer cannot exhaust memory.
fn read_response(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                buffer.extend_from_slice(&chunk[..count]);
                if buffer.len() >= MAX_RESPONSE_BYTES {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error).context("reading the cloud response"),
        }
    }
    ensure!(
        !buffer.is_empty(),
        "the cloud closed the connection without replying"
    );
    Ok(buffer)
}

/// The status code from the first line: `HTTP/1.1 200 OK`.
fn parse_status(response: &[u8]) -> Result<u16> {
    let head = String::from_utf8_lossy(response);
    let first = head.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let _http = parts.next();
    let code = parts.next().unwrap_or_default();
    code.parse()
        .with_context(|| format!("the cloud reply had no HTTP status: {first:?}"))
}

/// Everything after the blank line that ends the headers.
fn response_body(response: &[u8]) -> &str {
    let text = match std::str::from_utf8(response) {
        Ok(text) => text,
        Err(_) => return "",
    };
    match text.find("\r\n\r\n") {
        Some(index) => text[index + 4..].trim(),
        None => "",
    }
}

/// A claim token: 32 random bytes, hex-encoded.
///
/// This is the secret a phone presents to claim the device. It is shown once, in
/// the QR, and the cloud keeps only its hash.
pub fn generate_claim_token() -> Result<String> {
    identity::generate_device_token()
}

/// The payload a phone scans, via the shared protocol encoder.
///
/// The app parses exactly one shape, so the provisioner must emit through
/// `flora_protocol::pair_qr_payload` rather than its own format string.
pub fn qr_payload(device_id: &str, claim_token: &str, uuid: &str) -> Result<String> {
    let mut buffer = [0u8; 256];
    let bytes = flora_protocol::pair_qr_payload(device_id, claim_token, uuid, &mut buffer)
        .context("pairing payload exceeds the buffer")?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> Registration {
        Registration {
            device_id: "6167672d303030316167672d30303031".into(),
            pubkey: "aa".repeat(32),
            token_hash: "bb".repeat(32),
            claim_hash: "cc".repeat(32),
            hw: "pico_w".into(),
            fw: "0.1.0".into(),
            label: "plot-north".into(),
        }
    }

    #[test]
    fn the_body_uses_the_cloud_field_names_exactly() {
        // A renamed field is a 400 with no useful message, so the names are
        // pinned here rather than discovered against a live server.
        let body: serde_json::Value =
            serde_json::from_str(&registration().body()).expect("valid json");
        for key in [
            "device_id",
            "pubkey",
            "token_hash",
            "claim_hash",
            "hw",
            "fw_ver",
            "label",
        ] {
            assert!(body.get(key).is_some(), "missing field {key}: {body}");
        }
        assert_eq!(body["fw_ver"], "0.1.0");
        assert_eq!(body["device_id"], "6167672d303030316167672d30303031");
    }

    #[test]
    fn the_qr_payload_matches_the_cloud_side_encoder() {
        // The app parses one shape only, so this must agree with
        // `flora_protocol::pair_qr_payload` byte for byte.
        let payload = qr_payload("abc123", "deadbeef", "0202020202020202").unwrap();
        assert_eq!(
            payload,
            "flora://pair?v=1&id=abc123&ct=deadbeef&u=0202020202020202"
        );
        let parsed = flora_protocol::parse_pair_payload(&payload).unwrap();
        assert_eq!(parsed, ("abc123", "deadbeef", "0202020202020202"));
    }

    #[test]
    fn claim_tokens_are_unique_and_the_right_length() {
        let first = generate_claim_token().unwrap();
        let second = generate_claim_token().unwrap();
        assert_eq!(first.len(), 64, "32 bytes as hex");
        assert_ne!(first, second, "two claims must not collide");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base_urls_split_with_the_right_default_port() {
        assert_eq!(
            split_base_url("http://127.0.0.1:8080").unwrap(),
            ("127.0.0.1".into(), 8080, false)
        );
        assert_eq!(
            split_base_url("http://example.test").unwrap(),
            ("example.test".into(), 80, false)
        );
        assert_eq!(
            split_base_url("https://example.test").unwrap(),
            ("example.test".into(), 443, true)
        );
        // A trailing slash is common when copying a URL and must not break it.
        assert_eq!(
            split_base_url("http://example.test:9000/").unwrap(),
            ("example.test".into(), 9000, false)
        );
        assert!(split_base_url("example.test").is_err());
    }

    #[test]
    fn an_https_target_is_refused_rather_than_attempted_in_clear() {
        // The provisioner has no TLS stack. Silently sending the API key in
        // clear to port 443 would be worse than refusing.
        let error = register(
            "https://cloud.example",
            "key",
            &registration(),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS"),
            "the refusal must name the reason: {error}"
        );
    }

    #[test]
    fn a_reply_is_split_into_status_and_body() {
        let reply = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        assert_eq!(parse_status(reply).unwrap(), 201);
        assert_eq!(response_body(reply), "{\"ok\":true}");
        assert!(parse_status(b"garbage").is_err());
    }
}
