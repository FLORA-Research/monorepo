//! Uplink: how the aggregator delivers a batch to the cloud.
//!
//! Transport decision. The aggregator uploads with an authenticated HTTP POST
//! to the API's `/ingest/batch`, not MQTT.
//!
//! Why, in order of weight:
//!
//! 1. **Reachability.** The cloud sits behind a public HTTPS port; there is no
//!    broker to reach from a field device.
//! 2. **Footprint.** MQTT needs a broker handshake, keep-alives, QoS state
//!    machines, and a retained-session model, all over TLS. An RP2040 with no
//!    allocator gets none of that for free. One POST carrying a token header is
//!    a fraction of the code, flash, and RAM.
//! 3. **Semantics.** This data is inherently batched, periodic, and
//!    store-then-forward. There is no subscriber needing low-latency push, so
//!    publish/subscribe buys nothing a request does not already provide.
//! 4. **Failure handling.** The offline buffer holds batches across an outage,
//!    and a POST that fails is retried from that same buffer, so one retry path
//!    serves both transports.
//!
//! The cost is that the cloud cannot push a command down the same connection.
//! Commands originate in the app, are relayed by the API, and are verified by
//! signature at the aggregator, so they arrive on the poll schedule the
//! aggregator already runs.
//!
//! Everything here is allocation-free: the request is written into a
//! caller-owned buffer, so the firmware needs no global allocator.

use flora_protocol::{Batch, MAX_BATCH_JSON};

/// Path a batch is posted to.
pub const INGEST_PATH: &str = "/ingest/batch";

/// Path the device polls for queued commands.
pub const COMMANDS_PATH: &str = "/device/commands";

/// Method the batch upload uses, fixed so the request builder cannot drift.
pub const INGEST_METHOD: &str = "POST";

/// Content type of a batch body.
pub const CONTENT_TYPE: &str = "application/json";

/// Room for the request head: request line, host, a 32-byte device id, a
/// 64-character token, and the fixed headers.
pub const MAX_HEAD_BYTES: usize = 512;

/// Room for head plus the largest batch body.
pub const MAX_REQUEST_BYTES: usize = MAX_HEAD_BYTES + MAX_BATCH_JSON;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UplinkState {
    /// The device is provisioned and has somewhere to send.
    Ready,
    /// No cloud endpoint or credentials yet; batches accumulate.
    Unconfigured,
    /// The last attempt failed; the batch stays buffered.
    Retrying { attempts: u8 },
    /// Credentials were rejected. Retrying will not help.
    Rejected,
}

/// Everything the aggregator needs to deliver a batch.
///
/// Held in flash after provisioning. The token is the device token written by
/// `set_identity`, sent as `Authorization: Device <device_id>:<token_hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UplinkConfig<'a> {
    /// Base URL, for example `https://flora-api.onrender.com`.
    pub base_url: &'a str,
    pub device_id: &'a str,
    /// Hex-encoded 32-byte device token.
    pub device_token_hex: &'a str,
}

impl UplinkConfig<'_> {
    /// Whether the configuration is complete enough to attempt a request.
    pub fn is_ready(&self) -> bool {
        !self.base_url.trim().is_empty()
            && !self.device_id.trim().is_empty()
            && self.device_token_hex.len() == 64
    }

    /// Host portion of the base URL, stripping any scheme and trailing slash.
    ///
    /// Public because the firmware needs it to open the socket.
    pub fn host(&self) -> &str {
        self.base_url
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
    }

    /// Port the endpoint listens on, from an explicit `:port` in the URL.
    ///
    /// `None` means "the default for the scheme", which the caller resolves:
    /// the firmware speaks plaintext only, so the documented deferral is 80.
    pub fn port(&self) -> Option<u16> {
        let host = self.host();
        let (_, port) = host.rsplit_once(':')?;
        port.parse().ok()
    }

    /// Whether the endpoint is encrypted.
    ///
    /// The device token is a bearer credential, so sending it over plaintext
    /// would hand it to anyone on the path. Local development may use http, so
    /// this is reported rather than enforced, and the caller logs it.
    pub fn is_encrypted(&self) -> bool {
        self.base_url.trim().starts_with("https://")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    /// The supplied buffer cannot hold the request head.
    TooSmall,
}

/// Write the request head into `out`, returning its length.
///
/// Returned without a body: the caller writes the encoded batch immediately
/// after, so the payload is never copied.
pub fn write_request_head(
    config: &UplinkConfig<'_>,
    body_len: usize,
    out: &mut [u8],
) -> Result<usize, HeadError> {
    write_request(INGEST_METHOD, INGEST_PATH, config, body_len, out)
}

/// Write `METHOD PATH HTTP/1.1` plus the device's headers into `out`.
///
/// Shared by the batch upload, the command poll, and the command ack so the
/// credential header cannot be spelled differently in one of them.
pub fn write_request(
    method: &str,
    path: &str,
    config: &UplinkConfig<'_>,
    body_len: usize,
    out: &mut [u8],
) -> Result<usize, HeadError> {
    let mut writer = Writer { out, len: 0 };
    writer.push(method.as_bytes())?;
    writer.push(b" ")?;
    writer.push(path.as_bytes())?;
    writer.push(b" HTTP/1.1\r\nHost: ")?;
    writer.push(config.host().as_bytes())?;
    writer.push(b"\r\nAuthorization: Device ")?;
    writer.push(config.device_id.as_bytes())?;
    writer.push(b":")?;
    writer.push(config.device_token_hex.as_bytes())?;
    writer.push(b"\r\nContent-Type: ")?;
    writer.push(CONTENT_TYPE.as_bytes())?;
    writer.push(b"\r\nContent-Length: ")?;
    writer.push_u64(body_len as u64)?;
    writer.push(b"\r\nConnection: close\r\n\r\n")?;
    Ok(writer.len)
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn push(&mut self, part: &[u8]) -> Result<(), HeadError> {
        let end = self
            .len
            .checked_add(part.len())
            .ok_or(HeadError::TooSmall)?;
        if end > self.out.len() {
            return Err(HeadError::TooSmall);
        }
        self.out[self.len..end].copy_from_slice(part);
        self.len = end;
        Ok(())
    }

    fn push_u64(&mut self, value: u64) -> Result<(), HeadError> {
        let mut digits = [0u8; 20];
        let mut count = 0;
        let mut remaining = value;
        loop {
            digits[count] = b'0' + (remaining % 10) as u8;
            count += 1;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        for index in (0..count).rev() {
            self.push(&[digits[index]])?;
        }
        Ok(())
    }
}

/// Decide what to do after an attempt.
///
/// A 4xx means the request itself is wrong (bad token, malformed batch), so
/// retrying it unchanged would loop forever and burn the device's power. Only
/// transport failures and 5xx are worth another attempt.
pub fn next_state(status: Option<u16>, attempts: u8) -> UplinkState {
    match status {
        Some(code) if (200..300).contains(&code) => UplinkState::Ready,
        Some(400..=499) => UplinkState::Rejected,
        Some(_) => UplinkState::Retrying {
            attempts: attempts.saturating_add(1),
        },
        // No response at all: the radio or the network failed.
        None => UplinkState::Retrying {
            attempts: attempts.saturating_add(1),
        },
    }
}

/// Backoff before the next attempt, in seconds.
///
/// Bounded so a long outage cannot stretch the retry interval past the uplink
/// period, and so the device never sleeps through a reconnect.
pub fn backoff_seconds(attempts: u8) -> u64 {
    match attempts {
        0 => 0,
        1 => 5,
        2 => 15,
        3 => 60,
        _ => 300,
    }
}

/// Encode a batch body into `out`, returning its length.
pub fn encode_body(batch: &Batch, out: &mut [u8]) -> Option<usize> {
    batch.encode(out)
}

/// Status code out of `HTTP/1.1 <code> ...`.
pub fn parse_status(response: &[u8]) -> Option<u16> {
    let line_end = response.iter().position(|&b| b == b'\r')?;
    let mut parts = response[..line_end].split(|&b| b == b' ');
    parts.next()?;
    let code = parts.next()?;
    core::str::from_utf8(code).ok()?.parse().ok()
}

/// Split a response into the status code and body.
///
/// Returns `None` when the head is incomplete. The body is whatever followed
/// the blank line, which is all the command poll needs: the API answers with
/// `Connection: close`, so "until the socket ends" is the frame.
pub fn split_response(response: &[u8]) -> Option<(u16, &[u8])> {
    let status = parse_status(response)?;
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        + 4;
    Some((status, &response[head_end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::{String, ToString};

    const TOKEN: &str = "abababababababababababababababababababababababababababababababab";

    fn config() -> UplinkConfig<'static> {
        UplinkConfig {
            base_url: "https://flora-api.onrender.com",
            device_id: "6167672d30303031",
            device_token_hex: TOKEN,
        }
    }

    fn head(config: &UplinkConfig<'_>, body_len: usize) -> String {
        let mut out = [0u8; MAX_HEAD_BYTES];
        let len = write_request_head(config, body_len, &mut out).unwrap();
        core::str::from_utf8(&out[..len]).unwrap().to_string()
    }

    #[test]
    fn a_complete_configuration_is_ready_and_encrypted() {
        assert!(config().is_ready());
        assert!(config().is_encrypted());
        assert!(
            !UplinkConfig {
                base_url: "http://localhost:8080",
                ..config()
            }
            .is_encrypted()
        );
    }

    #[test]
    fn an_incomplete_configuration_is_not_ready() {
        for config in [
            UplinkConfig {
                base_url: "",
                ..config()
            },
            UplinkConfig {
                device_id: " ",
                ..config()
            },
            UplinkConfig {
                device_token_hex: "abcd",
                ..config()
            },
        ] {
            assert!(!config.is_ready());
        }
    }

    #[test]
    fn the_head_carries_the_token_and_the_body_length() {
        let head = head(&config(), 42);
        assert!(
            head.starts_with("POST /ingest/batch HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.contains("\r\nHost: flora-api.onrender.com\r\n"),
            "{head}"
        );
        assert!(
            head.contains(&format!(
                "\r\nAuthorization: Device 6167672d30303031:{TOKEN}\r\n"
            )),
            "{head}"
        );
        assert!(head.contains("\r\nContent-Type: application/json\r\n"));
        assert!(head.contains("\r\nContent-Length: 42\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_small_buffer_is_refused_rather_than_truncated() {
        let mut out = [0u8; 40];
        assert_eq!(
            write_request_head(&config(), 0, &mut out),
            Err(HeadError::TooSmall)
        );
    }

    #[test]
    fn scheme_and_trailing_slash_do_not_leak_into_the_host() {
        for base in [
            "https://flora.example",
            "https://flora.example/",
            "http://flora.example",
            "  flora.example  ",
        ] {
            assert_eq!(
                UplinkConfig {
                    base_url: base,
                    ..config()
                }
                .host(),
                "flora.example"
            );
        }
    }

    #[test]
    fn an_explicit_port_is_read_from_the_url() {
        assert_eq!(config().port(), None);
        let local = UplinkConfig {
            base_url: "http://192.168.1.10:8080",
            ..config()
        };
        assert_eq!(local.host(), "192.168.1.10:8080");
        assert_eq!(local.port(), Some(8080));
        assert!(!local.is_encrypted());
    }

    #[test]
    fn success_keeps_the_device_ready_and_4xx_stops_it() {
        assert_eq!(next_state(Some(200), 3), UplinkState::Ready);
        assert_eq!(next_state(Some(204), 0), UplinkState::Ready);
        assert_eq!(next_state(Some(400), 0), UplinkState::Rejected);
        assert_eq!(next_state(Some(401), 2), UplinkState::Rejected);
        assert_eq!(
            next_state(Some(503), 1),
            UplinkState::Retrying { attempts: 2 }
        );
        assert_eq!(next_state(None, 0), UplinkState::Retrying { attempts: 1 });
    }

    #[test]
    fn backoff_is_bounded() {
        assert_eq!(backoff_seconds(0), 0);
        assert_eq!(backoff_seconds(1), 5);
        assert_eq!(backoff_seconds(2), 15);
        assert_eq!(backoff_seconds(3), 60);
        assert_eq!(backoff_seconds(4), 300);
        assert_eq!(backoff_seconds(255), 300);
    }

    #[test]
    fn a_body_is_encoded_where_the_head_ended() {
        let mut batch = Batch::new(*b"agg-0001agg-0001", 1_700_000_000);
        assert!(batch.push(flora_protocol::NodeSample {
            node_uuid: [7; 8],
            addr: 4,
            moisture: 300,
            temperature: 212,
            humidity: 480,
            valve_state: 0,
            sequence: 1,
            firmware: 0x0100,
        }));
        let mut body = [0u8; MAX_BATCH_JSON];
        let len = encode_body(&batch, &mut body).unwrap();
        let json = core::str::from_utf8(&body[..len]).unwrap();
        assert!(
            json.contains("\"gw_id\":\"6167672d303030316167672d30303031\""),
            "{json}"
        );
        assert!(json.contains("\"addr\":4"), "{json}");
    }

    #[test]
    fn a_response_is_split_at_the_blank_line() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"commands\":[]}";
        let (status, body) = split_response(response).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"commands\":[]}");
    }

    #[test]
    fn a_status_line_is_parsed_or_rejected() {
        assert_eq!(parse_status(b"HTTP/1.1 204 No Content\r\n"), Some(204));
        assert_eq!(parse_status(b"HTTP/1.1 nope\r\n"), None);
        assert_eq!(parse_status(b"garbage"), None);
    }
}
