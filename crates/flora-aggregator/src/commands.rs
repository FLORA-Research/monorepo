//! The device command queue: parsing what `GET /device/commands` returned.
//!
//! The cloud hands out queued commands by marking them dispatched, so a
//! command that is parsed and then dropped is lost for good. This module
//! therefore parses the whole response up front into a caller-owned array
//! and reports how many were found; the firmware processes every one of
//! them before it polls again.
//!
//! No allocation: each command borrows its id string from the response
//! body, and the three hex fields are decoded into fixed arrays.

use core::fmt::Write as _;

use serde::Deserialize;

/// Most commands one poll accepts, matching the API's per-poll limit.
pub const MAX_COMMANDS: usize = 16;

/// Longest command id (a UUID, hyphenated) accepted.
pub const MAX_ID_LEN: usize = 36;

/// A command as the API sent it, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandWire<'a> {
    /// Command id, used to acknowledge it.
    pub id: &'a str,
    pub kind: u8,
    pub node_addr: u8,
    /// Four payload bytes, exactly as the app signed them.
    pub payload: [u8; 4],
    pub app_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub nonce: u32,
    pub ts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// The body is not the documented `{"commands":[...]}` shape.
    Malformed(&'static str),
    /// A hex field has the wrong length or a non-hex character.
    BadHex(&'static str),
    /// The response held more commands than the caller's array.
    TooManyCommands,
    /// A command object did not fit the struct (missing or extra fields).
    BadCommand,
}

/// The serde view of one command. Borrows the id and hex strings from the
/// response body; every other field is a number and copied.
#[derive(Deserialize)]
struct CommandJson<'a> {
    id: &'a str,
    kind: u8,
    node_addr: u8,
    payload: &'a str,
    app_pubkey: &'a str,
    signature: &'a str,
    nonce: u32,
    ts: u32,
}

/// Parse every command in a poll response.
///
/// Returns the number written into `out`. The caller sees `out[..count]`
/// filled and the rest `None`.
pub fn parse_commands<'a>(
    body: &'a str,
    out: &mut [Option<CommandWire<'a>>],
) -> Result<usize, CommandError> {
    let bytes = body.as_bytes();
    let key = find(bytes, b"\"commands\"").ok_or(CommandError::Malformed("commands key"))?;
    let open = key
        + 10
        + bytes[key + 10..]
            .iter()
            .position(|&b| b == b'[')
            .ok_or(CommandError::Malformed("commands array"))?;
    // `key + 10` is just past the key; the search is relative to that, so
    // add the offset back.
    let open = open.max(key + 10);

    let mut count = 0usize;
    let mut cursor = open + 1;
    while let Some((start, end)) = next_object(bytes, cursor) {
        let slice = core::str::from_utf8(&bytes[start..=end])
            .map_err(|_| CommandError::Malformed("utf-8"))?;
        let (json, _): (CommandJson<'_>, usize) =
            serde_json_core::from_str(slice).map_err(|_| CommandError::BadCommand)?;
        if count == out.len() {
            return Err(CommandError::TooManyCommands);
        }
        out[count] = Some(decode(json)?);
        count += 1;
        cursor = end + 1;
    }
    Ok(count)
}

fn decode<'a>(json: CommandJson<'a>) -> Result<CommandWire<'a>, CommandError> {
    if json.id.len() > MAX_ID_LEN || !json.id.is_ascii() {
        return Err(CommandError::Malformed("id"));
    }
    let mut payload = [0u8; 4];
    unhex_into(json.payload, &mut payload).ok_or(CommandError::BadHex("payload"))?;
    let mut app_pubkey = [0u8; 32];
    unhex_into(json.app_pubkey, &mut app_pubkey).ok_or(CommandError::BadHex("app_pubkey"))?;
    let mut signature = [0u8; 64];
    unhex_into(json.signature, &mut signature).ok_or(CommandError::BadHex("signature"))?;
    Ok(CommandWire {
        id: json.id,
        kind: json.kind,
        node_addr: json.node_addr,
        payload,
        app_pubkey,
        signature,
        nonce: json.nonce,
        ts: json.ts,
    })
}

/// The next `{...}` object at or after `from`, at array depth one.
///
/// Strings are tracked so a brace inside an id or a signature cannot end the
/// object early. Nested objects are skipped as part of their parent.
fn next_object(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut index = from;
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut start = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => {
                if depth == 0 {
                    start = index;
                }
                depth += 1;
            }
            b'}' => {
                if depth == 1 {
                    return Some((start, index));
                }
                depth = depth.saturating_sub(1);
            }
            b']' if depth == 0 => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Decode `hex` into `out`, requiring an exact length.
pub fn unhex_into(hex: &str, out: &mut [u8]) -> Option<()> {
    if hex.len() != out.len() * 2 {
        return None;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        let high = digit(hex.as_bytes()[index * 2])?;
        let low = digit(hex.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(())
}

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Body for `POST /device/commands/{id}/ack`.
pub fn ack_body(applied: bool) -> &'static str {
    if applied {
        "{\"result\":\"applied\"}"
    } else {
        "{\"result\":\"refused\"}"
    }
}

/// Write `/device/commands/{id}/ack` into `out`, returning its length.
pub fn ack_path(id: &str, out: &mut [u8]) -> Option<usize> {
    let mut prefix_len = 0;
    let mut writer = SliceWriter {
        out,
        len: &mut prefix_len,
    };
    write!(&mut writer, "/device/commands/{id}/ack").ok()?;
    Some(prefix_len)
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    len: &'a mut usize,
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
        if end > self.out.len() {
            return Err(core::fmt::Error);
        }
        self.out[*self.len..end].copy_from_slice(text.as_bytes());
        *self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SIGNATURE: &str = "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

    fn body(commands: &str) -> alloc::string::String {
        alloc::format!("{{\"commands\":[{commands}]}}")
    }

    fn one(id: &str) -> alloc::string::String {
        alloc::format!(
            "{{\"id\":\"{id}\",\"kind\":3,\"node_addr\":4,\"payload\":\"01001e00\",\"app_pubkey\":\"{PUBKEY}\",\"signature\":\"{SIGNATURE}\",\"nonce\":7,\"ts\":1700000000}}"
        )
    }

    #[test]
    fn an_empty_queue_parses_to_nothing() {
        let mut out = [None; MAX_COMMANDS];
        assert_eq!(parse_commands("{\"commands\":[]}", &mut out), Ok(0));
    }

    #[test]
    fn a_command_carries_every_signed_field() {
        let body = body(&one("6f1c2a9e-0000-4000-8000-123456789abc"));
        let mut out = [None; MAX_COMMANDS];
        let count = parse_commands(&body, &mut out).unwrap();
        assert_eq!(count, 1);
        let command = out[0].unwrap();
        assert_eq!(command.id, "6f1c2a9e-0000-4000-8000-123456789abc");
        assert_eq!(command.kind, 3);
        assert_eq!(command.node_addr, 4);
        assert_eq!(command.payload, [1, 0, 0x1e, 0]);
        assert_eq!(command.app_pubkey, [0x11; 32]);
        assert_eq!(command.signature, [0x22; 64]);
        assert_eq!(command.nonce, 7);
        assert_eq!(command.ts, 1_700_000_000);
    }

    #[test]
    fn several_commands_keep_their_order() {
        let body = body(&alloc::format!(
            "{},{}",
            one("aaaaaaaa-0000-4000-8000-000000000001"),
            one("bbbbbbbb-0000-4000-8000-000000000002")
        ));
        let mut out = [None; MAX_COMMANDS];
        let count = parse_commands(&body, &mut out).unwrap();
        assert_eq!(count, 2);
        assert!(out[0].unwrap().id.starts_with("aaaa"));
        assert!(out[1].unwrap().id.starts_with("bbbb"));
    }

    #[test]
    fn unknown_fields_and_whitespace_are_tolerated() {
        let command = one("aaaaaaaa-0000-4000-8000-000000000001")
            .replace("\"nonce\"", "\"extra\":{\"a\":1},\"nonce\"");
        let body = alloc::format!("{{\n  \"commands\" : [ {command} ],\n  \"more\": false\n}}");
        let mut out = [None; MAX_COMMANDS];
        assert_eq!(parse_commands(&body, &mut out), Ok(1));
    }

    #[test]
    fn a_brace_inside_a_string_does_not_end_the_object() {
        let mut body = body(&one("aaaaaaaa-0000-4000-8000-000000000001"));
        body = body.replace("aaaaaaaa-0000", "aaaa}aaa-0000");
        let mut out = [None; MAX_COMMANDS];
        let count = parse_commands(&body, &mut out).unwrap();
        assert_eq!(out[0].unwrap().id, "aaaa}aaa-0000-4000-8000-000000000001");
        assert_eq!(count, 1);
    }

    #[test]
    fn a_bad_payload_length_is_refused() {
        let command = one("aaaaaaaa-0000-4000-8000-000000000001").replace("01001e00", "0100");
        let mut out = [None; MAX_COMMANDS];
        assert_eq!(
            parse_commands(&body(&command), &mut out),
            Err(CommandError::BadHex("payload"))
        );
    }

    #[test]
    fn a_non_hex_digit_is_refused() {
        let command = one("aaaaaaaa-0000-4000-8000-000000000001").replace("01001e00", "01001e0z");
        let mut out = [None; MAX_COMMANDS];
        assert_eq!(
            parse_commands(&body(&command), &mut out),
            Err(CommandError::BadHex("payload"))
        );
    }

    #[test]
    fn a_missing_key_is_malformed() {
        let mut out = [None; MAX_COMMANDS];
        assert!(matches!(
            parse_commands("{\"other\":[]}", &mut out),
            Err(CommandError::Malformed(_))
        ));
    }

    #[test]
    fn more_commands_than_the_array_holds_is_an_error() {
        let mut commands = alloc::vec::Vec::new();
        for index in 0..MAX_COMMANDS + 1 {
            commands.push(one(&alloc::format!("aaaaaaaa-0000-4000-8000-{index:012}")));
        }
        let body = body(&commands.join(","));
        let mut out = [None; MAX_COMMANDS];
        assert_eq!(
            parse_commands(&body, &mut out),
            Err(CommandError::TooManyCommands)
        );
    }

    #[test]
    fn the_ack_body_and_path_are_exact() {
        assert_eq!(ack_body(true), "{\"result\":\"applied\"}");
        assert_eq!(ack_body(false), "{\"result\":\"refused\"}");
        let mut path = [0u8; 64];
        let len = ack_path("6f1c2a9e-0000-4000-8000-123456789abc", &mut path).unwrap();
        assert_eq!(
            core::str::from_utf8(&path[..len]).unwrap(),
            "/device/commands/6f1c2a9e-0000-4000-8000-123456789abc/ack"
        );
    }

    #[test]
    fn a_too_short_path_buffer_is_refused() {
        let mut path = [0u8; 8];
        assert!(ack_path("6f1c2a9e-0000-4000-8000-123456789abc", &mut path).is_none());
    }
}
