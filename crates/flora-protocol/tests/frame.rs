//! Frame codec pinned against the v1 golden bytes.
//!
//! These literals are copied from the v1 cross-repo vector set, which was
//! itself derived from the protocol document. They exist so a "harmless
//! refactor" of the encoder cannot silently change a byte on the wire:
//! the format is fixed, and the first deployment already has devices
//! speaking it.

use flora_protocol::{
    AGGREGATOR_ADDR, BROADCAST_ADDR, CMD_DATA, CMD_GET_INFO, CMD_INFO, CMD_NACK, CMD_PING,
    CMD_POLL, CMD_SET_THRESHOLD, CMD_SET_VALVE, FIRST_NODE_ADDR, Frame, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, Receiver, SOF, crc16_ccitt_false, decode, encode,
};

fn hex(bytes: &str) -> Vec<u8> {
    bytes
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let nib = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex literal"),
            };
            (nib(p[0]) << 4) | nib(p[1])
        })
        .collect()
}

/// (name, addr, cmd, sequence, payload_hex, frame_hex)
const GOLDEN: &[(&str, u8, u8, u16, &str, &str)] = &[
    ("poll_node_2", 2, CMD_POLL, 1, "", "aa0201000100100a55"),
    (
        "set_valve_open_300_seconds",
        2,
        CMD_SET_VALVE,
        2,
        "01012c",
        "aa020200020301012ce0cb55",
    ),
    (
        "set_threshold_200_700_per_mille",
        3,
        CMD_SET_THRESHOLD,
        258,
        "00c802bc",
        "aa030301020400c802bcc80755",
    ),
    (
        "info_response",
        2,
        CMD_INFO,
        3,
        "a1b2c3d4e5f60708020102",
        "aa028300030ba1b2c3d4e5f6070802010236c055",
    ),
    (
        "sensor_data_response",
        2,
        CMD_DATA,
        4,
        "a1b2c3d4e5f6070801020138011c02c6000f500000041200000e10",
        "aa028200041ba1b2c3d4e5f6070801020138011c02c6000f500000041200000e105ca655",
    ),
    (
        "sensor_data_optional_values_unavailable",
        2,
        CMD_DATA,
        5,
        "a1b2c3d4e5f607080102ffff8000ffff00ffff0000041300000e10",
        "aa028200051ba1b2c3d4e5f607080102ffff8000ffff00ffff0000041300000e10eae955",
    ),
    (
        "broadcast_ping",
        BROADCAST_ADDR,
        CMD_PING,
        5,
        "",
        "aa000500050052bc55",
    ),
    (
        "maximum_payload_and_sequence_wrap_boundary",
        2,
        127,
        65535,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "aa027fffff40000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fada955",
    ),
];

#[test]
fn crc_matches_the_catalog_value() {
    // The reference check value for CRC-16/CCITT-FALSE.
    assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
}

#[test]
fn encodes_every_golden_frame_byte_for_byte() {
    for (name, addr, cmd, sequence, payload_hex, frame_hex) in GOLDEN {
        let payload = hex(payload_hex);
        let expected = hex(frame_hex);
        let frame = Frame {
            addr: *addr,
            cmd: *cmd,
            sequence: *sequence,
            payload: &payload,
        };
        let mut out = [0u8; MAX_FRAME_LEN];
        let len = encode(&frame, &mut out).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(&out[..len], expected, "{name} encode");
    }
}

#[test]
fn decodes_every_golden_frame() {
    for (name, addr, cmd, sequence, payload_hex, frame_hex) in GOLDEN {
        let payload = hex(payload_hex);
        let bytes = hex(frame_hex);
        let frame = decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(frame.addr, *addr, "{name} addr");
        assert_eq!(frame.cmd, *cmd, "{name} cmd");
        assert_eq!(frame.sequence, *sequence, "{name} sequence");
        assert_eq!(frame.payload, payload, "{name} payload");
    }
}

#[test]
fn roundtrips_every_address_and_boundary_length() {
    for addr in [BROADCAST_ADDR, AGGREGATOR_ADDR, FIRST_NODE_ADDR, 0x7F, 0xFE] {
        for len in [0, 1, MAX_PAYLOAD_LEN] {
            let payload = vec![0xA5; len];
            let frame = Frame {
                addr,
                cmd: CMD_GET_INFO,
                sequence: 0xABCD,
                payload: &payload,
            };
            let mut out = [0u8; MAX_FRAME_LEN];
            let n = encode(&frame, &mut out).unwrap();
            let decoded = decode(&out[..n]).unwrap();
            assert_eq!(decoded, frame);
        }
    }
}

#[test]
fn rejects_each_documented_malformation() {
    // Too short.
    assert!(decode(&hex("aa02")).is_err());
    // Bad start.
    assert!(decode(&hex("ab0201000100100a55")).is_err());
    // Reserved address.
    assert!(decode(&hex("aaff01000100000055")).is_err());
    // Payload length over the limit.
    assert!(decode(&hex("aa0201000141000055")).is_err());
    // Length byte does not match the buffer.
    assert!(decode(&hex("aa020100010000000055")).is_err());
    // Bad end marker.
    assert!(decode(&hex("aa0201000100100a54")).is_err());
    // Bad CRC.
    assert!(decode(&hex("aa0201000100100b55")).is_err());
}

#[test]
fn refuses_oversized_and_reserved_encodes() {
    let mut out = [0u8; MAX_FRAME_LEN];

    // Reserved address never goes on the wire.
    let frame = Frame {
        addr: 0xFF,
        cmd: CMD_POLL,
        sequence: 1,
        payload: &[],
    };
    assert!(encode(&frame, &mut out).is_err());

    // One byte over the payload cap is refused, not truncated.
    let payload = [0u8; MAX_PAYLOAD_LEN + 1];
    let frame = Frame {
        addr: FIRST_NODE_ADDR,
        cmd: CMD_POLL,
        sequence: 1,
        payload: &payload,
    };
    assert!(encode(&frame, &mut out).is_err());

    // An output buffer one byte short of the frame is refused.
    let frame = Frame {
        addr: FIRST_NODE_ADDR,
        cmd: CMD_POLL,
        sequence: 1,
        payload: &[],
    };
    let mut tight = [0u8; 8];
    assert!(encode(&frame, &mut tight).is_err());
}

#[test]
fn a_nack_carries_its_reason_in_two_bytes() {
    // The reply shape a node sends for a refused command: NACK, the
    // offending command, the reason code.
    let frame = Frame {
        addr: FIRST_NODE_ADDR,
        cmd: CMD_NACK,
        sequence: 9,
        payload: &[CMD_SET_VALVE, 4],
    };
    let mut out = [0u8; MAX_FRAME_LEN];
    let n = encode(&frame, &mut out).unwrap();
    let decoded = decode(&out[..n]).unwrap();
    assert_eq!(decoded.payload, &[CMD_SET_VALVE, 4]);
}

#[test]
fn receiver_emits_a_frame_only_when_the_length_prefix_is_satisfied() {
    let bytes = hex("aa028200041ba1b2c3d4e5f6070801020138011c02c6000f500000041200000e105ca655");
    let mut receiver = Receiver::new();

    // Every strict prefix before the end yields None...
    for (i, b) in bytes.iter().enumerate() {
        let got = receiver.push(*b);
        if i + 1 < bytes.len() {
            assert!(got.is_none(), "byte {i} completed early");
        } else {
            // ...and the final byte yields exactly the frame.
            assert_eq!(got.unwrap(), &bytes[..], "final byte");
        }
    }
}

#[test]
fn receiver_resyncs_after_reset() {
    let bytes = hex("aa0201000100100a55");
    let mut receiver = Receiver::new();
    // Garbage then a real frame after reset.
    for b in hex("ff00a1") {
        assert!(receiver.push(b).is_none());
    }
    receiver.reset();
    let mut completed = None;
    for b in &bytes {
        completed = receiver.push(*b);
    }
    assert_eq!(completed.unwrap(), &bytes[..]);
}

#[test]
fn receiver_stops_at_buffer_capacity_instead_of_panicking() {
    let mut receiver = Receiver::new();
    for _ in 0..MAX_FRAME_LEN {
        assert!(receiver.push(0xAA).is_none());
    }
    // One past capacity: refused, not an index panic.
    assert!(receiver.push(0x55).is_none());
}

#[test]
fn sof_is_never_a_plausible_payload_byte_prefix() {
    // A property test in miniature: for any payload of SOF bytes, the
    // receiver cannot mistake an interior SOF for a frame start, because
    // completion is decided by the length prefix, not the start marker.
    let payload = [SOF; 10];
    let frame = Frame {
        addr: FIRST_NODE_ADDR,
        cmd: CMD_DATA,
        sequence: 0,
        payload: &payload,
    };
    let mut out = [0u8; MAX_FRAME_LEN];
    let n = encode(&frame, &mut out).unwrap();
    let mut receiver = Receiver::new();
    let mut completed = None;
    for b in &out[..n] {
        completed = receiver.push(*b);
    }
    assert_eq!(completed.unwrap(), &out[..n]);
}
