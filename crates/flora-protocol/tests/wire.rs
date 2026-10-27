//! Batch, provisioning handshake, and QR payload contracts.
//!
//! The batch encoder is pinned two ways: against the exact v1 payload
//! bytes, and against the serde model — the same JSON must parse as the
//! same values on both sides, so the firmware's hand-rolled encoder and
//! the server's serde structs cannot drift apart.

use flora_protocol::{
    Ack, AggregatorHello, Batch, NodeHello, NodeSample, SetIdentity, SetNodeAddress, WireBatch,
    pair_qr_payload, parse_pair_payload,
};

fn sample(node_uuid: [u8; 8], addr: u8) -> NodeSample {
    NodeSample {
        node_uuid,
        addr,
        moisture: 312,
        temperature: 284,
        humidity: 710,
        valve_state: 0,
        sequence: 1042,
        firmware: 256,
    }
}

const GATEWAY: [u8; 16] = *b"agg-0001agg-0001";

/// The exact payload the v1 aggregator encoder produced, byte for byte.
const V1_BATCH: &[u8] = br#"{"gw_id":"6167672d303030316167672d30303031","ts":1717000000,"nodes":[{"uuid":"0202020202020202","addr":2,"moist":312,"temp":284,"hum":710,"valve":0,"seq":1042,"fw_ver":256},{"uuid":"0303030303030303","addr":3,"moist":187,"temp":284,"hum":710,"valve":0,"seq":1042,"fw_ver":256}]}"#;

#[test]
fn firmware_encoder_matches_the_v1_payload_bytes() {
    let mut batch = Batch::new(GATEWAY, 1_717_000_000);
    assert!(batch.push(sample([2; 8], 2)));
    let mut second = sample([3; 8], 3);
    second.moisture = 187;
    assert!(batch.push(second));

    let mut out = [0u8; 1280];
    let len = batch.encode(&mut out).unwrap();
    assert_eq!(&out[..len], V1_BATCH);
}

#[test]
fn encoder_output_parses_as_the_serde_model() {
    // The two representations cannot drift: what the firmware writes is
    // exactly what the server reads.
    let mut batch = Batch::new(GATEWAY, 1_717_000_000);
    let mut node = sample([2; 8], 2);
    node.moisture = u16::MAX; // unavailable sentinel, carried verbatim
    node.temperature = i16::MIN; // unavailable sentinel, carried verbatim
    node.valve_state = 1;
    batch.dropped = 3;
    assert!(batch.push(node));

    let mut out = [0u8; 1280];
    let len = batch.encode(&mut out).unwrap();
    let parsed: WireBatch = serde_json::from_slice(&out[..len]).unwrap();
    assert_eq!(parsed.gw_id, "6167672d303030316167672d30303031");
    assert_eq!(parsed.ts, 1_717_000_000);
    assert_eq!(parsed.dropped, Some(3));
    let wire_node = &parsed.nodes[0];
    assert_eq!(wire_node.uuid, "0202020202020202");
    assert_eq!(wire_node.moist, u16::MAX);
    assert_eq!(wire_node.temp, i16::MIN);
    assert_eq!(wire_node.valve, 1);
    assert_eq!(wire_node.seq, 1042);
    assert_eq!(wire_node.fw_ver, 256);
}

#[test]
fn serde_json_core_parses_the_firmware_bytes_identically() {
    // The device side uses serde-json-core in v1 firmware; the same bytes
    // must decode identically under the host parser. This pins the
    // cross-backend compat contract.
    let mut batch = Batch::new(GATEWAY, 900);
    assert!(batch.push(sample([0xAB; 8], 4)));
    let mut out = [0u8; 1280];
    let len = batch.encode(&mut out).unwrap();

    let host: WireBatch = serde_json::from_slice(&out[..len]).unwrap();
    let (device, consumed) = serde_json_core::from_slice::<WireBatch>(&out[..len]).unwrap();
    assert_eq!(consumed, len);
    assert_eq!(host, device);
}

#[test]
fn a_batch_without_drops_omits_the_field() {
    // v1 behavior: `dropped` appears only when non-zero, so the common
    // case stays small and the absence means "nothing was lost".
    let mut batch = Batch::new(GATEWAY, 5);
    assert!(batch.push(sample([1; 8], 2)));
    let mut out = [0u8; 1280];
    let len = batch.encode(&mut out).unwrap();
    let text = core::str::from_utf8(&out[..len]).unwrap();
    assert!(!text.contains("dropped"));
    let parsed: WireBatch = serde_json::from_slice(&out[..len]).unwrap();
    assert_eq!(parsed.dropped, None);
}

#[test]
fn a_full_batch_encodes_within_the_ceiling() {
    let mut batch = Batch::new(GATEWAY, u32::MAX);
    for i in 0..8 {
        let mut node = sample([(i + 1) as u8; 8], 2 + i as u8);
        node.moisture = u16::MAX;
        node.temperature = i16::MIN;
        node.humidity = u16::MAX;
        node.sequence = u32::MAX;
        batch.push(node);
    }
    assert!(batch.is_full());
    assert!(!batch.push(sample([9; 8], 10)), "ninth sample refused");
    let mut out = [0u8; 1280];
    let len = batch.encode(&mut out).unwrap();
    assert!(len <= 1280);
    // A too-small buffer fails cleanly rather than truncating JSON.
    let mut small = [0u8; 32];
    assert!(batch.encode(&mut small).is_none());
}

#[test]
fn batch_helpers_report_capacity() {
    let mut batch = Batch::new(GATEWAY, 0);
    assert!(batch.is_empty());
    assert!(!batch.is_full());
    for i in 0..8 {
        assert!(batch.push(sample([i as u8; 8], 2)));
    }
    assert!(batch.is_full());
    assert!(!batch.is_empty());
}

#[test]
fn node_greeting_round_trips_through_json() {
    let hello = NodeHello {
        flora_prov: 1,
        hw: "pico",
        fw: "0.1.0",
        uuid: "a1b2c3d4e5f60708",
    };
    let json = serde_json::to_string(&hello).unwrap();
    let parsed: NodeHello = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, hello);
    // The v1 wire shape, field for field.
    assert!(json.contains(r#""flora_prov":1"#));
    assert!(json.contains(r#""hw":"pico""#));
}

#[test]
fn aggregator_greeting_round_trips_through_json() {
    let hello = AggregatorHello {
        flora_prov: 1,
        hw: "pico_w",
        fw: "0.2.0",
        pubkey: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        uuid: "a1b2c3d4e5f60708",
    };
    let json = serde_json::to_string(&hello).unwrap();
    let parsed: AggregatorHello = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, hello);
}

#[test]
fn provisioning_requests_carry_their_command_names() {
    assert_eq!(SetNodeAddress::CMD, "set_node_address");
    assert_eq!(SetIdentity::CMD, "set_identity");

    // A node request: cmd + address, nothing else.
    let request = SetNodeAddress {
        cmd: SetNodeAddress::CMD,
        address: 0x42,
    };
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(json, r#"{"cmd":"set_node_address","address":66}"#);
    let parsed: SetNodeAddress = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.address, 0x42);

    // The v1 bug class this struct exists to kill: an aggregator request
    // missing credentials must fail to deserialize, not silently default
    // to empty strings that would strand the device off the network.
    let request = SetIdentity {
        cmd: SetIdentity::CMD,
        gateway_id: "6167672d303030316167672d30303031",
        device_id: "6167672d303030316167672d30303031",
        device_token: "00112233445566778899aabbccddeeff",
        cloud_url: "https://cloud.flora.example",
        wifi_ssid: "field-net",
        wifi_password: "hunter2",
    };
    let json = serde_json::to_string(&request).unwrap();
    let parsed: SetIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.wifi_ssid, "field-net");

    // Dropping the wifi_password field breaks the parse — the v1
    // `#[serde(default)]` would have accepted it as an empty string.
    let broken: String = json
        .split(',')
        .filter(|field| !field.contains("wifi_password"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(serde_json::from_str::<SetIdentity>(&broken).is_err());
}

#[test]
fn acks_round_trip_with_and_without_errors() {
    let ok = Ack {
        ok: true,
        error: None,
    };
    let json = serde_json::to_string(&ok).unwrap();
    assert_eq!(json, r#"{"ok":true}"#);
    let parsed: Ack = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ok);

    let failed = Ack {
        ok: false,
        error: Some("unknown command"),
    };
    let json = serde_json::to_string(&failed).unwrap();
    let parsed: Ack = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, failed);
}

#[test]
fn qr_payload_builds_and_parses_the_one_shape() {
    let device_id = "630dcd2966c4336691125448bbb25b4f";
    let claim_token = "aabb00112233445566778899aabbccddeeff0011";
    let uuid = "0011223344556677";
    let mut out = [0u8; 256];
    let payload = pair_qr_payload(device_id, claim_token, uuid, &mut out).unwrap();
    assert_eq!(
        core::str::from_utf8(payload).unwrap(),
        "flora://pair?v=1&id=630dcd2966c4336691125448bbb25b4f&ct=aabb00112233445566778899aabbccddeeff0011&u=0011223344556677"
    );

    // Round trip: the app parses exactly this shape.
    let parsed = parse_pair_payload(core::str::from_utf8(payload).unwrap()).unwrap();
    assert_eq!(parsed, (device_id, claim_token, uuid));

    // A short buffer yields None rather than a truncated payload.
    let mut tiny = [0u8; 32];
    assert!(pair_qr_payload(device_id, claim_token, uuid, &mut tiny).is_none());
}

#[test]
fn qr_parser_refuses_foreign_shapes() {
    // Wrong scheme, missing version, unknown fields, missing parts.
    assert!(parse_pair_payload("https://pair?id=x&ct=y&u=z").is_none());
    assert!(parse_pair_payload("flora://pair?v=2&id=x&ct=y&u=z").is_none());
    assert!(parse_pair_payload("flora://pair?v=1&id=x&ct=y").is_none());
    assert!(parse_pair_payload("flora://pair?v=1&id=x&ct=y&u=z&extra=1").is_none());
    assert!(parse_pair_payload("").is_none());
}
