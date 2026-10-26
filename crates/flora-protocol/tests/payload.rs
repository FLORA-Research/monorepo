//! `DATA` and `INFO` payload layouts pinned to the wire contract, including
//! the v1 golden sensor frame and the unavailable-sentinel round trip.

use flora_protocol::{
    CMD_DATA, SensorFrame, SensorReading, UNAVAILABLE_I16, UNAVAILABLE_U16, data_payload,
    decode_data, decode_info, info_payload,
};

const UUID: [u8; 8] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x08];
/// Firmware 1.0 packed as major<<8 | minor.
const FW_PACKED: u16 = 0x0100;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn data_payload_encodes_the_documented_field_order() {
    // A full reading with all sensors live. Byte layout per
    // docs/protocol.md; the v1 fixture's `fw=0x0102` / `reserved=0x0f50`
    // bytes predate the current layout and are not the contract.
    let reading = SensorReading {
        soil_raw: 0x0138,
        moisture_per_mille: Some(0x0138),
        temperature_deci_c: Some(0x011c),
        humidity_per_mille: Some(0x02c6),
        sequence: 0x00000413,
    };
    let payload = data_payload(&UUID, FW_PACKED, reading, false, 0x00000e10);
    assert_eq!(
        hex(&payload),
        "a1b2c3d4e5f6070801000138011c02c600ffff0000041300000e10"
    );
    // Field-by-field against the documented offsets, so a shift fails
    // loudly with a named field rather than one big hex blob.
    assert_eq!(&payload[0..8], &UUID);
    assert_eq!(&payload[8..10], &FW_PACKED.to_be_bytes());
    assert_eq!(&payload[10..12], &0x0138u16.to_be_bytes());
    assert_eq!(&payload[12..14], &0x011ci16.to_be_bytes());
    assert_eq!(&payload[14..16], &0x02c6u16.to_be_bytes());
    assert_eq!(payload[16], 0);
    assert_eq!(&payload[17..19], &0xFFFFu16.to_be_bytes());
    assert_eq!(&payload[19..23], &0x00000413u32.to_be_bytes());
    assert_eq!(&payload[23..27], &0x00000e10u32.to_be_bytes());
}

fn hex_vec(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let nib = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("bad hex"),
            };
            (nib(p[0]) << 4) | nib(p[1])
        })
        .collect()
}

#[test]
fn unavailable_sensors_round_trip_as_none() {
    // A reading with nothing measurable must encode every optional field
    // as its sentinel and decode back to None — never a plausible number.
    let reading = SensorReading {
        soil_raw: 0,
        moisture_per_mille: None,
        temperature_deci_c: None,
        humidity_per_mille: None,
        sequence: 0x00000413,
    };
    let payload = data_payload(&UUID, FW_PACKED, reading, false, 0x00000e10);
    let decoded = decode_data(&payload).unwrap();

    assert_eq!(decoded.node_uuid, UUID);
    assert_eq!(decoded.fw_ver, FW_PACKED);
    assert_eq!(decoded.moisture_per_mille, None);
    assert_eq!(decoded.temperature_deci_c, None);
    assert_eq!(decoded.humidity_per_mille, None);
    assert!(!decoded.valve_open);
    assert_eq!(decoded.sequence, 0x00000413);
    assert_eq!(decoded.uptime_s, 0x00000e10);
}

#[test]
fn sentinels_go_on_the_wire_exactly_as_documented() {
    // Moisture/humidity: 0xFFFF. Temperature: 0x8000 (i16::MIN).
    // Reserved field 17-18: 0xFFFF.
    let reading = SensorReading::default();
    let payload = data_payload(&UUID, FW_PACKED, reading, false, 0);
    assert_eq!(&payload[10..12], &UNAVAILABLE_U16.to_be_bytes());
    assert_eq!(&payload[12..14], &UNAVAILABLE_I16.to_be_bytes());
    assert_eq!(&payload[14..16], &UNAVAILABLE_U16.to_be_bytes());
    assert_eq!(&payload[17..19], &UNAVAILABLE_U16.to_be_bytes());
}

#[test]
fn a_live_reading_round_trips_exactly() {
    let reading = SensorReading {
        soil_raw: 2048,
        moisture_per_mille: Some(743),
        temperature_deci_c: Some(-53), // -5.3 C, exercises the sign
        humidity_per_mille: Some(911),
        sequence: 0xDEAD_BEEF,
    };
    let payload = data_payload(&UUID, 0x0205, reading, true, 86_400);
    let decoded = decode_data(&payload).unwrap();
    assert_eq!(
        decoded,
        SensorFrame {
            node_uuid: UUID,
            fw_ver: 0x0205,
            moisture_per_mille: Some(743),
            temperature_deci_c: Some(-53),
            humidity_per_mille: Some(911),
            valve_open: true,
            sequence: 0xDEAD_BEEF,
            uptime_s: 86_400,
        }
    );
}

#[test]
fn extreme_values_survive_the_round_trip() {
    // Boundaries of the wire types, both directions.
    for temp in [i16::MIN, i16::MAX, 0] {
        for per_mille in [0, 1, u16::MAX - 1] {
            let reading = SensorReading {
                soil_raw: 0,
                moisture_per_mille: Some(per_mille),
                temperature_deci_c: Some(temp),
                humidity_per_mille: Some(per_mille),
                sequence: u32::MAX,
            };
            let payload = data_payload(&UUID, u16::MAX, reading, true, u32::MAX);
            let decoded = decode_data(&payload).unwrap();
            assert_eq!(decoded.moisture_per_mille, Some(per_mille));
            assert_eq!(decoded.humidity_per_mille, Some(per_mille));
            // i16::MIN is the unavailable sentinel; it cannot be a value.
            if temp == i16::MIN {
                assert_eq!(decoded.temperature_deci_c, None);
            } else {
                assert_eq!(decoded.temperature_deci_c, Some(temp));
            }
            assert_eq!(decoded.sequence, u32::MAX);
            assert_eq!(decoded.uptime_s, u32::MAX);
        }
    }
}

#[test]
fn the_unavailable_sentinel_is_unrepresentable_as_a_value() {
    // 0xFFFF per mille *is* the unavailable marker. Encoding a `Some`
    // with that value is legal (the encoder does not gate it), but the
    // decoder correctly reports it as unavailable — a node must never
    // send 0xFFFF as a real measurement.
    let reading = SensorReading {
        moisture_per_mille: Some(u16::MAX),
        temperature_deci_c: Some(i16::MIN),
        humidity_per_mille: Some(u16::MAX),
        ..SensorReading::default()
    };
    let payload = data_payload(&UUID, FW_PACKED, reading, false, 0);
    let decoded = decode_data(&payload).unwrap();
    assert_eq!(decoded.moisture_per_mille, None);
    assert_eq!(decoded.temperature_deci_c, None);
    assert_eq!(decoded.humidity_per_mille, None);
}

#[test]
fn wrong_lengths_are_refused_not_truncated() {
    // One byte short or long must not decode to a shifted reading.
    let payload = data_payload(&UUID, FW_PACKED, SensorReading::default(), false, 0);
    assert!(decode_data(&payload[..26]).is_none());
    let mut padded = payload.to_vec();
    padded.push(0);
    assert!(decode_data(&padded).is_none());
    assert!(decode_data(&[]).is_none());
}

#[test]
fn info_round_trips_and_rejects_wrong_lengths() {
    let payload = info_payload(&UUID, 0x02, FW_PACKED);
    assert_eq!(&payload[..], &hex_vec("a1b2c3d4e5f60708020100"));
    let decoded = decode_info(&payload).unwrap();
    assert_eq!(decoded.node_uuid, UUID);
    assert_eq!(decoded.address, 0x02);
    assert_eq!(decoded.fw_ver, FW_PACKED);

    assert!(decode_info(&payload[..10]).is_none());
    let mut padded = payload.to_vec();
    padded.push(0);
    assert!(decode_info(&padded).is_none());
}

#[test]
fn data_fits_inside_one_frame_payload() {
    // The whole point of the 27-byte layout: it must fit a frame.
    let payload = data_payload(&UUID, FW_PACKED, SensorReading::default(), false, 0);
    assert!(payload.len() <= flora_protocol::MAX_PAYLOAD_LEN);
    // And the 11-byte INFO body likewise.
    assert!(info_payload(&UUID, 0x02, FW_PACKED).len() <= flora_protocol::MAX_PAYLOAD_LEN);
}

#[test]
fn a_data_body_encodes_in_a_frame_the_aggregator_can_decode() {
    // Cross-module: encode a DATA reply as a frame, decode both layers,
    // the way the aggregator's poll loop will actually consume it.
    let reading = SensorReading {
        soil_raw: 512,
        moisture_per_mille: Some(512),
        temperature_deci_c: Some(284),
        humidity_per_mille: Some(710),
        sequence: 1042,
    };
    let body = data_payload(&UUID, FW_PACKED, reading, false, 3600);
    let frame = flora_protocol::Frame {
        addr: 2,
        cmd: CMD_DATA,
        sequence: 1042,
        payload: &body,
    };
    let mut out = [0u8; flora_protocol::MAX_FRAME_LEN];
    let n = flora_protocol::encode(&frame, &mut out).unwrap();
    let decoded_frame = flora_protocol::decode(&out[..n]).unwrap();
    let decoded = decode_data(decoded_frame.payload).unwrap();
    assert_eq!(decoded.moisture_per_mille, Some(512));
    assert_eq!(decoded.temperature_deci_c, Some(284));
}
