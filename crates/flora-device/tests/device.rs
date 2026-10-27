//! Node role behavior: command dispatch, safety NACKs, and the retry
//! cache. A retried transaction must never re-execute a side effect.

use flora_device::{NodeProcessor, Response, nack_for};
use flora_drivers::{IrrigationController, NodeConfig};
use flora_protocol::{
    BROADCAST_ADDR, CMD_ACK, CMD_CALIBRATE, CMD_DATA, CMD_GET_INFO, CMD_INFO, CMD_NACK, CMD_PING,
    CMD_POLL, CMD_SET_ADDRESS, CMD_SET_THRESHOLD, CMD_SET_VALVE, Frame, SensorReading,
    UNAVAILABLE_U16,
};

const UUID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08];

fn config() -> NodeConfig {
    NodeConfig {
        address: 2,
        soil_dry_adc: 3200,
        soil_wet_adc: 1200,
        min_off_s: 0,
        ..NodeConfig::default()
    }
}

fn reading() -> SensorReading {
    SensorReading {
        soil_raw: 3100,
        moisture_per_mille: Some(50),
        temperature_deci_c: Some(284),
        humidity_per_mille: Some(710),
        sequence: 1042,
    }
}

fn run(
    processor: &mut NodeProcessor,
    config: &mut NodeConfig,
    irrigation: &mut IrrigationController,
    cmd: u8,
    sequence: u16,
    payload: &[u8],
    now_s: u32,
) -> Option<Response> {
    let frame = Frame {
        addr: config.address,
        cmd,
        sequence,
        payload,
    };
    processor.process(frame, config, reading(), irrigation, UUID, now_s)
}

#[test]
fn poll_returns_a_data_frame_in_field_order() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    let response = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_POLL,
        1,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(response.cmd, CMD_DATA);
    assert_eq!(response.addr, 2);
    assert_eq!(response.sequence, 1);
    assert_eq!(response.payload_len, 27);
    assert_eq!(&response.payload[0..8], &UUID);
    // fw packed
    assert_eq!(
        u16::from_be_bytes([response.payload[8], response.payload[9]]),
        flora_drivers::FW_PACKED
    );
    // moisture per mille
    assert_eq!(
        u16::from_be_bytes([response.payload[10], response.payload[11]]),
        50
    );
    // temp deci-C
    assert_eq!(
        i16::from_be_bytes([response.payload[12], response.payload[13]]),
        284
    );
    // humidity per mille
    assert_eq!(
        u16::from_be_bytes([response.payload[14], response.payload[15]]),
        710
    );
    // reserved field: unavailable
    assert_eq!(
        u16::from_be_bytes([response.payload[17], response.payload[18]]),
        UNAVAILABLE_U16
    );
    // sample sequence
    assert_eq!(response.payload[19..23], 1042u32.to_be_bytes());
    // uptime
    assert_eq!(response.payload[23..27], 0u32.to_be_bytes());
}

#[test]
fn get_info_returns_identity_and_address() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    let response = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_GET_INFO,
        3,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(response.cmd, CMD_INFO);
    assert_eq!(response.payload_len, 11);
    assert_eq!(&response.payload[0..8], &UUID);
    assert_eq!(response.payload[8], 2);
    assert_eq!(
        u16::from_be_bytes([response.payload[9], response.payload[10]]),
        flora_drivers::FW_PACKED
    );
}

#[test]
fn frames_for_other_nodes_and_broadcasts_are_ignored() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);

    // A frame for another node is not ours to answer.
    let foreign = processor.process(
        Frame {
            addr: 9,
            cmd: CMD_POLL,
            sequence: 1,
            payload: &[],
        },
        &mut config,
        reading(),
        &mut irrigation,
        UUID,
        0,
    );
    assert!(foreign.is_none());

    // Broadcasts are processed for their side effects but never answered.
    let broadcast = processor.process(
        Frame {
            addr: BROADCAST_ADDR,
            cmd: CMD_PING,
            sequence: 2,
            payload: &[],
        },
        &mut config,
        reading(),
        &mut irrigation,
        UUID,
        0,
    );
    assert!(broadcast.is_none());
}

#[test]
fn duplicate_retry_reuses_the_cached_reply() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    let first = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_GET_INFO,
        7,
        &[],
        0,
    )
    .unwrap();
    // A valve command must not slip in between a retry of the same
    // transaction: the cached reply is returned, not a re-execution.
    let retry = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_GET_INFO,
        7,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(first, retry);
}

#[test]
fn a_different_command_with_the_same_sequence_is_not_a_retry() {
    // Sequence numbers are per transaction, not per bus; a new command
    // with a reused sequence must be dispatched, not served from cache.
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    let first = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_GET_INFO,
        7,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(first.cmd, CMD_INFO);
    let second = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_POLL,
        7,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(second.cmd, CMD_DATA);
}

#[test]
fn valve_open_is_timed_and_rejects_bad_durations() {
    let mut processor = NodeProcessor::default();
    let mut config = NodeConfig {
        min_off_s: 3,
        max_runtime_s: 5,
        ..config()
    };
    let mut irrigation = IrrigationController::new(0);

    // Open for zero seconds is refused.
    let rejected = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_VALVE,
        1,
        &[1, 0x00, 0x00],
        0,
    )
    .unwrap();
    assert_eq!(rejected.cmd, CMD_NACK);
    assert_eq!(
        rejected.payload[1],
        flora_device::node::NACK_SAFETY_REJECTED
    );

    let accepted = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_VALVE,
        2,
        &[1, 0x00, 0x04],
        3,
    )
    .unwrap();
    assert_eq!(accepted.cmd, CMD_ACK);
    assert!(irrigation.is_open());

    let closed = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_VALVE,
        3,
        &[0, 0x00, 0x00],
        4,
    )
    .unwrap();
    assert_eq!(closed.cmd, CMD_ACK);
    assert!(!irrigation.is_open());
}

#[test]
fn threshold_command_rejects_an_inverted_band() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);

    let accepted = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_THRESHOLD,
        1,
        &[0x00, 0xC8, 0x02, 0xBC],
        0,
    )
    .unwrap();
    assert_eq!(accepted.cmd, CMD_ACK);
    assert_eq!(config.dry_threshold, 200);
    assert_eq!(config.wet_threshold, 700);

    let rejected = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_THRESHOLD,
        2,
        &[0x02, 0xBC, 0x00, 0xC8],
        0,
    )
    .unwrap();
    assert_eq!(rejected.cmd, CMD_NACK);
    assert_eq!(
        rejected.payload[1],
        flora_device::node::NACK_INVALID_PAYLOAD
    );
    assert_eq!(
        config.dry_threshold, 200,
        "rejected command must not mutate config"
    );
}

#[test]
fn calibration_captures_both_references_from_live_samples() {
    let mut processor = NodeProcessor::default();
    let mut config = NodeConfig {
        address: 2,
        ..NodeConfig::default()
    };
    let mut irrigation = IrrigationController::new(0);

    // Dry reference: probe in air.
    let dry = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_CALIBRATE,
        1,
        &[0],
        0,
    )
    .unwrap();
    assert_eq!(dry.cmd, CMD_ACK);
    assert_eq!(config.soil_dry_adc, 3100);
    assert!(
        !config.soil_calibrated(),
        "one reference alone is not a scale"
    );

    // Wet reference: probe in water. The opposite polarity is legitimate.
    let mut wet_reading = reading();
    wet_reading.soil_raw = 1500;
    let wet = processor
        .process(
            Frame {
                addr: 2,
                cmd: CMD_CALIBRATE,
                sequence: 2,
                payload: &[1],
            },
            &mut config,
            wet_reading,
            &mut irrigation,
            UUID,
            0,
        )
        .unwrap();
    assert_eq!(wet.cmd, CMD_ACK, "either probe polarity is valid");
    assert_eq!(config.soil_wet_adc, 1500);
    assert!(config.soil_calibrated());
}

#[test]
fn calibration_refuses_identical_references() {
    let mut processor = NodeProcessor::default();
    let mut config = NodeConfig {
        address: 2,
        soil_dry_adc: 3100,
        ..NodeConfig::default()
    };
    let mut irrigation = IrrigationController::new(0);
    let rejected = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_CALIBRATE,
        1,
        &[1],
        0,
    )
    .unwrap();
    assert_eq!(rejected.cmd, CMD_NACK);
    assert_eq!(
        rejected.payload[1],
        flora_device::node::NACK_SAFETY_REJECTED
    );
    assert_eq!(
        config.soil_wet_adc, UNAVAILABLE_U16,
        "config must be unchanged"
    );
}

#[test]
fn calibration_refuses_an_unusable_adc_sample() {
    let mut processor = NodeProcessor::default();
    let mut config = NodeConfig {
        address: 2,
        ..NodeConfig::default()
    };
    let mut irrigation = IrrigationController::new(0);
    let mut broken = reading();
    broken.soil_raw = UNAVAILABLE_U16;
    let rejected = processor
        .process(
            Frame {
                addr: 2,
                cmd: CMD_CALIBRATE,
                sequence: 1,
                payload: &[0],
            },
            &mut config,
            broken,
            &mut irrigation,
            UUID,
            0,
        )
        .unwrap();
    assert_eq!(rejected.cmd, CMD_NACK);
    assert_eq!(config.soil_dry_adc, UNAVAILABLE_U16);
}

#[test]
fn set_address_moves_the_node() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    let response = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_ADDRESS,
        1,
        &[9],
        0,
    )
    .unwrap();
    assert_eq!(response.cmd, CMD_ACK);
    assert_eq!(config.address, 9);

    // The old address no longer answers.
    let at_old = processor.process(
        Frame {
            addr: 2,
            cmd: CMD_POLL,
            sequence: 2,
            payload: &[],
        },
        &mut config,
        reading(),
        &mut irrigation,
        UUID,
        0,
    );
    assert!(at_old.is_none());
}

#[test]
fn unknown_opcode_and_malformed_payloads_are_nacked() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);

    let unsupported = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        0x7F,
        1,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(unsupported.cmd, CMD_NACK);
    assert_eq!(
        &unsupported.payload[..2],
        [0x7F, flora_device::node::NACK_UNSUPPORTED]
    );

    let malformed = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_VALVE,
        2,
        &[1],
        0,
    )
    .unwrap();
    assert_eq!(
        &malformed.payload[..2],
        [CMD_SET_VALVE, flora_device::node::NACK_INVALID_PAYLOAD]
    );

    // A reserved address is never assignable.
    let bad_address = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_ADDRESS,
        3,
        &[0xFF],
        0,
    )
    .unwrap();
    assert_eq!(
        &bad_address.payload[..2],
        [CMD_SET_ADDRESS, flora_device::node::NACK_INVALID_PAYLOAD]
    );
}

#[test]
fn poll_with_a_payload_is_nacked_not_ignored() {
    // POLL must be empty; a poll with trailing bytes is a protocol
    // violation, and the coordinator needs the NACK to distinguish
    // "node broken" from "node gone".
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    let rejected = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_POLL,
        1,
        &[0x00],
        0,
    )
    .unwrap();
    assert_eq!(rejected.cmd, CMD_NACK);
}

#[test]
fn replaced_cached_response_is_returned_on_retry() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);

    let applied = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_THRESHOLD,
        5,
        &[0x00, 0xC8, 0x02, 0xBC],
        0,
    )
    .unwrap();
    assert_eq!(applied.cmd, CMD_ACK);

    // Simulate a failed persistence: the caller swaps in a BUSY NACK.
    let busy = nack_for(2, CMD_SET_THRESHOLD, 5, flora_device::node::NACK_BUSY);
    processor.replace_cached_response(busy);
    let retry = run(
        &mut processor,
        &mut config,
        &mut irrigation,
        CMD_SET_THRESHOLD,
        5,
        &[0x00, 0xC8, 0x02, 0xBC],
        0,
    )
    .unwrap();
    assert_eq!(retry, busy);
}

#[test]
fn ping_has_no_reply() {
    let mut processor = NodeProcessor::default();
    let mut config = config();
    let mut irrigation = IrrigationController::new(0);
    assert!(
        run(
            &mut processor,
            &mut config,
            &mut irrigation,
            CMD_PING,
            1,
            &[],
            0
        )
        .is_none()
    );
}

#[test]
fn response_new_copies_and_truncates_to_capacity() {
    // A payload beyond MAX_PAYLOAD_LEN is truncated at the capacity
    // boundary rather than panicking in a firmware loop.
    let big = [0xABu8; 128];
    let response = Response::new(2, CMD_DATA, 1, &big);
    assert_eq!(response.payload_len, 64);
    assert!(response.payload.iter().all(|b| *b == 0xAB));
}
