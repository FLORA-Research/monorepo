#![no_std]

//! Wire contracts shared by the firmware, the provisioner, and the server.
//!
//! One crate, compiled everywhere: `flora-node` and `flora-aggregator`
//! link it for thumbv6m, `flora-server` links it for the host. A change to
//! a wire format therefore fails the build of whichever side it breaks,
//! rather than failing in the field. The Dart app reimplements the parts
//! it speaks by hand against this source.
//!
//! Layout:
//! * [`frame`] — RS-485 framing, CRC, and the byte-at-a-time receiver.
//! * [`payload`] — the `DATA` and `INFO` bodies carried in frames.
//! * [`command`] — the canonical command bytes an app signs.
//! * [`signed`] — domain-separated signing messages and hex decoding.
//! * [`batch`] — the JSON telemetry batch, serde model + firmware encoder.
//! * [`provision`] — the USB-CDC provisioning handshake models.
//! * [`qr`] — the `flora://pair` payload a phone scans.
//!
//! Binary layouts are hand-rolled; JSON-shaped models use serde with
//! borrowed or allocated fields behind the `wire` feature, so the same
//! struct compiles for thumbv6m toolchains with `alloc` and the host.

#[cfg(feature = "wire")]
extern crate alloc;

pub mod batch;
pub mod command;
pub mod frame;
pub mod payload;
#[cfg(feature = "wire")]
pub mod provision;
pub mod qr;
pub mod signed;

pub use batch::{Batch, MAX_BATCH_JSON, MAX_BATCH_NODES, NodeSample};
#[cfg(feature = "wire")]
pub use batch::{WireBatch, WireNode};
pub use command::{
    CANONICAL_MESSAGE_LEN, CANONICAL_VERSION, GATEWAY_ID_LEN, KIND_CALIBRATE, KIND_SET_THRESHOLD,
    KIND_SET_VALVE, NONCE_LEN, PUBLIC_KEY_LEN, ProtocolError, SIGNATURE_LEN, TOKEN_LEN,
    canonical_message, device_id_bytes, device_id_hex,
};
pub use frame::{
    AGGREGATOR_ADDR, BROADCAST_ADDR, CMD_ACK, CMD_CALIBRATE, CMD_DATA, CMD_GET_INFO, CMD_INFO,
    CMD_NACK, CMD_PING, CMD_POLL, CMD_SET_ADDRESS, CMD_SET_THRESHOLD, CMD_SET_VALVE, Error,
    FIRST_NODE_ADDR, FRAME_OVERHEAD, Frame, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, NACK_BUSY,
    NACK_INVALID_PAYLOAD, NACK_SAFETY_REJECTED, NACK_UNSUPPORTED, PROTOCOL_VERSION, RESERVED_ADDR,
    Receiver, SOF, UNAVAILABLE_I16, UNAVAILABLE_U16, crc16_ccitt_false, decode, encode,
};
pub use payload::{
    DATA_PAYLOAD_LEN, INFO_PAYLOAD_LEN, NodeInfo, SensorFrame, SensorReading, data_payload,
    decode_data, decode_info, info_payload,
};
#[cfg(feature = "wire")]
pub use provision::{
    AGGREGATOR_HW, Ack, AggregatorHello, HANDSHAKE_VERSION, NODE_HW, NodeHello, SetIdentity,
    SetNodeAddress,
};
pub use qr::{PAIR_SCHEME, pair_qr_payload, parse_pair_payload};
pub use signed::{
    AUTH_PREFIX, INVITE_PREFIX, PAIR_PREFIX, auth_message, decode_hex_into, invite_message,
    pair_message,
};
