//! Bus command processing for a field node.
//!
//! Validate an inbound frame, apply it to configuration and the irrigation
//! controller, and build the reply. Duplicate suppression lives here: a
//! retried transaction must not re-execute a side-effecting command such
//! as a valve open or a calibration capture.
//!
//! Both firmware roles link this module: an aggregator is a superset
//! node, so its local plot is served by the same processor.

use flora_drivers::{FW_PACKED, IrrigationController, NodeConfig};
use flora_protocol::{
    BROADCAST_ADDR, CMD_ACK, CMD_CALIBRATE, CMD_DATA, CMD_GET_INFO, CMD_INFO, CMD_NACK, CMD_PING,
    CMD_POLL, CMD_SET_ADDRESS, CMD_SET_THRESHOLD, CMD_SET_VALVE, Frame, MAX_PAYLOAD_LEN,
    SensorReading, data_payload,
};

/// NACK reason codes, mirroring the protocol document.
pub const NACK_UNSUPPORTED: u8 = 1;
pub const NACK_INVALID_PAYLOAD: u8 = 2;
pub const NACK_BUSY: u8 = 3;
pub const NACK_SAFETY_REJECTED: u8 = 4;

/// A frame ready to transmit, with its payload copied out of the receive
/// buffer so a reply outlives the bus transaction that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub addr: u8,
    pub cmd: u8,
    pub sequence: u16,
    pub payload: [u8; MAX_PAYLOAD_LEN],
    pub payload_len: usize,
}

impl Response {
    pub fn new(addr: u8, cmd: u8, sequence: u16, payload: &[u8]) -> Self {
        let mut buffer = [0u8; MAX_PAYLOAD_LEN];
        let payload_len = payload.len().min(MAX_PAYLOAD_LEN);
        buffer[..payload_len].copy_from_slice(&payload[..payload_len]);
        Self {
            addr,
            cmd,
            sequence,
            payload: buffer,
            payload_len,
        }
    }
}

/// Build a NACK. Used both by the processor and by the firmware loop when
/// a configuration could not be persisted and the command must be denied.
pub fn nack_for(addr: u8, cmd: u8, sequence: u16, reason: u8) -> Response {
    Response::new(addr, CMD_NACK, sequence, &[cmd, reason])
}

/// Build an acknowledgement for a command that was applied.
pub fn ack_for(addr: u8, cmd: u8, sequence: u16) -> Response {
    Response::new(addr, CMD_ACK, sequence, &[cmd])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedResponse {
    sequence: u16,
    cmd: u8,
    response: Option<Response>,
}

/// Stateless-per-frame command handler with a single-entry retry cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeProcessor {
    cached: Option<CachedResponse>,
}

impl NodeProcessor {
    /// Handle one decoded frame.
    ///
    /// Returns `None` for frames addressed elsewhere, broadcasts, `PING`,
    /// and duplicate retries that have no reply.
    pub fn process(
        &mut self,
        frame: Frame<'_>,
        config: &mut NodeConfig,
        reading: SensorReading,
        irrigation: &mut IrrigationController,
        node_uuid: [u8; 8],
        now_s: u32,
    ) -> Option<Response> {
        let broadcast = frame.addr == BROADCAST_ADDR;
        if frame.addr != config.address && !broadcast {
            return None;
        }

        if let Some(cached) = self.cached
            && cached.sequence == frame.sequence
            && cached.cmd == frame.cmd
        {
            return cached.response;
        }

        let response = self.dispatch(frame, config, reading, irrigation, node_uuid, now_s);
        let reply = if broadcast { None } else { response };
        self.cached = Some(CachedResponse {
            sequence: frame.sequence,
            cmd: frame.cmd,
            response: reply,
        });
        reply
    }

    /// Overwrite the cached reply, so a retry repeats the corrected outcome
    /// rather than the superseded one.
    pub fn replace_cached_response(&mut self, response: Response) {
        if let Some(cached) = self.cached.as_mut() {
            cached.response = Some(response);
        } else {
            self.cached = Some(CachedResponse {
                sequence: response.sequence,
                cmd: response.payload.first().copied().unwrap_or_default(),
                response: Some(response),
            });
        }
    }

    fn dispatch(
        &self,
        frame: Frame<'_>,
        config: &mut NodeConfig,
        reading: SensorReading,
        irrigation: &mut IrrigationController,
        node_uuid: [u8; 8],
        now_s: u32,
    ) -> Option<Response> {
        let addr = config.address;
        let sequence = frame.sequence;
        let payload = frame.payload;

        match frame.cmd {
            CMD_POLL => {
                if !payload.is_empty() {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                Some(Response::new(
                    addr,
                    CMD_DATA,
                    sequence,
                    &data_payload(&node_uuid, FW_PACKED, reading, irrigation.is_open(), now_s),
                ))
            }
            CMD_GET_INFO => {
                if !payload.is_empty() {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                let mut body = [0u8; 11];
                body[0..8].copy_from_slice(&node_uuid);
                body[8] = addr;
                body[9..11].copy_from_slice(&FW_PACKED.to_be_bytes());
                Some(Response::new(addr, CMD_INFO, sequence, &body))
            }
            CMD_PING => None,
            CMD_SET_VALVE => {
                if payload.len() != 3 || payload[0] > 1 {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                let open = payload[0] == 1;
                let duration_s = u16::from_be_bytes([payload[1], payload[2]]);
                match irrigation.set_manual(open, duration_s, config, now_s) {
                    Ok(()) => Some(ack_for(addr, frame.cmd, sequence)),
                    Err(_) => Some(nack_for(addr, frame.cmd, sequence, NACK_SAFETY_REJECTED)),
                }
            }
            CMD_SET_THRESHOLD => {
                if payload.len() != 4 {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                let dry = u16::from_be_bytes([payload[0], payload[1]]);
                let wet = u16::from_be_bytes([payload[2], payload[3]]);
                if dry > 1000 || wet > 1000 || wet <= dry {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                config.dry_threshold = dry;
                config.wet_threshold = wet;
                Some(ack_for(addr, frame.cmd, sequence))
            }
            CMD_CALIBRATE => {
                if payload.len() != 1 || payload[0] > 1 {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                // A calibration sample must itself be a usable ADC count.
                if reading.soil_raw > 4095 {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_SAFETY_REJECTED));
                }
                let previous = *config;
                if payload[0] == 0 {
                    config.soil_dry_adc = reading.soil_raw;
                } else {
                    config.soil_wet_adc = reading.soil_raw;
                }
                if !config.validate() {
                    // Reject a reference that would invert or collapse the scale.
                    *config = previous;
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_SAFETY_REJECTED));
                }
                Some(ack_for(addr, frame.cmd, sequence))
            }
            CMD_SET_ADDRESS => {
                if payload.len() != 1 || !(0x02..=0xFE).contains(&payload[0]) {
                    return Some(nack_for(addr, frame.cmd, sequence, NACK_INVALID_PAYLOAD));
                }
                config.address = payload[0];
                Some(ack_for(addr, frame.cmd, sequence))
            }
            _ => Some(nack_for(addr, frame.cmd, sequence, NACK_UNSUPPORTED)),
        }
    }
}
