//! The coordinator role: node table, offline buffer, command routing,
//! and batch assembly.
//!
//! The aggregator runs the same local sensing and irrigation as a field
//! node, plus this role: poll each discovered node, and forward manual
//! commands once their signature verifies (verification itself arrives
//! with the crypto module; routing and assembly are here). Valve
//! actuation is shared with the local control path so a node and the
//! aggregator cannot disagree about whether a valve is open.

use crate::coordinator::{Poller, calibrate_request, set_threshold_request, set_valve_request};
use flora_drivers::{FW_PACKED, IrrigationController, NodeConfig};
use flora_protocol::{
    Batch, KIND_CALIBRATE, KIND_SET_THRESHOLD, KIND_SET_VALVE, MAX_FRAME_LEN, NodeSample,
    SensorReading,
};

/// Aggregator-local node table capacity.
pub const MAX_NODES: usize = 16;
/// Retained batches when the uplink is down.
pub const BUFFER_SLOTS: usize = 16;

/// Verified command routed to a bus address, including the aggregator's
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedCommand {
    pub kind: u8,
    pub addr: u8,
    pub payload: [u8; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// The command addressed the aggregator itself.
    Local,
    /// The command was routed onto the RS-485 bus.
    Routed([u8; MAX_FRAME_LEN], usize),
    /// The command targeted an address that is neither local nor known.
    UnknownNode,
}

/// Bounded ring of pending batches. When it overflows, the oldest batch
/// is dropped and the drop count is reported on the next successful
/// send, so the cloud can distinguish "no data" from "data we threw
/// away".
#[derive(Debug, Clone)]
pub struct OfflineBuffer<const N: usize> {
    slots: [Option<Batch>; N],
    head: usize,
    len: usize,
    dropped: u16,
}

impl<const N: usize> Default for OfflineBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> OfflineBuffer<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn dropped(&self) -> u16 {
        self.dropped
    }

    /// Queue a batch. On overflow the oldest is discarded and counted.
    pub fn push(&mut self, batch: Batch) {
        if self.len == N {
            self.slots[self.head] = Some(batch);
            self.head = (self.head + 1) % N;
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let index = (self.head + self.len) % N;
        self.slots[index] = Some(batch);
        self.len += 1;
    }

    /// Oldest queued batch, without removing it.
    pub fn peek(&self) -> Option<&Batch> {
        if self.len == 0 {
            return None;
        }
        self.slots[self.head].as_ref()
    }

    /// Remove the oldest batch after a successful send.
    pub fn pop(&mut self) -> Option<Batch> {
        if self.len == 0 {
            return None;
        }
        let batch = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        batch
    }

    /// Drop counter is reported once, then cleared.
    pub fn take_dropped(&mut self) -> u16 {
        core::mem::take(&mut self.dropped)
    }
}

/// Owns the coordinator's node table and offline buffer. The nonce cache
/// and signature verification land with the crypto module and are
/// composed in by the firmware bin.
pub struct Coordinator {
    poller: Poller<MAX_NODES>,
    buffer: OfflineBuffer<BUFFER_SLOTS>,
    gateway_id: [u8; 16],
    /// The aggregator's own plot, identified within its own bus.
    ///
    /// A node uuid is eight bytes on the wire, while the gateway id is
    /// sixteen, so this is the first half of the device id. It is only
    /// ever used to label the aggregator's own readings; bus nodes carry
    /// the uuid the provisioner gave them.
    local_uuid: [u8; 8],
    local_addr: u8,
}

impl Coordinator {
    pub fn new(gateway_id: [u8; 16], local_addr: u8) -> Self {
        Self {
            // The aggregator's own plot is sensed and actuated locally, so
            // it is deliberately absent from the poller: `0x01` is the
            // aggregator identity and is not a valid bus node address.
            poller: Poller::new(),
            buffer: OfflineBuffer::new(),
            gateway_id,
            local_uuid: gateway_id[..8].try_into().expect("16 bytes contain 8"),
            local_addr,
        }
    }

    pub fn gateway_id(&self) -> [u8; 16] {
        self.gateway_id
    }

    /// Uuid used for the aggregator's own plot readings.
    pub fn local_uuid(&self) -> [u8; 8] {
        self.local_uuid
    }

    pub fn local_addr(&self) -> u8 {
        self.local_addr
    }

    pub fn poller(&mut self) -> &mut Poller<MAX_NODES> {
        &mut self.poller
    }

    pub fn buffer(&mut self) -> &mut OfflineBuffer<BUFFER_SLOTS> {
        &mut self.buffer
    }

    /// Register a node found during discovery.
    pub fn register_node(&mut self, addr: u8, sequence: u16) -> bool {
        self.poller.register(addr, sequence)
    }

    /// Queue a telemetry batch, then report how many batches are pending.
    pub fn queue_batch(&mut self, batch: Batch) -> usize {
        self.buffer.push(batch);
        self.buffer.len()
    }

    /// Route a verified command. The signature has already been checked
    /// by the caller; this only decides where the bytes go.
    pub fn route(&mut self, command: RoutedCommand) -> DispatchOutcome {
        let sequence = self
            .poller
            .slots()
            .iter()
            .flatten()
            .find(|slot| slot.addr == command.addr)
            .map(|slot| slot.next_sequence)
            .unwrap_or(1);

        if command.addr == self.local_addr {
            return DispatchOutcome::Local;
        }

        match command.kind {
            KIND_SET_VALVE => {
                let (bytes, len) = set_valve_request(
                    command.addr,
                    sequence,
                    command.payload[0] == 1,
                    u16::from_be_bytes([command.payload[1], command.payload[2]]),
                );
                DispatchOutcome::Routed(bytes, len)
            }
            KIND_SET_THRESHOLD => {
                let (bytes, len) = set_threshold_request(
                    command.addr,
                    sequence,
                    u16::from_be_bytes([command.payload[0], command.payload[1]]),
                    u16::from_be_bytes([command.payload[2], command.payload[3]]),
                );
                DispatchOutcome::Routed(bytes, len)
            }
            KIND_CALIBRATE => {
                let (bytes, len) =
                    calibrate_request(command.addr, sequence, command.payload[0] == 1);
                DispatchOutcome::Routed(bytes, len)
            }
            _ => DispatchOutcome::UnknownNode,
        }
    }

    /// Build a telemetry batch from the current local reading and the
    /// latest reply from each polled node.
    pub fn build_batch(
        &mut self,
        timestamp: u32,
        local: SensorReading,
        local_valve_open: bool,
    ) -> Batch {
        let mut batch = Batch::new(self.gateway_id, timestamp);
        batch.dropped = self.buffer.take_dropped();
        let _ = batch.push(NodeSample {
            node_uuid: self.local_uuid,
            addr: self.local_addr,
            moisture: local.moisture_per_mille.unwrap_or(u16::MAX),
            temperature: local.temperature_deci_c.unwrap_or(i16::MIN),
            humidity: local.humidity_per_mille.unwrap_or(u16::MAX),
            valve_state: u8::from(local_valve_open),
            sequence: local.sequence,
            firmware: FW_PACKED,
        });
        batch
    }
}

/// Apply a local `SET_VALVE` payload through the shared irrigation
/// controller.
///
/// Routing local commands through the same controller as the node keeps
/// the aggregator's own valve subject to the runtime cap and off-time.
pub fn apply_local_valve(
    payload: &[u8; 4],
    config: &NodeConfig,
    irrigation: &mut IrrigationController,
    now_s: u32,
) -> bool {
    if payload[0] > 1 {
        return false;
    }
    let open = payload[0] == 1;
    let duration_s = u16::from_be_bytes([payload[1], payload[2]]);
    irrigation
        .set_manual(open, duration_s, config, now_s)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flora_protocol::{AGGREGATOR_ADDR, decode};

    #[test]
    fn a_routed_frame_decodes_back_to_its_command() {
        // The bytes handed to the UART must decode to the command the
        // app signed: addr, kind, and payload survive the round trip.
        let mut coordinator = Coordinator::new(*b"agg-0001agg-0001", AGGREGATOR_ADDR);
        coordinator.register_node(4, 77);
        let outcome = coordinator.route(RoutedCommand {
            kind: KIND_SET_VALVE,
            addr: 4,
            payload: [1, 0, 30, 0],
        });
        match outcome {
            DispatchOutcome::Routed(bytes, len) => {
                let frame = decode(&bytes[..len]).unwrap();
                assert_eq!(frame.addr, 4);
                assert_eq!(frame.cmd, flora_protocol::CMD_SET_VALVE);
                assert_eq!(frame.payload, [1, 0, 30]);
                assert_eq!(frame.sequence, 77);
            }
            other => panic!("expected a routed command, got {other:?}"),
        }
    }

    #[test]
    fn local_commands_are_flagged_not_routed() {
        let mut coordinator = Coordinator::new(*b"agg-0001agg-0001", AGGREGATOR_ADDR);
        assert_eq!(
            coordinator.route(RoutedCommand {
                kind: KIND_SET_THRESHOLD,
                addr: AGGREGATOR_ADDR,
                payload: [0, 200, 2, 188],
            }),
            DispatchOutcome::Local
        );
    }

    #[test]
    fn unknown_kinds_and_addresses_go_nowhere() {
        let mut coordinator = Coordinator::new(*b"agg-0001agg-0001", AGGREGATOR_ADDR);
        assert_eq!(
            coordinator.route(RoutedCommand {
                kind: 0x7F,
                addr: 4,
                payload: [0; 4],
            }),
            DispatchOutcome::UnknownNode
        );
    }

    #[test]
    fn local_valve_command_obeys_off_time_and_runtime_cap() {
        let config = NodeConfig {
            address: AGGREGATOR_ADDR,
            min_off_s: 0,
            max_runtime_s: 60,
            ..NodeConfig::default()
        };
        let mut irrigation = IrrigationController::new(0);
        assert!(apply_local_valve(
            &[1, 0, 30, 0],
            &config,
            &mut irrigation,
            0
        ));
        assert!(irrigation.is_open());
        // Above the cap is refused, matching the node's behaviour.
        assert!(!apply_local_valve(
            &[1, 0, 90, 0],
            &config,
            &mut irrigation,
            1
        ));
        assert!(apply_local_valve(
            &[0, 0, 0, 0],
            &config,
            &mut irrigation,
            2
        ));
        assert!(!irrigation.is_open());
        // A payload with an invalid mode byte is refused outright.
        assert!(!apply_local_valve(
            &[2, 0, 30, 0],
            &config,
            &mut irrigation,
            3
        ));
    }

    #[test]
    fn batch_reports_aggregator_local_reading_with_sentinels() {
        let mut coordinator = Coordinator::new(*b"agg-0001agg-0001", AGGREGATOR_ADDR);
        let reading = SensorReading {
            soil_raw: 3100,
            moisture_per_mille: Some(50),
            temperature_deci_c: None,
            humidity_per_mille: None,
            sequence: 7,
        };
        let batch = coordinator.build_batch(1_000, reading, true);
        assert_eq!(batch.len, 1);
        let sample = batch.samples[0].unwrap();
        assert_eq!(sample.addr, AGGREGATOR_ADDR);
        assert_eq!(sample.moisture, 50);
        assert_eq!(
            sample.temperature,
            i16::MIN,
            "no DHT22 sample means unavailable"
        );
        assert_eq!(sample.valve_state, 1);

        let mut out = [0u8; flora_protocol::MAX_BATCH_JSON];
        let len = batch.encode(&mut out).unwrap();
        let json = core::str::from_utf8(&out[..len]).unwrap();
        assert!(json.contains("\"temp\":-32768"), "{json}");
    }

    #[test]
    fn the_aggregators_own_plot_is_not_a_bus_node() {
        let mut coordinator = Coordinator::new(*b"agg-0001agg-0001", AGGREGATOR_ADDR);
        // Local sensing and actuation cover the aggregator's own plot,
        // so the poller only carries real bus addresses.
        assert!(coordinator.poller().next_poll().is_none());
        assert!(coordinator.register_node(4, 1));
        assert_eq!(coordinator.poller().next_poll().unwrap().addr, 4);
        assert!(!coordinator.register_node(AGGREGATOR_ADDR, 1));
    }

    #[test]
    fn queue_batch_reports_pending_count() {
        let mut coordinator = Coordinator::new(*b"agg-0001agg-0001", AGGREGATOR_ADDR);
        assert_eq!(
            coordinator.queue_batch(Batch::new(*b"agg-0001agg-0001", 1)),
            1
        );
        assert_eq!(
            coordinator.queue_batch(Batch::new(*b"agg-0001agg-0001", 2)),
            2
        );
        assert_eq!(coordinator.buffer().pop().unwrap().timestamp, 1);
    }

    #[test]
    fn buffer_drops_oldest_and_counts_overflow() {
        let mut buffer = OfflineBuffer::<2>::new();
        buffer.push(Batch::new(*b"a0000000a0000000", 1));
        buffer.push(Batch::new(*b"b0000000b0000000", 2));
        assert_eq!(buffer.len(), 2);

        buffer.push(Batch::new(*b"c0000000c0000000", 3));
        assert_eq!(buffer.len(), 2, "bounded");
        assert_eq!(buffer.dropped(), 1);
        // Oldest was evicted; the surviving order is b then c.
        assert_eq!(buffer.pop().unwrap().timestamp, 2);
        assert_eq!(buffer.pop().unwrap().timestamp, 3);
        assert!(buffer.pop().is_none());
    }

    #[test]
    fn take_dropped_clears_the_counter() {
        let mut buffer = OfflineBuffer::<1>::new();
        buffer.push(Batch::new(*b"a0000000a0000000", 1));
        buffer.push(Batch::new(*b"b0000000b0000000", 2));
        assert_eq!(buffer.take_dropped(), 1);
        assert_eq!(buffer.take_dropped(), 0);
    }

    #[test]
    fn peek_does_not_remove() {
        let mut buffer = OfflineBuffer::<4>::new();
        buffer.push(Batch::new(*b"a0000000a0000000", 7));
        assert_eq!(buffer.peek().unwrap().timestamp, 7);
        assert_eq!(buffer.len(), 1);
    }
}
