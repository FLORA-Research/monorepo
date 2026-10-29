//! RS-485 coordinator: round-robin polling, timeouts, and discovery.
//!
//! The transport is abstracted so the scheduling and error handling can
//! be tested on a host without a bus. A node that misses its reply window
//! is skipped for a few cycles rather than stalling the whole rotation —
//! one unreachable node must not starve its peers.

use flora_protocol::{
    CMD_CALIBRATE, CMD_GET_INFO, CMD_POLL, CMD_SET_THRESHOLD, CMD_SET_VALVE, FIRST_NODE_ADDR,
    Frame, MAX_FRAME_LEN, encode,
};

/// How many cycles an unreachable node is skipped before being retried.
pub const SKIP_CYCLES: u8 = 3;

/// First address the coordinator may poll.
pub const FIRST_ADDR: u8 = FIRST_NODE_ADDR;
/// Last address the coordinator may poll.
pub const LAST_ADDR: u8 = 0xFE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Answered the most recent poll.
    Reachable,
    /// Missed `failures` polls consecutively.
    Unreachable { failures: u8 },
    /// Skipped for `remaining` more cycles.
    Deferred { remaining: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeSlot {
    pub addr: u8,
    pub state: NodeState,
    /// Monotonic sequence used for the next request to this node.
    pub next_sequence: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollPlan {
    pub addr: u8,
    pub sequence: u16,
}

/// Round-robin poller over a discovered address range.
#[derive(Debug, Clone)]
pub struct Poller<const N: usize> {
    slots: [Option<NodeSlot>; N],
    len: usize,
    cursor: usize,
}

impl<const N: usize> Default for Poller<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Poller<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            len: 0,
            cursor: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn slots(&self) -> &[Option<NodeSlot>] {
        &self.slots[..self.len]
    }

    /// Register a node discovered by `GET_INFO`. Returns `false` when the
    /// table is full, the address is out of range, or already known.
    pub fn register(&mut self, addr: u8, sequence: u16) -> bool {
        if !(FIRST_ADDR..=LAST_ADDR).contains(&addr) {
            return false;
        }
        if self.slots[..self.len]
            .iter()
            .any(|slot| slot.is_some_and(|slot| slot.addr == addr))
        {
            return false;
        }
        if self.len == N {
            return false;
        }
        self.slots[self.len] = Some(NodeSlot {
            addr,
            state: NodeState::Reachable,
            next_sequence: sequence,
        });
        self.len += 1;
        true
    }

    /// Next address to poll, respecting deferrals. `None` when no node
    /// is due. One node per call: a full sweep happens across passes, so
    /// the loop is never blocked for sixteen timeouts.
    pub fn next_poll(&mut self) -> Option<PollPlan> {
        let mut inspected = 0;
        while inspected < self.len {
            let index = self.cursor % self.len;
            self.cursor = (self.cursor + 1) % self.len.max(1);
            inspected += 1;

            let Some(slot) = self.slots[index].as_mut() else {
                continue;
            };
            match slot.state {
                NodeState::Deferred { remaining } if remaining > 0 => {
                    slot.state = NodeState::Deferred {
                        remaining: remaining - 1,
                    };
                }
                NodeState::Deferred { .. } => {
                    slot.state = NodeState::Reachable;
                }
                _ => {}
            }
            if matches!(slot.state, NodeState::Reachable) {
                let plan = PollPlan {
                    addr: slot.addr,
                    sequence: slot.next_sequence,
                };
                slot.next_sequence = slot.next_sequence.wrapping_add(1);
                return Some(plan);
            }
        }
        None
    }

    /// Record a reply. Clears any failure count.
    pub fn note_reply(&mut self, addr: u8) {
        if let Some(slot) = self.slot_mut(addr) {
            slot.state = NodeState::Reachable;
        }
    }

    /// Record a missed reply, deferring the node after repeated failures.
    pub fn note_timeout(&mut self, addr: u8) {
        if let Some(slot) = self.slot_mut(addr) {
            let failures = match slot.state {
                NodeState::Unreachable { failures } => failures.saturating_add(1),
                _ => 1,
            };
            slot.state = if failures >= SKIP_CYCLES {
                NodeState::Deferred {
                    remaining: SKIP_CYCLES,
                }
            } else {
                NodeState::Unreachable { failures }
            };
        }
    }

    pub fn state(&self, addr: u8) -> Option<NodeState> {
        self.slots()
            .iter()
            .flatten()
            .find(|slot| slot.addr == addr)
            .map(|slot| slot.state)
    }

    fn slot_mut(&mut self, addr: u8) -> Option<&mut NodeSlot> {
        self.slots[..self.len]
            .iter_mut()
            .flatten()
            .find(|slot| slot.addr == addr)
    }
}

/// Build the `GET_INFO` request used to discover one address.
pub fn discovery_request(addr: u8, sequence: u16) -> ([u8; MAX_FRAME_LEN], usize) {
    let frame = Frame {
        addr,
        cmd: CMD_GET_INFO,
        sequence,
        payload: &[],
    };
    let mut bytes = [0u8; MAX_FRAME_LEN];
    let len = encode(&frame, &mut bytes).expect("empty discovery frame fits");
    (bytes, len)
}

/// Build the `POLL` request that asks a node for its sensors.
pub fn poll_request(addr: u8, sequence: u16) -> ([u8; MAX_FRAME_LEN], usize) {
    let frame = Frame {
        addr,
        cmd: CMD_POLL,
        sequence,
        payload: &[],
    };
    let mut bytes = [0u8; MAX_FRAME_LEN];
    let len = encode(&frame, &mut bytes).expect("empty poll frame fits");
    (bytes, len)
}

/// Build a `SET_VALVE` request routed to a node.
pub fn set_valve_request(
    addr: u8,
    sequence: u16,
    open: bool,
    duration_s: u16,
) -> ([u8; MAX_FRAME_LEN], usize) {
    let payload = [u8::from(open), (duration_s >> 8) as u8, duration_s as u8];
    let frame = Frame {
        addr,
        cmd: CMD_SET_VALVE,
        sequence,
        payload: &payload,
    };
    let mut bytes = [0u8; MAX_FRAME_LEN];
    let len = encode(&frame, &mut bytes).expect("set_valve payload fits");
    (bytes, len)
}

/// Build a `SET_THRESHOLD` request routed to a node.
pub fn set_threshold_request(
    addr: u8,
    sequence: u16,
    dry: u16,
    wet: u16,
) -> ([u8; MAX_FRAME_LEN], usize) {
    let payload = [(dry >> 8) as u8, dry as u8, (wet >> 8) as u8, wet as u8];
    let frame = Frame {
        addr,
        cmd: CMD_SET_THRESHOLD,
        sequence,
        payload: &payload,
    };
    let mut bytes = [0u8; MAX_FRAME_LEN];
    let len = encode(&frame, &mut bytes).expect("threshold payload fits");
    (bytes, len)
}

/// Build a `CALIBRATE` request routed to a node.
pub fn calibrate_request(addr: u8, sequence: u16, wet: bool) -> ([u8; MAX_FRAME_LEN], usize) {
    let payload = [u8::from(wet)];
    let frame = Frame {
        addr,
        cmd: CMD_CALIBRATE,
        sequence,
        payload: &payload,
    };
    let mut bytes = [0u8; MAX_FRAME_LEN];
    let len = encode(&frame, &mut bytes).expect("calibrate payload fits");
    (bytes, len)
}
