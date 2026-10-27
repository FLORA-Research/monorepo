//! Telemetry batch models: the JSON an aggregator publishes per uplink.
//!
//! Two representations of the same shape live here:
//!
//! * [`WireBatch`]/[`WireNode`] — serde structs, decoded by the server's
//!   ingest and encodable by any host-side tool. Field names are the wire
//!   contract (`gw_id`, `ts`, `moist`, ...).
//! * [`Batch`]/[`NodeSample`] plus [`Batch::encode`] — the allocation-free
//!   encoder the firmware uses: the same JSON, written byte for byte into
//!   a caller-owned buffer.
//!
//! Both are pinned to the same payload in tests, so the two encodings
//! cannot drift. Sentinels (`65535`, `-32768`) are emitted and carried
//! verbatim: the ingest layer maps them to "unavailable", and treating
//! them as readings would let analytics average a sentinel.

#[cfg(feature = "wire")]
use alloc::string::String;
#[cfg(feature = "wire")]
use alloc::vec::Vec;
#[cfg(feature = "wire")]
use serde::{Deserialize, Serialize};

/// Largest telemetry batch this firmware will emit in one uplink.
pub const MAX_BATCH_NODES: usize = 8;
/// Hex characters in a 16-byte gateway id.
pub const GATEWAY_ID_HEX_LEN: usize = 32;
/// Hex characters in an 8-byte node UUID.
pub const NODE_UUID_HEX_LEN: usize = 16;

/// One node's row in a batch, as published.
#[cfg(feature = "wire")]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct WireNode {
    /// Hex-encoded 8-byte node UUID.
    pub uuid: String,
    pub addr: u8,
    /// Per mille; `65535` (unavailable) is carried verbatim.
    pub moist: u16,
    /// Deci-degrees C; `-32768` (unavailable) is carried verbatim.
    pub temp: i16,
    /// Per mille; `65535` (unavailable) is carried verbatim.
    pub hum: u16,
    /// 0 or 1.
    pub valve: u8,
    pub seq: u32,
    /// Packed firmware version, `major << 8 | minor`.
    pub fw_ver: u16,
}

/// A whole batch as published.
#[cfg(feature = "wire")]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct WireBatch {
    /// Hex-encoded 16-byte gateway id.
    pub gw_id: String,
    /// Unix seconds, device clock.
    pub ts: i64,
    /// Present only when the aggregator had to drop buffered batches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u32>,
    pub nodes: Vec<WireNode>,
}

/// One node's contribution to a telemetry batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeSample {
    pub node_uuid: [u8; 8],
    pub addr: u8,
    pub moisture: u16,
    pub temperature: i16,
    pub humidity: u16,
    pub valve_state: u8,
    pub sequence: u32,
    pub firmware: u16,
}

/// An allocation-free batch being assembled for uplink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Batch {
    /// The full 16-byte `device_id`, matching the ingest expectation.
    pub gateway_id: [u8; 16],
    pub timestamp: u32,
    pub samples: [Option<NodeSample>; MAX_BATCH_NODES],
    pub len: usize,
    /// Batches discarded before this one, if the buffer overflowed.
    pub dropped: u16,
}

impl Batch {
    pub const fn new(gateway_id: [u8; 16], timestamp: u32) -> Self {
        Self {
            gateway_id,
            timestamp,
            samples: [None; MAX_BATCH_NODES],
            len: 0,
            dropped: 0,
        }
    }

    /// Append a sample. Returns `false` when the batch is full.
    pub fn push(&mut self, sample: NodeSample) -> bool {
        if self.len == MAX_BATCH_NODES {
            return false;
        }
        self.samples[self.len] = Some(sample);
        self.len += 1;
        true
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == MAX_BATCH_NODES
    }

    /// Render the batch as compact JSON into `out`, returning the byte
    /// length, or `None` when `out` cannot hold it.
    ///
    /// The output must parse as [`WireBatch`]; a test pins the two
    /// together so the encoder and the serde model cannot drift.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut writer = Writer { out, len: 0 };
        writer.put(b"{\"gw_id\":\"")?;
        writer.put_hex(&self.gateway_id)?;
        writer.put(b"\",\"ts\":")?;
        writer.put_u64(self.timestamp as u64)?;
        if self.dropped > 0 {
            writer.put(b",\"dropped\":")?;
            writer.put_u64(u64::from(self.dropped))?;
        }
        writer.put(b",\"nodes\":[")?;
        for (index, sample) in self.samples[..self.len].iter().enumerate() {
            let sample = sample.as_ref()?;
            if index > 0 {
                writer.put(b",")?;
            }
            writer.put(b"{\"uuid\":\"")?;
            writer.put_hex(&sample.node_uuid)?;
            writer.put(b"\",\"addr\":")?;
            writer.put_u64(u64::from(sample.addr))?;
            writer.put(b",\"moist\":")?;
            writer.put_u64(u64::from(sample.moisture))?;
            writer.put(b",\"temp\":")?;
            writer.put_i64(i64::from(sample.temperature))?;
            writer.put(b",\"hum\":")?;
            writer.put_u64(u64::from(sample.humidity))?;
            writer.put(b",\"valve\":")?;
            writer.put_u64(u64::from(sample.valve_state))?;
            writer.put(b",\"seq\":")?;
            writer.put_u64(u64::from(sample.sequence))?;
            writer.put(b",\"fw_ver\":")?;
            writer.put_u64(u64::from(sample.firmware))?;
            writer.put(b"}")?;
        }
        writer.put(b"]}")?;
        Some(writer.len)
    }
}

/// Encoded batch size ceiling, used to size transmit buffers.
///
/// Measured from a worst-case batch: eight nodes, every metric at its
/// sentinel or maximum, and a non-zero drop count. See `MAX_BATCH_JSON`
/// in the v1 aggregator: the previous 512-byte ceiling could not hold a
/// full batch, so `encode` failed and the aggregator silently dropped its
/// own telemetry.
pub const MAX_BATCH_JSON: usize = 1280;

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.len.checked_add(bytes.len())?;
        if end > self.out.len() {
            return None;
        }
        self.out[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Some(())
    }

    fn put_hex(&mut self, bytes: &[u8]) -> Option<()> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            self.put(&[HEX[(byte >> 4) as usize], HEX[(byte & 0x0F) as usize]])?;
        }
        Some(())
    }

    fn put_u64(&mut self, value: u64) -> Option<()> {
        let mut digits = [0u8; 20];
        let mut len = 0;
        let mut remaining = value;
        loop {
            digits[len] = b'0' + (remaining % 10) as u8;
            len += 1;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        for index in (0..len).rev() {
            self.put(&[digits[index]])?;
        }
        Some(())
    }

    fn put_i64(&mut self, value: i64) -> Option<()> {
        if value < 0 {
            self.put(b"-")?;
            // Negate in the unsigned domain so `i64::MIN` is handled.
            self.put_u64(value.unsigned_abs())
        } else {
            self.put_u64(value as u64)
        }
    }
}
