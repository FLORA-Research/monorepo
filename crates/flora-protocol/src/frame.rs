//! FLORA RS-485 v1 framing. Kept allocation-free for embedded use.
//!
//! This module owns the byte-level contract between an aggregator and the
//! nodes on its bus. It is compiled into the firmware, the provisioner,
//! and the server-side tools, so a change that breaks the format fails a
//! build rather than a deployment. The layout is documented in
//! `docs/protocol.md` and pinned by tests.

pub const PROTOCOL_VERSION: &str = "flora-rs485-v1";
pub const SOF: u8 = 0xAA;
pub const EOF: u8 = 0x55;
pub const BROADCAST_ADDR: u8 = 0x00;
pub const AGGREGATOR_ADDR: u8 = 0x01;
pub const FIRST_NODE_ADDR: u8 = 0x02;
pub const RESERVED_ADDR: u8 = 0xFF;
pub const MAX_PAYLOAD_LEN: usize = 64;
pub const FRAME_OVERHEAD: usize = 9;
pub const MAX_FRAME_LEN: usize = FRAME_OVERHEAD + MAX_PAYLOAD_LEN;

pub const CMD_POLL: u8 = 0x01;
pub const CMD_SET_VALVE: u8 = 0x02;
pub const CMD_SET_THRESHOLD: u8 = 0x03;
pub const CMD_CALIBRATE: u8 = 0x04;
pub const CMD_PING: u8 = 0x05;
pub const CMD_SET_ADDRESS: u8 = 0x06;
pub const CMD_GET_INFO: u8 = 0x07;
pub const CMD_ACK: u8 = 0x80;
pub const CMD_NACK: u8 = 0x81;
pub const CMD_DATA: u8 = 0x82;
pub const CMD_INFO: u8 = 0x83;

/// NACK reason codes, mirroring the protocol document.
pub const NACK_UNSUPPORTED: u8 = 1;
pub const NACK_INVALID_PAYLOAD: u8 = 2;
pub const NACK_BUSY: u8 = 3;
pub const NACK_SAFETY_REJECTED: u8 = 4;

/// Wire sentinels for values this build cannot measure. A reading that
/// could not be taken is never a plausible number.
pub const UNAVAILABLE_U16: u16 = 0xFFFF;
pub const UNAVAILABLE_I16: i16 = i16::MIN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub addr: u8,
    pub cmd: u8,
    pub sequence: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooShort,
    InvalidStart,
    InvalidAddress,
    PayloadTooLong,
    LengthMismatch,
    InvalidEnd,
    Checksum,
    OutputTooSmall,
}

/// Encodes one frame into `out`; the caller owns the buffer and payload memory.
pub fn encode(frame: &Frame<'_>, out: &mut [u8]) -> Result<usize, Error> {
    if frame.addr == RESERVED_ADDR {
        return Err(Error::InvalidAddress);
    }
    if frame.payload.len() > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLong);
    }

    let frame_len = FRAME_OVERHEAD + frame.payload.len();
    if out.len() < frame_len {
        return Err(Error::OutputTooSmall);
    }

    out[0] = SOF;
    out[1] = frame.addr;
    out[2] = frame.cmd;
    out[3] = (frame.sequence >> 8) as u8;
    out[4] = frame.sequence as u8;
    out[5] = frame.payload.len() as u8;
    out[6..6 + frame.payload.len()].copy_from_slice(frame.payload);

    let checksum_at = 6 + frame.payload.len();
    let checksum = crc16_ccitt_false(&out[1..checksum_at]);
    out[checksum_at] = (checksum >> 8) as u8;
    out[checksum_at + 1] = checksum as u8;
    out[checksum_at + 2] = EOF;
    Ok(frame_len)
}

/// Decodes exactly one complete frame without allocating or copying its payload.
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, Error> {
    if bytes.len() < FRAME_OVERHEAD {
        return Err(Error::TooShort);
    }
    if bytes[0] != SOF {
        return Err(Error::InvalidStart);
    }

    let payload_len = bytes[5] as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLong);
    }
    if bytes.len() != FRAME_OVERHEAD + payload_len {
        return Err(Error::LengthMismatch);
    }
    if bytes[bytes.len() - 1] != EOF {
        return Err(Error::InvalidEnd);
    }
    if bytes[1] == RESERVED_ADDR {
        return Err(Error::InvalidAddress);
    }

    let checksum_at = 6 + payload_len;
    let received = u16::from_be_bytes([bytes[checksum_at], bytes[checksum_at + 1]]);
    let expected = crc16_ccitt_false(&bytes[1..checksum_at]);
    if received != expected {
        return Err(Error::Checksum);
    }

    Ok(Frame {
        addr: bytes[1],
        cmd: bytes[2],
        sequence: u16::from_be_bytes([bytes[3], bytes[4]]),
        payload: &bytes[6..checksum_at],
    })
}

/// CRC-16/CCITT-FALSE: poly=0x1021, init=0xFFFF, refin=false,
/// refout=false, xorout=0x0000.
pub fn crc16_ccitt_false(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for byte in bytes {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Reassembles a length-prefixed frame across byte-at-a-time reads.
///
/// The frame carries its own payload length at byte 5, so completeness is
/// known without waiting for an idle gap. A partial buffer never panics:
/// the length byte is only read once enough bytes exist to contain it.
#[derive(Debug, Clone, Copy)]
pub struct Receiver {
    buffer: [u8; MAX_FRAME_LEN],
    len: usize,
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

impl Receiver {
    pub const fn new() -> Self {
        Self {
            buffer: [0; MAX_FRAME_LEN],
            len: 0,
        }
    }

    /// Drop any partial frame and start over.
    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// Push one byte, returning the complete frame once enough bytes have
    /// arrived that the length prefix is known and satisfied.
    ///
    /// Returns `None` for a partial frame or an oversized stream; the
    /// caller resets or ignores on its own timeout logic.
    pub fn push(&mut self, byte: u8) -> Option<&[u8]> {
        if self.len == self.buffer.len() {
            return None;
        }
        self.buffer[self.len] = byte;
        self.len += 1;
        if self.len >= 6 && self.len == FRAME_OVERHEAD + self.buffer[5] as usize {
            return Some(&self.buffer[..self.len]);
        }
        None
    }
}
