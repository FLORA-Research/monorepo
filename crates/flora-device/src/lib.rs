#![no_std]

//! Device logic shared by the node and the aggregator roles: sensing
//! schedule, irrigation limits, RS-485 answers, and bus coordination.
//!
//! A node and an aggregator are the same device; the aggregator adds
//! radio, uplink, and command verification. Both roles are tested on the
//! host, so the firmware binaries stay thin embassy entry points.
//!
//! The `firmware` feature pulls the embassy/HAL bindings; without it the
//! crate is pure logic and runs under the host toolchain.
// Tests run on the host, where `Vec`/`String` are available; the crate
// itself never allocates.
#[cfg(test)]
extern crate alloc;

pub mod coord;
pub mod coordinator;
pub mod crypto;
pub mod identity;
pub mod node;

pub use node::{NodeProcessor, Response, ack_for, nack_for};
