#![no_std]

/// Wire contracts shared by the firmware, the provisioner, and the server.
///
/// One crate, compiled everywhere: `flora-node` and `flora-aggregator` link
/// it for thumbv6m, `flora-server` links it for the host. A change to a wire
/// format therefore fails the build of whichever side it breaks, rather
/// than failing in the field. The Dart app reimplements the parts it
/// speaks by hand against this source.
pub fn hello() -> &'static str {
    "flora-protocol"
}
