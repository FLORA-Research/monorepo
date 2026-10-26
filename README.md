# FLORA

Soil-moisture-driven irrigation: RP2040 field nodes on an RS-485 bus, a
Pico W aggregator that relays telemetry to the cloud, a Rust API server,
and a Flutter app.

One repository, one Cargo workspace. Protocol, drivers, and device logic
are shared source; the wire format cannot drift between firmware and
server because both compile the same crate.

## Layout

```
crates/
  flora-protocol/    wire contracts shared by firmware, provision, and server
  flora-drivers/     sensors and actuators, generic over embedded-hal
  flora-device/      consolidated node/aggregator device logic
  flora-node/        firmware binary, plain Pico (thumbv6m)
  flora-aggregator/  firmware binary, Pico W: node + wifi + uplink (thumbv6m)
  flora-db/          database access and migrations
  flora-auth/        accounts, keys, sessions
  flora-ingest/      device batch decoding and persistence
  flora-analytics/   reports and cross-gateway queries
  flora-api/         HTTP surface (REST DTOs, handlers, routing)
  flora-server/      server binary: config, startup, listener
  flora-provision/   host CLI: flash, commission, register, print QR
app/                 Flutter app, mobile only
internal/            untracked operational documentation
```

## Development

```sh
cargo test --workspace                 # host tests, everything testable
cargo build --release -p flora-node \
  --features firmware --target thumbv6m-none-eabi
```

Firmware binaries live behind the `firmware` feature so the workspace
tests on the host without a cross toolchain. See `internal/` (untracked)
for operational documentation; a fresh clone will not contain it.
