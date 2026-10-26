//! HTTP surface: REST DTOs, handlers, routing. Server-internal request and
//! response types stay here; `flora-protocol` owns only what crosses a
//! component boundary on a wire.

pub fn hello() -> &'static str {
    "flora-api"
}
