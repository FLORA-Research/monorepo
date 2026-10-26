//! Integration tests live here, outside `src/`, so the library stays a
//! single clean module tree and each file is its own test binary.

use flora_protocol::hello;

#[test]
fn links_on_the_host() {
    assert_eq!(hello(), "flora-protocol");
}
