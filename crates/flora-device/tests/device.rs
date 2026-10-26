use flora_device::hello;

#[test]
fn links_on_the_host() {
    assert_eq!(hello(), "flora-device");
}
