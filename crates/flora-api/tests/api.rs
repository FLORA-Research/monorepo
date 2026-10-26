use flora_api::hello;

#[test]
fn links_on_the_host() {
    assert_eq!(hello(), "flora-api");
}
