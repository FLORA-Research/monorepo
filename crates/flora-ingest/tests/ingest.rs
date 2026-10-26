use flora_ingest::hello;

#[test]
fn links_on_the_host() {
    assert_eq!(hello(), "flora-ingest");
}
