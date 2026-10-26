use flora_drivers::hello;

#[test]
fn links_on_the_host() {
    assert_eq!(hello(), "flora-drivers");
}
