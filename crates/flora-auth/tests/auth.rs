use flora_auth::hello;

#[test]
fn links_on_the_host() {
    assert_eq!(hello(), "flora-auth");
}
