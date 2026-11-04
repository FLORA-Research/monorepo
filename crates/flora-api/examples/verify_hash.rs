//! Check a provisioning API key against a stored `PROVISION_API_KEY_HASH`.
//!
//! ```sh
//! cargo run -q -p flora-api --example verify_hash -- "$KEY" "$HASH"
//! ```
//!
//! Prints `Ok(true)` when the key matches. The comparison is constant-time
//! inside `flora_auth`, which is why this exists instead of doing it by eye.

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(key), Some(hash)) = (args.next(), args.next()) else {
        eprintln!("usage: cargo run -q -p flora-api --example verify_hash -- <key> <hash>");
        std::process::exit(2);
    };
    match flora_auth::verify_api_key(&key, &hash) {
        Ok(matches) => println!("{matches}"),
        Err(error) => {
            eprintln!("could not verify: {error}");
            std::process::exit(1);
        }
    }
}
