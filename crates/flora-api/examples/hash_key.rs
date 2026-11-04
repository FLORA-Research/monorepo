//! Hash a provisioning API key for `PROVISION_API_KEY_HASH`.
//!
//! The server stores an Argon2 hash, never the key, so the operator needs a
//! way to produce that hash without a running server. This is that way:
//!
//! ```sh
//! KEY="$(openssl rand -hex 24)"
//! cargo run -q -p flora-api --example hash_key -- "$KEY"
//! ```
//!
//! Argon2 hashes contain `$`, so quote the output in shell.

fn main() {
    let key = match std::env::args().nth(1) {
        Some(key) if !key.is_empty() => key,
        _ => {
            eprintln!("usage: cargo run -q -p flora-api --example hash_key -- <key>");
            std::process::exit(2);
        }
    };
    match flora_auth::hash_api_key(&key) {
        Ok(hash) => println!("{hash}"),
        Err(error) => {
            eprintln!("could not hash the key: {error}");
            std::process::exit(1);
        }
    }
}
