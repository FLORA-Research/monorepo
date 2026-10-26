//! Canonical command encoding and signing-message layouts, pinned to the
//! v1 test vectors so the app, cloud, and aggregator keep agreeing on
//! bytes. These messages are what an Ed25519 signature covers; a drift in
//! one place is a signature failure everywhere.

use flora_protocol::{
    AUTH_PREFIX, CANONICAL_MESSAGE_LEN, CANONICAL_VERSION, GATEWAY_ID_LEN, INVITE_PREFIX,
    KIND_CALIBRATE, KIND_SET_THRESHOLD, KIND_SET_VALVE, NONCE_LEN, PAIR_PREFIX, PUBLIC_KEY_LEN,
    TOKEN_LEN, auth_message, canonical_message, decode_hex_into, device_id_bytes, device_id_hex,
    invite_message, pair_message,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_encoding_pins_the_exact_v1_bytes() {
    // Fixed v1 vector: the aggregator derives the same bytes for the same
    // inputs, so this guards the shared contract across the port.
    let gateway = *b"agg-0001agg-0001";
    let message = canonical_message(
        KIND_SET_VALVE,
        &gateway,
        4,
        0x0000_0007,
        0x0000_0009,
        &[1, 0, 30, 0],
    );
    assert_eq!(
        hex(&message),
        concat!(
            "01",                               // canonical version
            "01",                               // KIND_SET_VALVE
            "6167672d303030316167672d30303031", // full 16-byte id
            "04",                               // node address
            "00000007",                         // nonce
            "00000009",                         // timestamp
            "01001e00",                         // payload: open, 30 s
        )
    );
    assert_eq!(message.len(), CANONICAL_MESSAGE_LEN);
    assert_eq!(message[0], CANONICAL_VERSION);
}

#[test]
fn canonical_encoding_covers_the_full_gateway_id() {
    // Two ids sharing their first fifteen bytes must still produce
    // different signed bytes, or one aggregator could accept another's
    // command.
    let first = *b"agg-0001agg-0001";
    let second = *b"agg-0001agg-0002";
    assert_eq!(
        first[..15],
        second[..15],
        "ids differ only in their last byte"
    );
    assert_ne!(
        canonical_message(KIND_SET_VALVE, &first, 4, 7, 9, &[0; 4]),
        canonical_message(KIND_SET_VALVE, &second, 4, 7, 9, &[0; 4]),
        "the full gateway id must affect the signed bytes"
    );
}

#[test]
fn every_kind_and_field_reaches_the_bytes() {
    // Kinds are stable numbers, not enum indices: pin all three.
    assert_eq!(KIND_SET_VALVE, 1);
    assert_eq!(KIND_SET_THRESHOLD, 2);
    assert_eq!(KIND_CALIBRATE, 3);

    let gateway = [7u8; GATEWAY_ID_LEN];
    let message = canonical_message(
        KIND_SET_THRESHOLD,
        &gateway,
        0xFE,
        u32::MAX,
        u32::MAX - 900,
        &[0, 200, 2, 188],
    );
    // Field boundaries with extreme values, checked slice by slice.
    assert_eq!(&message[2..18], &gateway);
    assert_eq!(message[18], 0xFE);
    assert_eq!(&message[19..23], &u32::MAX.to_be_bytes());
    assert_eq!(&message[23..27], &(u32::MAX - 900).to_be_bytes());
    assert_eq!(&message[27..31], &[0, 200, 2, 188]);
}

#[test]
fn device_id_matches_the_provisioner_derivation() {
    // SHA-256(0x00..=0x1f)[..16], the same value the v1 provisioner
    // computed for a public key of ascending bytes.
    let public_key: Vec<u8> = (0u8..32).collect();
    let id = device_id_bytes(&public_key).unwrap();
    assert_eq!(hex(&id), "630dcd2966c4336691125448bbb25b4f");

    // And the hex form, exactly 32 lowercase ASCII characters.
    let mut out = [0u8; 64];
    let n = device_id_hex(&public_key, &mut out).unwrap();
    assert_eq!(n, 32);
    assert_eq!(&out[..n], b"630dcd2966c4336691125448bbb25b4f");

    // A short buffer is refused, not truncated.
    let mut tiny = [0u8; 31];
    assert!(device_id_hex(&public_key, &mut tiny).is_err());
    // A wrong-length key is refused.
    assert!(device_id_bytes(&[0u8; 31]).is_err());
}

#[test]
fn pair_message_is_prefix_id_separator_token_nonce() {
    let device_id = b"630dcd2966c4336691125448bbb25b4f";
    let token = [0xABu8; TOKEN_LEN];
    let nonce = [3u8; NONCE_LEN];
    let mut out = [0u8; 256];
    let message = pair_message(device_id, &token, &nonce, &mut out).unwrap();

    assert!(message.starts_with(PAIR_PREFIX));
    // 12 prefix + 32 id + 1 separator + 32 token + 16 nonce.
    assert_eq!(
        message.len(),
        PAIR_PREFIX.len() + 32 + 1 + TOKEN_LEN + NONCE_LEN
    );
    let at = PAIR_PREFIX.len();
    assert_eq!(&message[at..at + 32], device_id);
    assert_eq!(message[at + 32], 0x00, "separator between id and token");
    assert_eq!(&message[at + 33..at + 33 + TOKEN_LEN], &token);
    assert_eq!(&message[at + 33 + TOKEN_LEN..], &nonce);

    // A too-small buffer yields None rather than a partial message.
    let mut small = [0u8; 64];
    assert!(pair_message(device_id, &token, &nonce, &mut small).is_none());
}

#[test]
fn pair_message_separator_disambiguates_ids() {
    // (device_id, token) pairs that concatenate identically must differ:
    // the 0x00 separator makes "ab"+"b.." and "a"+"bb.." distinct bytes.
    let token = [0x11u8; TOKEN_LEN];
    let nonce = [0x22u8; NONCE_LEN];
    let mut out1 = [0u8; 128];
    let mut out2 = [0u8; 128];
    let first = pair_message(b"ab", &token, &nonce, &mut out1).unwrap();
    let second = pair_message(b"a", &token, &nonce, &mut out2).unwrap();
    assert_ne!(first, second, "device id must be separated from the token");
}

#[test]
fn auth_message_is_prefix_pubkey_nonce() {
    let pubkey = [0x77u8; PUBLIC_KEY_LEN];
    let nonce = [0x88u8; NONCE_LEN];
    let mut out = [0u8; 128];
    let message = auth_message(&pubkey, &nonce, &mut out).unwrap();

    assert!(message.starts_with(AUTH_PREFIX));
    assert_eq!(
        message.len(),
        AUTH_PREFIX.len() + PUBLIC_KEY_LEN + NONCE_LEN
    );
    assert_eq!(
        &message[AUTH_PREFIX.len()..AUTH_PREFIX.len() + PUBLIC_KEY_LEN],
        &pubkey
    );
    assert_eq!(&message[AUTH_PREFIX.len() + PUBLIC_KEY_LEN..], &nonce);
}

#[test]
fn invite_message_is_prefix_pubkey_token_nonce() {
    let pubkey = [0x55u8; PUBLIC_KEY_LEN];
    let token = [0x66u8; TOKEN_LEN];
    let nonce = [0x99u8; NONCE_LEN];
    let mut out = [0u8; 128];
    let message = invite_message(&pubkey, &token, &nonce, &mut out).unwrap();

    assert!(message.starts_with(INVITE_PREFIX));
    assert_eq!(
        message.len(),
        INVITE_PREFIX.len() + PUBLIC_KEY_LEN + TOKEN_LEN + NONCE_LEN
    );
    let at = INVITE_PREFIX.len();
    assert_eq!(&message[at..at + PUBLIC_KEY_LEN], &pubkey);
    assert_eq!(
        &message[at + PUBLIC_KEY_LEN..at + PUBLIC_KEY_LEN + TOKEN_LEN],
        &token
    );
    assert_eq!(&message[at + PUBLIC_KEY_LEN + TOKEN_LEN..], &nonce);
}

#[test]
fn the_three_prefixes_are_pairwise_distinct() {
    // A signature made for one flow must not verify in another: the
    // prefixes differ, so the signed bytes differ for any input.
    let prefixes = [PAIR_PREFIX, AUTH_PREFIX, INVITE_PREFIX];
    for i in 0..prefixes.len() {
        for j in i + 1..prefixes.len() {
            assert_ne!(prefixes[i], prefixes[j]);
        }
    }
}

#[test]
fn hex_decoding_rejects_malformed_input() {
    let mut out = [0u8; 64];

    // Round trip: lowercase and uppercase both decode.
    let n = decode_hex_into("630dcd29", &mut out).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&out[..n], &[0x63, 0x0d, 0xcd, 0x29]);
    let n = decode_hex_into("630DCD29", &mut out).unwrap();
    assert_eq!(&out[..n], &[0x63, 0x0d, 0xcd, 0x29]);

    // Odd length, non-hex characters, and truncated buffers all fail.
    assert!(decode_hex_into("abc", &mut out).is_none());
    assert!(decode_hex_into("zz", &mut out).is_none());
    assert!(decode_hex_into("630dcd29", &mut out[..1]).is_none());
    // Zero-length input is fine and decodes nothing.
    assert_eq!(decode_hex_into("", &mut out), Some(0));
}
