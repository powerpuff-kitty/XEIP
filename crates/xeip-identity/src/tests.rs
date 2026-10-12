use crate::canonical::{canonicalize_json, strict_parse};
use crate::crypto::{
    is_weak_ed25519_public_key, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH,
    ED25519_SMALL_ORDER_POINTS,
};
use crate::encoding::{base64url_decode, base64url_encode};
use crate::envelope::verify_signed_envelope;
use crate::key_id::{
    base58btc_decode, base58btc_encode, decode_key_id, device_urn, encode_key_id, entity_urn,
    KeyIdError, BASE58BTC_ALPHABET, ED25519_MULTICODEC, ED25519_PUBLIC_KEY_LENGTH, PAYLOAD_LEN,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::json;

#[test]
fn base58btc_matches_known_answers() {
    // Canonical multibase/base58btc KAT: ASCII "Hello World!".
    assert_eq!(base58btc_encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
    // Empty input and leading-zero (0x00-heavy) special cases.
    assert_eq!(base58btc_encode(b""), "");
    assert_eq!(base58btc_encode(&[0x00]), "1");
    assert_eq!(base58btc_encode(&[0x00, 0x00]), "11");
    assert_eq!(base58btc_encode(&[0x00, 0x00, 0x00]), "111");
    assert_eq!(base58btc_encode(&[0x00, 0x00, 0x01]), "112");
    assert_eq!(base58btc_encode(&[0xff]), "5Q");
    assert_eq!(base58btc_encode(&[0x00, 0xff]), "15Q");
    // The alphabet is the exact 58-character Bitcoin set.
    assert_eq!(BASE58BTC_ALPHABET.len(), 58);
}

#[test]
fn base58btc_round_trips_leading_zeros() {
    // Key-ids always start with 0xed, so the leading-zero path is never
    // exercised by the conformance vectors; cover it directly here.
    let samples: &[&[u8]] = &[
        b"",
        &[0x00],
        &[0x00, 0x00, 0x00, 0x04],
        &[0x00, 0x00, 0x01, 0x02, 0x03],
        b"Hello World!",
    ];
    for sample in samples {
        let encoded = base58btc_encode(sample);
        assert_eq!(base58btc_decode(&encoded).unwrap(), sample.to_vec());
    }
    assert_eq!(
        base58btc_decode("0"),
        Err(KeyIdError::InvalidBase58Char('0'))
    );
    assert_eq!(
        base58btc_decode("O"),
        Err(KeyIdError::InvalidBase58Char('O'))
    );
}

#[test]
fn key_id_round_trips() {
    let mut key = [0u8; ED25519_PUBLIC_KEY_LENGTH];
    key[0] = 0x42;
    let key_id = encode_key_id(&key);
    assert!(key_id.starts_with('z'));
    assert_eq!(decode_key_id(&key_id).unwrap(), key);
}

#[test]
fn entity_and_device_urns_share_the_key_id() {
    let key = [7u8; ED25519_PUBLIC_KEY_LENGTH];
    let key_id = encode_key_id(&key);
    assert_eq!(entity_urn(&key_id), format!("urn:xeip:entity:{key_id}"));
    assert_eq!(device_urn(&key_id), format!("urn:xeip:device:{key_id}"));
    assert_ne!(entity_urn(&key_id), device_urn(&key_id));
}

#[test]
fn rejects_padded_and_missing_prefix_spellings() {
    let key = [0x11u8; ED25519_PUBLIC_KEY_LENGTH];
    let key_id = encode_key_id(&key);

    // A padded extra leading '1' decodes to the wrong payload length. (For a
    // fixed payload length base58btc is a bijection, so this is rejected
    // before the re-encode equality check; assert it is rejected regardless.)
    let mut padded = String::from("z");
    padded.push('1');
    padded.push_str(&key_id[1..]);
    assert_eq!(
        decode_key_id(&padded),
        Err(KeyIdError::InvalidPayloadLength { actual: 35 })
    );

    // Missing 'z' prefix.
    assert_eq!(
        decode_key_id(&key_id[1..]),
        Err(KeyIdError::MissingMultibasePrefix)
    );

    // Valid length but a wrong multicodec prefix (0x00 0x00).
    let wrong_prefix = {
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[ED25519_MULTICODEC.len()..].copy_from_slice(&key);
        format!("z{}", base58btc_encode(&payload))
    };
    assert_eq!(
        decode_key_id(&wrong_prefix),
        Err(KeyIdError::WrongMulticodecPrefix)
    );
}

#[test]
fn canonicalize_matches_rfc_8785() {
    assert_eq!(
        canonicalize_json(&json!({"b": 1, "a": 2})),
        r#"{"a":2,"b":1}"#
    );
    // Keys are sorted by UTF-16 code units and nesting is recursive.
    assert_eq!(
        canonicalize_json(&json!({"z": 1, "a": [1, {"y": 1, "x": 2}]})),
        r#"{"a":[1,{"x":2,"y":1}],"z":1}"#
    );
    assert_eq!(
        canonicalize_json(&json!({"a": "a/b\n", "b": "\u{2028}"})),
        "{\"a\":\"a/b\\n\",\"b\":\"\u{2028}\"}"
    );
}

#[test]
fn canonicalize_uses_ecmascript_numbers() {
    assert_eq!(canonicalize_json(&json!(-0.0)), "0");
    assert_eq!(canonicalize_json(&json!(1.0)), "1");
    assert_eq!(canonicalize_json(&json!(0.1)), "0.1");
    assert_eq!(canonicalize_json(&json!(1e21)), "1e+21");
    assert_eq!(canonicalize_json(&json!(1e-7)), "1e-7");
    assert_eq!(
        canonicalize_json(&json!(9007199254740991i64)),
        "9007199254740991"
    );
    assert_eq!(canonicalize_json(&serde_json::from_str("-0").unwrap()), "0");
}

#[test]
fn base64url_is_canonical_and_unpadded() {
    let bytes = [0u8, 1, 2, 253, 254, 255];
    let text = base64url_encode(&bytes);
    assert_eq!(text, "AAEC_f7_");
    assert_eq!(base64url_decode(&text).unwrap(), bytes);
    assert_eq!(base64url_decode("AAEC_f7_="), None);
    assert_eq!(base64url_decode("A"), None);
    assert_eq!(base64url_decode("not base64!"), None);
    assert_eq!(base64url_decode(""), None);
}

#[test]
fn seed_derives_the_reference_public_key() {
    let seed: [u8; ED25519_SEED_LENGTH] =
        hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        hex_decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    );
}

#[test]
fn strict_parse_rejects_duplicate_object_members() {
    assert!(strict_parse(r#"{"a":1,"a":2}"#).is_err());
    assert!(strict_parse(r#"{"a":1,"b":2,"a":3}"#).is_err());
    // Nested duplicates are rejected too.
    assert!(strict_parse(r#"{"a":{"b":1,"b":2}}"#).is_err());
    assert_eq!(
        strict_parse(r#"{"a":1,"b":2}"#),
        Ok(json!({"a": 1, "b": 2}))
    );
}

#[test]
fn strict_parse_rejects_lone_surrogates_and_nonfinite_and_big_integers() {
    assert!(strict_parse(r#""\uD800""#).is_err());
    assert!(strict_parse(r#""\uDC00""#).is_err());
    assert!(strict_parse(r#""a\uD800b""#).is_err());
    // A correctly paired surrogate is one scalar value.
    assert_eq!(strict_parse(r#""\uD83D\uDE00""#), Ok(json!("\u{1f600}")));
    // Non-finite and out-of-range integers.
    assert!(strict_parse("1e999").is_err());
    assert!(strict_parse("9007199254740992").is_err());
    assert!(strict_parse("-9007199254740992").is_err());
    assert_eq!(
        strict_parse("9007199254740991"),
        Ok(json!(9007199254740991i64))
    );
    assert_eq!(strict_parse("-0").unwrap().as_f64(), Some(0.0));
    assert!(strict_parse("01").is_err());
    assert!(strict_parse(r#"{"a":1}x"#).is_err());
}

#[test]
fn weak_keys_are_rejected_before_verification() {
    for point in ED25519_SMALL_ORDER_POINTS {
        assert!(is_weak_ed25519_public_key(&point));
        assert!(VerifyingKey::from_bytes(&point).unwrap().is_weak());
    }
    // A real key is not flagged.
    let real = hex_decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    assert!(!is_weak_ed25519_public_key(&real));
}

#[test]
fn identity_key_forgery_is_rejected() {
    // A genuine forgery of the old non-strict verifier: the identity key
    // `01` + 31 zero bytes with `R = [S]B`, `S = 1` verifies for *every*
    // message under `verify` (non-strict). It must now fail with "weak key".
    let envelope = json!({
        "xeip": "0.1",
        "id": "urn:xeip:message:forged",
        "kind": "message",
        "sender": "urn:xeip:entity:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj",
        "recipient": "urn:xeip:entity:recipient-01",
        "body": {"contentType": "text/plain", "data": "forged"},
        "extensions": {"xeip.sig": {
            "v": "0.1",
            "alg": "EdDSA",
            "kid": "z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj",
            "sig": "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }}
    });
    assert_eq!(
        verify_signed_envelope(&envelope).unwrap_err().to_string(),
        "weak key"
    );
}

#[test]
fn verify_strict_rejects_a_small_order_r_that_loose_verify_accepts() {
    // CTC/CCTV ed25519vectors #5: a signature over "ed25519vectors 3" whose
    // R is the all-zero (small-order) encoding, under a canonical, non-weak
    // public key. The cofactored, non-strict `verify` accepts it, but
    // `verify_strict` rejects the small-order R. [`verify_signed_envelope`]
    // uses `verify_strict`, so a wire signature with a small-order R is
    // rejected by the Rust port even when the key itself is fine.
    use ed25519_dalek::Verifier;

    let public = VerifyingKey::from_bytes(&hex_decode(
        "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
    ))
    .expect("a canonical, non-weak public key");
    assert!(!public.is_weak(), "the key must not be small-order");

    // R = 00…00 (small-order), S from the reference vector.
    let mut signature_bytes = [0u8; ED25519_SIGNATURE_LENGTH];
    signature_bytes[ED25519_PUBLIC_KEY_LENGTH..].copy_from_slice(&hex_decode(
        "9472a69cd9a701a50d130ed52189e2455b23767db52cacb8716fb896ffeeac09",
    ));
    let signature = Signature::from_bytes(&signature_bytes);

    let message = b"ed25519vectors 3";
    assert!(
        public.verify(message, &signature).is_ok(),
        "non-strict verify accepts the small-order-R vector"
    );
    assert!(
        public.verify_strict(message, &signature).is_err(),
        "verify_strict must reject the small-order R"
    );
}

/// Decode a 64-character lowercase hex string into 32 bytes.
fn hex_decode(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("hex is ASCII");
        out[index] = u8::from_str_radix(pair, 16).expect("valid hex");
    }
    out
}
