//! Cross-language conformance: every committed JSON vector must reproduce with
//! the Rust encoder/decoder, matching `tools/derive-keyid.mjs` byte-for-byte.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;
use xeip_identity::{decode_key_id, device_urn, encode_key_id, entity_urn};

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: Option<String>,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "entityUrn")]
    entity_urn: Option<String>,
    #[serde(rename = "deviceUrn")]
    device_urn: Option<String>,
    valid: Option<bool>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-keyid/identity-keyid.vectors.json")
}

fn hex_decode_32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "publicKeyHex must be 64 hex characters");
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("hex is ASCII");
        out[index] = u8::from_str_radix(pair, 16).expect("valid hex");
    }
    out
}

#[test]
fn conformance_vectors_reproduce_and_reject() {
    let raw = std::fs::read_to_string(vectors_path()).expect("read identity key-id vectors");
    let vectors: Vec<Vector> = serde_json::from_str(&raw).expect("parse vectors");
    assert!(vectors.len() >= 5, "at least five vectors are required");

    let mut names = HashSet::new();
    let mut positive = 0usize;
    let mut negative = 0usize;
    let mut saw_all_zero = false;
    let mut saw_all_ff = false;

    for vector in &vectors {
        assert!(names.insert(vector.name.clone()), "duplicate vector name");

        if vector.valid == Some(false) {
            negative += 1;
            assert!(
                decode_key_id(&vector.key_id).is_err(),
                "negative vector must be rejected: {}",
                vector.name
            );
            continue;
        }

        positive += 1;
        let hex = vector
            .public_key_hex
            .as_deref()
            .expect("positive vector carries publicKeyHex");
        if hex == "0".repeat(64) {
            saw_all_zero = true;
        }
        if hex == "f".repeat(64) {
            saw_all_ff = true;
        }

        let key = hex_decode_32(hex);
        let key_id = encode_key_id(&key);
        assert_eq!(key_id, vector.key_id, "keyId mismatch: {}", vector.name);
        assert_eq!(
            entity_urn(&key_id),
            vector.entity_urn.as_deref().expect("entityUrn"),
            "entityUrn mismatch: {}",
            vector.name
        );
        assert_eq!(
            device_urn(&key_id),
            vector.device_urn.as_deref().expect("deviceUrn"),
            "deviceUrn mismatch: {}",
            vector.name
        );
        assert_eq!(
            decode_key_id(&key_id).expect("round-trip"),
            key,
            "round-trip mismatch: {}",
            vector.name
        );
    }

    assert!(positive >= 5, "expected at least five positive vectors");
    assert!(negative >= 1, "expected at least one negative vector");
    assert!(saw_all_zero, "an all-zero key vector is required");
    assert!(saw_all_ff, "an all-0xff key vector is required");
}
