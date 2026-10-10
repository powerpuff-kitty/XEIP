//! Cross-language conformance for the signed-envelope profile.
//!
//! Every committed vector under `conformance/fixtures/identity-signed/` must
//! reproduce with the Rust canonicalizer/signer/verifier and yield the same
//! `valid`/`reason` result as `tools/signed-envelope.mjs`:
//!
//! - positive cases verify,
//! - negative cases are rejected with the documented reason,
//! - re-signing the positive envelope with the reference seed reproduces the
//!   committed signature byte-for-byte (Ed25519 is deterministic).

use std::collections::HashSet;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::Value;
use xeip_identity::{sign_envelope, verify_signed_envelope};

/// Deterministic RFC 8032 seed shared with the JavaScript reference. It must
/// yield the public key carried by every vector.
const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const EXPECTED_PUBLIC_KEY_HEX: &str =
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
    envelope: Value,
    valid: bool,
    reason: Option<String>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-signed/signed.vectors.json")
}

fn load_vectors() -> Vec<Vector> {
    let raw = std::fs::read_to_string(vectors_path()).expect("read signed-envelope vectors");
    serde_json::from_str(&raw).expect("parse signed-envelope vectors")
}

fn hex_decode_32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "expected 64 hex characters");
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("hex is ASCII");
        out[index] = u8::from_str_radix(pair, 16).expect("valid hex");
    }
    out
}

#[test]
fn every_vector_yields_its_documented_result() {
    let vectors = load_vectors();
    assert_eq!(
        vectors.len(),
        6,
        "one positive and five negative vectors are required"
    );

    let mut names = HashSet::new();
    let mut positives = 0usize;
    let mut negatives = 0usize;

    for vector in &vectors {
        assert!(names.insert(vector.name.clone()), "duplicate vector name");

        let result = verify_signed_envelope(&vector.envelope);
        if vector.valid {
            positives += 1;
            assert_eq!(
                result,
                Ok(()),
                "positive vector must verify: {}",
                vector.name
            );
        } else {
            negatives += 1;
            let expected = vector
                .reason
                .as_deref()
                .expect("a negative vector carries a reason");
            let error = result.expect_err("negative vector must be rejected");
            assert_eq!(
                error.to_string(),
                expected,
                "reason mismatch: {}",
                vector.name
            );
        }
    }

    assert!(positives >= 1, "at least one positive vector is required");
    assert!(negatives >= 1, "at least one negative vector is required");
}

#[test]
fn sign_reproduces_the_committed_positive_vector() {
    let vectors = load_vectors();
    let positive = vectors
        .iter()
        .find(|vector| vector.valid)
        .expect("a positive vector exists");

    let seed = hex_decode_32(SEED_HEX);
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        hex_decode_32(EXPECTED_PUBLIC_KEY_HEX),
        "seed must derive the reference public key"
    );
    assert_eq!(
        positive.public_key_hex, EXPECTED_PUBLIC_KEY_HEX,
        "vector publicKeyHex must be the reference key"
    );

    let kid = positive.envelope["extensions"]["xeip.sig"]["kid"]
        .as_str()
        .expect("carrier kid");
    let signed = sign_envelope(&positive.envelope, &seed, kid).expect("sign the positive envelope");
    assert_eq!(
        signed, positive.envelope,
        "re-signing must reproduce the committed carrier exactly"
    );
    assert_eq!(verify_signed_envelope(&signed), Ok(()));
}

#[test]
fn signing_an_unbound_sender_is_rejected_by_verification() {
    let seed = hex_decode_32(SEED_HEX);
    let kid = "z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
    let envelope = serde_json::json!({
        "xeip": "0.1",
        "id": "urn:xeip:message:unbound",
        "kind": "message",
        "sender": "urn:xeip:entity:someone-else",
        "recipient": "urn:xeip:entity:recipient-01",
        "body": { "contentType": "text/plain", "data": "hi" }
    });

    let signed = sign_envelope(&envelope, &seed, kid).expect("sign");
    assert_eq!(
        verify_signed_envelope(&signed).unwrap_err().to_string(),
        "sender binding"
    );
}
