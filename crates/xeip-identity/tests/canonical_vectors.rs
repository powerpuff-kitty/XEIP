//! Cross-language RFC 8785 (JCS) canonicalization known-answer tests.
//!
//! Every committed vector under
//! `conformance/fixtures/identity-canonical/canonical.vectors.json` carries a raw
//! JSON input `json` and the exact `canonical` output `tools/signed-envelope.mjs`
//! (the JavaScript reference) produces. This test parses each input with
//! `serde_json` and asserts the Rust canonicalizer emits the byte-identical
//! canonical string, pinning number formatting, key order, string escaping and
//! empty-container handling across JS/Node, Rust and TypeScript.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;
use xeip_identity::canonicalize_json;

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    /// Raw JSON input text.
    json: String,
    /// Expected RFC 8785 output.
    canonical: String,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-canonical/canonical.vectors.json")
}

#[test]
fn every_canonical_vector_matches_the_reference() {
    let raw = std::fs::read_to_string(vectors_path()).expect("read canonical vectors");
    let vectors: Vec<Vector> = serde_json::from_str(&raw).expect("parse canonical vectors");
    assert!(
        vectors.len() >= 20,
        "at least twenty canonicalization vectors are required"
    );

    let mut names = HashSet::new();
    for vector in &vectors {
        assert!(
            names.insert(vector.name.clone()),
            "duplicate vector name: {}",
            vector.name
        );
        let value: serde_json::Value =
            serde_json::from_str(&vector.json).expect("parse vector input json");
        assert_eq!(
            canonicalize_json(&value),
            vector.canonical,
            "canonicalization mismatch: {}",
            vector.name
        );
    }
}
