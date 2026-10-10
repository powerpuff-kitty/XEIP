//! Cross-language conformance for the signed key-document profile.
//!
//! Every committed vector under `conformance/fixtures/identity-keydoc/` must
//! reproduce with the Rust verifier and yield the same `valid`/`reason` result
//! as `tools/key-document.mjs`:
//!
//! - positive cases verify,
//! - negative cases are rejected with the documented reason,
//! - re-signing the positive genesis and dual-signed rotation documents with the
//!   reference seeds reproduces the committed signatures byte-for-byte
//!   (Ed25519 is deterministic).
//!
//! Verification goes through [`verify_key_document_text`] — the strict
//! pre-parse gate plus verification — for *every* vector, so duplicate-key and
//! out-of-range-integer text cases are exercised. Object vectors are serialized
//! to JSON text first; text vectors carry the raw wire bytes directly.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use xeip_identity::{
    key_document_chain_digest, sign_key_document, verify_key_document, verify_key_document_text,
    KeyDocumentChain, ED25519_SEED_LENGTH,
};

/// Deterministic RFC 8032 seeds shared with the JavaScript reference and the
/// committed vectors.
const SEED_A_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SEED_B_HEX: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const PUBLIC_A_HEX: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    valid: bool,
    reason: Option<String>,
    /// Parsed document, used when the vector is not a raw text case.
    document: Option<Value>,
    /// Raw JSON text, used for the strict pre-parse gate cases.
    text: Option<String>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-keydoc/keydoc.vectors.json")
}

fn chain_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-keydoc/keydoc-chain.vectors.json")
}

fn load_vectors() -> Vec<Vector> {
    let raw = std::fs::read_to_string(vectors_path()).expect("read key-document vectors");
    serde_json::from_str(&raw).expect("parse key-document vectors")
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

fn seed(hex: &str) -> [u8; ED25519_SEED_LENGTH] {
    hex_decode_32(hex)
}

/// The exact JSON text a vector asks the verifier to consume: raw `text` when
/// present, otherwise the `document` re-serialized.
fn vector_text(vector: &Vector) -> String {
    match (&vector.text, &vector.document) {
        (Some(text), None) => text.clone(),
        (None, Some(document)) => {
            serde_json::to_string(document).expect("serialize vector document")
        }
        _ => panic!(
            "vector must carry exactly one of `document` or `text`: {}",
            vector.name
        ),
    }
}

fn unsigned(document: &Value) -> Value {
    let mut copy = document.clone();
    copy.as_object_mut()
        .expect("document is an object")
        .remove("signatures");
    copy
}

#[test]
fn every_vector_yields_its_documented_result() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 9,
        "at least nine key-document vectors are required"
    );

    let mut names = HashSet::new();
    let mut positives = 0usize;
    let mut negatives = 0usize;
    let mut reasons = HashSet::new();
    let mut saw_text = false;

    for vector in &vectors {
        assert!(names.insert(vector.name.clone()), "duplicate vector name");

        let text = vector_text(vector);
        if vector.text.is_some() {
            saw_text = true;
        }
        let result = verify_key_document_text(&text);
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
            reasons.insert(expected.to_string());
        }
    }

    assert!(positives >= 1, "at least one positive vector is required");
    assert!(negatives >= 1, "at least one negative vector is required");
    assert!(
        saw_text,
        "at least one strict-parse text vector is required"
    );
    for reason in [
        "signature mismatch",
        "entity binding",
        "weak key",
        "unsupported version",
        "unknown field",
        "unknown signer",
        "malformed document",
    ] {
        assert!(reasons.contains(reason), "missing reason: {reason}");
    }
}

#[test]
fn sign_reproduces_the_committed_genesis_and_rotation() {
    let vectors = load_vectors();
    let genesis = vectors
        .iter()
        .find(|vector| vector.name == "genesis.valid")
        .and_then(|vector| vector.document.as_ref())
        .expect("the genesis.valid vector carries a document");
    let rotation = vectors
        .iter()
        .find(|vector| vector.name == "rotation.dual-signed")
        .and_then(|vector| vector.document.as_ref())
        .expect("the rotation.dual-signed vector carries a document");

    let kid_a = genesis["genesis"].as_str().expect("genesis kid");
    let kid_b = rotation["roots"][1].as_str().expect("successor root kid");

    let seed_a = seed(SEED_A_HEX);
    let seed_b = seed(SEED_B_HEX);

    // The reference seed derives the reference public key and genesis key-id.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_a);
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        hex_decode_32(PUBLIC_A_HEX),
        "seed A must derive the reference public key"
    );

    let re_signed_genesis =
        sign_key_document(&unsigned(genesis), &seed_a, kid_a).expect("sign genesis");
    assert_eq!(
        re_signed_genesis, *genesis,
        "re-signing must reproduce the committed genesis document"
    );

    let re_signed_rotation = sign_key_document(&unsigned(rotation), &seed_a, kid_a)
        .and_then(|once| sign_key_document(&once, &seed_b, kid_b))
        .expect("dual-sign rotation");
    assert_eq!(
        re_signed_rotation, *rotation,
        "dual-signing must reproduce the committed rotation document"
    );
    assert_eq!(verify_key_document(&re_signed_rotation), Ok(()));
}

/// A chain-vector file: a shared registry of documents plus ordered chains whose
/// every step carries the expected `valid`/`reason` result.
#[derive(Debug, Deserialize)]
struct ChainFile {
    documents: std::collections::HashMap<String, Value>,
    chains: Vec<ChainVector>,
}

#[derive(Debug, Deserialize)]
struct ChainVector {
    name: String,
    steps: Vec<ChainStep>,
}

#[derive(Debug, Deserialize)]
struct ChainStep {
    name: String,
    document: String,
    valid: bool,
    reason: Option<String>,
}

fn load_chain_file() -> ChainFile {
    let raw = std::fs::read_to_string(chain_vectors_path()).expect("read chain vectors");
    serde_json::from_str(&raw).expect("parse chain vectors")
}

#[test]
fn chain_digest_commits_to_the_signed_predecessor() {
    let file = load_chain_file();
    let genesis = &file.documents["genesis.gen1"];
    let rotation = &file.documents["rotation.gen2"];

    assert_eq!(
        rotation["previous"]
            .as_str()
            .expect("rotation carries previous"),
        key_document_chain_digest(genesis),
        "`previous` is the chain digest of the signed predecessor"
    );

    // The digest covers `signatures`: dropping them changes the digest.
    let mut without_signatures = genesis.clone();
    without_signatures
        .as_object_mut()
        .expect("genesis is an object")
        .remove("signatures");
    assert_ne!(
        key_document_chain_digest(genesis),
        key_document_chain_digest(&without_signatures)
    );
}

#[test]
fn every_chain_vector_yields_its_documented_per_step_result() {
    let file = load_chain_file();
    assert!(
        file.chains.len() >= 4,
        "at least four chains are required (valid, rollback, fork, gap)"
    );

    let mut names = HashSet::new();
    let mut reasons = HashSet::new();
    let mut valid_steps = 0usize;

    for chain in &file.chains {
        assert!(
            names.insert(chain.name.clone()),
            "duplicate chain name: {}",
            chain.name
        );
        let mut verifier = KeyDocumentChain::new();
        for step in &chain.steps {
            let document = file
                .documents
                .get(&step.document)
                .unwrap_or_else(|| panic!("{}/{}: unknown document", chain.name, step.name));
            let result = verifier.ingest(document);
            if step.valid {
                assert_eq!(
                    result,
                    Ok(()),
                    "step must verify: {}/{}",
                    chain.name,
                    step.name
                );
                valid_steps += 1;
            } else {
                let expected = step
                    .reason
                    .as_deref()
                    .expect("a negative step carries a reason");
                let error = result.expect_err("a negative step must be rejected");
                assert_eq!(
                    error.to_string(),
                    expected,
                    "reason mismatch: {}/{}",
                    chain.name,
                    step.name
                );
                reasons.insert(expected.to_string());
            }
        }
    }

    assert!(
        valid_steps >= 3,
        "the valid chain accepts its genesis and rotations"
    );
    for reason in ["rollback", "fork", "chain gap"] {
        assert!(reasons.contains(reason), "missing chain reason: {reason}");
    }
}
