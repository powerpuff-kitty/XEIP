//! Cross-language conformance for the signed identity status profile.
//!
//! Every committed case under `conformance/fixtures/identity-status/` must
//! reproduce with the Rust `StatusTracker` and yield the same
//! `valid`/`reason` result as `tools/identity-status.mjs`:
//!
//! - positive cases verify and their `is_revoked` assertions hold,
//! - negative cases are rejected with the documented reason,
//! - re-signing the positive status document with the reference seed reproduces
//!   the committed signature byte-for-byte (Ed25519 is deterministic), proving
//!   byte-identical signing input across languages.
//!
//! Verification goes through `StatusTracker::ingest_text` for raw `text` steps
//! (the strict pre-parse gate) and `StatusTracker::ingest` for parsed object
//! steps.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use xeip_identity::{
    sign_status_document, verify_status_document, verify_status_document_text, StatusError,
    StatusTracker, ED25519_SEED_LENGTH,
};

/// The deterministic RFC 8032 seed shared with the JavaScript reference and the
/// committed vectors.
const SEED_A_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[derive(Debug, Deserialize)]
struct StatusFile {
    trusted: HashMap<String, Value>,
    statuses: HashMap<String, Value>,
    trackers: Vec<TrackerVector>,
}

#[derive(Debug, Deserialize)]
struct TrackerVector {
    name: String,
    trusted: String,
    now: String,
    #[serde(default, rename = "maxAgeSeconds")]
    max_age_seconds: Option<i64>,
    steps: Vec<StepVector>,
}

#[derive(Debug, Deserialize)]
struct StepVector {
    name: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    text: Option<String>,
    valid: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    revoked: Vec<RevokedCheck>,
}

#[derive(Debug, Deserialize)]
struct RevokedCheck {
    kid: String,
    generation: i64,
    expected: bool,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-status/status.vectors.json")
}

fn load_file() -> StatusFile {
    let raw = std::fs::read_to_string(vectors_path()).expect("read status vectors");
    serde_json::from_str(&raw).expect("parse status vectors")
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

fn unsigned(document: &Value) -> Value {
    let mut copy = document.clone();
    copy.as_object_mut()
        .expect("document is an object")
        .remove("signatures");
    copy
}

#[test]
fn every_tracker_step_yields_its_documented_result() {
    let file = load_file();
    assert!(
        file.trackers.len() >= 6,
        "at least six trackers are required"
    );

    let mut names = HashSet::new();
    let mut reasons = HashSet::new();
    let mut valid_steps = 0usize;
    let mut saw_revoked = false;

    for tracker in &file.trackers {
        assert!(
            names.insert(tracker.name.clone()),
            "duplicate tracker name: {}",
            tracker.name
        );
        let trusted = file
            .trusted
            .get(&tracker.trusted)
            .unwrap_or_else(|| panic!("{}: unknown trusted document", tracker.name));
        let entity = trusted["entity"]
            .as_str()
            .expect("trusted entity")
            .to_string();
        let mut tracker_state = StatusTracker::new();

        for step in &tracker.steps {
            let result = match (&step.text, &step.status) {
                (Some(text), None) => {
                    tracker_state.ingest_text(text, trusted, &tracker.now, tracker.max_age_seconds)
                }
                (None, Some(status)) => {
                    let document = file.statuses.get(status).unwrap_or_else(|| {
                        panic!("{}/{}: unknown status", tracker.name, step.name)
                    });
                    tracker_state.ingest(document, trusted, &tracker.now, tracker.max_age_seconds)
                }
                _ => panic!(
                    "{}/{}: exactly one of `status` or `text` is required",
                    tracker.name, step.name
                ),
            };

            if step.valid {
                assert_eq!(
                    result,
                    Ok(()),
                    "step must verify: {}/{}",
                    tracker.name,
                    step.name
                );
                for check in &step.revoked {
                    let actual = tracker_state.is_revoked(&entity, &check.kid, check.generation);
                    assert_eq!(
                        actual, check.expected,
                        "is_revoked mismatch: {}/{} {}@{}",
                        tracker.name, step.name, check.kid, check.generation
                    );
                    saw_revoked = true;
                }
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
                    tracker.name,
                    step.name
                );
                reasons.insert(expected.to_string());
            }
        }
    }

    assert!(
        valid_steps >= 2,
        "the valid trackers must accept their status"
    );
    assert!(saw_revoked, "a revoked-key assertion is required");
    for reason in [
        "serial rollback",
        "stale status",
        "unknown signer",
        "weak key",
        "signature mismatch",
        "entity binding",
        "unknown field",
        "unsupported version",
        "malformed document",
    ] {
        assert!(reasons.contains(reason), "missing status reason: {reason}");
    }
}

#[test]
fn sign_reproduces_the_committed_status_document() {
    let file = load_file();
    let status = file
        .statuses
        .get("status.revoke.1")
        .expect("the status.revoke.1 vector carries a document");
    let trusted = file.trusted.get("keydoc.entity").expect("trusted keydoc");
    let kid = trusted["genesis"].as_str().expect("genesis kid");

    let seed: [u8; ED25519_SEED_LENGTH] = hex_decode_32(SEED_A_HEX);
    let re_signed =
        sign_status_document(&unsigned(status), &seed, kid).expect("sign status document");
    assert_eq!(
        re_signed, *status,
        "re-signing must reproduce the committed status document"
    );
    assert_eq!(verify_status_document(&re_signed, trusted), Ok(()));
}

#[test]
fn single_document_reasons_match_the_javascript_reference() {
    let file = load_file();
    let trusted = file.trusted.get("keydoc.entity").expect("trusted keydoc");

    let valid = file.statuses.get("status.revoke.1").expect("valid status");
    assert_eq!(verify_status_document(valid, trusted), Ok(()));
    assert_eq!(
        verify_status_document_text(&serde_json::to_string(valid).unwrap(), trusted),
        Ok(())
    );

    let cases = [
        ("status.entity-mismatch", StatusError::EntityBinding),
        ("status.unknown-field", StatusError::UnknownField),
        (
            "status.unsupported-version",
            StatusError::UnsupportedVersion,
        ),
        ("status.weak", StatusError::WeakKey),
        ("status.nonroot", StatusError::UnknownSigner),
        ("status.tampered", StatusError::SignatureMismatch),
    ];
    for (name, expected) in cases {
        let document = file
            .statuses
            .get(name)
            .unwrap_or_else(|| panic!("missing status {name}"));
        assert_eq!(
            verify_status_document(document, trusted),
            Err(expected),
            "reason mismatch for {name}"
        );
    }

    // The strict pre-parse gate collapses a duplicate-member document.
    assert_eq!(
        verify_status_document_text(
            r#"{"xeip":"xeip.status/0.1","entity":"a","entity":"b"}"#,
            trusted
        ),
        Err(StatusError::MalformedDocument)
    );
}

#[test]
fn tracker_commits_state_only_on_success() {
    let file = load_file();
    let trusted = file.trusted.get("keydoc.entity").expect("trusted keydoc");
    let entity = trusted["entity"].as_str().expect("entity").to_string();
    let valid = file.statuses.get("status.revoke.1").expect("valid status");
    let stale = file.statuses.get("status.stale").expect("stale status");
    let rolled = file
        .statuses
        .get("status.clean.1")
        .expect("rolled back status");

    let mut tracker = StatusTracker::new();
    assert!(!tracker.has_status(&entity));
    assert_eq!(tracker.accepted_serial(&entity), None);

    // A stale document is rejected and records nothing.
    assert_eq!(
        tracker.ingest(stale, trusted, "2026-10-12T00:00:00Z", Some(604_800)),
        Err(StatusError::Stale)
    );
    assert!(!tracker.has_status(&entity));

    // A fresh valid document is accepted and advances the serial.
    assert_eq!(
        tracker.ingest(valid, trusted, "2026-10-10T12:00:00Z", Some(604_800)),
        Ok(())
    );
    assert_eq!(tracker.accepted_serial(&entity), Some(1));

    // A lower serial is a rollback and leaves the accepted status untouched.
    assert_eq!(
        tracker.ingest(rolled, trusted, "2026-10-10T12:00:00Z", Some(604_800)),
        Err(StatusError::SerialRollback)
    );
    assert_eq!(tracker.accepted_serial(&entity), Some(1));
}
