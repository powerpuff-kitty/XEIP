//! Cross-language conformance for the signed device-rotation profile.
//!
//! Every committed case under `conformance/fixtures/identity-rotation/` must
//! reproduce with the Rust `DeviceRotationTracker` and yield the same
//! `valid`/`reason` result as `tools/identity-device-rotation.mjs`:
//!
//! - positive cases verify and their `is_active` assertions hold,
//! - negative cases are rejected with the documented reason,
//! - re-signing the positive rotation statement with the reference seed
//!   reproduces the committed signature byte-for-byte (Ed25519 is
//!   deterministic), proving byte-identical signing input across languages.
//!
//! Verification goes through `DeviceRotationTracker::ingest_text` for raw `text`
//! steps (the strict pre-parse gate) and `DeviceRotationTracker::ingest` for
//! parsed object steps.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use xeip_identity::{
    sign_device_rotation, verify_device_rotation, verify_device_rotation_text, DeviceRotationError,
    DeviceRotationTracker, ED25519_SEED_LENGTH,
};

/// The deterministic RFC 8032 seed shared with the JavaScript reference and the
/// committed vectors.
const SEED_A_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[derive(Debug, Deserialize)]
struct RotationFile {
    trusted: HashMap<String, Value>,
    rotations: HashMap<String, Value>,
    trackers: Vec<TrackerVector>,
}

#[derive(Debug, Deserialize)]
struct TrackerVector {
    name: String,
    trusted: String,
    #[serde(default, rename = "maxOverlapSeconds")]
    max_overlap_seconds: Option<i64>,
    steps: Vec<StepVector>,
}

#[derive(Debug, Deserialize)]
struct StepVector {
    kind: String,
    name: String,
    #[serde(default)]
    rotation: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    active: Option<bool>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/identity-rotation/rotation.vectors.json")
}

fn load_file() -> RotationFile {
    let raw = std::fs::read_to_string(vectors_path()).expect("read rotation vectors");
    serde_json::from_str(&raw).expect("parse rotation vectors")
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
        let mut state = DeviceRotationTracker::new();

        for step in &tracker.steps {
            match step.kind.as_str() {
                "ingest" => {
                    let result = match (&step.text, &step.rotation) {
                        (Some(text), None) => {
                            state.ingest_text(text, trusted, tracker.max_overlap_seconds)
                        }
                        (None, Some(rotation)) => {
                            let document = file.rotations.get(rotation).unwrap_or_else(|| {
                                panic!("{}/{}: unknown rotation", tracker.name, step.name)
                            });
                            state.ingest(document, trusted, tracker.max_overlap_seconds)
                        }
                        _ => panic!(
                            "{}/{}: exactly one of `rotation` or `text` is required",
                            tracker.name, step.name
                        ),
                    };
                    if step.valid == Some(true) {
                        assert_eq!(
                            result,
                            Ok(()),
                            "step must verify: {}/{}",
                            tracker.name,
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
                            tracker.name,
                            step.name
                        );
                        reasons.insert(expected.to_string());
                    }
                }
                "active" => {
                    let kid = step.kid.as_deref().expect("an active step carries a kid");
                    let now = step.now.as_deref().expect("an active step carries now");
                    let result = state.is_active(&entity, kid, now);
                    if step.active == Some(true) {
                        assert_eq!(
                            result,
                            Ok(()),
                            "key must be active: {}/{}",
                            tracker.name,
                            step.name
                        );
                    } else {
                        let expected = step
                            .reason
                            .as_deref()
                            .expect("an inactive step carries a reason");
                        let error = result.expect_err("an inactive step must be rejected");
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
                other => panic!(
                    "{}/{}: unknown step kind {other:?}",
                    tracker.name, step.name
                ),
            }
        }
    }

    assert!(
        valid_steps >= 2,
        "the valid trackers must accept their rotations"
    );
    for reason in [
        "rotation conflict",
        "overlap too long",
        "expired predecessor",
        "unknown device",
        "unknown signer",
        "weak key",
        "signature mismatch",
        "entity binding",
        "unknown field",
        "unsupported version",
        "malformed document",
    ] {
        assert!(
            reasons.contains(reason),
            "missing rotation reason: {reason}"
        );
    }
}

#[test]
fn sign_reproduces_the_committed_rotation_statement() {
    let file = load_file();
    let rotation = file
        .rotations
        .get("rotation.valid")
        .expect("the rotation.valid vector carries a statement");
    let trusted = file.trusted.get("keydoc.entity").expect("trusted keydoc");
    let kid = trusted["genesis"].as_str().expect("genesis kid");

    let seed: [u8; ED25519_SEED_LENGTH] = hex_decode_32(SEED_A_HEX);
    let re_signed =
        sign_device_rotation(&unsigned(rotation), &seed, kid).expect("sign device rotation");
    assert_eq!(
        re_signed, *rotation,
        "re-signing must reproduce the committed rotation statement"
    );
    assert_eq!(verify_device_rotation(&re_signed, trusted), Ok(()));
}

#[test]
fn single_document_reasons_match_the_javascript_reference() {
    let file = load_file();
    let trusted = file.trusted.get("keydoc.entity").expect("trusted keydoc");

    let valid = file
        .rotations
        .get("rotation.valid")
        .expect("valid rotation");
    assert_eq!(verify_device_rotation(valid, trusted), Ok(()));
    assert_eq!(
        verify_device_rotation_text(&serde_json::to_string(valid).unwrap(), trusted),
        Ok(())
    );

    // A weak successor is reported after entity binding and before signatures.
    assert_eq!(
        verify_device_rotation(
            file.rotations.get("rotation.weak-successor").unwrap(),
            trusted
        ),
        Err(DeviceRotationError::WeakKey)
    );

    let cases = [
        (
            "rotation.entity-mismatch",
            DeviceRotationError::EntityBinding,
        ),
        ("rotation.unknown-field", DeviceRotationError::UnknownField),
        (
            "rotation.unsupported-version",
            DeviceRotationError::UnsupportedVersion,
        ),
        ("rotation.nonroot", DeviceRotationError::UnknownSigner),
        ("rotation.tampered", DeviceRotationError::SignatureMismatch),
        (
            "rotation.bad-issued",
            DeviceRotationError::MalformedDocument,
        ),
        ("rotation.bad-kid", DeviceRotationError::MalformedDocument),
        (
            "rotation.equal-kids",
            DeviceRotationError::MalformedDocument,
        ),
    ];
    for (name, expected) in cases {
        let document = file
            .rotations
            .get(name)
            .unwrap_or_else(|| panic!("missing rotation {name}"));
        assert_eq!(
            verify_device_rotation(document, trusted),
            Err(expected),
            "reason mismatch for {name}"
        );
    }

    // The strict pre-parse gate collapses a duplicate-member statement.
    assert_eq!(
        verify_device_rotation_text(
            r#"{"xeip":"xeip.device-rotation/0.1","entity":"a","entity":"b"}"#,
            trusted
        ),
        Err(DeviceRotationError::MalformedDocument)
    );
}

#[test]
fn tracker_commits_state_only_on_success() {
    let file = load_file();
    let trusted = file.trusted.get("keydoc.entity").expect("trusted keydoc");
    let entity = trusted["entity"].as_str().expect("entity").to_string();
    let valid = file
        .rotations
        .get("rotation.valid")
        .expect("valid rotation");
    let tampered = file
        .rotations
        .get("rotation.tampered")
        .expect("tampered rotation");
    let second = file
        .rotations
        .get("rotation.second-rotation")
        .expect("second rotation");

    let mut tracker = DeviceRotationTracker::new();
    assert!(!tracker.has_rotations(&entity));

    // A tampered rotation is rejected and records nothing.
    assert_eq!(
        tracker.ingest(tampered, trusted, Some(2_592_000)),
        Err(DeviceRotationError::SignatureMismatch)
    );
    assert!(!tracker.has_rotations(&entity));

    // A fresh, valid rotation is accepted.
    assert_eq!(tracker.ingest(valid, trusted, Some(2_592_000)), Ok(()));
    assert!(tracker.has_rotations(&entity));

    // A second rotation of the same predecessor is a conflict and does not
    // advance the accepted state.
    assert_eq!(
        tracker.ingest(second, trusted, Some(2_592_000)),
        Err(DeviceRotationError::RotationConflict)
    );
    assert_eq!(
        tracker.is_active(
            &entity,
            second["successor_kid"].as_str().unwrap(),
            "2026-10-25T00:00:00Z"
        ),
        Err(DeviceRotationError::UnknownDevice)
    );
}
