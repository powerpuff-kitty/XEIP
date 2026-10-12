use crate::canonical::{canonicalize_json, strict_parse};
use crate::crypto::{is_weak_ed25519_public_key, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH};
use crate::encoding::{base64url_decode, base64url_encode};
use crate::key_id::decode_key_id;
use crate::status::{status_trusted_entity, status_trusted_roots};
use crate::time::{is_utc_timestamp, parse_utc_seconds};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::fmt;

// ---------------------------------------------------------------------------
// Signed device-rotation statements: `xeip.device-rotation/0.1`
//
// The device-rotation slice of `spec/identity-keys.md` §5.3/§6 / ADR 0010. This
// covers single-document verification (structure, entity binding to a trusted
// key document, and at least one signature by a current root key) plus the
// bounded-overlap lifecycle rules `DeviceRotationTracker` adds on top: rotation
// conflict, a caller-bounded overlap and predecessor expiry. Root rotation,
// overlap enforcement distribution and directory discovery remain out of scope.
// The grammar and the stable reasons are byte-identical to
// `tools/identity-device-rotation.mjs` and the shared vectors under
// `conformance/fixtures/identity-rotation/`.
// ---------------------------------------------------------------------------

/// The only accepted `xeip` value; anything else is `UnsupportedVersion`.
pub const ROTATION_VERSION: &str = "xeip.device-rotation/0.1";

/// The complete device-rotation member set. Any other member is rejected as
/// [`DeviceRotationError::UnknownField`].
const ROTATION_FIELDS: [&str; 7] = [
    "xeip",
    "entity",
    "previous_kid",
    "successor_kid",
    "issuedAt",
    "overlapUntil",
    "signatures",
];

/// Reasons a signed device-rotation statement can be rejected by
/// [`verify_device_rotation`] or [`DeviceRotationTracker::ingest`].
///
/// The first seven variants are the single-document reasons, shared verbatim
/// with the key-document and status profiles. `RotationConflict` and
/// `OverlapTooLong` are the stateful ingest rules; `ExpiredPredecessor` and
/// `UnknownDevice` are reported by [`DeviceRotationTracker::is_active`].
///
/// The [`fmt::Display`] spelling of each variant matches the stable `reason`
/// strings of the JavaScript reference (`tools/identity-device-rotation.mjs`),
/// so cross-language reason comparisons are byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRotationError {
    /// Not an object (or invalid JSON through a text entry point), a field has
    /// the wrong type, a key-id does not decode, or `issuedAt`/`overlapUntil`
    /// is not a UTC instant.
    MalformedDocument,
    /// `xeip` is not exactly `xeip.device-rotation/0.1`.
    UnsupportedVersion,
    /// The statement carries a member outside the fixed profile.
    UnknownField,
    /// `entity` is not the trusted key document's `entity`.
    EntityBinding,
    /// No signature by a current root key listed in the trusted key document.
    UnknownSigner,
    /// A device or signer key-id decodes to a small-order (weak) Ed25519 point.
    WeakKey,
    /// The canonical bytes do not verify under any listed root key.
    SignatureMismatch,
    /// Lifecycle only: the `previous_kid` was already rotated, or the
    /// `successor_kid` was already retired (was itself a predecessor).
    RotationConflict,
    /// Lifecycle only: the overlap exceeds the caller-supplied maximum.
    OverlapTooLong,
    /// `is_active` only: the predecessor's bounded overlap has ended.
    ExpiredPredecessor,
    /// `is_active` only: no accepted rotation names the key.
    UnknownDevice,
}

impl fmt::Display for DeviceRotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MalformedDocument => "malformed document",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnknownField => "unknown field",
            Self::EntityBinding => "entity binding",
            Self::UnknownSigner => "unknown signer",
            Self::WeakKey => "weak key",
            Self::SignatureMismatch => "signature mismatch",
            Self::RotationConflict => "rotation conflict",
            Self::OverlapTooLong => "overlap too long",
            Self::ExpiredPredecessor => "expired predecessor",
            Self::UnknownDevice => "unknown device",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for DeviceRotationError {}

/// The RFC 8785 signing input of a device-rotation statement: the statement
/// with the `signatures` member removed in its entirety, canonicalized.
fn rotation_signing_input(document: &Value) -> String {
    let mut base = document.clone();
    if let Some(object) = base.as_object_mut() {
        object.remove("signatures");
    }
    canonicalize_json(&base)
}

/// Sign a device-rotation statement: canonicalize the statement with
/// `signatures` removed (RFC 8785) and Ed25519-sign those UTF-8 bytes, then
/// append `{ kid, sig }` to any existing `signatures` array.
///
/// Returns [`DeviceRotationError::MalformedDocument`] if `document` is not a
/// JSON object. Verification is what enforces the root-signer requirement.
pub fn sign_device_rotation(
    document: &Value,
    seed: &[u8; ED25519_SEED_LENGTH],
    kid: &str,
) -> Result<Value, DeviceRotationError> {
    if !document.is_object() {
        return Err(DeviceRotationError::MalformedDocument);
    }
    let signing_key = SigningKey::from_bytes(seed);
    let message = rotation_signing_input(document);
    let signature = signing_key.sign(message.as_bytes());

    let mut signed = document.clone();
    let object = signed.as_object_mut().expect("checked above");
    let mut signatures = match object.get("signatures").and_then(Value::as_array) {
        Some(existing) => existing.clone(),
        None => Vec::new(),
    };
    signatures.push(json!({
        "kid": kid,
        "sig": base64url_encode(&signature.to_bytes()),
    }));
    object.insert("signatures".to_string(), Value::Array(signatures));
    Ok(signed)
}

/// Verify a single signed device-rotation statement against a trusted (already
/// verified) key document for the entity and return `Ok(())` when valid, or a
/// [`DeviceRotationError`] reason. Never panics for a well-formed call.
///
/// Order (with stable reasons): unknown member → `xeip` → field types and
/// `previous_kid`/`successor_kid`/`issuedAt`/`overlapUntil` shape → `entity ==
/// trusted.entity` → weak device kids → at least one valid signature by a key
/// listed in `trusted.roots`.
///
/// This is the stateless single-document check. Rotation conflict and the
/// bounded-overlap rule are lifecycle rules and live in
/// [`DeviceRotationTracker`].
///
/// This accepts a pre-parsed value and therefore skips the strict pre-parse
/// gate; use [`verify_device_rotation_text`] for wire bytes.
pub fn verify_device_rotation(
    document: &Value,
    trusted_key_document: &Value,
) -> Result<(), DeviceRotationError> {
    let object = document
        .as_object()
        .ok_or(DeviceRotationError::MalformedDocument)?;

    for key in object.keys() {
        if !ROTATION_FIELDS.contains(&key.as_str()) {
            return Err(DeviceRotationError::UnknownField);
        }
    }

    match object.get("xeip").and_then(Value::as_str) {
        Some(version) if version == ROTATION_VERSION => {}
        Some(_) => return Err(DeviceRotationError::UnsupportedVersion),
        None => return Err(DeviceRotationError::MalformedDocument),
    }

    let entity = object
        .get("entity")
        .and_then(Value::as_str)
        .ok_or(DeviceRotationError::MalformedDocument)?;
    let previous_kid = object
        .get("previous_kid")
        .and_then(Value::as_str)
        .ok_or(DeviceRotationError::MalformedDocument)?;
    let successor_kid = object
        .get("successor_kid")
        .and_then(Value::as_str)
        .ok_or(DeviceRotationError::MalformedDocument)?;
    let issued_at = object
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or(DeviceRotationError::MalformedDocument)?;
    if !is_utc_timestamp(issued_at) {
        return Err(DeviceRotationError::MalformedDocument);
    }
    if let Some(overlap) = object.get("overlapUntil") {
        let overlap = overlap
            .as_str()
            .ok_or(DeviceRotationError::MalformedDocument)?;
        if !is_utc_timestamp(overlap) {
            return Err(DeviceRotationError::MalformedDocument);
        }
        let overlap_sec =
            parse_utc_seconds(overlap).ok_or(DeviceRotationError::MalformedDocument)?;
        let issued_sec =
            parse_utc_seconds(issued_at).ok_or(DeviceRotationError::MalformedDocument)?;
        if overlap_sec <= issued_sec {
            return Err(DeviceRotationError::MalformedDocument);
        }
    }

    // Both device key-ids must be canonical. A malformed spelling is a
    // structural error; weakness is reported after the entity binding, matching
    // the single-document order.
    let previous_raw =
        decode_key_id(previous_kid).map_err(|_| DeviceRotationError::MalformedDocument)?;
    let successor_raw =
        decode_key_id(successor_kid).map_err(|_| DeviceRotationError::MalformedDocument)?;
    if previous_kid == successor_kid {
        return Err(DeviceRotationError::MalformedDocument);
    }

    let signatures = object
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or(DeviceRotationError::MalformedDocument)?;
    for entry in signatures {
        let entry = entry
            .as_object()
            .ok_or(DeviceRotationError::MalformedDocument)?;
        if !entry.get("kid").is_some_and(Value::is_string)
            || !entry.get("sig").is_some_and(Value::is_string)
        {
            return Err(DeviceRotationError::MalformedDocument);
        }
    }

    if status_trusted_entity(trusted_key_document) != Some(entity) {
        return Err(DeviceRotationError::EntityBinding);
    }

    if is_weak_ed25519_public_key(&previous_raw) || is_weak_ed25519_public_key(&successor_raw) {
        return Err(DeviceRotationError::WeakKey);
    }

    if signatures.is_empty() {
        return Err(DeviceRotationError::UnknownSigner);
    }

    let roots = status_trusted_roots(trusted_key_document);
    let message = rotation_signing_input(document);
    let mut saw_root_signer = false;
    for entry in signatures {
        let entry = entry.as_object().expect("validated shape above");
        let kid = entry["kid"].as_str().expect("validated shape above");
        let sig_text = entry["sig"].as_str().expect("validated shape above");
        let public_key = decode_key_id(kid).map_err(|_| DeviceRotationError::MalformedDocument)?;
        // Reject small-order/identity signer keys with a stable, platform-
        // independent reason before any curve backend can diverge.
        if is_weak_ed25519_public_key(&public_key) {
            return Err(DeviceRotationError::WeakKey);
        }
        let signature_bytes =
            base64url_decode(sig_text).ok_or(DeviceRotationError::MalformedDocument)?;
        if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(DeviceRotationError::MalformedDocument);
        }
        if !roots.contains(&kid) {
            continue;
        }
        saw_root_signer = true;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DeviceRotationError::MalformedDocument)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| DeviceRotationError::MalformedDocument)?;
        if verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    if !saw_root_signer {
        return Err(DeviceRotationError::UnknownSigner);
    }
    Err(DeviceRotationError::SignatureMismatch)
}

/// Verify device-rotation *JSON text*: strict-parse (rejecting duplicate keys,
/// lone surrogates and out-of-range integers) and then run
/// [`verify_device_rotation`]. This is the entry point a consumer of wire bytes
/// must use so the strict pre-parse gate is always applied.
pub fn verify_device_rotation_text(
    text: &str,
    trusted_key_document: &Value,
) -> Result<(), DeviceRotationError> {
    let document = strict_parse(text).map_err(|_| DeviceRotationError::MalformedDocument)?;
    verify_device_rotation(&document, trusted_key_document)
}

/// The accepted rotations for one entity: the predecessor `kid`s that have been
/// rotated (mapped to the end of their bounded overlap window, in whole epoch
/// seconds) and the current successor.
#[derive(Debug, Default, Clone)]
struct AcceptedDeviceRotations {
    predecessors: std::collections::HashMap<String, i64>,
    current: Option<String>,
}

/// Stateful, per-`entity` device-rotation tracker for
/// `xeip.device-rotation/0.1`.
///
/// [`DeviceRotationTracker::ingest`] first runs [`verify_device_rotation`] and
/// then enforces the lifecycle rules against the rotations already accepted for
/// the entity:
///
/// - **rotation conflict** — a candidate whose `previous_kid` was already used
///   as a predecessor (a second rotation of the same predecessor), or whose
///   `successor_kid` is already retired (was itself a predecessor), is
///   [`DeviceRotationError::RotationConflict`];
/// - **overlap too long** — when `max_overlap_seconds` is `Some`, a candidate
///   whose overlap (`overlapUntil - issuedAt`, or zero when `overlapUntil` is
///   absent) exceeds it is [`DeviceRotationError::OverlapTooLong`].
///
/// State is committed only when every check passes, so a rejected candidate
/// never advances the accepted rotations.
///
/// [`DeviceRotationTracker::is_active`] reports whether a `kid` may still
/// authenticate for an entity at `now`: the current successor is active
/// immediately; a predecessor is active through `overlapUntil` (inclusive) and
/// then [`DeviceRotationError::ExpiredPredecessor`]; any other `kid` is
/// [`DeviceRotationError::UnknownDevice`].
#[derive(Debug, Default, Clone)]
pub struct DeviceRotationTracker {
    entities: std::collections::HashMap<String, AcceptedDeviceRotations>,
}

impl DeviceRotationTracker {
    /// Create an empty tracker with no accepted rotations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and record `document` (a parsed object) for its entity.
    ///
    /// This accepts a pre-parsed value and therefore skips the strict pre-parse
    /// gate; use [`DeviceRotationTracker::ingest_text`] for wire bytes.
    pub fn ingest(
        &mut self,
        document: &Value,
        trusted_key_document: &Value,
        max_overlap_seconds: Option<i64>,
    ) -> Result<(), DeviceRotationError> {
        verify_device_rotation(document, trusted_key_document)?;

        let object = document
            .as_object()
            .expect("verify_device_rotation accepts only objects");
        let entity = object["entity"]
            .as_str()
            .expect("verify_device_rotation guarantees an entity string")
            .to_string();
        let previous_kid = object["previous_kid"]
            .as_str()
            .expect("verify_device_rotation guarantees a previous_kid string")
            .to_string();
        let successor_kid = object["successor_kid"]
            .as_str()
            .expect("verify_device_rotation guarantees a successor_kid string")
            .to_string();
        let issued_at = object["issuedAt"]
            .as_str()
            .expect("verify_device_rotation guarantees an issuedAt string");
        let overlap_until = object.get("overlapUntil").and_then(Value::as_str);

        if let Some(state) = self.entities.get(&entity) {
            if state.predecessors.contains_key(&previous_kid)
                || state.predecessors.contains_key(&successor_kid)
            {
                return Err(DeviceRotationError::RotationConflict);
            }
        }

        let issued_sec =
            parse_utc_seconds(issued_at).ok_or(DeviceRotationError::MalformedDocument)?;
        let overlap_sec = match overlap_until {
            Some(text) => parse_utc_seconds(text).ok_or(DeviceRotationError::MalformedDocument)?,
            None => issued_sec,
        };
        if let Some(max) = max_overlap_seconds {
            if overlap_sec - issued_sec > max {
                return Err(DeviceRotationError::OverlapTooLong);
            }
        }

        let state = self.entities.entry(entity).or_default();
        state.predecessors.insert(previous_kid, overlap_sec);
        state.current = Some(successor_kid);
        Ok(())
    }

    /// Verify and record device-rotation *JSON text*: strict-parse and then run
    /// [`DeviceRotationTracker::ingest`].
    pub fn ingest_text(
        &mut self,
        text: &str,
        trusted_key_document: &Value,
        max_overlap_seconds: Option<i64>,
    ) -> Result<(), DeviceRotationError> {
        let document = strict_parse(text).map_err(|_| DeviceRotationError::MalformedDocument)?;
        self.ingest(&document, trusted_key_document, max_overlap_seconds)
    }

    /// Whether `kid` may authenticate for `entity` at `now`. `Ok(())` when
    /// active; otherwise [`DeviceRotationError::ExpiredPredecessor`] (a
    /// predecessor past its overlap) or [`DeviceRotationError::UnknownDevice`]
    /// (no accepted rotation names the key).
    pub fn is_active(&self, entity: &str, kid: &str, now: &str) -> Result<(), DeviceRotationError> {
        let state = self
            .entities
            .get(entity)
            .ok_or(DeviceRotationError::UnknownDevice)?;
        if state.current.as_deref() == Some(kid) {
            return Ok(());
        }
        let overlap_until = state
            .predecessors
            .get(kid)
            .copied()
            .ok_or(DeviceRotationError::UnknownDevice)?;
        let now_sec = parse_utc_seconds(now).ok_or(DeviceRotationError::MalformedDocument)?;
        if now_sec <= overlap_until {
            Ok(())
        } else {
            Err(DeviceRotationError::ExpiredPredecessor)
        }
    }

    /// Whether any rotation has been accepted for `entity`.
    pub fn has_rotations(&self, entity: &str) -> bool {
        self.entities.contains_key(entity)
    }
}
