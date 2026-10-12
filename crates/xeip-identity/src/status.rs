use crate::canonical::{canonicalize_json, strict_parse, MAX_SAFE_INTEGER};
use crate::crypto::{is_weak_ed25519_public_key, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH};
use crate::encoding::{base64url_decode, base64url_encode};
use crate::key_id::decode_key_id;
use crate::time::{is_utc_timestamp, parse_utc_seconds};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::fmt;

// ---------------------------------------------------------------------------
// Signed identity status documents: `xeip.status/0.1`
//
// The revocation/status slice of `spec/identity-keys.md` §9 / ADR 0010. This
// covers single-document verification (structure, entity binding to a trusted
// key document, and at least one signature by a current root key) plus the two
// lifecycle rules `StatusTracker` adds on top: serial rollback and staleness.
// Status distribution/anchoring, live-stream effects and device rotation remain
// out of scope. The grammar and the stable reasons are byte-identical to
// `tools/identity-status.mjs` and the shared vectors under
// `conformance/fixtures/identity-status/`.
// ---------------------------------------------------------------------------

/// The only accepted `xeip` value; anything else is `UnsupportedVersion`.
pub const STATUS_VERSION: &str = "xeip.status/0.1";

/// The complete status-document member set. Any other member is rejected as
/// [`StatusError::UnknownField`].
const STATUS_FIELDS: [&str; 6] = [
    "xeip",
    "entity",
    "serial",
    "issuedAt",
    "revoked",
    "signatures",
];

/// Reasons a signed status document can be rejected by
/// [`verify_status_document`] or [`StatusTracker::ingest`].
///
/// The first seven variants are the single-document reasons, shared verbatim
/// with the key-document profile. `SerialRollback` and `Stale` are the two
/// lifecycle rules the stateful tracker adds.
///
/// The [`fmt::Display`] spelling of each variant matches the stable `reason`
/// strings of the JavaScript reference (`tools/identity-status.mjs`), so
/// cross-language reason comparisons are byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusError {
    /// Not an object (or invalid JSON through a text entry point), a field has
    /// the wrong type, `serial` is not an integer `>= 0`, `issuedAt` is not a
    /// UTC instant, or a revoked `kid`/`generation` is malformed.
    MalformedDocument,
    /// `xeip` is not exactly `xeip.status/0.1`.
    UnsupportedVersion,
    /// The document carries a member outside the fixed profile.
    UnknownField,
    /// `entity` is not the trusted key document's `entity`.
    EntityBinding,
    /// No signature by a current root key listed in the trusted key document.
    UnknownSigner,
    /// A signature `kid` decodes to a small-order (weak) Ed25519 point.
    WeakKey,
    /// The canonical bytes do not verify under any listed root key.
    SignatureMismatch,
    /// Lifecycle only: the candidate `serial` is less than or equal to the
    /// highest serial already accepted for the entity.
    SerialRollback,
    /// Lifecycle only: `issuedAt` is older than the caller-supplied maximum age.
    Stale,
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MalformedDocument => "malformed document",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnknownField => "unknown field",
            Self::EntityBinding => "entity binding",
            Self::UnknownSigner => "unknown signer",
            Self::WeakKey => "weak key",
            Self::SignatureMismatch => "signature mismatch",
            Self::SerialRollback => "serial rollback",
            Self::Stale => "stale status",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for StatusError {}

/// The RFC 8785 signing input of a status document: the document with the
/// `signatures` member removed in its entirety, canonicalized.
fn status_signing_input(document: &Value) -> String {
    let mut base = document.clone();
    if let Some(object) = base.as_object_mut() {
        object.remove("signatures");
    }
    canonicalize_json(&base)
}

/// The `entity` of a trusted key document, or `None` when it is not usable. The
/// caller asserts the trusted document is already verified; this reads only the
/// binding field.
pub(crate) fn status_trusted_entity(trusted_key_document: &Value) -> Option<&str> {
    trusted_key_document
        .as_object()
        .and_then(|object| object.get("entity"))
        .and_then(Value::as_str)
}

/// The set of current root key-ids listed in a trusted key document.
pub(crate) fn status_trusted_roots(trusted_key_document: &Value) -> Vec<&str> {
    trusted_key_document
        .as_object()
        .and_then(|object| object.get("roots"))
        .and_then(Value::as_array)
        .map(|roots| roots.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Sign a status document: canonicalize the document with `signatures` removed
/// (RFC 8785) and Ed25519-sign those UTF-8 bytes, then append `{ kid, sig }` to
/// any existing `signatures` array.
///
/// Returns [`StatusError::MalformedDocument`] if `document` is not a JSON
/// object. Verification is what enforces the root-signer requirement.
pub fn sign_status_document(
    document: &Value,
    seed: &[u8; ED25519_SEED_LENGTH],
    kid: &str,
) -> Result<Value, StatusError> {
    if !document.is_object() {
        return Err(StatusError::MalformedDocument);
    }
    let signing_key = SigningKey::from_bytes(seed);
    let message = status_signing_input(document);
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

/// Verify a single signed status document against a trusted (already verified)
/// key document for the entity and return `Ok(())` when valid, or a
/// [`StatusError`] reason. Never panics for a well-formed call.
///
/// Order (with stable reasons): unknown member → `xeip` → field types and
/// `serial`/`issuedAt`/revoked `kid`+`generation` shape → `entity ==
/// trusted.entity` → at least one valid signature by a key listed in
/// `trusted.roots`.
///
/// This is the stateless single-document check. Serial rollback and staleness
/// are lifecycle rules and live in [`StatusTracker`].
///
/// This accepts a pre-parsed value and therefore skips the strict pre-parse
/// gate; use [`verify_status_document_text`] for wire bytes.
pub fn verify_status_document(
    document: &Value,
    trusted_key_document: &Value,
) -> Result<(), StatusError> {
    let object = document.as_object().ok_or(StatusError::MalformedDocument)?;

    for key in object.keys() {
        if !STATUS_FIELDS.contains(&key.as_str()) {
            return Err(StatusError::UnknownField);
        }
    }

    match object.get("xeip").and_then(Value::as_str) {
        Some(version) if version == STATUS_VERSION => {}
        Some(_) => return Err(StatusError::UnsupportedVersion),
        None => return Err(StatusError::MalformedDocument),
    }

    let entity = object
        .get("entity")
        .and_then(Value::as_str)
        .ok_or(StatusError::MalformedDocument)?;
    let serial = object
        .get("serial")
        .and_then(Value::as_f64)
        .ok_or(StatusError::MalformedDocument)?;
    if serial.fract() != 0.0 || serial < 0.0 || serial > MAX_SAFE_INTEGER as f64 {
        return Err(StatusError::MalformedDocument);
    }
    let issued_at = object
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or(StatusError::MalformedDocument)?;
    if !is_utc_timestamp(issued_at) {
        return Err(StatusError::MalformedDocument);
    }
    let revoked = object
        .get("revoked")
        .and_then(Value::as_array)
        .ok_or(StatusError::MalformedDocument)?;
    for entry in revoked {
        let entry = entry.as_object().ok_or(StatusError::MalformedDocument)?;
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(StatusError::MalformedDocument)?;
        let generation = entry
            .get("generation")
            .and_then(Value::as_f64)
            .ok_or(StatusError::MalformedDocument)?;
        if generation.fract() != 0.0 || generation < 1.0 || generation > MAX_SAFE_INTEGER as f64 {
            return Err(StatusError::MalformedDocument);
        }
        // A revoked key-id must be a canonical key-id; a malformed spelling is a
        // structural error, not `unknown signer` / `weak key`.
        decode_key_id(kid).map_err(|_| StatusError::MalformedDocument)?;
    }
    let signatures = object
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or(StatusError::MalformedDocument)?;
    for entry in signatures {
        let entry = entry.as_object().ok_or(StatusError::MalformedDocument)?;
        if !entry.get("kid").is_some_and(Value::is_string)
            || !entry.get("sig").is_some_and(Value::is_string)
        {
            return Err(StatusError::MalformedDocument);
        }
    }

    if status_trusted_entity(trusted_key_document) != Some(entity) {
        return Err(StatusError::EntityBinding);
    }

    if signatures.is_empty() {
        return Err(StatusError::UnknownSigner);
    }

    let roots = status_trusted_roots(trusted_key_document);
    let message = status_signing_input(document);
    let mut saw_root_signer = false;
    for entry in signatures {
        let entry = entry.as_object().expect("validated shape above");
        let kid = entry["kid"].as_str().expect("validated shape above");
        let sig_text = entry["sig"].as_str().expect("validated shape above");
        let public_key = decode_key_id(kid).map_err(|_| StatusError::MalformedDocument)?;
        // Reject small-order/identity signer keys with a stable, platform-
        // independent reason before any curve backend can diverge.
        if is_weak_ed25519_public_key(&public_key) {
            return Err(StatusError::WeakKey);
        }
        let signature_bytes = base64url_decode(sig_text).ok_or(StatusError::MalformedDocument)?;
        if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(StatusError::MalformedDocument);
        }
        if !roots.contains(&kid) {
            continue;
        }
        saw_root_signer = true;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| StatusError::MalformedDocument)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| StatusError::MalformedDocument)?;
        if verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    if !saw_root_signer {
        return Err(StatusError::UnknownSigner);
    }
    Err(StatusError::SignatureMismatch)
}

/// Verify status-document *JSON text*: strict-parse (rejecting duplicate keys,
/// lone surrogates and out-of-range integers) and then run
/// [`verify_status_document`]. This is the entry point a consumer of wire bytes
/// must use so the strict pre-parse gate is always applied.
pub fn verify_status_document_text(
    text: &str,
    trusted_key_document: &Value,
) -> Result<(), StatusError> {
    let document = strict_parse(text).map_err(|_| StatusError::MalformedDocument)?;
    verify_status_document(&document, trusted_key_document)
}

/// The accepted status for one entity: the highest serial and the full accepted
/// document (needed by [`StatusTracker::is_revoked`]).
#[derive(Debug, Clone)]
struct AcceptedStatus {
    serial: i64,
    document: Value,
}

/// Stateful, per-`entity` status tracker for `xeip.status/0.1`.
///
/// [`StatusTracker::ingest`] first runs [`verify_status_document`] and then
/// enforces the two lifecycle rules against the status already accepted for the
/// entity:
///
/// - **serial rollback** — a candidate whose `serial` is less than or equal to
///   the highest serial already accepted for the entity is
///   [`StatusError::SerialRollback`], so a replayed old "clean" status is never
///   accepted;
/// - **staleness** — when `max_age_seconds` is `Some`, a candidate whose
///   `issuedAt` is more than that age behind `now` is [`StatusError::Stale`].
///
/// State is committed only when every check passes, so a rejected candidate
/// never advances the serial or replaces the accepted status.
///
/// [`StatusTracker::is_revoked`] reports whether the accepted status for an
/// entity revokes a `kid` at a key-document generation. An entry
/// `{ kid, generation: G }` revokes that key for generation `G` **and later**, so
/// a rotated-but-republished key stays revoked. A missing accepted status is
/// reported as "not revoked"; callers MUST treat *no fresh status* as unknown,
/// never as proof that a key is live (`spec/identity-keys.md` §9).
#[derive(Debug, Default, Clone)]
pub struct StatusTracker {
    entities: std::collections::HashMap<String, AcceptedStatus>,
}

impl StatusTracker {
    /// Create an empty tracker with no accepted status.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and record `document` for its entity.
    ///
    /// `now` is a UTC instant (used only when `max_age_seconds` is `Some`). This
    /// accepts a pre-parsed value and therefore skips the strict pre-parse gate;
    /// use [`StatusTracker::ingest_text`] for wire bytes.
    pub fn ingest(
        &mut self,
        document: &Value,
        trusted_key_document: &Value,
        now: &str,
        max_age_seconds: Option<i64>,
    ) -> Result<(), StatusError> {
        verify_status_document(document, trusted_key_document)?;

        let object = document
            .as_object()
            .expect("verify_status_document accepts only objects");
        let entity = object["entity"]
            .as_str()
            .expect("verify_status_document guarantees an entity string")
            .to_string();
        let serial = object["serial"]
            .as_f64()
            .expect("verify_status_document guarantees a numeric serial")
            as i64;

        if let Some(accepted) = self.entities.get(&entity) {
            if serial <= accepted.serial {
                return Err(StatusError::SerialRollback);
            }
        }

        if let Some(max_age) = max_age_seconds {
            let issued = parse_utc_seconds(
                object["issuedAt"]
                    .as_str()
                    .expect("verify_status_document guarantees an issuedAt string"),
            )
            .ok_or(StatusError::MalformedDocument)?;
            let reference = parse_utc_seconds(now).ok_or(StatusError::MalformedDocument)?;
            if reference - issued > max_age {
                return Err(StatusError::Stale);
            }
        }

        self.entities.insert(
            entity,
            AcceptedStatus {
                serial,
                document: document.clone(),
            },
        );
        Ok(())
    }

    /// Verify and record status-document *JSON text*: strict-parse and then run
    /// [`StatusTracker::ingest`].
    pub fn ingest_text(
        &mut self,
        text: &str,
        trusted_key_document: &Value,
        now: &str,
        max_age_seconds: Option<i64>,
    ) -> Result<(), StatusError> {
        let document = strict_parse(text).map_err(|_| StatusError::MalformedDocument)?;
        self.ingest(&document, trusted_key_document, now, max_age_seconds)
    }

    /// Whether the accepted status for `entity` revokes `kid` for key-document
    /// generation `generation` (a revoked entry applies to its recorded
    /// generation and every later one). Returns `false` when no status has been
    /// accepted for the entity.
    pub fn is_revoked(&self, entity: &str, kid: &str, generation: i64) -> bool {
        let Some(accepted) = self.entities.get(entity) else {
            return false;
        };
        accepted
            .document
            .get("revoked")
            .and_then(Value::as_array)
            .map(|entries| {
                entries.iter().any(|entry| {
                    entry.get("kid").and_then(Value::as_str) == Some(kid)
                        && entry
                            .get("generation")
                            .and_then(Value::as_f64)
                            .is_some_and(|g| generation as f64 >= g)
                })
            })
            .unwrap_or(false)
    }

    /// The highest serial accepted for `entity`, or `None` if none.
    pub fn accepted_serial(&self, entity: &str) -> Option<i64> {
        self.entities.get(entity).map(|accepted| accepted.serial)
    }

    /// Whether a status has been accepted for `entity`.
    pub fn has_status(&self, entity: &str) -> bool {
        self.entities.contains_key(entity)
    }
}
