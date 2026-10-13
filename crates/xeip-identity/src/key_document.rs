use crate::canonical::{canonicalize_json, strict_parse, MAX_SAFE_INTEGER};
use crate::crypto::{is_weak_ed25519_public_key, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH};
use crate::encoding::{base64url_decode, base64url_encode};
use crate::key_id::{decode_key_id, entity_urn, ED25519_PUBLIC_KEY_LENGTH};
use crate::time::is_utc_timestamp;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

// ---------------------------------------------------------------------------
// Signed key documents: `xeip.keydoc/0.1`
//
// The testable slice of `spec/identity-keys.md` / ADR 0010. This covers
// single-document verification and, on top of it, per-entity chain verification
// (`KeyDocumentChain`): genesis, `generation`/`previous` linking (the SHA-256 of
// the full signed predecessor), rollback rejection, fork/equivocation detection
// and gap detection. Trust-store resolution and revocation remain out of scope.
// The grammar and the stable reasons are byte-identical to
// `tools/key-document.mjs` and the shared vectors under
// `conformance/fixtures/identity-keydoc/`.
// ---------------------------------------------------------------------------

/// The only accepted `xeip` value; anything else is `UnsupportedVersion`.
pub const KEYDOC_VERSION: &str = "xeip.keydoc/0.1";

/// The complete key-document member set. Any other member is rejected as
/// [`KeyDocumentError::UnknownField`].
const KEYDOC_FIELDS: [&str; 9] = [
    "xeip",
    "entity",
    "genesis",
    "generation",
    "issuedAt",
    "previous",
    "roots",
    "devices",
    "signatures",
];

/// Reasons a signed key document can be rejected by [`verify_key_document`],
/// [`KeyDocumentChain::ingest`] or [`KeyDocumentTrust::ingest`].
///
/// The first eight variants are the single-document reasons. `Rollback`,
/// `Fork` and `ChainGap` are produced only by chain verification;
/// `NoAnchor`, `UntrustedAnchor` and `GenerationExceedsMaximum` are produced
/// only by trust-store resolution. Every document must first pass
/// single-document verification and chain linking, so a chain or trust reason is
/// only ever returned after the structural reasons have been cleared.
///
/// The [`fmt::Display`] spelling of each variant matches the stable `reason`
/// strings of the JavaScript reference (`tools/key-document.mjs`), so
/// cross-language reason comparisons are byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDocumentError {
    /// Not an object (or invalid JSON through a text entry point), a field has
    /// the wrong type, `generation` is not an integer `>= 1`, `issuedAt` is not
    /// a UTC instant, a `kid` or `sig` is malformed, or `previous` is not a
    /// SHA-256 hex digest.
    MalformedDocument,
    /// `xeip` is not exactly `xeip.keydoc/0.1`.
    UnsupportedVersion,
    /// The document carries a member outside the fixed profile.
    UnknownField,
    /// `entity` is not `urn:xeip:entity:<genesis>`.
    EntityBinding,
    /// No signature by a key listed in `roots` (unknown or missing signer).
    UnknownSigner,
    /// A `kid` decodes to a small-order (weak) Ed25519 point.
    WeakKey,
    /// The canonical bytes do not verify under any listed root key.
    SignatureMismatch,
    /// A genesis document (`generation == 1`, no `previous`) is not
    /// self-certified: the genesis key is not listed in `roots`, or the genesis
    /// key did not sign, even though another root did.
    GenesisNotSelfSigned,
    /// Chain only: the candidate generation is less than or equal to the
    /// highest generation already accepted for the entity.
    Rollback,
    /// Chain only: a distinct document at the accepted generation
    /// (equivocation / double-signing).
    Fork,
    /// Chain only: a generation jump (`generation > prev + 1`) or a `previous`
    /// that does not match the accepted document's digest.
    ChainGap,
    /// Chain only: a successor document carries no valid signature by any key in
    /// the predecessor's `roots` set (the retiry authorization). The successor
    /// root signature is already required by single-document verification; the
    /// pre-endorsed case (a successor already listed in the predecessor's roots)
    /// is satisfied by its own retiring-root signature.
    RootRotationNotDualSigned,
    /// Trust only: no anchor is configured for the entity (and TOFU is off), so
    /// the verifier fails closed instead of trusting on first use.
    NoAnchor,
    /// Trust only: the chain's genesis key-id or digest does not match the
    /// pinned anchor.
    UntrustedAnchor,
    /// Trust only: the document's generation exceeds the configured maximum.
    GenerationExceedsMaximum,
}

impl fmt::Display for KeyDocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MalformedDocument => "malformed document",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnknownField => "unknown field",
            Self::EntityBinding => "entity binding",
            Self::UnknownSigner => "unknown signer",
            Self::WeakKey => "weak key",
            Self::SignatureMismatch => "signature mismatch",
            Self::GenesisNotSelfSigned => "genesis not self-signed",
            Self::Rollback => "rollback",
            Self::Fork => "fork",
            Self::ChainGap => "chain gap",
            Self::RootRotationNotDualSigned => "root rotation not dual-signed",
            Self::NoAnchor => "no anchor",
            Self::UntrustedAnchor => "untrusted anchor",
            Self::GenerationExceedsMaximum => "generation exceeds maximum",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for KeyDocumentError {}

/// Whether `text` is 64 lowercase hex characters (a SHA-256 digest).
fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The RFC 8785 signing input of a key document: the document with the
/// `signatures` member removed in its entirety, canonicalized.
fn keydoc_signing_input(document: &Value) -> String {
    let mut base = document.clone();
    if let Some(object) = base.as_object_mut() {
        object.remove("signatures");
    }
    canonicalize_json(&base)
}

/// Decode a key-id to its 32 raw bytes, mapping a malformed spelling to
/// [`KeyDocumentError::MalformedDocument`] and a small-order point to
/// [`KeyDocumentError::WeakKey`].
fn decode_keydoc_kid(kid: &str) -> Result<[u8; ED25519_PUBLIC_KEY_LENGTH], KeyDocumentError> {
    let raw = decode_key_id(kid).map_err(|_| KeyDocumentError::MalformedDocument)?;
    if is_weak_ed25519_public_key(&raw) {
        return Err(KeyDocumentError::WeakKey);
    }
    Ok(raw)
}

/// Whether any key in `kids` has a signature entry that verifies over
/// `document`'s canonical signing input. Chain verification uses this to require
/// a signature by a key drawn from the *predecessor's* root set (the retiry
/// authorization); it re-checks the bytes rather than trusting the
/// single-document result, which only records that *some* current root signed.
///
/// The single-document check runs first and guarantees every entry is
/// well-formed and non-weak, but each step stays defensive so a malformed entry
/// simply does not count.
fn keydoc_signs_with_any_kid(document: &Value, kids: &[String]) -> bool {
    if kids.is_empty() {
        return false;
    }
    let signatures = match document
        .as_object()
        .and_then(|object| object.get("signatures"))
        .and_then(Value::as_array)
    {
        Some(signatures) => signatures,
        None => return false,
    };
    let message = keydoc_signing_input(document);
    for entry in signatures {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let Some(kid) = entry.get("kid").and_then(Value::as_str) else {
            continue;
        };
        if !kids.iter().any(|candidate| candidate == kid) {
            continue;
        }
        let Ok(public_key) = decode_key_id(kid) else {
            continue;
        };
        let Some(signature_bytes) = entry
            .get("sig")
            .and_then(Value::as_str)
            .and_then(base64url_decode)
        else {
            continue;
        };
        if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
            continue;
        }
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            continue;
        };
        if verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_ok()
        {
            return true;
        }
    }
    false
}

/// Sign a key document: canonicalize the document with `signatures` removed
/// (RFC 8785) and Ed25519-sign those UTF-8 bytes, then append `{ kid, sig }` to
/// any existing `signatures` array (so a dual-signed rotation is produced by
/// signing twice).
///
/// Returns [`KeyDocumentError::MalformedDocument`] if `document` is not a JSON
/// object. Existing signatures are preserved; verification is what enforces the
/// root-signer requirement.
pub fn sign_key_document(
    document: &Value,
    seed: &[u8; ED25519_SEED_LENGTH],
    kid: &str,
) -> Result<Value, KeyDocumentError> {
    if !document.is_object() {
        return Err(KeyDocumentError::MalformedDocument);
    }
    let signing_key = SigningKey::from_bytes(seed);
    let message = keydoc_signing_input(document);
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

/// Verify a single signed key document and return `Ok(())` when valid, or a
/// [`KeyDocumentError`] reason. Never panics for a well-formed call.
///
/// Order (with stable reasons): unknown member → `xeip` → field types and
/// `generation`/`issuedAt`/`previous` shape → genesis decode → `entity ==
/// entity_urn(genesis)` → every root/device `kid` decodes non-weak → at least
/// one valid signature by a key listed in `roots` → for a genesis document, the
/// genesis key is a root and signed it ([`KeyDocumentError::GenesisNotSelfSigned`]).
///
/// A genesis document (`generation == 1`, no `previous`) is **self-certifying**
/// (`spec/identity-keys.md` §5.1): the entity ID commits to the genesis key, so
/// a valid genesis MUST be signed by that genesis key and MUST list it in
/// `roots`. This stops a third party who only knows the victim's entity ID from
/// publishing `{ entity: victim, genesis: victim, roots: [attacker] }` signed by
/// the attacker key. A successor keeps the generic root-signature rule; its
/// retiry/successor authorization is enforced by [`KeyDocumentChain`].
///
/// `previous` is shape-checked but never chased: chain/rollback verification is
/// out of scope. Weak or unknown signers never satisfy the root-signature
/// requirement; extra non-root signatures are ignored.
///
/// This accepts a pre-parsed value and therefore skips the strict pre-parse
/// gate; use [`verify_key_document_text`] for wire bytes.
pub fn verify_key_document(document: &Value) -> Result<(), KeyDocumentError> {
    let object = document
        .as_object()
        .ok_or(KeyDocumentError::MalformedDocument)?;

    for key in object.keys() {
        if !KEYDOC_FIELDS.contains(&key.as_str()) {
            return Err(KeyDocumentError::UnknownField);
        }
    }

    match object.get("xeip").and_then(Value::as_str) {
        Some(version) if version == KEYDOC_VERSION => {}
        Some(_) => return Err(KeyDocumentError::UnsupportedVersion),
        None => return Err(KeyDocumentError::MalformedDocument),
    }

    let entity = object
        .get("entity")
        .and_then(Value::as_str)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    let genesis = object
        .get("genesis")
        .and_then(Value::as_str)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_f64)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    if generation.fract() != 0.0 || generation < 1.0 || generation > MAX_SAFE_INTEGER as f64 {
        return Err(KeyDocumentError::MalformedDocument);
    }
    let issued_at = object
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    if !is_utc_timestamp(issued_at) {
        return Err(KeyDocumentError::MalformedDocument);
    }
    if let Some(previous) = object.get("previous") {
        let previous = previous
            .as_str()
            .ok_or(KeyDocumentError::MalformedDocument)?;
        if !is_sha256_hex(previous) {
            return Err(KeyDocumentError::MalformedDocument);
        }
    }
    let roots = object
        .get("roots")
        .and_then(Value::as_array)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    if !roots.iter().all(Value::is_string) {
        return Err(KeyDocumentError::MalformedDocument);
    }
    let devices = object
        .get("devices")
        .and_then(Value::as_array)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    if !devices.iter().all(Value::is_string) {
        return Err(KeyDocumentError::MalformedDocument);
    }
    let signatures = object
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or(KeyDocumentError::MalformedDocument)?;
    for entry in signatures {
        let entry = entry
            .as_object()
            .ok_or(KeyDocumentError::MalformedDocument)?;
        if !entry.get("kid").is_some_and(Value::is_string)
            || !entry.get("sig").is_some_and(Value::is_string)
        {
            return Err(KeyDocumentError::MalformedDocument);
        }
    }

    let _genesis_bytes = decode_keydoc_kid(genesis)?;
    if entity_urn(genesis) != entity {
        return Err(KeyDocumentError::EntityBinding);
    }
    for kid in roots {
        decode_keydoc_kid(kid.as_str().expect("validated above"))?;
    }
    for kid in devices {
        decode_keydoc_kid(kid.as_str().expect("validated above"))?;
    }

    if signatures.is_empty() {
        return Err(KeyDocumentError::UnknownSigner);
    }

    // A genesis document is self-certifying: its entity ID commits to the
    // genesis key, so it MUST be signed by that genesis key and MUST list it in
    // `roots`. The generic "any root signed" rule below would otherwise accept a
    // forgery that claims the victim's entity/genesis with an attacker root.
    let is_genesis = generation == 1.0 && object.get("previous").is_none();
    let genesis_is_root = roots.iter().any(|value| value.as_str() == Some(genesis));

    let message = keydoc_signing_input(document);
    let mut saw_root_signer = false;
    let mut valid_root_signer = false;
    let mut valid_genesis_signer = false;
    for entry in signatures {
        let entry = entry.as_object().expect("validated shape above");
        let kid = entry["kid"].as_str().expect("validated shape above");
        let sig_text = entry["sig"].as_str().expect("validated shape above");
        let public_key = decode_keydoc_kid(kid)?;
        let signature_bytes =
            base64url_decode(sig_text).ok_or(KeyDocumentError::MalformedDocument)?;
        if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(KeyDocumentError::MalformedDocument);
        }
        let is_root_entry = roots.iter().any(|value| value.as_str() == Some(kid));
        let is_genesis_entry = is_genesis && kid == genesis;
        if !is_root_entry && !is_genesis_entry {
            continue;
        }
        if is_root_entry {
            saw_root_signer = true;
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| KeyDocumentError::MalformedDocument)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| KeyDocumentError::MalformedDocument)?;
        // `verify_strict` additionally rejects non-canonical `R` values,
        // matching the JavaScript small-order gate.
        if verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_err()
        {
            continue;
        }
        if is_root_entry {
            valid_root_signer = true;
            // Successors keep the original rule: any valid root signature
            // accepts.
            if !is_genesis {
                return Ok(());
            }
        }
        if is_genesis_entry {
            valid_genesis_signer = true;
        }
    }

    if is_genesis {
        if valid_root_signer && genesis_is_root && valid_genesis_signer {
            return Ok(());
        }
        // A genesis document that would otherwise pass the generic root rule is
        // not self-certified: reject it with the stable genesis reason.
        if valid_root_signer {
            return Err(KeyDocumentError::GenesisNotSelfSigned);
        }
    }

    if !saw_root_signer {
        return Err(KeyDocumentError::UnknownSigner);
    }
    Err(KeyDocumentError::SignatureMismatch)
}

/// Verify key-document *JSON text*: strict-parse (rejecting duplicate keys,
/// lone surrogates and out-of-range integers) and then run
/// [`verify_key_document`]. This is the entry point a consumer of wire bytes
/// must use so the strict pre-parse gate is always applied.
pub fn verify_key_document_text(text: &str) -> Result<(), KeyDocumentError> {
    let document = strict_parse(text).map_err(|_| KeyDocumentError::MalformedDocument)?;
    verify_key_document(&document)
}

/// `previous` link digest: lowercase hex SHA-256 of the RFC 8785 canonical form
/// of `document` **including** its `signatures` member, so each generation
/// commits to the exact signed predecessor. This is the definition of
/// `previous` in [`KeyDocumentChain`] and in `spec/plans/identity-keydoc.md`, and
/// it matches `keyDocumentChainDigest` in `tools/key-document.mjs`.
///
/// It is deliberately different from the single-document signing-input digest
/// (which excludes `signatures`): a chain links signed documents, not unsigned
/// drafts.
pub fn key_document_chain_digest(document: &Value) -> String {
    let canonical = canonicalize_json(document);
    hex_lower(&Sha256::digest(canonical.as_bytes()))
}

/// Lowercase hex encoding. This is a base conversion, not a cryptographic
/// primitive, and exists only so the chain digest can be rendered without a
/// `hex` dependency.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble is a hex digit"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("a nibble is a hex digit"));
    }
    out
}

/// The highest key document accepted for an entity, kept only as the state a
/// [`KeyDocumentChain`] needs to enforce the next link: its `generation`, its
/// full-document digest and its `roots` (the signer set the next successor must
/// draw its retiry authorization from).
#[derive(Debug, Clone)]
struct AcceptedKeyDocument {
    generation: i64,
    digest: String,
    roots: Vec<String>,
}

/// Stateful, per-`entity` chain verifier for `xeip.keydoc/0.1`.
///
/// [`KeyDocumentChain::ingest`] first runs [`verify_key_document`] on the
/// candidate (so every structural and signature rule still applies) and only
/// then enforces the chain rules against the highest document already accepted
/// for that entity. It never panics for a well-formed call:
///
/// - a genesis document (`generation == 1`, no `previous`) starts the chain;
/// - a successor must have `generation == prev.generation + 1` and
///   `previous == key_document_chain_digest(prev)` (the full signed
///   predecessor);
/// - a successor must additionally carry a valid signature by at least one key
///   in `prev.roots` (the **retiry authorization**); the successor root is
///   already required by single-document verification, and the pre-endorsed case
///   (a successor already listed in `prev.roots`) is satisfied by that same
///   retiring-root signature, otherwise [`KeyDocumentError::RootRotationNotDualSigned`];
/// - a candidate whose `generation <=` the accepted generation is
///   [`KeyDocumentError::Rollback`], except that a *distinct* document at the
///   accepted generation is [`KeyDocumentError::Fork`] (equivocation);
/// - a generation jump (`generation > prev.generation + 1`) or a `previous` that
///   does not match the accepted document is [`KeyDocumentError::ChainGap`].
///
/// Re-ingesting the exact accepted document is rejected as
/// [`KeyDocumentError::Rollback`] (it is not newer); a caller that needs
/// at-least-once delivery must treat `rollback` as "already known". Trust-store
/// resolution and revocation stay out of scope.
#[derive(Debug, Default, Clone)]
pub struct KeyDocumentChain {
    entities: std::collections::HashMap<String, AcceptedKeyDocument>,
}

impl KeyDocumentChain {
    /// Create an empty chain with no accepted documents.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and add `document` to the chain for its `entity`.
    ///
    /// This accepts a pre-parsed value and therefore skips the strict pre-parse
    /// gate; use [`KeyDocumentChain::ingest_text`] for wire bytes.
    pub fn ingest(&mut self, document: &Value) -> Result<(), KeyDocumentError> {
        verify_key_document(document)?;

        let object = document
            .as_object()
            .expect("verify_key_document accepts only objects");
        let entity = object["entity"]
            .as_str()
            .expect("verify_key_document guarantees an entity string")
            .to_string();
        // Single-document verification guarantees an integer `>= 1` within the
        // safe range, so the cast is lossless.
        let generation = object["generation"]
            .as_f64()
            .expect("verify_key_document guarantees a numeric generation")
            as i64;
        let previous = object.get("previous").and_then(Value::as_str);

        match self.entities.get(&entity) {
            None => {
                if generation != 1 || previous.is_some() {
                    return Err(KeyDocumentError::ChainGap);
                }
                self.accept(entity, document, generation);
                Ok(())
            }
            Some(accepted) => {
                if generation < accepted.generation {
                    return Err(KeyDocumentError::Rollback);
                }
                if generation == accepted.generation {
                    if key_document_chain_digest(document) == accepted.digest {
                        return Err(KeyDocumentError::Rollback);
                    }
                    return Err(KeyDocumentError::Fork);
                }
                if generation != accepted.generation + 1 {
                    return Err(KeyDocumentError::ChainGap);
                }
                if previous != Some(accepted.digest.as_str()) {
                    return Err(KeyDocumentError::ChainGap);
                }
                // Root-rotation authorization: the successor is already known to
                // carry a valid signature by one of its own roots (single-document
                // verification); the chain adds the retiry requirement that a key
                // from the predecessor's root set also signed. A pre-endorsed
                // successor root is itself in that old set, so its signature
                // satisfies both at once (retiry-only case).
                if !keydoc_signs_with_any_kid(document, &accepted.roots) {
                    return Err(KeyDocumentError::RootRotationNotDualSigned);
                }
                self.accept(entity, document, generation);
                Ok(())
            }
        }
    }

    /// Verify and add key-document *JSON text*: strict-parse and then run
    /// [`KeyDocumentChain::ingest`].
    pub fn ingest_text(&mut self, text: &str) -> Result<(), KeyDocumentError> {
        let document = strict_parse(text).map_err(|_| KeyDocumentError::MalformedDocument)?;
        self.ingest(&document)
    }

    fn accept(&mut self, entity: String, document: &Value, generation: i64) {
        let digest = key_document_chain_digest(document);
        let roots = document
            .get("roots")
            .and_then(Value::as_array)
            .map(|roots| {
                roots
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        self.entities.insert(
            entity,
            AcceptedKeyDocument {
                generation,
                digest,
                roots,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Trust-store anchor resolution.
//
// `KeyDocumentChain` links generations but deliberately has no notion of *which*
// genesis to start from. `KeyDocumentTrust` adds that out-of-band anchor: it
// wraps a chain and, for a single configured entity, accepts a document only
// when it passes single-document verification and the chain rules *and* is
// reached from the configured anchor.
// ---------------------------------------------------------------------------

/// The out-of-band anchor a [`KeyDocumentTrust`] pins. Either or both fields may
/// be set; `genesis_digest` is the [`key_document_chain_digest`] of the genesis
/// document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchor {
    /// Pinned genesis key-id (the `genesis` member of the genesis document).
    pub genesis_kid: Option<String>,
    /// Pinned genesis chain digest (the full signed genesis document digest).
    pub genesis_digest: Option<String>,
}

/// How a document was trusted by [`KeyDocumentTrust::ingest`].
///
/// [`TrustLevel::Pinned`] is a configured anchor and may be presented as verified
/// identity. [`TrustLevel::Tofu`] is first-use, **unverified** trust that MUST
/// NOT be presented to applications as verified (`spec/identity-keys.md` §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// The document was reached from the operator-pinned anchor.
    Pinned,
    /// The document was accepted by opt-in, bounded first-use (TOFU); unverified.
    Tofu,
}

/// Trust-store anchor resolution for `xeip.keydoc/0.1`.
///
/// Wraps a [`KeyDocumentChain`] and enforces the anchor for one `entity` after
/// the candidate has passed single-document verification and chain linking (run
/// on a private clone, so a rejected document is never recorded). A candidate is
/// rejected with:
///
/// - **No anchor** — when no anchor is configured and TOFU is off, every
///   document is [`KeyDocumentError::NoAnchor`]: the default is to fail closed
///   rather than trust on first use.
/// - **Wrong anchor** — a document whose `entity`, `genesis` key-id or (for the
///   genesis document) chain digest does not match the pinned anchor is
///   [`KeyDocumentError::UntrustedAnchor`].
/// - **Generation bound** — a document whose `generation > max_generation`
///   (when configured) is [`KeyDocumentError::GenerationExceedsMaximum`].
///
/// **Bounded TOFU (opt-in, not verified).** With `tofu = true` and no pinned
/// anchor, the first document accepted for the entity records its
/// `(entity, genesis-kid, genesis-digest)` as the effective anchor and every
/// later document must chain from it; the recorded anchor is bounded by the same
/// `max_generation`. A successful [`TrustLevel::Tofu`] result is **not**
/// verified identity and must not be conflated with [`TrustLevel::Pinned`].
#[derive(Debug, Clone)]
pub struct KeyDocumentTrust {
    entity: String,
    anchor: Option<TrustAnchor>,
    max_generation: Option<i64>,
    tofu: bool,
    chain: KeyDocumentChain,
    tofu_anchors: std::collections::HashMap<String, TrustAnchor>,
}

impl KeyDocumentTrust {
    /// Create a trust store pinned to `entity`.
    ///
    /// `anchor` is the operator-pinned genesis key-id and/or digest; `None` means
    /// no anchor is configured (fail closed unless `tofu`). When `max_generation`
    /// is set, a document above it is rejected. `tofu` opts in to bounded,
    /// *unverified* first-use trust.
    pub fn new(
        entity: impl Into<String>,
        anchor: Option<TrustAnchor>,
        max_generation: Option<i64>,
        tofu: bool,
    ) -> Self {
        Self {
            entity: entity.into(),
            anchor,
            max_generation,
            tofu,
            chain: KeyDocumentChain::new(),
            tofu_anchors: std::collections::HashMap::new(),
        }
    }

    /// Verify and anchor `document` for the configured entity.
    ///
    /// This accepts a pre-parsed value and therefore skips the strict pre-parse
    /// gate; use [`KeyDocumentTrust::ingest_text`] for wire bytes.
    pub fn ingest(&mut self, document: &Value) -> Result<TrustLevel, KeyDocumentError> {
        // Run the existing single-document and chain rules on an independent
        // copy. Nothing is committed unless every trust check also passes.
        let mut trial = self.chain.clone();
        trial.ingest(document)?;

        let object = document
            .as_object()
            .expect("verify_key_document accepts only objects");
        let entity = object["entity"]
            .as_str()
            .expect("verify_key_document guarantees an entity string")
            .to_string();
        let genesis = object["genesis"]
            .as_str()
            .expect("verify_key_document guarantees a genesis string")
            .to_string();
        // Single-document verification guarantees an integer `>= 1`.
        let generation = object["generation"]
            .as_f64()
            .expect("verify_key_document guarantees a numeric generation")
            as i64;

        let (anchor, level) = if let Some(anchor) = &self.anchor {
            (anchor.clone(), TrustLevel::Pinned)
        } else if self.tofu {
            if let Some(recorded) = self.tofu_anchors.get(&entity) {
                (recorded.clone(), TrustLevel::Tofu)
            } else if generation == 1 && object.get("previous").is_none() {
                let recorded = TrustAnchor {
                    genesis_kid: Some(genesis.clone()),
                    genesis_digest: Some(key_document_chain_digest(document)),
                };
                (recorded, TrustLevel::Tofu)
            } else {
                return Err(KeyDocumentError::NoAnchor);
            }
        } else {
            return Err(KeyDocumentError::NoAnchor);
        };

        if entity != self.entity {
            return Err(KeyDocumentError::UntrustedAnchor);
        }
        if let Some(max) = self.max_generation {
            if generation > max {
                return Err(KeyDocumentError::GenerationExceedsMaximum);
            }
        }
        if let Some(kid) = &anchor.genesis_kid {
            if &genesis != kid {
                return Err(KeyDocumentError::UntrustedAnchor);
            }
        }
        if let Some(digest) = &anchor.genesis_digest {
            if generation == 1 && key_document_chain_digest(document) != *digest {
                return Err(KeyDocumentError::UntrustedAnchor);
            }
        }

        if level == TrustLevel::Tofu && !self.tofu_anchors.contains_key(&entity) {
            self.tofu_anchors.insert(entity, anchor);
        }
        self.chain = trial;
        Ok(level)
    }

    /// Verify and anchor key-document *JSON text*: strict-parse and then run
    /// [`KeyDocumentTrust::ingest`].
    pub fn ingest_text(&mut self, text: &str) -> Result<TrustLevel, KeyDocumentError> {
        let document = strict_parse(text).map_err(|_| KeyDocumentError::MalformedDocument)?;
        self.ingest(&document)
    }
}
