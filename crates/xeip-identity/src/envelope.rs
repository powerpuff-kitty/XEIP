use crate::canonical::{canonicalize_json, strict_parse};
use crate::crypto::{is_weak_ed25519_public_key, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH};
use crate::encoding::{base64url_decode, base64url_encode};
use crate::key_id::{decode_key_id, entity_urn};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use std::fmt;

// ---------------------------------------------------------------------------
// Signed envelopes: `xeip.local-signed-envelopes/0.1`
// ---------------------------------------------------------------------------

/// Extensions member that carries the detached signature.
pub const SIG_EXTENSION: &str = "xeip.sig";

/// Version of the signature carrier.
pub const SIG_VERSION: &str = "0.1";

/// Fixed algorithm identifier; `EdDSA` is the only accepted value.
pub const SIG_ALG: &str = "EdDSA";

/// Reasons a signed envelope can be rejected by [`verify_signed_envelope`].
///
/// The [`fmt::Display`] spelling of each variant matches the stable `reason`
/// strings of the JavaScript reference (`tools/signed-envelope.mjs`), so
/// cross-language reason comparisons are byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedEnvelopeError {
    /// Not a JSON object, or (from a text entry point) invalid JSON.
    MalformedEnvelope,
    /// No `extensions["xeip.sig"]` carrier (absent or JSON `null`).
    MissingSignature,
    /// The carrier is not an object, `kid`/`sig` are missing or the wrong
    /// type, or `sig` is not canonical 64-byte base64url.
    MalformedSignature,
    /// `alg` is not exactly `EdDSA`.
    UnsupportedAlgorithm,
    /// The key in `kid` decodes to a small-order (weak) Ed25519 point.
    WeakKey,
    /// `kid` is not a canonical key-id, or `entity_urn(kid) != sender`.
    SenderBinding,
    /// The canonical bytes do not verify under the key in `kid`.
    SignatureMismatch,
}

impl fmt::Display for SignedEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MalformedEnvelope => "malformed envelope",
            Self::MissingSignature => "missing signature",
            Self::MalformedSignature => "malformed signature",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::WeakKey => "weak key",
            Self::SenderBinding => "sender binding",
            Self::SignatureMismatch => "signature mismatch",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for SignedEnvelopeError {}

/// The RFC 8785 signing input: the envelope with `extensions` removed in its
/// entirety, canonicalized and encoded as UTF-8 when the caller needs bytes.
fn canonical_signing_input(envelope: &Value) -> String {
    let mut base = envelope.clone();
    if let Some(object) = base.as_object_mut() {
        object.remove("extensions");
    }
    canonicalize_json(&base)
}

/// Sign `envelope`: canonicalize the envelope with `extensions` removed (RFC
/// 8785) and Ed25519-sign those UTF-8 bytes with the key derived from `seed`,
/// then attach `extensions["xeip.sig"]`. Existing extensions are preserved.
///
/// Returns [`SignedEnvelopeError::MalformedEnvelope`] if `envelope` is not a
/// JSON object. Sender binding is deliberately *not* enforced here, matching
/// the JavaScript reference: signing must be able to produce unbound vectors,
/// and [`verify_signed_envelope`] is what requires `entity_urn(kid) == sender`.
pub fn sign_envelope(
    envelope: &Value,
    seed: &[u8; ED25519_SEED_LENGTH],
    kid: &str,
) -> Result<Value, SignedEnvelopeError> {
    if !envelope.is_object() {
        return Err(SignedEnvelopeError::MalformedEnvelope);
    }

    let signing_key = SigningKey::from_bytes(seed);
    let message = canonical_signing_input(envelope);
    let signature = signing_key.sign(message.as_bytes());

    let mut signed = envelope.clone();
    let object = signed.as_object_mut().expect("checked above");
    let extensions = object
        .entry("extensions")
        .or_insert_with(|| Value::Object(Map::new()));
    if !extensions.is_object() {
        *extensions = Value::Object(Map::new());
    }
    let carrier = json!({
        "v": SIG_VERSION,
        "alg": SIG_ALG,
        "kid": kid,
        "sig": base64url_encode(&signature.to_bytes()),
    });
    extensions
        .as_object_mut()
        .expect("set to an object above")
        .insert(SIG_EXTENSION.to_string(), carrier);
    Ok(signed)
}

/// Verify a signed envelope and return a structured result: `Ok(())` when
/// valid, or an [`SignedEnvelopeError`] reason. Never panics for a well-formed
/// call.
///
/// The checks run in the same order as `tools/signed-envelope.mjs`: carrier
/// presence and shape, `alg`, carrier `v`, key-id decoding, weak-key rejection,
/// sender binding, signature decoding, then strict canonical-bytes
/// verification.
///
/// This accepts a pre-parsed value and therefore skips the strict pre-parse
/// gate; use [`verify_signed_envelope_text`] for wire bytes.
pub fn verify_signed_envelope(envelope: &Value) -> Result<(), SignedEnvelopeError> {
    let object = envelope
        .as_object()
        .ok_or(SignedEnvelopeError::MalformedEnvelope)?;

    let carrier = match object.get("extensions").and_then(Value::as_object) {
        Some(extensions) => extensions.get(SIG_EXTENSION),
        None => None,
    };
    let carrier = match carrier {
        None | Some(Value::Null) => return Err(SignedEnvelopeError::MissingSignature),
        Some(Value::Object(carrier)) => carrier,
        Some(_) => return Err(SignedEnvelopeError::MalformedSignature),
    };

    let (kid, signature) = match (
        carrier.get("kid").and_then(Value::as_str),
        carrier.get("sig").and_then(Value::as_str),
    ) {
        (Some(kid), Some(signature)) => (kid, signature),
        _ => return Err(SignedEnvelopeError::MalformedSignature),
    };
    if carrier.get("alg").and_then(Value::as_str) != Some(SIG_ALG) {
        return Err(SignedEnvelopeError::UnsupportedAlgorithm);
    }
    if carrier.get("v").and_then(Value::as_str) != Some(SIG_VERSION) {
        return Err(SignedEnvelopeError::MalformedSignature);
    }

    let public_key = decode_key_id(kid).map_err(|_| SignedEnvelopeError::SenderBinding)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SignedEnvelopeError::SenderBinding)?;
    // Reject small-order/identity keys with a stable, platform-independent
    // reason *before* sender binding, so no curve backend can diverge.
    if verifying_key.is_weak() || is_weak_ed25519_public_key(&public_key) {
        return Err(SignedEnvelopeError::WeakKey);
    }
    let sender = object
        .get("sender")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entity_urn(kid) != sender {
        return Err(SignedEnvelopeError::SenderBinding);
    }

    let signature_bytes =
        base64url_decode(signature).ok_or(SignedEnvelopeError::MalformedSignature)?;
    if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
        return Err(SignedEnvelopeError::MalformedSignature);
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| SignedEnvelopeError::MalformedSignature)?;

    let message = canonical_signing_input(envelope);
    // `verify_strict` (not `verify`) additionally rejects non-canonical `R`
    // values, matching the ported JS/TS small-order gate.
    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| SignedEnvelopeError::SignatureMismatch)
}

/// Verify signed envelope *JSON text*: strict-parse (rejecting duplicate keys,
/// lone surrogates and out-of-range integers) and then run
/// [`verify_signed_envelope`]. This is the entry point a relay that consumes
/// wire bytes must use so the strict pre-parse gate is always applied.
pub fn verify_signed_envelope_text(text: &str) -> Result<(), SignedEnvelopeError> {
    let envelope = strict_parse(text).map_err(|_| SignedEnvelopeError::MalformedEnvelope)?;
    verify_signed_envelope(&envelope)
}
