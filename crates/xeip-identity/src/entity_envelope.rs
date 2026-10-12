//! Experimental entity-bound 0.2 profile; no legacy fallback.
use crate::canonical::{canonicalize_json, strict_parse, MAX_SAFE_INTEGER};
use crate::crypto::is_weak_ed25519_public_key;
use crate::encoding::{base64url_decode, base64url_encode};
use crate::key_document::{KeyDocumentTrust, TrustAnchor};
use crate::key_id::decode_key_id;
use crate::status::verify_status_document;
use crate::time::parse_utc_seconds;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use std::fmt;

pub const ENTITY_SIGNATURE_PROFILE: &str = "xeip.entity-signed-envelopes/0.2";
pub const ENTITY_SIGNATURE_DOMAIN: &str = "XEIP entity-bound envelope v0.2\n";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityEnvelopeError(&'static str);
impl fmt::Display for EntityEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for EntityEnvelopeError {}
fn error(reason: &'static str) -> EntityEnvelopeError {
    EntityEnvelopeError(reason)
}

/// Complete pinned provisioning is required; this stateless API has no restart history.
pub struct EntityTrustOptions<'a> {
    pub key_documents: &'a [Value],
    pub anchor: Option<TrustAnchor>,
    pub status_document: &'a Value,
    pub now_seconds: i64,
    pub max_age_seconds: i64,
    pub known_extensions: &'a [String],
}
fn seconds(value: &Value) -> Option<i64> {
    let text = value.as_str()?;
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        if ![4, 7, 10, 13, 16, 19].contains(&i) && !b.is_ascii_digit() {
            return None;
        }
    }
    let number = |a: usize, b: usize| text[a..b].parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if year < 1970
        || !(1..=days).contains(&day)
        || number(11, 13)? > 23
        || number(14, 16)? > 59
        || number(17, 19)? > 59
    {
        return None;
    }
    parse_utc_seconds(text)
}
fn carrier(envelope: &Value) -> Result<&Map<String, Value>, EntityEnvelopeError> {
    let extensions = envelope
        .get("extensions")
        .and_then(Value::as_object)
        .ok_or_else(|| error("malformed signature"))?;
    let proof = extensions
        .get("xeip.sig")
        .and_then(Value::as_object)
        .ok_or_else(|| error("malformed signature"))?;
    if proof.get("v").and_then(Value::as_str) != Some("0.2")
        || proof.get("alg").and_then(Value::as_str) != Some("EdDSA")
    {
        return Err(error("unsupported profile"));
    }
    if proof.len() != 5
        || !["v", "alg", "kid", "crit", "sig"]
            .iter()
            .all(|key| proof.contains_key(*key))
        || !proof["kid"].is_string()
        || !proof["sig"].is_string()
    {
        return Err(error("malformed signature"));
    }
    let critical = proof["crit"]
        .as_array()
        .ok_or_else(|| error("malformed signature"))?;
    let mut names = std::collections::HashSet::new();
    for name in critical {
        let name = name.as_str().ok_or_else(|| error("malformed signature"))?;
        if name.is_empty()
            || name == "xeip.sig"
            || !extensions.contains_key(name)
            || !names.insert(name)
        {
            return Err(error("malformed signature"));
        }
    }
    Ok(proof)
}
pub fn entity_envelope_signing_input(envelope: &Value) -> Result<String, EntityEnvelopeError> {
    let mut value =
        strict_parse(&canonicalize_json(envelope)).map_err(|_| error("malformed envelope"))?;
    let proof = carrier(&value)?;
    let metadata =
        json!({"v":proof["v"],"alg":proof["alg"],"kid":proof["kid"],"crit":proof["crit"]});
    value["extensions"]
        .as_object_mut()
        .expect("carrier checked")
        .remove("xeip.sig");
    Ok(format!(
        "{}{}",
        ENTITY_SIGNATURE_DOMAIN,
        canonicalize_json(&json!({"envelope":value,"proof":metadata}))
    ))
}
pub fn sign_entity_envelope(
    envelope: &Value,
    seed: &[u8; 32],
    kid: &str,
    critical_extensions: &[String],
) -> Result<Value, EntityEnvelopeError> {
    let mut value =
        strict_parse(&canonicalize_json(envelope)).map_err(|_| error("malformed envelope"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| error("malformed envelope"))?;
    let extensions = object
        .entry("extensions")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| error("malformed envelope"))?;
    extensions.insert(
        "xeip.sig".into(),
        json!({"v":"0.2","alg":"EdDSA","kid":kid,"crit":critical_extensions,"sig":""}),
    );
    let input = entity_envelope_signing_input(&value)?;
    let signature = SigningKey::from_bytes(seed).sign(input.as_bytes());
    value["extensions"]["xeip.sig"]["sig"] = Value::String(base64url_encode(&signature.to_bytes()));
    Ok(value)
}
fn validate_trust<'a>(
    entity: &str,
    options: &'a EntityTrustOptions<'a>,
) -> Result<(&'a Value, &'a Value), EntityEnvelopeError> {
    let now = options.now_seconds;
    if !(0..=MAX_SAFE_INTEGER).contains(&now) || !(1..=86400).contains(&options.max_age_seconds) {
        return Err(error("stale status"));
    }
    let anchor = options
        .anchor
        .clone()
        .ok_or_else(|| error("untrusted identity"))?;
    if options.key_documents.is_empty()
        || ![&anchor.genesis_kid, &anchor.genesis_digest]
            .iter()
            .any(|s| s.as_ref().is_some_and(|s| !s.is_empty()))
    {
        return Err(error("untrusted identity"));
    }
    let mut trust = KeyDocumentTrust::new(entity, Some(anchor), None, false);
    for document in options.key_documents {
        strict_parse(&canonicalize_json(document)).map_err(|_| error("untrusted identity"))?;
        if seconds(&document["issuedAt"]).map_or(true, |issued| issued > now) {
            return Err(error("untrusted identity"));
        }
        trust
            .ingest(document)
            .map_err(|_| error("untrusted identity"))?;
    }
    let current = options.key_documents.last().expect("nonempty checked");
    let status = options.status_document;
    strict_parse(&canonicalize_json(status)).map_err(|_| error("untrusted identity"))?;
    verify_status_document(status, current).map_err(|_| error("untrusted identity"))?;
    if seconds(&status["issuedAt"]).map_or(true, |issued| {
        issued > now || now - issued > options.max_age_seconds
    }) {
        return Err(error("stale status"));
    }
    Ok((current, status))
}
pub fn verify_entity_envelope(
    envelope: &Value,
    options: &EntityTrustOptions<'_>,
) -> Result<(), EntityEnvelopeError> {
    let value =
        strict_parse(&canonicalize_json(envelope)).map_err(|_| error("malformed envelope"))?;
    let sender = value
        .get("sender")
        .and_then(Value::as_str)
        .ok_or_else(|| error("malformed envelope"))?;
    let proof = carrier(&value)?;
    if proof["crit"].as_array().expect("checked").iter().any(|v| {
        !options
            .known_extensions
            .iter()
            .any(|known| Some(known.as_str()) == v.as_str())
    }) {
        return Err(error("unsupported critical extension"));
    }
    let kid = proof["kid"].as_str().expect("checked");
    let raw = decode_key_id(kid).map_err(|_| error("malformed signature"))?;
    if is_weak_ed25519_public_key(&raw) {
        return Err(error("weak key"));
    }
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| error("malformed signature"))?;
    if key.is_weak() {
        return Err(error("weak key"));
    }
    let signature = base64url_decode(proof["sig"].as_str().expect("checked"))
        .ok_or_else(|| error("malformed signature"))?;
    let signature = Signature::from_slice(&signature).map_err(|_| error("malformed signature"))?;
    key.verify_strict(
        entity_envelope_signing_input(&value)?.as_bytes(),
        &signature,
    )
    .map_err(|_| error("signature mismatch"))?;
    let (current, status) = validate_trust(sender, options)?;
    if !["roots", "devices"].iter().any(|field| {
        current[*field]
            .as_array()
            .expect("verified")
            .iter()
            .any(|v| v.as_str() == Some(kid))
    }) {
        return Err(error("unauthorized key"));
    }
    if status["revoked"]
        .as_array()
        .expect("verified")
        .iter()
        .any(|entry| entry["kid"].as_str() == Some(kid))
    {
        return Err(error("revoked key"));
    }
    Ok(())
}
pub fn verify_entity_envelope_text(
    text: &str,
    options: &EntityTrustOptions<'_>,
) -> Result<(), EntityEnvelopeError> {
    let value = strict_parse(text).map_err(|_| error("malformed envelope"))?;
    verify_entity_envelope(&value, options)
}
