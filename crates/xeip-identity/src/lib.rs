//! Self-certifying XEIP identity key-ID encoding.
//!
//! This crate implements the encoding layer of the proposed identity profile
//! (`spec/identity.md` §2): a `did:key`-style
//! `multibase(MULTICODEC(public-key-type, raw-public-key-bytes))` value.
//!
//! ```text
//! key-id = "z" + base58btc(0xed 0x01 || raw-ed25519-public-key-bytes)
//!          \_/   \_______/
//!       multibase   multicodec (ed25519-pub, unsigned LEB128 varint)
//!       base58btc
//! ```
//!
//! The key-ID layer is dependency-free and hand-writes base58btc (a base
//! conversion, not a cryptographic primitive) so that it matches
//! `tools/derive-keyid.mjs` byte-for-byte.
//!
//! On top of it this crate implements the first verification slice of
//! [issue #1](https://github.com/powerpuff-kitty/XEIP/issues/1): the
//! `xeip.local-signed-envelopes/0.1` profile. [`sign_envelope`] and
//! [`verify_signed_envelope`] sign and verify the RFC 8785 (JCS) canonical
//! bytes of an envelope with `extensions` removed, attach the signature in
//! `extensions["xeip.sig"]`, and require `entity_urn(kid) == sender`. Ed25519
//! (RFC 8032) comes from the audited `ed25519-dalek` crate selected by
//! [ADR 0007](../../../spec/decisions/0007-crypto-dependencies.md); the
//! canonicalizer here is deterministic serialization, not a primitive. The
//! framing matches `tools/signed-envelope.mjs` and the vectors under
//! `conformance/fixtures/identity-signed/`.
//!
//! As `spec/identity.md` §2 requires, a caller that treats a recomputed key-id
//! as authentic must still validate the key as a canonical curve point before
//! doing so.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};

/// Multicodec code `0xed01` (`ed25519-pub`) written as an unsigned LEB128
/// varint. `0xed01` is greater than `0x7f`, so the varint needs two bytes.
pub const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Raw Ed25519 public keys are exactly 32 bytes (RFC 8032 §5.1.3).
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Multibase prefix for base58btc (<https://github.com/multiformats/multibase>).
pub const MULTIBASE_BASE58BTC: char = 'z';

/// Total byte length of the base58btc payload: multicodec prefix plus the key.
const PAYLOAD_LEN: usize = ED25519_MULTICODEC.len() + ED25519_PUBLIC_KEY_LENGTH;

/// The Bitcoin base58btc alphabet: no `0`, `O`, `I` or `l` to avoid visual
/// ambiguity. This exact, case-sensitive alphabet is fixed by the profile.
const BASE58BTC_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reasons a key-id can be rejected by [`decode_key_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyIdError {
    /// The string does not start with the base58btc multibase prefix `z`.
    MissingMultibasePrefix,
    /// A character outside the base58btc alphabet was encountered.
    InvalidBase58Char(char),
    /// The base58btc payload was not exactly 34 bytes.
    InvalidPayloadLength { actual: usize },
    /// The payload did not begin with the `0xed 0x01` multicodec prefix.
    WrongMulticodecPrefix,
    /// The spelling was not the canonical base58btc encoding of the payload.
    NonCanonical,
}

impl fmt::Display for KeyIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMultibasePrefix => {
                write!(
                    f,
                    "key-id must start with the base58btc multibase prefix 'z'"
                )
            }
            Self::InvalidBase58Char(ch) => {
                write!(f, "invalid base58btc character: {ch:?}")
            }
            Self::InvalidPayloadLength { actual } => {
                write!(
                    f,
                    "key-id payload must be {PAYLOAD_LEN} bytes; received {actual}"
                )
            }
            Self::WrongMulticodecPrefix => {
                write!(f, "key-id does not carry the ed25519-pub multicodec prefix")
            }
            Self::NonCanonical => write!(f, "key-id is not in canonical form"),
        }
    }
}

impl std::error::Error for KeyIdError {}

/// Base58btc-encode bytes using the Bitcoin alphabet. Each leading `0x00`
/// byte becomes one leading `1`; the remaining bytes are converted as a big
/// integer, exactly like the reference implementation.
fn base58btc_encode(input: &[u8]) -> String {
    let leading_zeros = input.iter().take_while(|&&byte| byte == 0).count();

    // Base58 digits of the integer part, least significant first.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &input[leading_zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut encoded = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        encoded.push('1');
    }
    for &digit in digits.iter().rev() {
        encoded.push(BASE58BTC_ALPHABET[digit as usize] as char);
    }
    encoded
}

/// Base58btc-decode text using the Bitcoin alphabet. Leading `1` characters
/// become leading `0x00` bytes. Returns [`KeyIdError::InvalidBase58Char`] for
/// any character outside the alphabet.
fn base58btc_decode(text: &str) -> Result<Vec<u8>, KeyIdError> {
    let leading_ones = text.bytes().take_while(|&byte| byte == b'1').count();

    // Decoded bytes of the integer part, least significant first.
    let mut bytes: Vec<u8> = Vec::new();
    for &byte in &text.as_bytes()[leading_ones..] {
        let digit = BASE58BTC_ALPHABET
            .iter()
            .position(|&candidate| candidate == byte)
            .ok_or(KeyIdError::InvalidBase58Char(byte as char))? as u32;

        let mut carry = digit;
        for value in bytes.iter_mut() {
            let acc = u32::from(*value) * 58 + carry;
            *value = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; leading_ones];
    out.extend(bytes.iter().rev().copied());
    Ok(out)
}

/// Encode a 32-byte raw Ed25519 public key as the identity-profile key-id:
/// base58btc of the `ed25519-pub` multicodec prefix followed by the key bytes,
/// with the `z` multibase prefix. This is the exact value embedded in the
/// entity and device URNs.
pub fn encode_key_id(public_key: &[u8; ED25519_PUBLIC_KEY_LENGTH]) -> String {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..ED25519_MULTICODEC.len()].copy_from_slice(&ED25519_MULTICODEC);
    payload[ED25519_MULTICODEC.len()..].copy_from_slice(public_key);

    let mut key_id = String::with_capacity(1 + 47);
    key_id.push(MULTIBASE_BASE58BTC);
    key_id.push_str(&base58btc_encode(&payload));
    key_id
}

/// Decode and canonical-validate a key-id produced by [`encode_key_id`],
/// returning the 32 raw public-key bytes.
///
/// Rejects a missing `z` multibase prefix, a payload length other than 34, a
/// missing `ed25519-pub` multicodec prefix, invalid base58btc characters and any
/// non-canonical spelling (checked by re-encoding the decoded payload).
pub fn decode_key_id(key_id: &str) -> Result<[u8; ED25519_PUBLIC_KEY_LENGTH], KeyIdError> {
    let body = key_id
        .strip_prefix(MULTIBASE_BASE58BTC)
        .ok_or(KeyIdError::MissingMultibasePrefix)?;

    let payload = base58btc_decode(body)?;
    if payload.len() != PAYLOAD_LEN {
        return Err(KeyIdError::InvalidPayloadLength {
            actual: payload.len(),
        });
    }
    if payload[0] != ED25519_MULTICODEC[0] || payload[1] != ED25519_MULTICODEC[1] {
        return Err(KeyIdError::WrongMulticodecPrefix);
    }

    let mut canonical = String::with_capacity(1 + body.len());
    canonical.push(MULTIBASE_BASE58BTC);
    canonical.push_str(&base58btc_encode(&payload));
    if canonical != key_id {
        return Err(KeyIdError::NonCanonical);
    }

    let mut key = [0u8; ED25519_PUBLIC_KEY_LENGTH];
    key.copy_from_slice(&payload[ED25519_MULTICODEC.len()..]);
    Ok(key)
}

/// `urn:xeip:entity:<key-id>`.
///
/// This is a pure string construction and does not validate `key_id`; callers
/// that need to reject non-canonical identifiers must pass `key_id` through
/// [`decode_key_id`] first.
pub fn entity_urn(key_id: &str) -> String {
    format!("urn:xeip:entity:{key_id}")
}

/// `urn:xeip:device:<key-id>`.
///
/// This is a pure string construction and does not validate `key_id`; callers
/// that need to reject non-canonical identifiers must pass `key_id` through
/// [`decode_key_id`] first.
pub fn device_urn(key_id: &str) -> String {
    format!("urn:xeip:device:{key_id}")
}

// ---------------------------------------------------------------------------
// Signed envelopes: `xeip.local-signed-envelopes/0.1`
// ---------------------------------------------------------------------------

/// Extensions member that carries the detached signature.
pub const SIG_EXTENSION: &str = "xeip.sig";

/// Version of the signature carrier.
pub const SIG_VERSION: &str = "0.1";

/// Fixed algorithm identifier; `EdDSA` is the only accepted value.
pub const SIG_ALG: &str = "EdDSA";

/// Raw Ed25519 seeds (private keys) are exactly 32 bytes (RFC 8032 §5.1.5).
pub const ED25519_SEED_LENGTH: usize = 32;

/// Ed25519 signatures are exactly 64 bytes (RFC 8032 §5.1.6).
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

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
            Self::SenderBinding => "sender binding",
            Self::SignatureMismatch => "signature mismatch",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for SignedEnvelopeError {}

/// RFC 8785 (JSON Canonicalization Scheme) of a parsed JSON value: object keys
/// sorted by UTF-16 code units, no insignificant whitespace, ECMAScript number
/// formatting and JSON string escaping, arrays in order.
///
/// This is deterministic serialization, not a cryptographic primitive (ADR
/// 0007 permits it alongside an audited signing library). Numbers are treated
/// as IEEE-754 doubles, so `-0` maps to `0` and values format exactly as
/// ECMAScript `Number::toString` does within the interoperable range.
pub fn canonicalize_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            let float = number
                .as_f64()
                .expect("a JSON number is always representable as f64");
            out.push_str(&format_ecmascript_number(float));
        }
        Value::String(text) => write_json_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical_json(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// Serialize a string as a JSON quoted string with the ecosystem's escaping:
/// short escapes for the JSON control characters, literal non-ASCII UTF-8 and
/// `/` left unescaped.
fn write_json_string(text: &str, out: &mut String) {
    let escaped = serde_json::to_string(text).expect("a string always serializes to JSON");
    out.push_str(&escaped);
}

/// Format an `f64` exactly as ECMAScript `Number::toString` (and therefore
/// `JSON.stringify`) does, per RFC 8785 §3.2.2.3. Finite values only.
fn format_ecmascript_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value < 0.0 {
        let mut out = String::from("-");
        out.push_str(&format_ecmascript_number(-value));
        return out;
    }

    // Rust's `{:e}` yields the shortest round-tripping decimal mantissa,
    // normalised to one leading digit. Split it into digits and a decimal
    // exponent, then apply the ECMAScript fixed/exponential decision.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("LowerExp output always contains 'e'");
    let exponent: i32 = exponent.parse().expect("LowerExp exponent is an integer");
    let digits: String = mantissa.chars().filter(|&c| c != '.').collect();
    let digit_count = digits.len() as i32;
    // Position of the decimal point relative to the digits.
    let point = exponent + 1;

    if digit_count <= point && point <= 21 {
        let mut out = digits;
        out.push_str(&"0".repeat((point - digit_count) as usize));
        out
    } else if 0 < point && point <= 21 {
        let point = point as usize;
        format!("{}.{}", &digits[..point], &digits[point..])
    } else if -6 < point && point <= 0 {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else {
        let exponent = point - 1;
        let sign = if exponent < 0 { '-' } else { '+' };
        let first = &digits[..1];
        let rest = &digits[1..];
        if rest.is_empty() {
            format!("{first}e{sign}{}", exponent.abs())
        } else {
            format!("{first}.{rest}e{sign}{}", exponent.abs())
        }
    }
}

/// The URL-safe base64 alphabet (RFC 4648 §5) without padding.
const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Canonical, unpadded base64url encoding.
fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64URL_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(BASE64URL_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL_ALPHABET[(triple & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decode canonical, unpadded base64url. Returns `None` for padding, invalid
/// characters, the length ≡ 1 (mod 4) case, non-zero trailing bits, or any
/// non-canonical spelling (checked by re-encoding).
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 4 == 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in text.as_bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    if base64url_encode(&bytes) != text {
        return None;
    }
    Some(bytes)
}

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
/// presence and shape, `alg`, key-id decoding, sender binding, signature
/// decoding, then canonical-bytes verification.
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

    let public_key = decode_key_id(kid).map_err(|_| SignedEnvelopeError::SenderBinding)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SignedEnvelopeError::SenderBinding)?;
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
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| SignedEnvelopeError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58btc_matches_known_answers() {
        // Canonical multibase/base58btc KAT: ASCII "Hello World!".
        assert_eq!(base58btc_encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        // Empty input and leading-zero (0x00-heavy) special cases.
        assert_eq!(base58btc_encode(b""), "");
        assert_eq!(base58btc_encode(&[0x00]), "1");
        assert_eq!(base58btc_encode(&[0x00, 0x00]), "11");
        assert_eq!(base58btc_encode(&[0x00, 0x00, 0x00]), "111");
        assert_eq!(base58btc_encode(&[0x00, 0x00, 0x01]), "112");
        assert_eq!(base58btc_encode(&[0xff]), "5Q");
        assert_eq!(base58btc_encode(&[0x00, 0xff]), "15Q");
        // The alphabet is the exact 58-character Bitcoin set.
        assert_eq!(BASE58BTC_ALPHABET.len(), 58);
    }

    #[test]
    fn base58btc_round_trips_leading_zeros() {
        // Key-ids always start with 0xed, so the leading-zero path is never
        // exercised by the conformance vectors; cover it directly here.
        let samples: &[&[u8]] = &[
            b"",
            &[0x00],
            &[0x00, 0x00, 0x00, 0x04],
            &[0x00, 0x00, 0x01, 0x02, 0x03],
            b"Hello World!",
        ];
        for sample in samples {
            let encoded = base58btc_encode(sample);
            assert_eq!(base58btc_decode(&encoded).unwrap(), sample.to_vec());
        }
        assert_eq!(
            base58btc_decode("0"),
            Err(KeyIdError::InvalidBase58Char('0'))
        );
        assert_eq!(
            base58btc_decode("O"),
            Err(KeyIdError::InvalidBase58Char('O'))
        );
    }

    #[test]
    fn key_id_round_trips() {
        let mut key = [0u8; ED25519_PUBLIC_KEY_LENGTH];
        key[0] = 0x42;
        let key_id = encode_key_id(&key);
        assert!(key_id.starts_with('z'));
        assert_eq!(decode_key_id(&key_id).unwrap(), key);
    }

    #[test]
    fn entity_and_device_urns_share_the_key_id() {
        let key = [7u8; ED25519_PUBLIC_KEY_LENGTH];
        let key_id = encode_key_id(&key);
        assert_eq!(entity_urn(&key_id), format!("urn:xeip:entity:{key_id}"));
        assert_eq!(device_urn(&key_id), format!("urn:xeip:device:{key_id}"));
        assert_ne!(entity_urn(&key_id), device_urn(&key_id));
    }

    #[test]
    fn rejects_padded_and_missing_prefix_spellings() {
        let key = [0x11u8; ED25519_PUBLIC_KEY_LENGTH];
        let key_id = encode_key_id(&key);

        // A padded extra leading '1' decodes to the wrong payload length. (For a
        // fixed payload length base58btc is a bijection, so this is rejected
        // before the re-encode equality check; assert it is rejected regardless.)
        let mut padded = String::from("z");
        padded.push('1');
        padded.push_str(&key_id[1..]);
        assert_eq!(
            decode_key_id(&padded),
            Err(KeyIdError::InvalidPayloadLength { actual: 35 })
        );

        // Missing 'z' prefix.
        assert_eq!(
            decode_key_id(&key_id[1..]),
            Err(KeyIdError::MissingMultibasePrefix)
        );

        // Valid length but a wrong multicodec prefix (0x00 0x00).
        let wrong_prefix = {
            let mut payload = [0u8; PAYLOAD_LEN];
            payload[ED25519_MULTICODEC.len()..].copy_from_slice(&key);
            format!("z{}", base58btc_encode(&payload))
        };
        assert_eq!(
            decode_key_id(&wrong_prefix),
            Err(KeyIdError::WrongMulticodecPrefix)
        );
    }

    #[test]
    fn canonicalize_matches_rfc_8785() {
        assert_eq!(
            canonicalize_json(&json!({"b": 1, "a": 2})),
            r#"{"a":2,"b":1}"#
        );
        // Keys are sorted by UTF-16 code units and nesting is recursive.
        assert_eq!(
            canonicalize_json(&json!({"z": 1, "a": [1, {"y": 1, "x": 2}]})),
            r#"{"a":[1,{"x":2,"y":1}],"z":1}"#
        );
        assert_eq!(
            canonicalize_json(&json!({"a": "a/b\n", "b": "\u{2028}"})),
            "{\"a\":\"a/b\\n\",\"b\":\"\u{2028}\"}"
        );
    }

    #[test]
    fn canonicalize_uses_ecmascript_numbers() {
        assert_eq!(canonicalize_json(&json!(-0.0)), "0");
        assert_eq!(canonicalize_json(&json!(1.0)), "1");
        assert_eq!(canonicalize_json(&json!(0.1)), "0.1");
        assert_eq!(canonicalize_json(&json!(1e21)), "1e+21");
        assert_eq!(canonicalize_json(&json!(1e-7)), "1e-7");
        assert_eq!(
            canonicalize_json(&json!(9007199254740991i64)),
            "9007199254740991"
        );
        assert_eq!(canonicalize_json(&serde_json::from_str("-0").unwrap()), "0");
    }

    #[test]
    fn base64url_is_canonical_and_unpadded() {
        let bytes = [0u8, 1, 2, 253, 254, 255];
        let text = base64url_encode(&bytes);
        assert_eq!(text, "AAEC_f7_");
        assert_eq!(base64url_decode(&text).unwrap(), bytes);
        assert_eq!(base64url_decode("AAEC_f7_="), None);
        assert_eq!(base64url_decode("A"), None);
        assert_eq!(base64url_decode("not base64!"), None);
        assert_eq!(base64url_decode(""), None);
    }

    #[test]
    fn seed_derives_the_reference_public_key() {
        let seed: [u8; ED25519_SEED_LENGTH] =
            hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let signing_key = SigningKey::from_bytes(&seed);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            hex_decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
        );
    }

    /// Decode a 64-character lowercase hex string into 32 bytes.
    fn hex_decode(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).expect("hex is ASCII");
            out[index] = u8::from_str_radix(pair, 16).expect("valid hex");
        }
        out
    }
}
