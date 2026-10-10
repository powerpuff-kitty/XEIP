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

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
// SHA-256 for the chain `previous` link digest. `sha2 0.10.9` is already a
// transitive dependency of the pinned `ed25519-dalek` and is the crate named by
// ADR 0007; it is used directly here so the digest matches
// `tools/key-document.mjs` byte for byte.
use sha2::{Digest, Sha256};

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

/// Largest integer that round-trips through an IEEE-754 double exactly. The
/// strict pre-parse gate rejects any integer outside `±(2^53 - 1)`.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// The eight canonical encodings of the small-order (torsion) points of the
/// Ed25519 curve, including the identity `01 00…00` and the all-zero encoding.
///
/// A verifying key that decompresses to one of these points is a *weak key*: a
/// small-order key can be used to forge a signature that verifies for almost
/// every message (for the identity key, `R = [S]B` with `S = 1` verifies for
/// *every* message). [`VerifyingKey::is_weak`] detects them, but the JavaScript
/// and TypeScript ports must reject them independently of the platform's
/// WebCrypto implementation, so the encodings are pinned here too.
pub const ED25519_SMALL_ORDER_POINTS: [[u8; ED25519_PUBLIC_KEY_LENGTH]; 8] = [
    // 0x01 followed by 31 zero bytes: the identity point (order 1).
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // All-zero encoding.
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // y = 0 with the sign bit set.
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
    // y = 1 with the sign bit set.
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
    // y = -1 (0xec ff…7f) and its sign-bit variant.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    // The two order-8 encodings (0xed ff…7f and 0xed ff…ff).
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
];

/// Whether `key` is one of the eight canonical small-order (torsion) points,
/// i.e. a weak key that MUST be rejected. This is a byte-level blacklist that
/// does not depend on any curve library, for platform-independent rejection.
pub fn is_weak_ed25519_public_key(key: &[u8; ED25519_PUBLIC_KEY_LENGTH]) -> bool {
    ED25519_SMALL_ORDER_POINTS.contains(key)
}

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

    // Get the shortest correctly-rounded significant digits, then apply the
    // ECMAScript fixed/exponential decision. Rust's own `{:e}`/`{}` formatting
    // tie-breaks an exact decimal midpoint away from zero (for example
    // `2084516549501568.25`), which disagrees with the ECMAScript/RFC 8785 rule
    // of choosing the even final digit; `serde_json`'s float formatter follows
    // the required shortest-round-trip rule, so the digits are taken from it.
    let (digits, point) = shortest_significant_digits(value);
    let digit_count = digits.len() as i32;

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

/// The shortest significant decimal digits of a positive, finite `f64` and the
/// position of the decimal point relative to those digits, such that the value
/// is `digits * 10^(point - digits.len())`.
///
/// RFC 8785 §3.2.2.3 (and ECMAScript `Number::toString`) require the shortest
/// digit string that round-trips, breaking an exact midpoint toward the even
/// final digit. `serde_json`'s float formatter implements that rule; parsing
/// its output normalises away its own fixed/exponential style so the digits can
/// be re-rendered with the ECMAScript thresholds in
/// [`format_ecmascript_number`].
fn shortest_significant_digits(value: f64) -> (String, i32) {
    let text = serde_json::Number::from_f64(value)
        .expect("a finite number is representable")
        .to_string();
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (
            mantissa,
            exponent
                .parse::<i32>()
                .expect("a serde_json exponent is an integer"),
        ),
        None => (text.as_str(), 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };

    let mut digits: Vec<u8> = integer.bytes().chain(fraction.bytes()).collect();
    let mut point = integer.len() as i32 + exponent;
    let leading = digits.iter().take_while(|&&byte| byte == b'0').count();
    digits.drain(..leading);
    point -= leading as i32;
    while digits.last() == Some(&b'0') {
        digits.pop();
    }

    (
        String::from_utf8(digits).expect("decimal digits are ASCII"),
        point,
    )
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

/// Reason a JSON document was rejected by [`strict_parse`].
///
/// The message is intended for diagnostics only; the signed-envelope entry
/// points collapse every strict-parse failure to
/// [`SignedEnvelopeError::MalformedEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictParseError {
    message: String,
}

impl StrictParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for StrictParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StrictParseError {}

/// Strict JSON parser, the Rust twin of `strictParse` in
/// `tools/signed-envelope.mjs`. Before canonicalization it rejects the
/// ambiguity that would let two different wire byte sequences share one
/// signature:
///
/// - duplicate object member names,
/// - lone surrogate escapes (`\uD800`, `\uDC00` and an unpaired high surrogate
///   followed by a non-low escape),
/// - numbers that are non-finite (`1e999`),
/// - integer values outside `±(2^53-1)`.
///
/// What `serde_json` already enforces: its parser rejects lone surrogate
/// escapes (`unexpected end of hex escape` / `lone leading surrogate in hex
/// escape`) and non-finite numbers (`number out of range`), and a raw lone
/// surrogate is impossible in a Rust `&str` (UTF-8 invariant). What `serde_json`
/// cannot express: deserializing into [`Value`] silently keeps the *last* value
/// for a duplicate key, so duplicate detection is implemented here by hand.
///
/// Integers are parsed as IEEE-754 doubles, matching the JavaScript reference
/// (which applies `Number.isInteger` to the parsed double), so `1e15` is
/// accepted while `9007199254740992` is rejected.
pub fn strict_parse(text: &str) -> Result<Value, StrictParseError> {
    let mut parser = StrictJsonParser::new(text);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if !parser.at_end() {
        return Err(parser.error("unexpected trailing content"));
    }
    Ok(value)
}

struct StrictJsonParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> StrictJsonParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn error(&self, message: &str) -> StrictParseError {
        StrictParseError::new(format!("{message} at position {}", self.pos))
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), StrictParseError> {
        if self.peek() != Some(byte) {
            return Err(self.error(&format!("expected {}", byte as char)));
        }
        self.pos += 1;
        Ok(())
    }

    fn parse_value(&mut self) -> Result<Value, StrictParseError> {
        self.skip_whitespace();
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(b't') => self.parse_literal("true", Value::Bool(true)),
            Some(b'f') => self.parse_literal("false", Value::Bool(false)),
            Some(b'n') => self.parse_literal("null", Value::Null),
            Some(byte) => Err(self.error(&format!("unexpected character {}", char::from(byte)))),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Value) -> Result<Value, StrictParseError> {
        if self.text[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn parse_object(&mut self) -> Result<Value, StrictParseError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        let mut object = Map::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(object));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a string object key"));
            }
            let key = self.parse_string()?;
            if object.contains_key(&key) {
                return Err(self.error("duplicate object member name"));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(object));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, StrictParseError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        let mut array = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(array));
        }
        loop {
            array.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(array));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, StrictParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = match self.peek() {
                Some(byte) => byte,
                None => return Err(self.error("unterminated string")),
            };
            if byte == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if byte == b'\\' {
                self.pos += 1;
                let escape = self
                    .peek()
                    .ok_or_else(|| self.error("unterminated escape"))?;
                self.pos += 1;
                match escape {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => self.parse_unicode_escape(&mut out)?,
                    _ => return Err(self.error("invalid escape")),
                }
                continue;
            }
            if byte < 0x20 {
                return Err(self.error("unescaped control character in string"));
            }
            // `self.pos` is always on a UTF-8 boundary here, so this is valid.
            let ch = self.text[self.pos..]
                .chars()
                .next()
                .expect("non-empty remaining string");
            out.push(ch);
            self.pos += ch.len_utf8();
        }
    }

    fn parse_unicode_escape(&mut self, out: &mut String) -> Result<(), StrictParseError> {
        let first = self.read_hex4()?;
        if (0xd800..=0xdbff).contains(&first) {
            // A high surrogate must be immediately followed by a low escape.
            if self.bytes.get(self.pos) != Some(&b'\\')
                || self.bytes.get(self.pos + 1) != Some(&b'u')
            {
                return Err(self.error("string contains a lone high surrogate"));
            }
            self.pos += 2;
            let second = self.read_hex4()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(self.error("string contains a lone high surrogate"));
            }
            let scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
            out.push(char::from_u32(scalar).expect("a valid surrogate pair is a scalar value"));
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(self.error("string contains a lone low surrogate"));
        } else {
            out.push(char::from_u32(first).expect("a non-surrogate code unit is a scalar value"));
        }
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, StrictParseError> {
        let end = self.pos + 4;
        if end > self.bytes.len() {
            return Err(self.error("invalid \\u escape"));
        }
        let digits = &self.bytes[self.pos..end];
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.error("invalid \\u escape"));
        }
        let value = u32::from_str_radix(&self.text[self.pos..end], 16)
            .map_err(|_| self.error("invalid \\u escape"))?;
        self.pos = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, StrictParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(byte) if byte.is_ascii_digit() => {
                while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let token = &self.text[start..self.pos];
        let value: f64 = token.parse().map_err(|_| self.error("invalid number"))?;
        if !value.is_finite() {
            return Err(self.error("non-finite number"));
        }
        if value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64 {
            return Err(self.error("integer outside the safe range"));
        }
        // Preserve the integer spelling when the token is a pure integer, so
        // the parsed value mirrors `serde_json`'s own representation.
        let number = if !token.contains(['.', 'e', 'E']) {
            match token.parse::<i64>() {
                Ok(value) => serde_json::Number::from(value),
                Err(_) => match token.parse::<u64>() {
                    Ok(value) => serde_json::Number::from(value),
                    Err(_) => serde_json::Number::from_f64(value)
                        .ok_or_else(|| self.error("non-finite number"))?,
                },
            }
        } else {
            serde_json::Number::from_f64(value).ok_or_else(|| self.error("non-finite number"))?
        };
        Ok(Value::Number(number))
    }
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
/// The first seven variants are the single-document reasons. `Rollback`,
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
    /// Chain only: the candidate generation is less than or equal to the
    /// highest generation already accepted for the entity.
    Rollback,
    /// Chain only: a distinct document at the accepted generation
    /// (equivocation / double-signing).
    Fork,
    /// Chain only: a generation jump (`generation > prev + 1`) or a `previous`
    /// that does not match the accepted document's digest.
    ChainGap,
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
            Self::Rollback => "rollback",
            Self::Fork => "fork",
            Self::ChainGap => "chain gap",
            Self::NoAnchor => "no anchor",
            Self::UntrustedAnchor => "untrusted anchor",
            Self::GenerationExceedsMaximum => "generation exceeds maximum",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for KeyDocumentError {}

/// Whether `text` is an RFC 3339 instant in UTC (`YYYY-MM-DDTHH:MM:SS[.fff]Z`).
/// Offsets are rejected: the profile fixes UTC.
fn is_utc_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    let digit = |index: usize| bytes[index].is_ascii_digit();
    let fixed = digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && bytes[4] == b'-'
        && digit(5)
        && digit(6)
        && bytes[7] == b'-'
        && digit(8)
        && digit(9)
        && bytes[10] == b'T'
        && digit(11)
        && digit(12)
        && bytes[13] == b':'
        && digit(14)
        && digit(15)
        && bytes[16] == b':'
        && digit(17)
        && digit(18);
    if !fixed {
        return false;
    }
    if bytes[19] == b'Z' {
        return bytes.len() == 20;
    }
    if bytes[19] != b'.' {
        return false;
    }
    let mut index = 20;
    let start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    index > start && index + 1 == bytes.len() && bytes[index] == b'Z'
}

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
/// one valid signature by a key listed in `roots`.
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

    let message = keydoc_signing_input(document);
    let mut saw_root_signer = false;
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
        if !roots.iter().any(|value| value.as_str() == Some(kid)) {
            continue;
        }
        saw_root_signer = true;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| KeyDocumentError::MalformedDocument)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| KeyDocumentError::MalformedDocument)?;
        // `verify_strict` additionally rejects non-canonical `R` values,
        // matching the JavaScript small-order gate.
        if verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_ok()
        {
            return Ok(());
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
/// [`KeyDocumentChain`] needs to enforce the next link.
#[derive(Debug, Clone)]
struct AcceptedKeyDocument {
    generation: i64,
    digest: String,
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
        self.entities
            .insert(entity, AcceptedKeyDocument { generation, digest });
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
fn status_trusted_entity(trusted_key_document: &Value) -> Option<&str> {
    trusted_key_document
        .as_object()
        .and_then(|object| object.get("entity"))
        .and_then(Value::as_str)
}

/// The set of current root key-ids listed in a trusted key document.
fn status_trusted_roots(trusted_key_document: &Value) -> Vec<&str> {
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

/// Days from the civil date `y-m-d` to 1970-01-01 (Howard Hinnant's algorithm).
/// This is calendar arithmetic, not a cryptographic primitive.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Whole epoch seconds of a UTC instant already validated by
/// [`is_utc_timestamp`]. Fractional seconds are truncated, matching
/// `parseUtcSeconds` in `tools/identity-status.mjs`.
fn parse_utc_seconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let number = |start: usize, end: usize| text.get(start..end)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
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

    #[test]
    fn strict_parse_rejects_duplicate_object_members() {
        assert!(strict_parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(strict_parse(r#"{"a":1,"b":2,"a":3}"#).is_err());
        // Nested duplicates are rejected too.
        assert!(strict_parse(r#"{"a":{"b":1,"b":2}}"#).is_err());
        assert_eq!(
            strict_parse(r#"{"a":1,"b":2}"#),
            Ok(json!({"a": 1, "b": 2}))
        );
    }

    #[test]
    fn strict_parse_rejects_lone_surrogates_and_nonfinite_and_big_integers() {
        assert!(strict_parse(r#""\uD800""#).is_err());
        assert!(strict_parse(r#""\uDC00""#).is_err());
        assert!(strict_parse(r#""a\uD800b""#).is_err());
        // A correctly paired surrogate is one scalar value.
        assert_eq!(strict_parse(r#""\uD83D\uDE00""#), Ok(json!("\u{1f600}")));
        // Non-finite and out-of-range integers.
        assert!(strict_parse("1e999").is_err());
        assert!(strict_parse("9007199254740992").is_err());
        assert!(strict_parse("-9007199254740992").is_err());
        assert_eq!(
            strict_parse("9007199254740991"),
            Ok(json!(9007199254740991i64))
        );
        assert_eq!(strict_parse("-0").unwrap().as_f64(), Some(0.0));
        assert!(strict_parse("01").is_err());
        assert!(strict_parse(r#"{"a":1}x"#).is_err());
    }

    #[test]
    fn weak_keys_are_rejected_before_verification() {
        for point in ED25519_SMALL_ORDER_POINTS {
            assert!(is_weak_ed25519_public_key(&point));
            assert!(VerifyingKey::from_bytes(&point).unwrap().is_weak());
        }
        // A real key is not flagged.
        let real = hex_decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        assert!(!is_weak_ed25519_public_key(&real));
    }

    #[test]
    fn identity_key_forgery_is_rejected() {
        // A genuine forgery of the old non-strict verifier: the identity key
        // `01` + 31 zero bytes with `R = [S]B`, `S = 1` verifies for *every*
        // message under `verify` (non-strict). It must now fail with "weak key".
        let envelope = json!({
            "xeip": "0.1",
            "id": "urn:xeip:message:forged",
            "kind": "message",
            "sender": "urn:xeip:entity:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj",
            "recipient": "urn:xeip:entity:recipient-01",
            "body": {"contentType": "text/plain", "data": "forged"},
            "extensions": {"xeip.sig": {
                "v": "0.1",
                "alg": "EdDSA",
                "kid": "z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj",
                "sig": "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }}
        });
        assert_eq!(
            verify_signed_envelope(&envelope).unwrap_err().to_string(),
            "weak key"
        );
    }

    #[test]
    fn verify_strict_rejects_a_small_order_r_that_loose_verify_accepts() {
        // CTC/CCTV ed25519vectors #5: a signature over "ed25519vectors 3" whose
        // R is the all-zero (small-order) encoding, under a canonical, non-weak
        // public key. The cofactored, non-strict `verify` accepts it, but
        // `verify_strict` rejects the small-order R. [`verify_signed_envelope`]
        // uses `verify_strict`, so a wire signature with a small-order R is
        // rejected by the Rust port even when the key itself is fine.
        use ed25519_dalek::Verifier;

        let public = VerifyingKey::from_bytes(&hex_decode(
            "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        ))
        .expect("a canonical, non-weak public key");
        assert!(!public.is_weak(), "the key must not be small-order");

        // R = 00…00 (small-order), S from the reference vector.
        let mut signature_bytes = [0u8; ED25519_SIGNATURE_LENGTH];
        signature_bytes[ED25519_PUBLIC_KEY_LENGTH..].copy_from_slice(&hex_decode(
            "9472a69cd9a701a50d130ed52189e2455b23767db52cacb8716fb896ffeeac09",
        ));
        let signature = Signature::from_bytes(&signature_bytes);

        let message = b"ed25519vectors 3";
        assert!(
            public.verify(message, &signature).is_ok(),
            "non-strict verify accepts the small-order-R vector"
        );
        assert!(
            public.verify_strict(message, &signature).is_err(),
            "verify_strict must reject the small-order R"
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
