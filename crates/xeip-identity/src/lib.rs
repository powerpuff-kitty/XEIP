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
//! It is dependency-free and hand-writes base58btc (a base conversion, not a
//! cryptographic primitive) so that it matches `tools/derive-keyid.mjs`
//! byte-for-byte. It performs **no** signing, verification, key generation or
//! curve-point validation; those require the audited libraries selected in ADR
//! 0007 and are deliberately out of scope. As `spec/identity.md` §2 requires, a
//! caller that treats a recomputed key-id as authentic must still validate the
//! key as a canonical curve point before doing so.

use std::fmt;

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
}
