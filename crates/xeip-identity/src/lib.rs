//! XEIP identity encoding, signed documents and envelope verification.
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
//!
//! Key documents support anchored trust, chain continuity and root rotation.
//! Status and device-rotation trackers enforce their respective lifecycle rules.
//! The experimental entity-bound envelope profile verifies provisioned trust
//! and fresh status without falling back to the legacy envelope profile.

mod canonical;
mod crypto;
mod encoding;
mod entity_envelope;
mod envelope;
mod key_document;
mod key_id;
mod rotation;
mod status;
mod time;

pub use canonical::{canonicalize_json, strict_parse, StrictParseError, MAX_SAFE_INTEGER};
pub use crypto::{
    is_weak_ed25519_public_key, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH,
    ED25519_SMALL_ORDER_POINTS,
};
pub use entity_envelope::{
    entity_envelope_signing_input, sign_entity_envelope, verify_entity_envelope,
    verify_entity_envelope_text, EntityEnvelopeError, EntityTrustOptions, ENTITY_SIGNATURE_DOMAIN,
    ENTITY_SIGNATURE_PROFILE,
};
pub use envelope::{
    sign_envelope, verify_signed_envelope, verify_signed_envelope_text, SignedEnvelopeError,
    SIG_ALG, SIG_EXTENSION, SIG_VERSION,
};
pub use key_document::{
    key_document_chain_digest, sign_key_document, verify_key_document, verify_key_document_text,
    KeyDocumentChain, KeyDocumentError, KeyDocumentTrust, TrustAnchor, TrustLevel, KEYDOC_VERSION,
};
pub use key_id::{
    decode_key_id, device_urn, encode_key_id, entity_urn, KeyIdError, ED25519_MULTICODEC,
    ED25519_PUBLIC_KEY_LENGTH, MULTIBASE_BASE58BTC,
};
pub use rotation::{
    sign_device_rotation, verify_device_rotation, verify_device_rotation_text, DeviceRotationError,
    DeviceRotationTracker, ROTATION_VERSION,
};
pub use status::{
    sign_status_document, verify_status_document, verify_status_document_text, StatusError,
    StatusTracker, STATUS_VERSION,
};

#[cfg(test)]
mod tests;
