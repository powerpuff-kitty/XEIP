# Identity key document plan and record

Scope: implement the **first testable slice** of the identity key-lifecycle
design in [../identity-keys.md](../identity-keys.md) and
[ADR 0010](../decisions/0010-identity-key-lifecycle.md): a *signed key document*
and *single-document verification* in JavaScript and Rust, with shared vectors.
This is a deliberately narrow slice. Chain verification, rollback rejection,
trust-store resolution, revocation/status, device rotation statements and
bounded overlap are **not** implemented here and remain deferred. It reuses the
implemented key-ID codec (`tools/derive-keyid.mjs`, `crates/xeip-identity`) and
the RFC 8785 + Ed25519 signing primitives of the signed-envelope slice; it adds
no dependency and no hand-written primitive.

## Fixed document format (`xeip.keydoc/0.1`)

```json
{
  "xeip": "xeip.keydoc/0.1",
  "entity": "urn:xeip:entity:<genesis-kid>",
  "genesis": "<genesis-kid>",
  "generation": 1,
  "issuedAt": "2026-10-10T00:00:00Z",
  "previous": "<sha256-hex of previous canonical doc>",
  "roots": ["<kid>", "..."],
  "devices": ["<kid>", "..."],
  "signatures": [{ "kid": "<root-kid>", "sig": "<unpadded base64url 64-byte sig>" }]
}
```

- `xeip` is exactly `xeip.keydoc/0.1`.
- `entity` is the entity URI whose key-id is derived from the **genesis** key;
  it stays constant across rotation.
- `genesis` is the genesis key-id.
- `generation` is an integer `>= 1`.
- `issuedAt` is an RFC 3339 instant in UTC (`...Z`, optional fractional second);
  offsets are rejected.
- `previous` is optional. When present it is 64 lowercase hex characters (the
  SHA-256 digest of the previous document's canonical signing input, produced by
  the JS `keyDocumentDigest` helper when generating a vector). It is **recorded,
  never chased** in this slice, and no chain digest is recomputed during
  verification.
- `roots` and `devices` are arrays of canonical key-ids.
- `signatures` is the only member excluded from the signing input.

This carrier intentionally differs from the illustrative draft in
[../identity-keys.md](../identity-keys.md) §3 (which uses `profile`/`type`/
`root`/`generation: 0`): the slice fixes a concrete, minimal frame with an
explicit `xeip` version, key-id lists and no validity bounds, so the first
implementation step is unambiguous. A later revision can widen it under a new
`xeip` value.

## Signing input

`UTF-8(RFC8785(document_without_signatures))`, Ed25519 (RFC 8032). Removing
`signatures` and canonicalizing is identical to the signed-envelope slice;
`previous` (when present) and every other member are covered.

## Single-document verification

The JavaScript reference `tools/key-document.mjs` and the Rust twin in
`crates/xeip-identity/src/lib.rs` run the same ordered checks and return the same
stable reasons (JS `{ valid: true }` / `{ valid: false, reason }`; Rust
`Ok(())` / `Err(KeyDocumentError)` whose `Display` is the reason):

| Step | Rejection reason |
| --- | --- |
| Strict parse (text entry point): duplicate members, lone surrogates, non-finite/unsafe integers | `malformed document` |
| Document is not an object | `malformed document` |
| Member outside the fixed field set | `unknown field` |
| `xeip` present but not exactly `xeip.keydoc/0.1` | `unsupported version` |
| `xeip` missing/non-string, bad field types, `generation` not an integer `>= 1`, `issuedAt` not UTC, `previous` not SHA-256 hex | `malformed document` |
| Genesis key-id does not decode, or any root/device/signature kid does not decode, or `sig` is not canonical 64-byte base64url | `malformed document` |
| `entity != entityUrn(genesis)` | `entity binding` |
| Any kid (genesis, root, device or signer) is a small-order/weak Ed25519 point | `weak key` |
| No signature at all, or none by a key listed in `roots` | `unknown signer` |
| A listed root signed but the canonical bytes do not verify | `signature mismatch` |

"At least one valid signature by a key listed in `roots`" is the whole
acceptance rule. Weak keys are rejected before any curve backend can diverge;
extra non-root signatures are ignored (acceptance still requires a valid root
signature), so an unsigned or only-device-signed document fails closed. The
parser builds objects with a null prototype / checked duplicate detection, and
Ed25519 verification uses `verify_strict`, matching the signed-envelope slice.

## Cross-language vectors

`conformance/fixtures/identity-keydoc/keydoc.vectors.json` is generated
deterministically from the fixed seed
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
(public key `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`)
plus two further fixed seeds for a successor root and a device. Each entry is
`{ name, valid, reason?, document? , text? }`:

- positive: `genesis.valid` (self-certifying single-root document) and
  `rotation.dual-signed` (generation 2, both roots sign, `previous` set);
- negative: `doc.bad-signature`, `doc.entity-mismatch`, `doc.weak-signer`,
  `doc.unsupported-version`, `doc.unknown-field`, `doc.invalid-base64url`,
  `doc.unknown-signer`, `doc.missing-signature` and a strict-parse
  `doc.malformed-text`.

`tools/validate-fixtures.mjs` consumes the vectors with the JS verifier, and
`crates/xeip-identity/tests/keydoc_vectors.rs` consumes the same file through
the Rust strict-parse entry point. Both the JS test and the Rust test re-sign
the positive documents from the reference seeds and require byte-identical
signatures, proving identical signing input across languages.

## Deferred (explicitly out of scope)

- Chain verification: `previous` digest matching, `generation == prev + 1`,
  per-entity rollback rejection, fork/equivocation detection.
- Trust roots: pinned anchor, bounded TOFU, inline bootstrap, `max_generation`,
  pinned digests; resolving a `kid` to a trusted document.
- Rotation semantics: retiring/successor signature rules, pre-endorsed
  successors, bounded `overlapUntil`, post-overlap rejection.
- Revocation/status documents, serial rollback, staleness, live-stream effects.
- Device rotation statements and device validity windows (`notBefore`/
  `notAfter`); endorsed devices are validated structurally only.
- Short-lived credentials and recovery.

## Verification (all passing)

- `node --test tools/key-document.test.mjs` — 11 tests.
- `npm run validate:fixtures` — key-document vectors included.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --all-targets --locked`.
- `npm run check:js`.
