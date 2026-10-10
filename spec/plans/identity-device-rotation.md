# Identity device rotation plan and record

Scope: implement the signed **device-rotation** statement slice of the identity
key lifecycle in [../identity-keys.md](../identity-keys.md) §5.3 and §6 and
[../decisions/0010-identity-key-lifecycle.md](../decisions/0010-identity-key-lifecycle.md)
in JavaScript and Rust, with shared vectors. A device-rotation statement is a
root-endorsed claim that one device key is replaced by a successor, with a
bounded overlap during which the predecessor may still authenticate. This covers
*single-document verification* (structure, binding to a trusted key document and
a root signature) and the lifecycle rules the design requires: *bounded overlap*,
*rotation conflict* rejection and *predecessor expiry*. It reuses the
implemented key-id codec (`tools/derive-keyid.mjs`, `crates/xeip-identity`) and
the RFC 8785 + Ed25519 signing primitives of the signed-envelope / key-document
/ status slices (`tools/signed-envelope.mjs`); it adds no hand-written primitive
and no dependency. Root-rotation rules, post-overlap enforcement distribution
and directory discovery remain deferred (see below).

## Fixed statement format (`xeip.device-rotation/0.1`)

```json
{
  "xeip": "xeip.device-rotation/0.1",
  "entity": "urn:xeip:entity:<genesis-kid>",
  "previous_kid": "<kid>",
  "successor_kid": "<kid>",
  "issuedAt": "2026-10-10T00:00:00Z",
  "overlapUntil": "2026-11-09T00:00:00Z",
  "signatures": [
    { "kid": "<root-kid>", "sig": "<unpadded base64url 64-byte sig>" }
  ]
}
```

- `xeip` is exactly `xeip.device-rotation/0.1`.
- `entity` is the entity URI whose key-id is derived from the **genesis** key; it
  must equal the trusted key document's `entity`.
- `previous_kid` is the canonical key-id being replaced; `successor_kid` is the
  canonical key-id that replaces it. They must differ; both must decode and be
  non-weak.
- `issuedAt` is an RFC 3339 instant in UTC (`...Z`, optional fractional second);
  offsets are rejected, matching key documents.
- `overlapUntil` is optional. When present it is a UTC instant strictly greater
  than `issuedAt`: the end of the window in which the predecessor may still
  authenticate. When absent the overlap is zero (the predecessor is replaced
  immediately).
- `signatures` is the only member excluded from the signing input. At least one
  signature by a **current root** listed in the trusted key document is required.

This carrier intentionally differs from the illustrative draft in
[../identity-keys.md](../identity-keys.md) §6 (which uses
`profile`/`type`/`old`/`new`/`notAfter` and requires both the old device key and
the root to sign): the slice fixes a concrete, minimal frame with an explicit
`xeip` version and named `previous_kid`/`successor_kid` members, and accepts the
statement on a current root signature alone. A later revision can widen it under
a new `xeip` value. (The draft's dual old+root signature is a stricter
composition that a future revision could require without changing the wire
fields.)

## Signing input

`UTF-8(RFC8785(statement_without_signatures))`, Ed25519 (RFC 8032). Removing
`signatures` and canonicalizing is identical to the key-document and status
slices; `entity`, `previous_kid`, `successor_kid`, `issuedAt` and `overlapUntil`
are covered. Signing is deterministic from a 32-byte RFC 8032 seed, so the
committed vectors reproduce byte for byte.

## Single-document verification

`verifyDeviceRotation` (JS `tools/identity-device-rotation.mjs`, Rust
`crates/xeip-identity`) takes the statement and a trusted (already verified) key
document for the entity, and returns `{ valid: true }` / `{ valid: false, reason
}` (Rust `Ok(())` / `Err(DeviceRotationError)` whose `Display` is the reason):

| Step | Rejection reason |
| --- | --- |
| Strict parse (text entry point): duplicate members, lone surrogates, non-finite/unsafe integers | `malformed document` |
| Statement is not an object | `malformed document` |
| Member outside the fixed field set | `unknown field` |
| `xeip` present but not exactly `xeip.device-rotation/0.1` | `unsupported version` |
| `xeip` missing/non-string, bad field types, `previous_kid`/`successor_kid` not a canonical key-id, `previous_kid == successor_kid`, `issuedAt`/`overlapUntil` not UTC, `overlapUntil <= issuedAt`, `sig` not canonical 64-byte base64url | `malformed document` |
| `entity != trusted.entity` | `entity binding` |
| Any device or signer `kid` is a small-order/weak Ed25519 point | `weak key` |
| No signature at all, or none by a key listed in `trusted.roots` | `unknown signer` |
| A listed root signed but the canonical bytes do not verify | `signature mismatch` |

"At least one valid signature by a current root key listed in the trusted key
document" is the whole acceptance rule. The trusted key document is supplied out
of band and is assumed verified; the statement never re-derives the `kid` →
entity mapping. Weak keys are rejected before any curve backend can diverge
(`verify_strict` in Rust, the pinned small-order blacklist in both), and extra
non-root signatures are ignored, so an unsigned or only-device-signed statement
fails closed.

## Lifecycle: bounded overlap, rotation conflict, predecessor expiry

`DeviceRotationTracker` (JS `tools/identity-device-rotation.mjs`, Rust
`crates/xeip-identity`) keeps, per `entity`, the predecessors it has retired
(mapped to the end of their overlap window) and the current successor. `ingest`
first runs the whole single-document rule set above and only then applies:

| Case | Condition | Rejection reason |
| --- | --- | --- |
| Rotation conflict | `previous_kid` was already a predecessor (a second rotation of the same predecessor) | `rotation conflict` |
| Rotation conflict | `successor_kid` is already retired (was itself a predecessor) | `rotation conflict` |
| Overlap too long | `overlapUntil - issuedAt > maxOverlapSeconds` (when a maximum is supplied) | `overlap too long` |

Conflict is checked before the overlap bound and state is committed only when
every check passes, so a rejected candidate never advances the accepted
rotations (a rejected `successor` is still `unknown device`). When the caller does
not supply a maximum overlap, no bound is enforced (the profile leaves the value
to the deployment, §5.3).

`isActive(entity, kid, now)` reports whether `kid` may authenticate for `entity`
at `now`:

- the **current successor** is active immediately after the rotation is accepted;
- a **predecessor** is active through `overlapUntil` (inclusive) and is then
  rejected with `expired predecessor`; when `overlapUntil` is absent the
  predecessor is treated as expiring at `issuedAt` (zero overlap);
- any other `kid`, or an entity with no accepted rotation, is `unknown device`.

Callers MUST treat `unknown device` as "not endorsed", never as proof that a key
is live (`spec/identity-keys.md` §6).

## Cross-language vectors

`conformance/fixtures/identity-rotation/rotation.vectors.json` is generated
deterministically from the fixed seed
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
(root A, public key `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`)
plus the device seeds already used by the key-document and status vectors. The
file carries a `trusted` registry (a verified `xeip.keydoc/0.1` genesis document
with root A), a `rotations` registry of signed statements, and a list of
`trackers`, each with its own `maxOverlapSeconds` and ordered `steps` that are
either `{ kind: "ingest", rotation|text, valid, reason? }` or
`{ kind: "active", kid, now, active, reason? }`:

- `rotation.valid` — a root-signed rotation is accepted; the successor is active
  immediately, the predecessor is active through `overlapUntil` (inclusive), is
  `expired predecessor` one second later and an unrelated key is `unknown
  device`;
- `rotation.conflict` — a second rotation of the same predecessor and a rotation
  whose successor is already retired are both `rotation conflict`;
- `rotation.chain` — a valid successor-to-next-successor rotation keeps each
  retired predecessor active only through its own overlap;
- `rotation.nonroot` — a device-signed statement is `unknown signer`;
- `rotation.weak-successor` — a small-order successor is `weak key`;
- `rotation.tampered` — a tampered signature is `signature mismatch`;
- `rotation.overlap-too-long` — an overlap above the supplied maximum is
  `overlap too long`;
- `rotation.entity-binding`, `rotation.unknown-field`,
  `rotation.unsupported-version` and `rotation.malformed` (bad `issuedAt`, bad
  `previous_kid`, equal device kids, and a strict-parse `text` case) cover the
  reused single-document reasons.

`tools/validate-fixtures.mjs` consumes the vectors with the JS tracker, and
`crates/xeip-identity/tests/rotation_vectors.rs` consumes the same file through
the Rust `DeviceRotationTracker`. Both `tools/identity-device-rotation.test.mjs`
and the Rust test re-sign the positive `rotation.valid` statement from the
reference seed and require byte-identical signatures, proving identical signing
input across languages.

## Deferred (explicitly out of scope)

- **Root rotation rules**: the retiring/successor root signature rules of
  `spec/identity-keys.md` §5.2, pre-endorsed successors, root-generation
  rotation and root-key recovery. This slice is device-only; it accepts a
  statement on a current root signature alone.
- **Post-overlap enforcement distribution**: how every verifier learns the
  accepted rotation and enforces `expired predecessor` once the window closes,
  without a central authority, and how the bounded overlap interacts with status
  documents and live-stream termination (`spec/identity-keys.md` §5.3, §9.2).
- **Directory discovery**: how a verifier fetches the trusted key document and
  the current rotation without an out-of-band anchor (`spec/identity-keys.md`
  §7.3).
- **The wider draft carrier**: the `profile`/`type`/`old`/`new`/`notAfter`
  fields and the dual old+root signature of `spec/identity-keys.md` §6.
- **Durable rotation history**: retaining beyond the predecessors needed for the
  current overlap, and equivocation evidence across restarts.
- **Envelope `kid` → device-activity composition**: wiring `isActive` into the
  §8 envelope-binding rule.

## Verification (all passing)

- `node --test tools/identity-device-rotation.test.mjs` — 10 tests.
- `npm run validate:fixtures` — rotation vectors included (26 rotation steps).
- `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --all-targets --locked` — 4 `rotation_vectors` tests.
- `npm run check:js`.
