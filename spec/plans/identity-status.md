# Identity status (revocation) plan and record

Scope: implement the signed **status-document** slice of the identity key
lifecycle in [../identity-keys.md](../identity-keys.md) §6 and
[../decisions/0010-identity-key-lifecycle.md](../decisions/0010-identity-key-lifecycle.md)
in JavaScript and Rust, with shared vectors. A status document is a signed,
monotonic-serial list of revoked keys for an entity. This covers *single-document
verification* (structure, binding to a trusted key document, and a root
signature) and the two lifecycle rules the design requires: *serial rollback*
rejection and *staleness* rejection. It reuses the implemented key-id codec
(`tools/derive-keyid.mjs`, `crates/xeip-identity`) and the RFC 8785 + Ed25519
signing primitives of the signed-envelope / key-document slices
(`tools/signed-envelope.mjs`); it adds no hand-written primitive and no
dependency (`ed25519-dalek 2.2.0` and `sha2 0.10.9` already present). Status
distribution/anchoring, live-stream effects, device-rotation statements and
durable fork evidence remain deferred (see below).

## Fixed document format (`xeip.status/0.1`)

```json
{
  "xeip": "xeip.status/0.1",
  "entity": "urn:xeip:entity:<genesis-kid>",
  "serial": 12,
  "issuedAt": "2026-10-10T00:00:00Z",
  "revoked": [
    { "kid": "<kid>", "generation": 1 }
  ],
  "signatures": [
    { "kid": "<root-kid>", "sig": "<unpadded base64url 64-byte sig>" }
  ]
}
```

- `xeip` is exactly `xeip.status/0.1`.
- `entity` is the entity URI whose key-id is derived from the **genesis** key; it
  must equal the trusted key document's `entity`.
- `serial` is an integer `>= 0`.
- `issuedAt` is an RFC 3339 instant in UTC (`...Z`, optional fractional second);
  offsets are rejected, matching key documents.
- `revoked` lists `{ kid, generation }` entries. `kid` is a canonical key-id;
  `generation` is an integer `>= 1` naming the key-document generation the key
  belongs to. A revoked entry applies to its recorded generation **and every
  later one** (see `isRevoked`).
- `signatures` is the only member excluded from the signing input.

This carrier intentionally differs from the illustrative draft in
[../identity-keys.md](../identity-keys.md) §9 (which keeps `profile`/`type`/
`generation`/`expiresAt`/`nextUpdate`/`reasonCode`): the slice fixes a concrete,
minimal frame with an explicit `xeip` version, a top-level monotonic `serial`,
key-id+generation revocation entries and no reason codes or document expiry.
Staleness is a caller-supplied maximum age rather than a document field, so no
new validity-window parsing is introduced. A later revision can widen it under a
new `xeip` value.

## Signing input

`UTF-8(RFC8785(document_without_signatures))`, Ed25519 (RFC 8032). Removing
`signatures` and canonicalizing is identical to the key-document and
signed-envelope slices; `entity`, `serial`, `issuedAt` and every `revoked` entry
are covered. Signing is deterministic from a 32-byte RFC 8032 seed, so the
committed vectors reproduce byte for byte.

## Single-document verification

`verifyStatusDocument` (JS `tools/identity-status.mjs`, Rust
`crates/xeip-identity`) takes the document and a trusted (already verified) key
document for the entity, and returns `{ valid: true }` / `{ valid: false, reason
}` (Rust `Ok(())` / `Err(StatusError)` whose `Display` is the reason):

| Step | Rejection reason |
| --- | --- |
| Strict parse (text entry point): duplicate members, lone surrogates, non-finite/unsafe integers | `malformed document` |
| Document is not an object | `malformed document` |
| Member outside the fixed field set | `unknown field` |
| `xeip` present but not exactly `xeip.status/0.1` | `unsupported version` |
| `xeip` missing/non-string, bad field types, `serial` not an integer `>= 0`, `issuedAt` not UTC, revoked `kid` not a canonical key-id, revoked `generation` not an integer `>= 1`, `sig` not canonical 64-byte base64url | `malformed document` |
| `entity != trusted.entity` | `entity binding` |
| Any signature `kid` is a small-order/weak Ed25519 point | `weak key` |
| No signature at all, or none by a key listed in `trusted.roots` | `unknown signer` |
| A listed root signed but the canonical bytes do not verify | `signature mismatch` |

"At least one valid signature by a current root key listed in the trusted key
document" is the whole acceptance rule. The trusted key document is supplied out
of band and is assumed verified; the status document never re-derives the
`kid` → entity mapping. Weak signers are rejected before any curve backend can
diverge (`verify_strict` in Rust, the pinned small-order blacklist in both), and
extra non-root signatures are ignored, so an unsigned or only-device-signed
document fails closed.

## Lifecycle: rollback and staleness

`StatusTracker` (JS `tools/identity-status.mjs`, Rust `crates/xeip-identity`)
keeps, per `entity`, the highest serial and the full accepted status. `ingest`
first runs the whole single-document rule set above and only then applies:

| Case | Condition | Rejection reason |
| --- | --- | --- |
| Rollback | `serial <=` the highest serial accepted for the entity | `serial rollback` |
| Stale | `now - issuedAt > maxAgeSeconds` (when a maximum age is supplied) | `stale status` |

Rollback is checked before staleness and state is committed only when every
check passes, so a rejected candidate never advances the serial or replaces the
accepted status. Re-ingesting an already-accepted serial is `serial rollback`
(the monotonic rule), and a *distinct* document at an equal serial is also
`serial rollback`, so an old "clean" status cannot be replayed. When the caller
does not supply a maximum age, staleness is not enforced (the profile leaves the
value to the deployment, §9).

`isRevoked(entity, kid, generation)` reports whether the accepted status for
`entity` revokes `kid` for key-document generation `generation`. An entry
`{ kid, generation: G }` applies to generation `G` **and later**, so a
rotated-but-republished key stays revoked. A missing accepted status is reported
as not revoked; callers MUST treat *no fresh status* as **unknown**, never as
proof that a key is live (`spec/identity-keys.md` §9). `acceptedSerial` and
`hasStatus` let a caller distinguish "unknown" from "clean".

## Cross-language vectors

`conformance/fixtures/identity-status/status.vectors.json` is generated
deterministically from the fixed seed
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
(root A, public key `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`) plus
the successor-root and device seeds already used by the key-document vectors. The
file carries a `trusted` registry (a verified `xeip.keydoc/0.1` genesis document
with root A and device C), a `statuses` registry of signed status documents, and
a list of `trackers`, each with its own `now`/`maxAgeSeconds` and ordered
`steps`:

- `status.valid` — a fresh, root-signed status is accepted and revokes the
  device key (with `isRevoked` assertions, including the "generation and later"
  rule and a non-revoked key);
- `status.rollback` — a replayed equal serial and a lower serial are `serial
  rollback`, while a genuinely newer serial is accepted;
- `status.serial-zero` — serial `0` is a valid cold start and repeats roll back;
- `status.unknown-signer` — a device-signed status and an empty `signatures`
  array are `unknown signer`;
- `status.weak-signer` — a small-order signer is `weak key`;
- `status.tampered` — a tampered signature is `signature mismatch`;
- `status.stale` — an `issuedAt` older than the supplied maximum age is `stale
  status`;
- `status.entity-binding`, `status.unknown-field`, `status.unsupported-version`
  and `status.malformed` (bad `serial`, bad `issuedAt`, bad `generation`, and a
  strict-parse `text` case) cover the reused single-document reasons.

`tools/validate-fixtures.mjs` consumes the vectors with the JS tracker, and
`crates/xeip-identity/tests/status_vectors.rs` consumes the same file through the
Rust `StatusTracker`. Both `tools/identity-status.test.mjs` and the Rust test
re-sign the positive `status.revoke.1` document from the reference seed and
require byte-identical signatures, proving identical signing input across
languages.

## Deferred (explicitly out of scope)

- **Status distribution and anchoring**: how a verifier fetches an
  authenticated, fresh status for an entity without a central authority, and how
  a status is bound to a chain/anchor (`spec/identity-keys.md` §9.1, §17).
- **Live-stream effects**: relay-enforced termination of authenticated streams on
  a learned revocation, and the hosted end-to-end "takes effect on next check"
  limitation (`spec/identity-keys.md` §9.2).
- **Device rotation**: `xeip.device-rotation` statements and bounded overlap
  (`spec/identity-keys.md` §6, §5.3).
- **Document-level validity**: `generation`, `expiresAt`/`nextUpdate` and
  `reasonCode` fields of the wider draft; staleness here is a caller-supplied
  maximum age, not a signed `nextUpdate`.
- **Durable fork/equivocation evidence** and short-lived credentials/recovery.
- **Envelope `kid` → status resolution** and the composition rule of
  `spec/identity-keys.md` §8.

## Verification (all passing)

- `node --test tools/identity-status.test.mjs` — 10 tests.
- `npm run validate:fixtures` — status vectors included (20 status steps).
- `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --all-targets --locked` — 4 `status_vectors` tests.
- `npm run check:js`.
