# Identity key document plan and record

Scope: implement the signed **key-document** slice of the identity key-lifecycle
design in [../identity-keys.md](../identity-keys.md) and
[ADR 0010](../decisions/0010-identity-key-lifecycle.md) in JavaScript and Rust,
with shared vectors. This covers *single-document verification*, *per-entity
chain verification* (genesis anchoring, `generation`/`previous` linking, rollback
rejection, fork/equivocation detection, gap detection and the §5.2
root-rotation retiry/successor signature rule) and *trust-store anchor
resolution* (a pinned genesis anchor plus bounded, opt-in TOFU). Revocation/status
documents, bounded `overlapUntil`, directory discovery and durable fork evidence
are still deferred (see below). It reuses the implemented key-ID codec
(`tools/derive-keyid.mjs`, `crates/xeip-identity`) and the RFC 8785 + Ed25519
signing primitives of the signed-envelope slice; it adds no hand-written
primitive. (`sha2 0.10.9`, already a transitive dependency of the pinned
`ed25519-dalek` and the version named by ADR 0007, is now a direct dependency of
`crates/xeip-identity` for the chain digest; no new crate version enters the
lockfile.)

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
- `previous` is optional. When present it is 64 lowercase hex characters: the
  lowercase hex SHA-256 of the RFC 8785 canonical form of the predecessor key
  document **including** its `signatures` member (`keyDocumentChainDigest` in JS,
  `key_document_chain_digest` in Rust). A chain therefore commits to the *signed*
  predecessor, not merely to its signing input. It is absent on the genesis
  (`generation == 1`) document and required on every later generation.
  (The single-document `rotation.dual-signed` vector carries the older
  signing-input digest of its predecessor; it is only ever verified as a
  standalone document, never chased, so it is unaffected.)
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

## Chain verification

`KeyDocumentChain` (JS `tools/key-document.mjs`, Rust
`crates/xeip-identity`) keeps, per `entity`, the highest key document it has
accepted (its `generation` and its full-document digest). `ingest` first runs the
whole single-document rule set above and only then applies the chain rules, so a
structural or signature failure is always reported with its single-document
reason before any chain reason. It never throws and returns `{ valid: true }` /
`{ valid: false, reason }` (Rust `Ok(())` / `Err(KeyDocumentError)`):

| Case | Condition | Rejection reason |
| --- | --- | --- |
| Genesis | no accepted document for the entity and `generation == 1`, no `previous` | *accepted* |
| No genesis | no accepted document and (`generation != 1` or `previous` present) | `chain gap` |
| Successor | `generation == prev.generation + 1` and `previous == digest(prev)` | *accepted* |
| Root rotation | successor passes generation/digest but carries no valid signature by any key in `prev.roots` | `root rotation not dual-signed` |
| Rollback | `generation <` the accepted generation | `rollback` |
| Rollback | `generation ==` the accepted generation and the same digest | `rollback` |
| Fork | `generation ==` the accepted generation and a different digest | `fork` |
| Gap | `generation > prev.generation + 1` | `chain gap` |
| Gap | `generation == prev.generation + 1` but `previous != digest(prev)` | `chain gap` |

The digest compared against `previous` is the **full signed predecessor**
including `signatures` (see `previous` above). Re-ingesting the exact accepted
document is `rollback` (it is not newer); a caller that needs at-least-once
delivery treats `rollback` as "already known". Fork detection is only as strong
as what a verifier has already accepted for that `entity`: it rejects a distinct
document at the accepted generation, not a fork the verifier has never seen.
`KeyDocumentChain` stays anchor-less — the caller decides which genesis to start
from — while trust-store anchor resolution is layered on top by
`KeyDocumentTrust` below; a durable conflict store remains out of scope.

## Root-rotation signature rules (`spec/identity-keys.md` §5.2)

A genesis document is self-certifying and its single-root signature rule is
unchanged. For a successor `D` at generation `g`, accepted against the
predecessor `P` at generation `g - 1`, the chain derives the required signer set
from `P`, never from `D`:

- Let `oldRoots = P.roots` and `newRoots = D.roots`.
- **Retiry authorization.** `D` MUST carry a valid signature by at least one key
  in `oldRoots`. This is the requirement the chain adds; it is re-verified over
  the exact canonical signing input rather than inferred from the
  single-document result (which only records that *some* current root signed).
  A successor with no old-root signature is rejected as
  `root rotation not dual-signed`.
- **Successor authorization.** `D` MUST carry a valid signature by at least one
  key in `newRoots`. This is already enforced by single-document verification
  ("at least one valid signature by a key listed in `roots`") and is therefore
  not duplicated as a separate chain reason.
- **Pre-endorsed successor.** When the successor root was already listed in
  `oldRoots` (for example `P.roots = [A, B]` → `D.roots = [B]`), its own
  signature is simultaneously a retiry signature and a successor signature, so
  a retiry-only document is accepted. No extra successor signature is required.

The generation+1, digest-linkage, rollback, fork and gap rules run first and are
unchanged, so a rollback/fork/gap candidate reports its existing reason and only
a structurally valid successor can reach the new `root rotation not dual-signed`
rejection. `KeyDocumentChain` keeps the accepted document's `roots` so the next
successor's retiry check can be evaluated; `clone()` copies that state.

This slice implements the signature rule only. Bounded `overlapUntil`,
post-overlap rejection, `issuedAt` monotonicity and durable fork evidence remain
deferred.

## Trust-store anchor resolution

`KeyDocumentChain` links generations but has no notion of *which* genesis to
start from. `KeyDocumentTrust` (JS `tools/key-document.mjs`, Rust
`crates/xeip-identity`) adds that out-of-band anchor: it wraps a chain and, for a
single configured `entity`, accepts a document only when it passes
single-document verification and the chain rules **and** is reached from the
configured anchor. The anchor is `{ genesisKid?, genesisDigest? }` — a pinned
genesis key-id and/or the genesis document's chain digest — plus an optional
`maxGeneration`.

It implements §7.1 (pinned anchor) and §7.2 (bounded TOFU) of
`spec/identity-keys.md` and fails closed (§7.4). `ingest` returns
`{ valid: true, trust: "pinned" | "tofu" }` / `{ valid: false, reason }` (Rust
`Ok(TrustLevel)` / `Err(KeyDocumentError)`).

| Anchor state | Document | Result / reason |
| --- | --- | --- |
| No anchor, TOFU off (default) | anything that passes the chain | `no anchor` |
| Pinned anchor | `entity`, `genesis` key-id or genesis digest mismatch | `untrusted anchor` |
| Any | `generation > maxGeneration` (when configured) | `generation exceeds maximum` |
| Pinned or recorded anchor | chain reached from the anchor | *accepted* (`pinned` / `tofu`) |

Ordering composes the existing checks unchanged: single-document verification,
then the chain rules, then the anchor. The chain rules are run on a private
`clone()` of the accepted chain state, so a document rejected by the anchor is
**never recorded** — a subsequent correctly anchored genesis still starts the
chain cleanly rather than colliding as a `fork`.

**Bounded TOFU (opt-in, not verified).** With `tofu: true` and no pinned anchor,
the first genesis accepted for the entity records
`(entity, genesis-kid, genesis-digest)` as the effective anchor; every later
document must chain from it (a different genesis is `untrusted anchor`) and is
bounded by the same `maxGeneration`. A `tofu` result is **not verified identity**:
callers MUST present it as unverified and MUST NOT conflate it with a `pinned`
anchor (`spec/identity-keys.md` §7.2, [../identity.md](../identity.md) §3). TOFU
is never the default.

This makes the previously anchor-less chain usable as a trust store: the genesis
key-id pins the entity, the digest pins the exact genesis document (defeating a
tampered-but-self-certifying genesis), and `maxGeneration` bounds how far a chain
may advance.

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

Chain vectors live beside them in
`conformance/fixtures/identity-keydoc/keydoc-chain.vectors.json`, generated
deterministically from the same seed plus the successor/device seeds. The file
has a shared `documents` registry and a list of `chains`, each an ordered list of
`{ name, document, valid, reason? }` steps consumed by both
`tools/key-document.test.mjs` and `crates/xeip-identity/tests/keydoc_vectors.rs`:

- `chain.valid` — genesis (generation 1) → rotation (generation 2, dual-signed)
  → rotation (generation 3);
- `chain.rollback` — re-ingesting an older or already-accepted generation;
- `chain.fork` — a distinct, single-document-valid generation-2 document, after
  which the accepted branch continues (generation 3 still verifies);
- `chain.gap-jump` / `chain.gap-previous` — a generation jump and an exact
  successor whose `previous` does not match the accepted digest;
- `chain.no-genesis` — a non-genesis first document;
- `chain.single-document-failure` — an invalid signature, proving the
  single-document check runs first.

Trust vectors live in
`conformance/fixtures/identity-keydoc/keydoc-trust.vectors.json`, generated
deterministically from the same pinned seed and genesis. The file reuses the same
`documents` registry and adds a list of `trusts`, each a `{ name, entity,
anchor, maxGeneration?, tofu?, steps }` case whose steps are
`{ name, document, valid, reason?, trust? }` and are consumed by both
`tools/key-document.test.mjs` and `crates/xeip-identity/tests/keydoc_vectors.rs`:

- `trust.pinned-chain` — a pinned `{ genesisKid, genesisDigest }` with
  `maxGeneration: 3` accepts generations 1–3 (`trust: "pinned"`);
- `trust.wrong-genesis-key-id` and `trust.wrong-genesis-digest` — a pinned
  genesis key-id or digest that does not match the presented genesis is
  `untrusted anchor`;
- `trust.no-anchor` — no anchor configured (the default) is `no anchor` for an
  otherwise valid chain;
- `trust.generation-exceeds-max` — a chain that reaches generation 3 with
  `maxGeneration: 2` is `generation exceeds maximum`;
- `trust.tofu-bounded` — opt-in TOFU records the first-seen genesis
  (`trust: "tofu"`) and is bounded by `maxGeneration`.

Both tests also assert that an anchor-rejected genesis leaves the committed
chain untouched (JS `KeyDocumentChain.clone`; Rust `#[derive(Clone)]`), and that
single-document and chain reasons are reported before trust reasons.

Root-rotation vectors live in
`conformance/fixtures/identity-keydoc/keydoc-root-rotation.vectors.json`,
generated deterministically from the same pinned seed plus the successor/device
seeds and carrying the same `documents` registry and ordered `chains` shape as
the chain file. Both `tools/key-document.test.mjs` and
`crates/xeip-identity/tests/keydoc_vectors.rs` consume it and re-sign the
dual-signed rotation from the reference seeds to prove byte-identical signing
input:

- `root-rotation.dual-signed` — `genesis.gen1` (roots `[A]`) → a generation-2
  document with roots `[B]` signed by both the retiring `A` and the successor
  `B`; accepted;
- `root-rotation.successor-preendorsed` — a genesis with roots `[A, B]` → a
  generation-2 document with roots `[B]` signed only by the pre-endorsed `B`;
  accepted (retiry-only);
- `root-rotation.successor-only` — a generation-2 document with roots `[B]`
  signed only by `B`, with an old root `A` on the predecessor: rejected as
  `root rotation not dual-signed`;
- `root-rotation.no-old-root` — signed by the new root `B` and a non-root `C`,
  with no old-root signature: rejected as `root rotation not dual-signed`;
- `root-rotation.added-without-old-root` — the successor adds root `B` to
  `[A, B]` but only `B` signs (no old-root signature): rejected as
  `root rotation not dual-signed`.

The existing single-document `keydoc.vectors.json` is unchanged and still carries
its own positive and negative cases.

## Deferred (explicitly out of scope)

- Directory discovery and inline bootstrap: how a verifier learns a genesis or a
  current document without an out-of-band anchor (`spec/identity-keys.md` §7.3).
  The trust store here is configured out of band; discovery records stay
  self-asserted until this verification succeeds.
- Resolving an arbitrary envelope `kid` to a trusted document and binding it to
  an entity at generation time (`spec/identity-keys.md` §8); this slice verifies
  documents and their anchoring, not envelope `kid` → document resolution.
- Rotation semantics beyond the retired/successor signature rule: bounded
  `overlapUntil`, post-overlap rejection and `issuedAt` monotonicity.
- Revocation/status documents, serial rollback, staleness, live-stream effects.
- Device rotation statements and device validity windows (`notBefore`/
  `notAfter`); endorsed devices are validated structurally only.
- Durable, keyed fork evidence: a conflict store that remembers forks a verifier
  has seen (and attributes them to an entity/anchor), beyond rejecting a distinct
  document at the accepted generation. The anchor here detects a wrong genesis
  but does not persist equivocation across restarts.
- Short-lived credentials and recovery.

## Verification (all passing)

- `node --test tools/key-document.test.mjs` — 28 tests (11 single-document, 6
  chain, 3 root-rotation, 8 trust).
- `npm run validate:fixtures` — key-document vectors included.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --all-targets --locked` — 9 `keydoc_vectors` tests.
- `npm run check:js`.
