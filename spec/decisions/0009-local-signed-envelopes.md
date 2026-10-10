# ADR 0009: Local signed-envelope reference profile

Status: Accepted for local prototype (reference implementation and conformance
consumer in [`tools/signed-envelope.mjs`](../../tools/signed-envelope.mjs); not
wired into the relay). Date: 2026-10-10. This decision advances
[issue #1](https://github.com/powerpuff-kitty/XEIP/issues/1) by landing the
first **verification slice** of the identity profile: a detached Ed25519
signature over a canonicalized envelope, bound to `sender` through the key-id.
It is an opt-in, verifier-side prototype and does not approve production
identity, key distribution, revocation or relay enforcement.

## Context

[ADR 0004](0004-verifiable-identity.md) and
[identity.md](../identity.md) §4–§5 design verifiable entity identity and
principal-to-`sender` binding, but land no code: the envelope still carries a
self-asserted `sender`, and the only implemented authentication is the shared
token and the opt-in [local admission](../local-admission.md) bearer.
[ADR 0007](0007-crypto-dependencies.md) selects Ed25519, JCS and the strict
pre-parse gate, and explicitly permits deterministic serialization and strict
parsing as hand-written code alongside an audited cryptography library.

Two prerequisites already exist: the dependency-free key-ID codec
([`tools/derive-keyid.mjs`](../../tools/derive-keyid.mjs)) and its conformance
vectors. What was missing is the canonical-bytes-plus-signature step that turns
the self-asserted `sender` into a verifiable claim, so a recipient that does not
control a relay can bound a message to a key-derived principal.

The remaining identity work — trust roots, key documents, rotation, revocation
and recovery — is large and unsettled ([identity.md](../identity.md) §11). None
of it is required to specify and test a signature, so it is deliberately
deferred.

## Decision

Adopt the profile in [../local-signed-envelopes.md](../local-signed-envelopes.md).
In summary:

1. **Carrier.** `envelope.extensions["xeip.sig"] = { v: "0.1", alg: "EdDSA",
   kid, sig }`, where `kid` is the §2 key-id and `sig` is canonical, unpadded
   base64url of the 64-byte Ed25519 signature. `alg` MUST be `EdDSA`. Envelopes
   stay `"0.1"` and every existing schema is unchanged; the carrier lives in
   `extensions`, which the schemas already permit.
2. **Signing input.** The envelope object with the `extensions` property
   removed, canonicalized per RFC 8785 (JCS) and encoded as UTF-8, signed with
   Ed25519 (RFC 8032) through `node:crypto` with a `null` algorithm. No custom
   crypto and no new dependency.
3. **Strict pre-parse gate.** Before canonicalization, reject duplicate object
   member names, lone surrogate escapes, non-finite numbers and integers
   outside ±(2^53-1), with no Unicode normalization, per
   [ADR 0007](0007-crypto-dependencies.md). `verifySignedEnvelope` applies the
   gate to JSON text.
4. **Sender binding.** Require `entityUrn(kid) === envelope.sender`. The public
   key is always derived from `kid`; `sender` is only cross-checked.
5. **Structured result.** Verification returns `{ valid: true }` or
   `{ valid: false, reason }` with a stable reason, so every negative vector
   maps to a documented failure and verification never throws for a well-formed
   call.
6. **Conformance.** Commit deterministic vectors
   (`conformance/fixtures/identity-signed/signed.vectors.json`) and check them
   from `node --test tools/signed-envelope.test.mjs`, `npm run validate:fixtures`
   and the Rust `crates/xeip-identity` signed-vector test, so implementations
   prove byte-identical signing input and identical results.
7. **Scope.** State honestly what a signature does and does not prove: it
   proves integrity of the non-`extensions` fields and possession of the `kid`
   key, and nothing about authorization, trust, freshness, revocation or
   `extensions` (which are unsigned). No relay path consumes it.

## Alternatives

- **Implement signing only after trust roots, rotation and recovery.** Rejected:
  the signature is self-contained and independently testable, and deferring it
  would leave no way to converge cross-language conformance on canonical bytes.
  The remaining identity work stays deferred but unblocked.
- **Sign the envelope including `extensions`.** Rejected for 0.1: the carrier
  contains the signature, which is circular, and other extensions are
  application claims. Signing everything except `extensions` is the smallest
  well-defined input; a future version may sign a canonical `extensions` map.
- **A JWS/JWK container instead of a raw carrier.** Deferred:
  [ADR 0007](0007-crypto-dependencies.md) selected a JOSE library but it is not
  yet added, and JWS's base64url payload plus protected-header framing would
  still need this profile's canonical bytes defined. The raw carrier is
  dependency-free and sufficient for this slice; a JOSE encoding can wrap the
  same signing input later.
- **Verify in the relay and reject unsigned envelopes.** Rejected now: it would
  change relay behavior and default rejection before identity, migration and
  trust-root questions are settled, and contradicts the
  [identity.md](../identity.md) §8 "no silent upgrade" rule. This slice is
  verifier-side only.
- **Trust a `kid` or key supplied by the envelope.** Rejected: the key is always
  derived from `kid` and `sender` must match; header-supplied key material is
  never accepted, matching [ADR 0007](0007-crypto-dependencies.md).
- **Hand-rolled Ed25519, or canonicalization without a strict parse.** Rejected:
  forbidden by [security.md](../security.md) and
  [ADR 0007](0007-crypto-dependencies.md); the primitive is `node:crypto` and
  the parser/canonicalizer implement only deterministic serialization.

## Consequences

Positive: issue #1 gains its first implemented and tested verification step — a
detached signature whose canonical bytes, carrier and sender binding are fixed
and consumed by deterministic vectors. It reuses the existing key-ID codec,
changes no schema and no dependency, keeps the `"0.1"` wire format, and gives a
concrete answer to "A cannot send as B" at the message level (a signature under
A's key with `sender: B` fails the binding check).

Negative and limiting: this is not authentication or admission and is not wired
into the relay, so the running relay still accepts a self-asserted `sender`.
There is no key distribution, trust root, rotation, revocation, freshness or
replay handling, no end-to-end encryption, and `extensions` are unsigned, so a
verifier can prove very little beyond integrity and key possession. Canonical
key-ids make linkage analysis possible. A future implementation must reproduce
these bytes exactly or conformance fails. `crates/xeip-identity` now provides a
byte-identical Rust consumer (pinned `ed25519-dalek =2.2.0` with
`default-features = false` to avoid `zeroize >= 1.9.1`, which would require
Rust 1.85 and break the workspace MSRV of 1.81; the trade-off is no secret
zeroization and no precomputed tables). TypeScript SDK consumption, relay
integration, key distribution/rotation/revocation, freshness/replay handling
and independent review remain future work, so issue #1 stays incomplete. See
[../local-signed-envelopes.md](../local-signed-envelopes.md) for the contract.
