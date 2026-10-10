# ADR 0010: Identity key lifecycle — key documents, trust roots, rotation, revocation, recovery

Status: Proposed (design only; not implemented). Date: 2026-10-10. This decision
records a design direction for the remaining blocker of
[issue #1](https://github.com/powerpuff-kitty/XEIP/issues/1). It adds no code, no
dependency and no schema change, and nothing described here is implemented.

## Context

[issue #1](https://github.com/powerpuff-kitty/XEIP/issues/1) requires verifiable
entity identities and per-entity authentication. [ADR 0004](0004-verifiable-identity.md)
and [../identity.md](../identity.md) §3, §6 and §11 design trust roots, rotation,
revocation and recovery, and [ADR 0009](0009-local-signed-envelopes.md) lands the
first implemented slice: a detached Ed25519 signature over the canonical envelope,
bound to `sender` through the key-ID
([../local-signed-envelopes.md](../local-signed-envelopes.md)). The key-ID codec
([`../../tools/derive-keyid.mjs`](../../tools/derive-keyid.mjs),
[`../../crates/xeip-identity`](../../crates/xeip-identity)) is implemented and
conformance-tested.

What remains is exactly the gap the signature slice names but does not close: a
signed envelope proves possession of the key in `kid`, but nothing proves that
`kid` belongs to the entity in `sender`, that the key is current, endorsed and
unrevoked, or what happens when keys rotate or are lost. [ADR 0007](0007-crypto-dependencies.md)
fixes the audited libraries and the strict pre-parse gate; [threat-model.md](../threat-model.md)
records T2 (impersonation / stolen credentials) and T6 (parsing ambiguity before
signing) as residual risks. This ADR records the decision for the key-lifecycle
profile that closes the distribution/trust gap without inventing cryptography or a
central authority.

## Decision

Adopt the design in [../identity-keys.md](../identity-keys.md)
(`xeip.identity-key-lifecycle/0.2`). In summary:

1. **Signed key document.** A JSON key document, RFC 8785-canonicalized and
   Ed25519-signed, maps a stable `urn:xeip:entity:<genesis-key-id>` to the current
   root key and endorsed device keys. `signatures` is the only member excluded from
   the signing input; all other fields (including `extensions`) are covered. The
   strict pre-parse gate of [ADR 0007](0007-crypto-dependencies.md) applies.
2. **Self-certifying genesis, chained generations.** Generation 0 is the genesis
   document; the entity ID is derived from the genesis root key, so it is stable
   across rotation. Each generation carries a monotonic `generation`, a `previous`
   content digest, and is signed by the retiring and successor roots (retiring
   alone when the successor was already endorsed).
3. **Bounded overlap and rollback rejection.** Root rotation uses an explicit,
   deployment-bounded `overlapUntil`; after it, the retiring root is rejected.
   Verifiers persist the highest accepted generation and MUST reject rollback,
   broken chains, generation skips and detected forks.
4. **Explicit trust roots.** Pinned anchor (the only model called "verified
   identity"), self-certifying genesis with bounded TOFU, and inline bootstrap;
   unsigned, unanchored or network-fetched documents are not authority. Fail closed
   when none is configured.
5. **`kid` → entity binding.** A verifier resolves `envelope.sender` to a trusted key
   document and requires the envelope `kid` to be the current/retiring root or an
   active endorsed device, then runs the existing signed-envelope verification.
6. **Revocation via status documents and short-lived credentials.** A signed,
   serialized, monotonic status document lists revoked key-IDs; stale or rolled-back
   status fails closed; learned revocation closes affected live streams in
   relay-enforced profiles. Short validity is the primary control where status
   distribution is unreliable.
7. **Honest recovery.** Lost device keys and (where a surviving successor root
   exists) root compromise are recoverable; a lost last root has **no
   protocol-level recovery**. Threshold, social and custodial recovery are explicit
   non-goals, and any new genesis key is a new identity, not continuity.
8. **Scoped disclosure.** Public keys, IDs and generations may be public; private
   keys, credentials, membership, presence and revocation reasons must not be.
   Self-certifying IDs remain correlation-capable and this is not claimed otherwise.
9. **Conformance.** Propose `identity-keydoc` vectors (positive and negative)
   consumed by the JavaScript reference, `crates/xeip-identity` and the future SDK
   identity layer, mirroring `identity-signed` and `identity-keyid`.

## Alternatives

- **X.509 / PKI or a mandatory CA.** Rejected: a global PKI, CA and revocation
  infrastructure is exactly the central authority this work avoids, and mTLS alone
  does not provide end-to-end sender binding across a relay ([ADR 0004](0004-verifiable-identity.md)).
- **Full DID ecosystem (resolvers, `did:web`, registries).** Partially adopted for
  the key-derived identifier style; the resolver/federation machinery is deferred
  because its network trust and privacy rules are not designed.
- **Centralized CRL/OCSP.** Rejected: durable global revocation is a central-authority
  design; this profile bounds revocation with status documents and short validity
  instead and states the limitation honestly.
- **Key documents including their own signatures member.** Rejected as circular;
  the signature excludes `signatures` only.
- **A new entity ID per rotation.** Rejected: it discards the stable principal that
  [../identity.md](../identity.md) §1–§2 require and breaks correlation-free
  continuity. The genesis anchor keeps the entity ID stable.
- **Trust a `kid` or key document supplied by the envelope or discovery.** Rejected:
  matches [ADR 0009](0009-local-signed-envelopes.md) and [ADR 0007](0007-crypto-dependencies.md);
  keys are resolved from a verified anchor, never from the message.
- **Treat TOFU as verified identity.** Rejected: TOFU is a distinct, revocable trust
  level and MUST NOT be presented to applications as verified identity.
- **Threshold/social recovery now.** Deferred: it is a large design that risks
  weakening authentication if rushed; it is an explicit non-goal of this draft.
- **Implement key documents immediately.** Deferred: this ADR is design only. The
  lifecycle depends on transport, storage and distribution decisions that are not
  yet made, and [ADR 0009](0009-local-signed-envelopes.md) already landed the
  self-contained, independently testable signature slice.

## Consequences

Positive: this decision gives a coherent, non-overclaiming answer to the remaining
issue #1 blocker — how a verifier learns a `kid`'s entity, how rotation stays
stable and rollback-resistant, how revocation and short-lived credentials interact,
and what recovery is and is not possible. It reuses the implemented key-ID and
signed-envelope work, changes no envelope or schema, forbids custom crypto, and
proposes deterministic cross-language vectors so Rust and TypeScript can converge
before implementation.

Negative and limiting: this is design only, so issue #1 remains incomplete until
implementation, cross-language conformance and review land. Durable, decentralised
revocation and root-key recovery are unresolved open questions, not solved
problems; status propagation is best-effort and a hosted recipient may lag a
revocation. Fork detection covers only forks a verifier has already seen. Key
documents and status documents reduce privacy and enable correlation, especially if
full chain history is published. The profile adds parsing surface (documents,
status, rotation statements) that must all receive the strict pre-parse gate, and a
verifier must store trust state per entity. No hosted trust service, key storage,
status distribution or recovery service is added by this decision, and existing
shared-token and local admission behavior is unchanged and remains the only
implemented authentication.
