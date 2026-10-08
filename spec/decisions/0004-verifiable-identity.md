# ADR 0004: Verifiable entity identities and per-entity authentication

Status: Proposed (design only; not implemented). Date: 2026-10-09. This decision records a design direction for [issue 1](https://github.com/powerpuff-kitty/XEIP/issues/1). It does not approve production deployment, and nothing described here is implemented.

## Context

[Issue 1](https://github.com/powerpuff-kitty/XEIP/issues/1) requires verifiable entity identities and per-entity authentication: a sender cannot impersonate another entity, revoked credentials cannot reconnect, and both the Rust and TypeScript implementations can enforce the same binding without inventing cryptography. The current work does not satisfy this. The shared-token mode intentionally binds no sender, and the opt-in [local admission profile](../local-admission.md) binds a bearer credential to a locally provisioned entity only; [ADR 0001](0001-local-admission.md) states that it is authoritative local binding, not a portable cryptographic identity proof.

[security.md](../security.md) already requires authenticating each connection and binding it to the sender entity, using existing audited mechanisms and never custom crypto. [threat-model.md](../threat-model.md) lists the residual risks: T2 impersonation and stolen credentials, and T6 parsing ambiguity that would undermine any future signature. [core.md](../core.md) fixes two constraints the design must respect: identifier fields are opaque and compared exactly with no normalization, and the JSON wire format is explicitly **not** a canonical signing serialization. [discovery.md](../discovery.md) requires that manifests are not trusted by themselves. A design is needed before any code is written.

## Decision

Adopt the design in [../identity.md](../identity.md). In summary:

1. **Separate entity, device and connection identity.** An entity is a stable, key-derived principal; a device holds an operational key and acts for exactly one entity; a connection is ephemeral and never an identity. Reconnection never mints a new entity.
2. **Self-certifying identifiers.** Entity and device IDs are `urn:xeip:entity:<key-id>` and `urn:xeip:device:<key-id>`, where `<key-id>` is an established key-derived encoding (prefer a `did:key`-style multicodec/multibase). Display `name` is presentation only and never authority.
3. **Untrusted manifests, explicit trust roots.** Manifests and advertisements are self-asserted claims, verified in order by structural validation, self-certification against the advertised key, optional pinned-anchor signature, and SSRF-constrained endpoint resolution.
4. **Principal-to-sender binding.** After authentication, the authenticated `entity_id` must exactly equal the envelope `sender`; a mismatch is rejected and never routed.
5. **Standards-only authentication profiles.** Ed25519, JWS, JWK, JCS and TLS 1.3 (optionally mTLS), with a local nonce challenge/response profile and a hosted TLS-plus-detached-JWS profile. Custom cryptography is forbidden. Because the wire format is not canonical, signing requires deterministic parsing that rejects duplicate names, lone surrogates and out-of-range numbers first.
6. **Rotation, revocation and recovery.** Rotation uses signed key documents with monotonic generations; revocation fails new authentication and closes live streams; device keys can be re-enrolled, but root-key recovery has no protocol-level mechanism in this design.
7. **Explicit migration.** The shared token stays development-only; the local admission bearer becomes a bootstrap/enrollment mechanism rather than proof of identity. One mode is selected per deployment and authentication never falls back to a weaker mode.
8. **Scoped disclosure.** Public keys, IDs, capabilities and coarse health bounds may be public; private keys, tokens, membership, presence, message bodies and revocation reasons must not be.

## Alternatives

- **Keep bearer-only local admission.** Rejected as the end state: a provisioned secret proves possession, not a portable identity, and cannot be verified by a party that did not provision it.
- **Adopt the full DID ecosystem (resolvers, `did:web`, federated registries).** Partially adopted: the key-derived identifier style is reused, but resolver/federation machinery is deferred to avoid network trust and privacy rules that are not yet designed.
- **PGP/Web-of-Trust identity.** Rejected: unsuitable canonicalization, awkward key discovery and poor fit for agent/device operation.
- **HMAC or a bespoke challenge/response with shared secrets.** Rejected: no public verifiability, and it invites custom cryptography that [security.md](../security.md) forbids.
- **Sign envelopes ad hoc without canonicalization.** Rejected: [core.md](../core.md) states the wire format is not canonical; signing it as parsed would reintroduce the T6 ambiguity.
- **X.509 client certificates only.** Used for transport where appropriate, but rejected as the sole mechanism because mTLS does not provide end-to-end sender binding across a relay that terminates TLS.
- **Implement signed envelopes immediately.** Deferred: identifiers, trust roots, canonical parsing and recovery must be reviewed together first, matching the deferral already recorded in [ADR 0001](0001-local-admission.md).

## Consequences

Positive: a design exists that lets Rust and TypeScript converge on shared key-encoding, canonicalization and sender-binding vectors; it reuses established standards and the existing self-asserted `sender` field without changing the 0.1 schemas; it gives a concrete answer to the issue #1 criteria of no impersonation, revoked reconnect denial and no custom crypto.

Negative and limiting: this ADR and [../identity.md](../identity.md) are design only, so issue #1 remains incomplete until implementation, cross-language conformance and review land. Self-certifying IDs are correlation-capable, so privacy is reduced relative to opaque handles. Durable, decentralised revocation and root-key recovery are unresolved open questions, not solved problems. Defining canonicalization may force stricter parsing than the current relay performs, and it must not silently reinterpret existing 0.1 data. No hosted TLS, key storage, rotation distribution or recovery service is added by this decision. Existing shared-token and local admission behavior is unchanged and remains the only implemented authentication.
