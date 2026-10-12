# ADR 0011: Versioned entity-bound signatures and persistent relay trust

Status: Accepted for experimental implementation, 2026-10-10. Authorization: user requested continuation after the concrete successor-profile plan. This does not authorize a release or production deployment.

The existing 0.1 signature binds sender directly to the signing key and excludes application extensions. It cannot authorize an endorsed device as a stable parent identity. Reinterpreting those signed bytes or introducing a bypass would weaken compatibility and trust boundaries.

Adopt [entity-signed-envelopes.md](../entity-signed-envelopes.md): a distinct 0.2 carrier, domain-separated Ed25519 signing over payload and proof metadata, explicit anchored current key ownership, mandatory fresh status, and persisted relay generation/serial digests. Keep 0.1 behavior unchanged. Prefer a separately named explicit option over negotiation/fallback; prefer pinned provisioning over network discovery for this single-organization experimental slice.

Consequences: coordinated JS/TS/Rust vectors and APIs; configuration migration is explicit; checkpoints and status refresh become operator responsibilities. The first implementation refreshes only on restart. This extends the proposed lifecycle direction in ADR 0010 without marking that broader design complete or superseding the historical 0.1 ADR. Independent review and the remaining production gates still apply.
