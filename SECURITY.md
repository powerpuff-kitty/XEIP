# Security policy

**XEIP is experimental and NOT safe for publicly exposed, untrusted or multi-tenant use.** The default demo relay uses one shared bearer token and no enforced group membership. The opt-in [local admission profile](spec/local-admission.md) adds locally provisioned per-entity bearer binding, membership checks and live revocation. An optional signed-envelope profile verifies key-bound signatures, and trusted key/status documents can restrict sending keys. The separately selected [entity-bound 0.2 profile](spec/entity-signed-envelopes.md) adds parent/device binding, authenticated extensions, mandatory status freshness and local restart checkpoints. A production trust lifecycle remains incomplete. All modes must remain loopback-only. See [production readiness](PRODUCTION_READINESS.md) for release gates.

The optional [local replay extension](spec/local-replay.md) suppresses repeated authenticated acceptances within a bounded in-memory window. Expiry or a new relay instance loses that suppression; it cannot guarantee durable delivery or prevent duplicate application/command effects. No mode implements automatic recipient acknowledgments or exactly-once execution.

## Reporting vulnerabilities

Please use GitHub's private **Report a vulnerability** feature (Security tab → Advisories) if enabled. If unavailable, open an issue that requests a private reporting channel **without disclosing exploit details or credentials**. Do not post sensitive evidence publicly.

## Supported versions

When status enforcement is enabled, sends require an accepted status for the
key's owning entity. Configured `maxAgeSeconds` is enforced at send time, and
caller mutation cannot change verified provisioning snapshots. The local profile
still permits an omitted age bound; production must require one. The separate 0.2 profile requires an age bound and persists rollback checkpoints.
The trusted owner can refresh 0.2 provisioning atomically through an in-process
API. Credentials in this profile require a bound `kid`; revoked/removed keys and
stale status deny activity and close active streams. Automated status distribution,
certified trust recovery and independent review remain release gates.

No stable releases are supported yet. Changes are made on main until a versioned release and maintenance policy are established.

See [spec/security.md](spec/security.md) for production requirements and [spec/threat-model.md](spec/threat-model.md) for the reviewed local implementation, controls and remaining risks. A development token is **not** a replacement for identity binding, authorization, signed/verifiable discovery, session admission, secure transport and command validation.

## Dependencies and supply chain

Cryptographic and canonicalization dependencies for the proposed identity profile are selected in [ADR 0007](spec/decisions/0007-crypto-dependencies.md); [threat-model.md](spec/threat-model.md) T8 records the current dependency/build risk. In short: use audited, standards-only libraries and never custom crypto; pin exact versions and commit `Cargo.lock`/`package-lock.json`; keep `xeip-core` free of crypto, network and JOSE dependencies; and rely on locked installs (`npm ci --ignore-scripts`, cargo `--locked`) plus `cargo-deny`/`cargo audit`/`npm audit` and SHA-pinned CI actions as those profiles land. Lockfiles provide reproducibility, not provenance.
