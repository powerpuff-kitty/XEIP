# Security policy

**XEIP is experimental and NOT safe for publicly exposed, untrusted or multi-tenant use.** The default demo relay uses one shared bearer token and no enforced group membership. The opt-in [local admission profile](spec/local-admission.md) adds locally provisioned per-entity bearer binding, membership checks and live revocation. Neither mode verifies portable cryptographic identities or provides a production trust system. Both must remain loopback-only.

The optional [local replay extension](spec/local-replay.md) suppresses repeated authenticated acceptances within a bounded in-memory window. Expiry or a new relay instance loses that suppression; it cannot guarantee durable delivery or prevent duplicate application/command effects. No mode implements automatic recipient acknowledgments or exactly-once execution.

## Reporting vulnerabilities

Please use GitHub's private **Report a vulnerability** feature (Security tab → Advisories) if enabled. If unavailable, open an issue that requests a private reporting channel **without disclosing exploit details or credentials**. Do not post sensitive evidence publicly.

## Supported versions

No stable releases are supported yet. Changes are made on main until a versioned release and maintenance policy are established.

See [spec/security.md](spec/security.md) for production requirements and [spec/threat-model.md](spec/threat-model.md) for the reviewed local implementation, controls and remaining risks. A development token is **not** a replacement for identity binding, authorization, signed/verifiable discovery, session admission, secure transport and command validation.

## Dependencies and supply chain

Cryptographic and canonicalization dependencies for the proposed identity profile are selected in [ADR 0007](spec/decisions/0007-crypto-dependencies.md); [threat-model.md](spec/threat-model.md) T8 records the current dependency/build risk. In short: use audited, standards-only libraries and never custom crypto; pin exact versions and commit `Cargo.lock`/`package-lock.json`; keep `xeip-core` free of crypto, network and JOSE dependencies; and rely on locked installs (`npm ci --ignore-scripts`, cargo `--locked`) plus `cargo-deny`/`cargo audit`/`npm audit` and SHA-pinned CI actions as those profiles land. Lockfiles provide reproducibility, not provenance.
