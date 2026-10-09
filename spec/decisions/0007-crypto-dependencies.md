# ADR 0007: Audited cryptographic and canonicalization dependencies for the identity profile

Status: Proposed (design only; not implemented). Date: 2026-10-09. This decision selects audited libraries for the Ed25519 + JWS/JWK + JCS/TLS profile proposed by [ADR 0004](0004-verifiable-identity.md) and [../identity.md](../identity.md), and records the dependency-addition policy that makes "no custom cryptography" enforceable. It adds no dependency and no code: the versions below are recommendations to be re-verified in the PR that adds them.

## Context

[ADR 0004](0004-verifiable-identity.md) and [../identity.md](../identity.md) §5 require Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)), EdDSA/`OKP` in JOSE ([RFC 8037](https://www.rfc-editor.org/rfc/rfc8037)), JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)), JWK ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)), RFC 8785 JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) and TLS 1.3, and forbid custom cryptography. [security.md](../security.md) item 3 and [CONTRIBUTING.md](../../CONTRIBUTING.md) require audited mechanisms and a transport-neutral core. [threat-model.md](../threat-model.md) T8 records dependency/supply-chain risk: checked-in lockfiles, `npm ci --ignore-scripts`, `--locked` cargo and read-only CI permissions help, but CI actions are tag-pinned and Cargo build scripts remain executable. [RELEASING.md](../../RELEASING.md) requires committed lockfiles and full local verification.

The repository currently ships no cryptography: `xeip-core` depends only on `serde`/`serde_json` ([Cargo.toml](../../crates/xeip-core/Cargo.toml)), and neither the root nor the SDK manifest has a runtime dependency ([package.json](../../package.json), [sdks/typescript/package.json](../../sdks/typescript/package.json)). Issue #1 asks for a standard profile with no invented cryptography; selecting and pinning libraries now unblocks implementation without hand-rolling primitives.

## Decision

Adopt the per-language set and the dependency-addition policy below. This ADR adds and modifies no manifest or lockfile.

### Rust (workspace MSRV 1.81, `rust-version = "1.81"`)

| Purpose | Recommended crate | Pinned version | License | Notes |
| --- | --- | --- | --- | --- |
| Ed25519 (RFC 8032) | `ed25519-dalek` | `=2.2.0` | BSD-3-Clause | Primary; RustCrypto/dalek ecosystem. `rust-version = 1.81`. 3.0.0 requires 1.85 and is rejected. |
| Ed25519 (`no_std`/WASM) | `ed25519-compact` | `=2.6.0` | MIT | Alternative when a compact `no_std`, no-alloc signer is required; smaller review base than `ed25519-dalek`. |
| JWS/JWK (EdDSA/`OKP`) | `josekit` | `=0.10.3` | MIT OR Apache-2.0 | Most complete JOSE crate, but see the OpenSSL caveat below; belongs outside `xeip-core`. |
| JWS (JWT-only fallback) | `jsonwebtoken` | `=9.3.1` | MIT | `rust-version = 1.73`; edits are `ring`-backed but cover JWT-shaped JWS only, not general JWK/JWS. 10.x+ requires 1.85+. |
| Hash (SHA-256) | `sha2` (RustCrypto) | `=0.10.9` | MIT OR Apache-2.0 | Do **not** use 0.11.0: it requires Rust 1.85. |
| RFC 8785 JCS | `serde_json_canonicalizer` | `=0.3.2` | MIT | Uses `ryu-js` for ECMAScript number formatting; the correct RFC 8785 number behavior. Alternative: `serde_jcs` 0.2.0. |

MSRV and advisory constraints:

- `ed25519-dalek` 3.0.0 and `sha2` 0.11.0 declare `rust-version = 1.85`, which is **incompatible with the workspace MSRV 1.81**; pin the 2.x/0.10.x lines.
- Require `ed25519-dalek >= 2.1` (RUSTSEC-2022-0093 affects < 2.0.0) and force `curve25519-dalek >= 4.1.3` (RUSTSEC-2024-0344; 4.2.0 is currently yanked) in the lockfile via the dependency PR and `cargo-deny`/`cargo update`.
- `ed25519-dalek` supports `no_std` through `default-features = false` plus `alloc`/`zeroize`, and needs `rand_core` only for key generation. `xeip-core` is `std` and uses `serde`, so crypto must be feature-gated in a dedicated layer rather than forced into the core.
- `josekit` declares no `rust-version` and has a **mandatory, non-optional `openssl ^0.10` dependency** (a native library and build-script surface). That conflicts with a transport-neutral, dependency-light core and is the primary unresolved supply-chain question below.

### Node/TypeScript (Node >= 22, ESM)

| Purpose | Recommended implementation | Version | License | Notes |
| --- | --- | --- | --- | --- |
| Ed25519 | WebCrypto `crypto.subtle` (`node:crypto` on Node, `crypto.subtle` in browsers) | built-in | n/a | No dependency. Feature-detect `Ed25519` and fail closed if absent. |
| Ed25519 fallback | `@noble/ed25519` | `=3.2.0` | MIT | Only for targets whose WebCrypto lacks Ed25519; not needed on Node 22 or current browsers. |
| JWS/JWK (EdDSA/`OKP`) | `jose` | `=6.2.12` | MIT | Zero runtime dependencies, WebCrypto-based, widely deployed; supports EdDSA/`OKP`, JWS and JWK. |
| RFC 8785 JCS | `canonicalize` | `=5.1.0` | Apache-2.0 | Zero dependencies, `engines: node >= 22` matching the repo. Alternative: `json-canonicalize` 3.0.1 (MIT). |

WebCrypto Ed25519 is available in Node 22 and current Chrome/Safari/Firefox. An environment that lacks it must fail closed, not fall back to a bespoke signer; `@noble/ed25519` is acceptable only as a vetted library fallback.

### Dependency boundary (core vs SDK vs example)

- `xeip-core` (Rust) and the TypeScript SDK's protocol/validation layer stay primitive-free: no signing, no JOSE, no canonicalization-as-security, no network. `xeip-core` keeps `serde`/`serde_json` only.
- Crypto lives in a dedicated, separately versioned identity layer, not in the wire models: a future `crates/xeip-identity` workspace member and the signing portion of `sdks/typescript`. Neither exists yet; creating them is implementation work.
- Examples and demos may depend on these crates/packages, but they are never the only home of required behavior and stay development-only.
- A signing profile MUST call a library API. Hand-building an Ed25519 primitive, a JWS protected header/signature, or a JWK/JCS encoder is prohibited. Using a JCS canonicalizer and a JSON parser is permitted because canonicalization is deterministic serialization, not a primitive.

### Supply-chain controls

- **Lockfiles.** Commit `Cargo.lock` ([Cargo.lock](../../Cargo.lock)) and `package-lock.json` ([package-lock.json](../../package-lock.json)); every dependency change updates them intentionally. CI keeps `npm ci --ignore-scripts` and `--locked` cargo.
- **Pinning.** Add exact versions (`=` in Cargo, exact strings in npm), matching the repo's existing pins (`ureq = "=3.2.1"`, `ajv "8.20.0"`). Never float a crypto dependency on `^`; re-verify `rust-version` and advisories in the adding PR.
- **Advisory tooling.** Add `cargo-deny` (advisories, licenses, bans, sources) with a committed `deny.toml` and a CI job, plus `cargo audit` as defense in depth. No deny config exists today ([ci.yml](../../.github/workflows/ci.yml)). For npm, add a separate `npm audit --omit=dev` or Dependabot/Renovate job; CI currently passes `--no-audit`.
- **CI hardening (T8).** Pin third-party actions by commit SHA (today they are tags), keep least-privilege `permissions`, and treat executable Cargo build scripts as residual risk. Lockfiles give reproducibility, not provenance.
- **Review.** A crypto dependency PR must name the crate, exact version, license, advisories cleared, transitive native/build-script dependencies, and the audit/maintenance evidence.

### "No custom cryptography" enforcement

- Maintain a prohibited-primitive list (curve/field arithmetic, signature padding, key derivation, bespoke JWS/JWK/JCS encoders) enforced in review and by `cargo-deny` `bans` / an npm dependency allowlist.
- No in-repo `unsafe` crypto and no vendored primitives. If a needed primitive has no audited library, the feature is blocked, not hand-built.
- Keep the identity layer opt-in so `xeip-core` cannot silently become crypto-bearing; the core's transport-neutral dependency set is itself a review gate.

## Alternatives

- **Hand-rolled Ed25519/JWS/JCS.** Rejected: forbidden by [security.md](../security.md) and [identity.md](../identity.md), and it would reintroduce the T6 parsing ambiguity this profile exists to remove.
- **Minimal-dependency / no-library ("std only").** Rejected: neither Rust std nor Node exposes Ed25519, JWS or JCS; implementing them is exactly the custom cryptography the profile bars.
- **One crypto stack via WASM bindings** (a single audited library compiled once and consumed by Rust and TypeScript). Deferred: it can reduce cross-language divergence but adds a toolchain, a build artifact and a second runtime to audit; revisit only if per-language libraries cannot keep conformance vectors in sync.
- **`ring`/BoringSSL as the single primitive provider.** Not adopted standalone: `ring` supplies Ed25519 but not JWS/JWK/JCS, and its C/asm build complicates MSRV and the pure-Rust posture (acceptable transitively through `jsonwebtoken`).
- **`josekit` inside `xeip-core`.** Rejected: its mandatory OpenSSL dependency and absent `rust-version` conflict with a transport-neutral, dependency-light core.
- **Node WebCrypto alone, no JOSE library.** Rejected: `crypto.subtle` exposes primitives, not JWS/JWK/JCS serialization; assembling them by hand is custom framing.

## Consequences

Positive: issue #1 can be implemented against named, permissively licensed, maintained libraries with an explicit core/SDK/example boundary; the MSRV-1.81 traps (`ed25519-dalek` 3, `sha2` 0.11) and known RUSTSEC advisories are recorded before code lands; and "no custom crypto" becomes reviewable rather than aspirational.

Negative and limiting: this is design only, so nothing is validated until an implementation PR and cross-language conformance vectors exist. Any dependency increases T8 exposure, especially a native OpenSSL-backed JOSE crate. The recommended set must be re-checked against advisories and MSRV at implementation time; the versions above will age.

## Unresolved supply-chain questions

1. **JOSE backend (primary).** Accept `josekit`'s mandatory OpenSSL native dependency in a non-core crate, or restrict Rust to a narrower path (`jsonwebtoken` + `ring`, JWT-shaped JWS) and keep JWK/JCS composition minimal and reviewed? This is the main open question.
2. **Rust crate boundary.** Create a new `crates/xeip-identity` workspace member with opt-in features, or feature-gate crypto inside an existing crate? This affects `xeip-core` dependency-lightness and the CI matrix.
3. **TypeScript dependency home.** The SDK `package.json` has no dependencies and there is no per-SDK lockfile. Do `jose`/`canonicalize` belong in the SDK (requiring a lock/install story) or should the monorepo adopt npm workspaces so the root `package-lock.json` governs them?
4. **CI provenance strictness.** Third-party actions are tag-pinned and there is no `cargo-deny` or `npm audit` job yet. Enabling crypto dependencies should land with those controls, but the required strictness (SHA pinning, scheduled audits) is undecided.
5. **Independent audit expectation.** No external review of the recommended libraries is recorded in-repo. Is a maintainer advisory/license check sufficient pre-release, or is an external review required before signing becomes normative?
