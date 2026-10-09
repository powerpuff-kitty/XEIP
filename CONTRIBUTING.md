# Contributing to XEIP

XEIP is an experimental specification. Contributions to schemas, test vectors, Rust and TypeScript implementations, adapters, and security reviews are welcome.

## Setup

- Node.js 22+ for the dependency-free relay demo and Node tests.
- Rust 1.81+ for `cargo test --workspace --all-targets --locked` and the interoperability harness.
- Run `npm ci --ignore-scripts` to install the locked TypeScript compiler and JSON Schema development tools.

Run `npm run typecheck`, `npm run build:ts`, `npm test`, `npm run test:ts`, `npm run validate:fixtures`, `npm run demo:admission`, `npm run demo:replay`, `npm run demo:delivery`, `npm run demo:receipts`, `npm run demo:durable`, `npm run demo:limits`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --all-targets --locked`, and `npm run test:interop` before submitting a PR. CI checks both Rust 1.81 and the pinned newer toolchain, including cross-language HTTP/SSE exchange in shared-token, local-admission and local-replay modes. Update lockfiles intentionally when changing dependencies. See [RELEASING.md](RELEASING.md) before proposing a versioned release.

`conformance/vectors.json` applies top-level patches/removals to each schema's golden fixture and specifies the expected acceptance result. Add valid and invalid cases here when changing validation. The same cases run against JSON Schema, both SDKs, and the relay's message endpoint. Ajv independently checks structure, dates and lengths; its URI format uses the JavaScript reference syntax checker, while Rust implements URI checks independently. The fixture CLI also accepts `--fixtures-dir PATH` to validate another fixture directory.

## Protocol changes

Open a GitHub issue with: motivating use case, affected entity/message/schema fields, backward compatibility, transport assumptions, security/privacy impact, test vectors, and proposed normative wording. Breaking changes require an explicit version bump. Profiles MAY be experimental and separately versioned.

## Development rules

- Maintain transport-neutral core and do not import UI/cloud-specific dependencies into `xeip-core`.
- Use data-only manifest and UI definitions; no arbitrary executable code in remote descriptions.
- Every protocol field requires matching schema, fixture, documentation and at least one negative test.
- Do not mark v0.1 examples production-ready or present bearer-string sender IDs as verified identities.
- Avoid committing secrets, tokens, personal information or real user transcripts.

## Dependencies

Cryptographic and canonicalization choices are recorded in [ADR 0007](spec/decisions/0007-crypto-dependencies.md). Until those libraries are added, the rules below govern every dependency PR.

- **Audited and standards-based.** Prefer maintained, permissively licensed libraries with clear advisories and independent review. Implement only standards (Ed25519, JWS/JWK, RFC 8785 JCS, TLS); never hand-roll cryptographic primitives or bespoke signature/JOSE/JCS encoders.
- **Pinned.** Add exact versions (`=` in Cargo, exact strings in npm) and re-verify the library's `rust-version` against the 1.81 MSRV. Do not float a new dependency on `^`.
- **Minimal.** Add a dependency only when the standard library or an existing dependency cannot cover the need, and keep transitive native/build-script dependencies to a minimum.
- **Per-ecosystem lockfile.** Update and commit the relevant `Cargo.lock` or `package-lock.json` in the same PR; CI runs `npm ci --ignore-scripts` and cargo with `--locked`.
- **Core stays dependency-light.** `xeip-core` keeps `serde`/`serde_json` and gains no crypto, network or JOSE dependency; signing belongs in a dedicated identity layer or the SDK, not the wire models.
- **Supply-chain checks.** Dependency PRs must state the crate/package, exact version, license, advisories cleared, native/build-script dependencies, and the maintenance/audit evidence. Expect `cargo-deny`, `cargo audit`, `npm audit` and SHA-pinned CI actions as these profiles are implemented.

Code of conduct: be constructive and respectful. Security reports should be sent privately according to SECURITY.md.
