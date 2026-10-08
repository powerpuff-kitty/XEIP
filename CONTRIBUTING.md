# Contributing to XEIP

XEIP is an experimental specification. Contributions to schemas, test vectors, Rust and TypeScript implementations, adapters, and security reviews are welcome.

## Setup

- Node.js 22+ for the dependency-free relay demo and Node tests.
- Rust 1.81+ for `cargo test --workspace --all-targets --locked` and the interoperability harness.
- Run `npm ci --ignore-scripts` to install the locked TypeScript compiler and JSON Schema development tools.

Run `npm run typecheck`, `npm run build:ts`, `npm test`, `npm run test:ts`, `npm run validate:fixtures`, `npm run demo:admission`, `npm run demo:replay`, `cargo test --workspace --all-targets --locked`, and `npm run test:interop` before submitting a PR. CI checks both Rust 1.81 and the pinned newer toolchain, including cross-language HTTP/SSE exchange in shared-token, local-admission and local-replay modes. Update lockfiles intentionally when changing dependencies.

`conformance/vectors.json` applies top-level patches/removals to each schema's golden fixture and specifies the expected acceptance result. Add valid and invalid cases here when changing validation. The same cases run against JSON Schema, both SDKs, and the relay's message endpoint. Ajv independently checks structure, dates and lengths; its URI format uses the JavaScript reference syntax checker, while Rust implements URI checks independently. The fixture CLI also accepts `--fixtures-dir PATH` to validate another fixture directory.

## Protocol changes

Open a GitHub issue with: motivating use case, affected entity/message/schema fields, backward compatibility, transport assumptions, security/privacy impact, test vectors, and proposed normative wording. Breaking changes require an explicit version bump. Profiles MAY be experimental and separately versioned.

## Development rules

- Maintain transport-neutral core and do not import UI/cloud-specific dependencies into `xeip-core`.
- Use data-only manifest and UI definitions; no arbitrary executable code in remote descriptions.
- Every protocol field requires matching schema, fixture, documentation and at least one negative test.
- Do not mark v0.1 examples production-ready or present bearer-string sender IDs as verified identities.
- Avoid committing secrets, tokens, personal information or real user transcripts.

Code of conduct: be constructive and respectful. Security reports should be sent privately according to SECURITY.md.
