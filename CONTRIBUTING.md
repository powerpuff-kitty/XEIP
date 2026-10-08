# Contributing to XEIP

XEIP is an experimental specification. Contributions to schemas, test vectors, Rust and TypeScript implementations, adapters, and security reviews are welcome.

## Setup

- Node.js 22+ for the dependency-free relay demo and Node tests.
- Rust stable for `cargo test --workspace`.
- TypeScript compiler (`npm install --no-save typescript@5.9.3`) for `npm run typecheck`.

Run `npm test`, `npm run validate:fixtures`, `npm run typecheck`, and `cargo test --workspace` before submitting a PR.

## Protocol changes

Open a GitHub issue with: motivating use case, affected entity/message/schema fields, backward compatibility, transport assumptions, security/privacy impact, test vectors, and proposed normative wording. Breaking changes require an explicit version bump. Profiles MAY be experimental and separately versioned.

## Development rules

- Maintain transport-neutral core and do not import UI/cloud-specific dependencies into `xeip-core`.
- Use data-only manifest and UI definitions; no arbitrary executable code in remote descriptions.
- Every protocol field requires matching schema, fixture, documentation and at least one negative test.
- Do not mark v0.1 examples production-ready or present bearer-string sender IDs as verified identities.
- Avoid committing secrets, tokens, personal information or real user transcripts.

Code of conduct: be constructive and respectful. Security reports should be sent privately according to SECURITY.md.
