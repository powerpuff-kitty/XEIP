# Releasing XEIP

XEIP is **experimental and pre-release**. There is no published SDK or relay release yet, and no interoperability or security guarantee is implied. This document defines the checklist a maintainer must satisfy before tagging any version, addressing [issue #10](https://github.com/powerpuff-kitty/XEIP/issues/10). It does not itself publish anything.

## Versioning

- Protocol versions are independent from SDK and relay versions. The current draft is `0.1`; a breaking wire change requires an explicit protocol version bump and migration notes.
- The `xeip` field of an envelope/entity/session declares the wire version. Experimental profiles (`xeip.local-admission/0.1`, `xeip.local-replay/0.1`, `xeip.local-delivery/0.1`) version independently.
- Until v1.0, any draft may change. Do not advertise compatibility that has not been tested.

## Pre-release checklist

1. **Clean tree and lockfiles.** `git status` is clean; `Cargo.lock` and `package-lock.json` are committed and intentional.
2. **Full local verification passes:** `npm ci --ignore-scripts`, `npm run typecheck`, `npm run build:ts`, `npm run validate:fixtures`, `npm test`, `npm run test:ts`, `npm run test:interop`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --all-targets --locked`, and all `npm run demo:*`.
3. **CI is green** on a fresh checkout for every job (Node, Rust lint, both Rust toolchains).
4. **Schema/spec drift:** `conformance/vectors.json` passes against JSON Schema, the Rust core and the TypeScript SDK; changed wire shape has updated schemas, fixtures, spec text and negative tests.
5. **Security truth:** `spec/security.md` and `spec/threat-model.md` describe the exact implemented scope and residual risk; no example is marked production-ready.
6. **Docs and links:** README, ROADMAP, `spec/**` and profile docs agree with the code; relative links resolve.
7. **Permissions and actions:** workflow permissions are minimized and third-party actions are pinned by commit SHA or reviewed (currently version tags; see threat-model T8).
8. **Release notes:** state the protocol/SDK version, wire-compatibility notes, security-relevant changes, and known gaps.

## Tagging

- Tag the exact reviewed commit. Draft releases stay marked **pre-release**.
- The relay and SDKs are examples; a release must not imply a hosted service or production support.
- Record security advisories separately and follow [SECURITY.md](SECURITY.md).

## Not yet satisfied

GitHub Actions are referenced by version tag rather than immutable SHA, there is no signed release provenance, and no independent security review or external-client interoperability has been completed. A v1.0 release additionally requires the exit criteria in [ROADMAP.md](ROADMAP.md).
