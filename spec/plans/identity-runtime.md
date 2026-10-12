# Separate identity runtime from command-line tools

Accepted scope: original repository audit A5 maintainability finding. Preserve Node APIs, CLI commands, signing bytes, errors and independent TypeScript/Rust implementations. No new protocol, hosting choice or deployment.

- [x] Establish a failing production dependency check, then extract key IDs, signed envelopes, key documents and status documents into `packages/identity`.
- [x] Keep `tools/` commands and named imports compatible; rewire identity/relay consumers and explicit Docker packaging.
- [x] Verify root CLI/vector tests, SDK/interop, organization tests, strict types and isolated Linux artifact. Record evidence and residual gates.

The dependency check must reject any transitive production import of `tools/`. Existing subprocess tests exercise successful and rejected CLI requests, including key generation; shared fixtures constrain signing bytes and stable errors. Runtime modules contain no CLI dispatch or filesystem input handling. Node crypto remains unchanged.

Rollback: revert this extraction and matching Docker COPY list together, retaining the earlier artifact. No persistent schema/data migration. Existing private Cloudflare smoke remains on its approved artifact; this work does not authorize deployment. Production remains no-go for the recovery, capacity, hosting and operator acceptance gates in `PRODUCTION_READINESS.md`.

## Evidence — 11 October 2026

- Dependency guard: failed before extraction with the four `tools/` runtime imports, then passed after extraction. `/tmp/xeip-identity-runtime-{red,green}.log`.
- `npm test`: **371/371**; `/tmp/xeip-identity-runtime-root.log`. Includes original CLI subprocess, signature, rejection, trust and relay tests.
- `npm run test:organization`: **205/205**; `/tmp/xeip-identity-runtime-organization.log`.
- `npm run test:interop`: **36/36**, including Rust/TypeScript relay exchange; exit 0 in the execution transcript. `npm run test:ts`: **241/241**, `/tmp/xeip-identity-runtime-interop.log` (the grouped command redirected only its final SDK command).
- `cargo test --locked -p xeip-identity`: **39/39**, plus zero doc tests; `/tmp/xeip-identity-runtime-rust.log`.
- Relay, organization, console and Cloudflare strict type checks: all exit 0. The execution transcript contains the first three commands; `/tmp/xeip-identity-runtime-types.log` contains the final Cloudflare command.
- Scoped read-only review: no confirmed findings. All 45 exports, core implementations and CLI bodies preserved. Its focused 59/59 run independently covers the boundary and existing CLI/vector suites. The stale Docker context allowlist was corrected; the initial build had already succeeded, so this was maintenance ambiguity, not a reproduced COPY failure.
- Final Linux/amd64 image `xeip-organization:local-identity-runtime-review`, ID `sha256:b42925890861c1b614a3f4bd615040d9185ca401df8e7a647afbd514baecdd77`, 67,336,415 bytes. Build and isolated artifact checks exit 0: non-root, read-only, network disabled, dependency inventory, file checksums, no `tools/`, runtime/maintenance imports, and redacted missing-configuration exit 1. `/tmp/xeip-identity-runtime-image-final.log`.
- `git diff --check`: clean. No cloud deployment, commit or release occurred.

Original audit A5 is partially resolved: the runtime/CLI boundary is complete. Rust module decomposition was subsequently completed in the [separate extraction](rust-identity-modules.md); broader semantic-analysis coverage remains open. These are correctness and packaging checks on local resources, not rollout capacity or recovery certification. The previously recorded controlled-browser timeout and recovery-HTTP timing failure are not superseded by these unrelated checks. The approved private Cloudflare smoke remains on its earlier artifact.
