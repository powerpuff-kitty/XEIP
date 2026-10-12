# Organization staging artifact implementation plan

Spec: [organization-artifact.md](../organization-artifact.md). Authorized by continued production-readiness work and the selected dedicated Linux staging target. Execute inline, preserve uncommitted work, do not tag/publish/deploy.

- [x] Add a digest-pinned multi-stage build with explicit runtime file selection, compiled SDK, production-only dependencies, non-root execution, CycloneDX inventory and file checksums.
- [x] Build and inspect the actual artifact; exercise CLI loading and protection checks in a network-disabled read-only container. Correct packaging failures before proceeding.
- [x] Document the reserved-host installation and acceptance procedure, wire a build/smoke CI gate, and perform one fresh-context final review with one Important-finding fix pass.

Ruling: use the tested Node 22.23.3 Alpine digest and Linux/amd64 as the initial artifact target. Other architectures are unverified. Cost: additional platforms need explicit build and behavior evidence.
Ruling: artifact preparation is reversible and authorized; publication and production rollout are not part of this batch. Cost: a maintainer must later select the reviewed commit/version and sign/publish the tested artifact.

Review focus: hidden runtime imports or SQL files omitted by packaging; accidental fixture/secret/dev-tool inclusion; writable application files or unsafe state/configuration mounts; inaccurate dependency/OS inventory or source provenance claims; image smoke checks mistaken for real deployment/capacity/recovery proof.

Initial artifact build exposed npm 10.9.9 `ESBOMPROBLEMS`: generating an installed-tree SBOM after production-only installation still reported omitted dev dependencies as missing. Use npm's documented `--package-lock-only --omit=dev` mode, then independently compare the generated inventory against installed package metadata in the smoke check. Keep production-only installation; do not add compiler/dev packages to make inventory generation succeed. The SBOM remains an unsigned lock-derived npm inventory, not complete OS provenance.

Actual second-image smoke regression failed: the lock-derived npm omit selector left `@modelcontextprotocol/core` out of the inventory (17 components versus 27 installed production packages), also omitting zod/pg-types families. A separate temporary-manifest experiment confirmed that removing development-only package records and root development edges produces all 27 components without TypeScript. The image now preserves the original source manifests, derives production-only manifests after the locked production installation, and generates the SBOM from that graph without the omit selector. The smoke test compares installed names/versions to both lock and SBOM. No dependency version or integrity was changed.

Pre-review verification: actual Linux/amd64 image builds and the isolated smoke runner exits 0. Inventory comparison covers all 27 production packages from the original source lock; immutable application files, runtime/maintenance imports and redacted missing-config failure pass. Local image digest `sha256:4d4fdc4fbf37e91b9fe8c9487808279a80970ae5ddbc933b1ce08c83df3c45ea`, size 67,206,003 bytes. CI build/smoke gate is added but hosted CI is not run. Single fresh-context artifact review is active.

Final review: fresh-context organization_artifact_review found no Critical, Important or Minor findings in this packaging batch. It inspected the import graph, explicit file selection, original-lock/production-manifest inventory, permissions, staging/CI/release claims and actual build/smoke logs. It performed no mutations or Docker operations. No fix pass or rereview was needed.
Final: Ruling: previously reviewed runtime authorization/database behavior — retain its separate evidence; packaging review establishes import/content preservation only — cost if wrong: an earlier runtime defect is not discovered here.
Final: Ruling: actual installed startup, mounted configuration and dependency connectivity — require the reserved staging host and actual configuration — cost if wrong: a smoke pass mistaken for deployment success.
Final: Ruling: human/tool acceptance and capacity/recovery targets — remain open independent gates — cost if wrong: unusable workflow or unsupported reliability claims.
Final: Ruling: complete OS/package vulnerability assessment and signed provenance — unsigned npm inventory is partial supply-chain evidence only — cost if wrong: unidentified base-image risks or untrusted source attribution.
Final: Ruling: other architectures — only Linux/amd64 is built and checked — cost if wrong: unsupported platform behavior.

Batch complete as an experimental unpublished staging artifact. No production rollout or publication took place. The user has no staging host and selected Cloudflare-native exploration; see the [feasibility assessment](../audits/2026-10-11-cloudflare-feasibility.md). Keep this artifact as the experimental Linux option; production provider adoption and provisioning remain undecided.
