# Organization adapter boundary implementation plan

Execute inline using the executing-plans and TDD skills. Spec: [organization-adapters.md](../organization-adapters.md). Goal: remove concrete storage/connector imports from approval orchestration while preserving the current self-hosted implementation. No backend adoption, dependency upgrade, publication or deployment.

## Task 1: Separate the shared approval contract

Files: new `services/organization/errors.mjs`, `contracts.d.ts`, `adapter-boundary.test.mjs`; update store/controller/execution/authorization/auth/actions/mcp type boundaries, `tsconfig.json` and the explicit Dockerfile file list.

- [x] Add a real import regression with a child-process loader that denies concrete adapter and filesystem dependencies. Run it before implementation; expect controller import to fail through the migration dependency and executor import to fail through the MCP dependency.
- [x] Move shared error classes, retain legacy re-exports, declare structural contracts and type-check existing adapters. Preserve all runtime behavior.
- [x] Run import regression plus organization unit tests/type checking; expect all pass. Rebuild the actual Linux artifact and run its existing smoke verifier; expect exit 0.
- [x] Update documentation, perform one fresh-context final review of this change and resolve Critical/Important findings once. Leave wider production gates open.

Interfaces: `errors.mjs` provides identical `StoreConflict`, `StoreUnavailable` and `ConnectorFailure` classes to adapters and consumers. `contracts.d.ts` contains no emitted runtime implementation and no concrete storage/connector imports. Existing store/MCP exports remain compatible.

Review focus: class identity across old/new import paths; accidental authority/result/claim type widening; any changed commit or pre-effect checks; omissions from explicit artifact packaging; tests claiming a full Workers backend from a Node import check.

Ruling: continue inline under the user's existing autonomous hardening authorization — this is a reversible internal refactor of the accepted implementation, not adoption of the proposed cloud architecture — cost if wrong: a new adapter could be mistakenly treated as selected production infrastructure; documentation must keep that distinction.
Ruling: use this repository's `spec/` documents and existing uncommitted hardening branch for the plan/ledger; do not commit or recreate a worktree — preserves the shared accumulated work — cost if wrong: the final reviewer must compare this plan's explicit files and pre-change copies, not assume all branch changes belong to this task.
Ruling: use targeted organization verification and a real image smoke; no unchanged Rust/relay suite rerun — production mutations affect only organization import/type boundaries and packaging — cost if wrong: an unexpected cross-component runtime dependency needs expanded tests if encountered.
Pre-flight: error producers and orchestration consumers change together; legacy exports must point to the same classes. Packaging consumes the new error module and must include it before image verification. No other task interfaces.

Task 1 evidence: the import regression failed twice on the expected concrete imports (`store.mjs` and `mcp.mjs`) before production edits, then passed after extraction. Initial test-script escaping was corrected before that meaningful RED run. The final harness prefers synchronous loader hooks and falls back to the older asynchronous API for earlier Node 22; this avoids the Node 26 deprecated API warning that initially caused two harness-only failures. No runtime behavior was changed to satisfy the harness.

Strict organization type checking passes. Full organization unit suite: 167/167 pass (`/tmp/xeip-adapter-boundary-suite.log`). Type-check log: `/tmp/xeip-adapter-boundary-types.log`. Exact pre-change source copies for final review: `/var/folders/qv/v91hrrlx0_z1b5sjvv9x_1600000gn/T/xeip-adapter-boundary-baseline-olqltbc4`.

Actual Linux/amd64 image build and isolated artifact verifier pass (`/tmp/xeip-adapter-boundary-image-build.log`, `/tmp/xeip-adapter-boundary-image-smoke.log`). New local-only tag `xeip-organization:local-adapters-review`, digest `sha256:40ec4ea32c4e9a7487fe8b976912688f3e8ebdc450e49d84ee5bfd69a857d922`, 67,206,317 bytes; previous reviewed artifact/tag retained. No publication or deployment. The separate non-root, network-disabled, read-only Node 22.23.3/Linux organization run also passes 167/167 (`/tmp/xeip-adapter-boundary-node22.log`). The fresh-context final review is complete.

Additional local compatibility probe: Miniflare 4.20260730.0/workerd 1.20260730.1, compatibility date 2026-07-30 and nodejs_compat imported unchanged copies of the current controller/executor graph without copying store, migrations or the MCP adapter. Malformed input returned 400 before authentication. Exit 0, `/tmp/xeip-cloudflare-orchestration-probe.log`; throwaway runner `orchestration-run.mjs` in the prior Cloudflare probe directory. This does not test an alternate backend.

Final review: organization_adapter_review independently compared every pre-change source, ran the two import tests and verified identity of the legacy/shared error classes. No Critical, Important or Minor findings; no fix pass or rereview required. Its Node 22 observation was preliminary; the parent subsequently confirmed that same run finished 167/167, exit 0.
Final: Ruling: full Workers execution compatibility — retain only the narrow local import/malformed-input probe; full provider/store/effect integration remains unverified — cost if wrong: an import pass mistaken for a working native backend.
Final: Ruling: alternative adapter durability/authorization — no alternate adapter exists in this batch and none is certified — cost if wrong: structural types mistaken for behavioral/security conformance.
Final: Ruling: capacity/recovery/operator readiness — keep existing acceptance gates open — cost if wrong: unsupported production reliability claims.
Final: Ruling: unrelated accumulated changes — retain earlier review evidence and scope this review to pre-change file copies — cost if wrong: unrelated defects are not rediscovered here.
Final: Ruling: reviewer did not reconstruct the image — actual parent build/smoke evidence verifies inclusion/imports; independent rebuild remains a release gate — cost if wrong: the review alone could be mistaken for reproducible signed supply-chain evidence.

Task 1 complete: unchanged runtime semantics, type checks, 167/167 organization tests on both local Node 26 and isolated Node 22/Linux, real rebuilt artifact smoke and final review. The production-readiness goal remains active; no backend adoption, publication or deployment occurred.
