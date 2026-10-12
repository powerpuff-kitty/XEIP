# Cloudflare Worker composition and packaging plan

Spec: [cloudflare-worker.md](../cloudflare-worker.md). Execute inline, TDD, preserve the current branch/worktree, one fresh scoped final review.

1. [x] Implement strict public/secret/owner command validation with failing-then-passing cases. Preserve fixture allowances only in existing lower-level adapters.
2. [x] Add production Worker/Object/private OwnerEntrypoint; native binding tests cover public isolation, invalid configuration no writes, exact owner setup/refresh/update, late guards, restart/no replay and redacted errors.
3. [x] Build public-only offline package with pinned compatible Wrangler dry-run and a verified local operator RPC invocation path. Test artifact exclusion/secrets/default exposure and operator failure handling. Document any hosted limitations.
4. [x] Full Cloudflare conformance/types on macOS and pinned Node22/Linux, dependency audit, affected shared tests if changed; fresh review and one regression-driven fix pass. Update readiness/audit/plan with evidence and unresolved production gates.

## Review focus

- No public route, request payload or default RPC binding can reach owner mutation methods.
- Runtime/configuration drift cannot select a new empty object or weaken HTTPS/secret separation.
- RPC argument/result bounds and error handling must prevent credential or capability disclosure.
- Owner attribution must accurately describe the privileged binding, not pretend request labels establish human authentication.
- Packaging defaults must not expose preview/public routes, include test controls, or silently change persistence identity.
- The operator path must actually invoke the named binding and must not silently fall back from a remote target to a local empty database.

## Rulings and evidence

Previous goal turn: progress — lifecycle review findings fixed and 183/183 native cases/types passed on both platforms; authoritative docs updated. No blocked condition.
Ruling: continue reversible native architecture work under standing user/developer authorization — no repeated approval ceremony for local specs/code — cost if wrong: experimental changes remain reversible and no hosted resources are touched.
Ruling: canonical spec/plan and current uncommitted branch are the review record — preserve accumulated work, no new worktree/commit or duplicate skill workspace — cost if wrong: final review needs explicit file scope/baselines.
Ruling: private owner binding is the authorization capability; deployment props identify the operator capability — avoids a new public admin secret or signature protocol — cost if wrong: named human attribution and durable administrative audit remain separate production gates.
Ruling: fixed object name is independent of configured organization — prevent typo-induced empty replacement state — cost if wrong: intentional organization/namespace moves require explicit migration.
Ruling: pin Wrangler 4.116.0 to match Miniflare 4.20260730.0/workerd 1.20260730.1 — registry metadata confirms exact dependency match; current Wrangler would introduce a new alpha Miniflare generation — cost if wrong: tooling security/support must be checked before deployment.
Pre-flight: task 1 produces strict configuration/command parsers consumed by object/owner and packager; same parsers must be used at all boundaries. Task 2 exposes serialized named-binding RPC consumed by task 3 operator path; no public HTTP bridge. Task 3 packages the exact task 2 entrypoint; local integration must run that bundle, not a fixture copy. No unresolved interface conflict.

Task 1 verification: 20/20 boundary cases pass after implementing the missing parser module. Two initial assertions compared ordinary and null-prototype JSON objects; corrected the test to compare their serialized plain data. Wrangler 4.116.0 installed with lifecycle scripts disabled; npm reports zero known vulnerabilities. Platform documentation limits each text/secret binding to 5 KiB; apply that deployment limit to both profile and credentials (owner RPC remains 2 MiB). Larger routing/credential sets need a separate configuration mechanism, not silently oversized bindings.

Task 2: 26/26 profile/native binding cases and strict types pass. The bundle exposes no public/default-RPC administration, requires binding operator props, rejects invalid secrets without bootstrapping, preserves fixed object identity through organization drift, and runs actual signed MCP/restart/revocation cases. Test-only HTTPS egress translation initially retained an obsolete Content-Length after rewriting an OAuth resource URL; deleting that fixture header corrected the two integration failures. Hosted TLS/private routes remain untested. Worker types use the matching Wrangler peer version 5.20260730.1; attempted 4.x types did not exist/match and were not installed.

Ruling: do not equate any node:fs import with a deployed filesystem dependency — shared cryptographic reference modules contain guarded CLI helpers, while the production Worker imports their synchronous verification exports; actual workerd execution already passes — cost if wrong: unused CLI code remains in the bundle, and package verification must execute the exact artifact to catch runtime assumptions. The package test still forbids conformance classes/fault controls and records all bundled dependencies. Refactoring reference CLI modules is separate maintainability work, not a reason to weaken runtime verification.

Ruling: add a real 700-identity owner setup/refresh regression before closing the Worker batch — the authorized rollout needs a full signed replacement, but the inherited 8,192-node action snapshot limit also caps provisioning — cost if wrong: a bounded provisioning-specific budget touches the shared snapshot helper and requires organization/root regressions plus refreshed Linux packaging evidence. Keep default action bounds unchanged. This is required workload alignment, not a hosted throughput claim.

The 700-identity native setup/refresh regression failed at the inherited JSON node cap, then passed after adding an explicit bounded snapshot budget for owner/provisioning data. Default action limits and depth/byte limits are unchanged; two shared-helper tests prove default rejection and invalid budget rejection. The full signed population persists across actual workerd restart. Logs: `/tmp/xeip-cloudflare-worker-rollout-red.log`, `/tmp/xeip-cloudflare-worker-rollout-green.log`, `/tmp/xeip-snapshot-budget-red.log`.

The first full local suite passed 214/215: packaged RPC failed because Wrangler returned a live handle before the local service registry published its entry. Standalone package RPC had passed. The fixture now polls only the read-only status call while that specific registry-not-found condition persists, with a 20-second bound; production owner commands remain single-attempt. Teardown now stops the exact worker before deleting its own fixture directory, and local mode is explicit. No hosted fallback or mutation retry was added.

Task 3 complete: offline public-only artifact, hashes/dependency inventory, pinned Wrangler dry-run and real local operator binding invocation pass. Runtime plus build/operator strict types pass. Corrected local full suite:215/215, `/tmp/xeip-cloudflare-worker-all-local-corrected.log`. Shared snapshot change also passes370/370 root tests and201/201 organization tests/types locally. Fresh Linux image `xeip-organization:local-cloudflare-worker-review` built and passed immutable/nonroot/isolated artifact smoke. Dependency audit reports zero known vulnerabilities. Linux full conformance/organization verification remains in progress before final review.

The first Linux full run also passed214/215 and failed only the known local registry-publication race in its pre-correction fixture copy. Corrected full Linux rerun is underway; do not infer pass from the local result.

Task 4 pre-review evidence: corrected Node22.23.3/Linux run passes215/215 Cloudflare and201/201 organization tests plus both strict type checks (`/tmp/xeip-cloudflare-worker-all-linux-corrected.log`). Local counterparts pass, as do370/370 root tests. Rebuilt image digest `sha256:a384e8fa3de034c43c580f903865ab1af94aa61d4ef8715ec8e4ee5417a52b8a`,67,336,058 bytes; isolated artifact smoke passes. Example Worker artifact908,361 bytes, SHA256 `5b5b6cb60bf3694b838143c3685e33412a319e6f4fd94ad7e83cd1e3aaf9fa80`; inventory has seven bundled packages. No hosted environment was used.
Ruling: BASE=HEAD remains unchanged with accumulated uncommitted work — use explicit `/tmp/xeip-cloudflare-worker-review-scope.md` and saved shared-file baselines rather than an empty Git range — cost if wrong: reviewer must follow named scope to avoid conflating prior batches. One fresh read-only final review is requested now; no implementation changes during review.

Final review found no Critical/Important issues and one Minor: operator receipts accept extra fields and incomplete success. Accept and fix it in the authorized single regression-driven pass: exact success/failure variants, bounded status values, correlated metadata on both outcomes, and no unexpected response output. No second review. Cost if wrong: incompatible future receipt schemas require an explicit client update rather than permissive output.


Final reviewer dispositions: no Critical/Important issues; the single Minor receipt issue reproduced (CLI exited zero with a sentinel extra field), then passed after exact receipt validation. Three added tests cover valid status/error variants, malformed/incomplete/unmatched fields and actual child-process CLI output suppression. Targeted tests:5/5 and strict types pass. Logs: `/tmp/xeip-cloudflare-owner-receipt-red.log`; final platform logs below include the green cases. Shared runtime, dependencies and Worker bundle are unchanged by this fix.

Reviewer declined-to-judge rulings (explicit remaining costs, not implied acceptance):
- Hosted IAM/actual remote binding: keep open until an operator-controlled deployed invocation and privilege review; local/static evidence cannot certify it.
- Hosted TLS/public routing/private MCP/production Keycloak: keep open; fixture URL translation only tests protocol behavior.
- Hosted capacity/recovery: keep open; 700 identities demonstrate provisioning only, not P95, throughput, restore or no-loss guarantees.
- Durable administrative attribution/export, retention and automatic signed refresh: retain as implementation/acceptance work; diagnostic logs are insufficient.
- Human PKCE/browser workflow: retain real-provider browser acceptance; privileged binding labels are not human identity.
- Compromised namespace/binding administrators: accepted privileged capability boundary; IAM ownership/review and administrative journal remain necessary operational controls.
- Dormant shared Node CLI imports: retain earlier ruling; exact artifact execution passes, but bundle cleanup remains maintainability work and no unrelated refactor is justified here.
- Artifact signing/independent dependency-content verification: keep release attestation gate open; hashes and lockfile provenance alone do not establish supply-chain attestation.
- Accumulated implementation outside named scope: no global security sign-off inferred; prior evidence remains scoped and independent production review remains required.


Final post-fix macOS conformance/types passes218/218 (`/tmp/xeip-cloudflare-worker-final-local.log`). The first post-fix Linux concurrent run passed216/218 (`/tmp/xeip-cloudflare-worker-final-linux.log`): the first MCP fixture exceeded its 3-second connector deadline during an 84.9-second test, and a trust fixture with maxAgeSeconds=1 had already expired after its renewed update. Host load was62 on this workstation. Both cases passed in the earlier platform run; neither imports the changed operator module. Hypothesis: concurrent native runtimes exhausted available CPU scheduling time. Verify unchanged source under --test-concurrency=1, without enlarging production/fixture limits or suppressing the failed run. This is functional diagnosis, never capacity acceptance.


Task 4 complete: final unchanged-source Node22.23.3/Linux sequential run passes218/218 plus strict Cloudflare types (`/tmp/xeip-cloudflare-worker-final-linux-serial.log`,124.65 seconds). Both previously failing timing cases pass with original limits. This supports scheduling contention as the cause of the concurrent failures; it does not establish hosted performance. macOS passes218/218 plus types. Prior unaffected shared results remain 370/370 root locally, 201/201 organization on both platforms, both organization type checks and fresh Linux artifact smoke. The receipt-only fix changes neither the deployed Worker bundle nor Linux service image; verified candidate Worker SHA256 remains `5b5b6cb60bf3694b838143c3685e33412a319e6f4fd94ad7e83cd1e3aaf9fa80`. Dependency audit reports zero known vulnerabilities; git diff --check passes. The single fresh review is complete, its one Minor is fixed, and no scoped finding remains. Experimental packaging increment complete; broader service/production goal remains active. No resources, cloud account, real credentials or organization data were used.

Next production work: durable administrative attribution/export, reliable signed-status refresh, retention, and independent recovery journal/fencing. The failure boundary for zero acknowledged-action loss is still awaiting the user's optional clarification; do not infer a narrower boundary. Hosted IAM/TLS/private MCP, real browser/Keycloak and capacity/recovery/security/operator acceptance remain required.
