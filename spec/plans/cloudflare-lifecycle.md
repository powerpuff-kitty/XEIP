# Cloudflare lifecycle implementation plan

Spec: [cloudflare-lifecycle.md](../cloudflare-lifecycle.md). Execute inline on the preserved branch with TDD and one fresh final reviewer.

## Tasks

1. [x] Add checked schema v4 for immutable bootstrap intent and terminal initialization. Preserve v1-v3 SQL/checksums and prove v3 upgrade retains actions/trust/authority. Add actual-workerd regressions for replacement/deletion/invalid transition and initial empty/public no-write behavior.
2. [x] Implement OrganizationService's explicit initialization, exact resumable retry and validated reopen. Add failure/restart tests at each bootstrap phase, missing/corrupt completed-state refusal, runtime drift/secret separation, close and concurrent mutation behavior.
3. [x] Compose signed Fetch/controller/MCP with private owner refresh and policy operations, expected revisions and meaningful readiness. Verify real provider/MCP workflow, fresh trust gating, provider outage/revision race, ledger quarantine, late revocation and no replay across restart. Strict types and full Cloudflare conformance on Node26/macOS and pinned Node22/Linux; appropriate existing organization tests if shared adapters change.
4. [x] Document owner integration/recovery constraints and readiness evidence; one fresh scoped review, one regression-driven fix pass if needed. Keep the deployable RPC wrapper/owner runner/packaging and hosted/operator/security gates open until they actually exist.

## Review focus

- Neither public open nor completed initialization retry may recreate missing trust, authority or consumed claims.
- Interrupted bootstrap may resume only its recorded intent; altered configuration, component drift or unexpected prior data fails closed.
- Runtime target changes cannot silently repoint approved work; secrets never persist in lifecycle/public authority state.
- Readiness reflects local quarantine, fresh trust and provider health, including updates during a probe.
- Owner changes and close during awaits cannot reactivate stale authority or permit a late tool effect.

## Rulings

Ruling: continue the authorized reversible architecture work without new approval ceremonies — the user asked to continue to production readiness and selected native exploration — cost if wrong: experimental code is reversible; resources and production adoption remain unapproved.
Ruling: canonical spec/plan and existing uncommitted branch remain the source of truth — no duplicate workspace or commits — cost if wrong: final review must use saved baselines and named scope.
Ruling: separate bootstrap from signed trust refresh — empty trust authorizes nobody and avoids stale provisioning stranding a partial bootstrap — cost if wrong: setup requires a second explicit owner operation before readiness.
Ruling: implement and verify lifecycle before deployable control-plane packaging — public/owner routing cannot safely substitute for durable bootstrap semantics — cost if wrong: this batch alone is not a deployable service.
Ruling: immutable runtime route configuration for this version — changing an endpoint under an existing approved revision must fail closed — cost if wrong: legitimate target-route changes require a future explicit migration workflow.

Task 1: schema guards and additive v3 migration tests failed against v3 (missing service table), then passed against v4. The original v1/v2/v3 migration SQL remains unchanged; the existing v1 migration expectation now targets v4. Bootstrap/readiness tests preceded the service module. The first 15 native cases pass; strict typing found unannotated storage-wrapper parameters, corrected by typing the Storage field.

Task 2: 16/16 native lifecycle cases and strict types pass. Injected faults at all four synchronization points quarantine the instance; exact owner retry resumes after a real runtime restart. Empty public requests leave no schema; complete missing-state and configuration-drift cases fail closed. A first-intent write fault initially left an empty schema behind; its regression failed, then passed after moving schema installation and first-intent insertion into one nested synchronous transaction. No public reset or delete path was added.

The full suite initially passed 178/180; two old conformance expectations still named schema v3/the pre-lifecycle table list. Updated those expectations to v4/xeip_service_state while retaining the actual row-preservation assertions. The already-started Linux copy predates the table-list correction and is not final evidence. No migration or runtime defect is inferred from these expected schema-shape changes.

Additional verification: 30/30 native lifecycle cases pass, including an exact v3→v4 copy of real signed trust, authority chain, consumed MCP claim and audit rows. Unknown target credential fields initially passed configuration validation; their regression failed, then passed after restricting target keys so extra secrets cannot enter the public runtime fingerprint. The first full Linux run passed 179/180 and failed only the known stale table-list expectation. Corrected local full suite passes 180/180 and strict types; corrected Linux repeat is in progress.
Ruling: the standard Git review package again rejects BASE=HEAD — use `/tmp/xeip-cloudflare-lifecycle-review-scope.md` and saved source baselines — cost if wrong: review depends on the named uncommitted files, not a commit diff.

Task 3 complete: local Node 26/macOS and pinned Node 22.23.3/Linux each pass 180/180 combined Cloudflare tests and strict Cloudflare types. Logs: `/tmp/xeip-cloudflare-lifecycle-all-verified.log`, `/tmp/xeip-cloudflare-lifecycle-node22-verified.log`. The 30 new cases include real signed requests/provider responses/MCP effects, bootstrap and result synchronization faults, missing-state refusal, expected-revision conflicts, readiness races and exact v3 data preservation. No shared Linux runtime code/dependencies changed; previous 199 organization tests and immutable artifact evidence remain applicable, and the experimental directory remains excluded from that artifact. Documentation and threat model are current. One scoped final review is now requested; no implementation changes during review.

Final review returned two Important findings, accepted after checking the composition: partial bootstrap lacks action/audit emptiness checks, and final execution authorization lacks ledger-health checks. Add real-workerd regressions before fixing; preserve completed retry semantics. Guard health both before and after asynchronous authorization, and validate empty action/audit state before resume and before the terminal transition. No new review cycle.

Review disposition: no Critical or Minor findings; both Important findings fixed. The original two real-workerd regressions failed with 200 instead of 500 for unexpected bootstrap data and one tool effect instead of zero after quarantine, then passed. A third case corrupts the ledger during final provider authorization; removing only the post-await health check reproduced one unwanted effect, and restoring it passes. Logs: `/tmp/xeip-lifecycle-review-red.log`, `/tmp/xeip-lifecycle-review-guards.log`, `/tmp/xeip-lifecycle-late-health-red.log`. Full post-fix platform checks are in progress.

Ruling: deployed owner authentication/IAM, actor attribution, runner and packaging remain open — reviewer declined because this batch exposes only internal owner APIs — cost if wrong: deploying them without the next control-plane boundary would expose privileged operations.
Ruling: hosted recovery, replica-loss fencing, capacity and Cloudflare deployment behavior remain acceptance gates — reviewer declined because local conformance cannot certify them — cost if wrong: latency and zero acknowledged-action loss remain unproven.
Ruling: inherited adapter internals and unrelated accumulated changes retain their earlier scoped evidence — reviewer examined only lifecycle integration — cost if wrong: this review is not a renewed whole-repository certification.
Ruling: prior-state detection deliberately covers the XEIP namespace; this object's database is exclusively owned by the adapter — reviewer declined to classify unrelated tables as organization state — cost if wrong: another application's tables are not a bootstrap blocker; production packaging must never share a database with another application. The spec/guide now say empty XEIP namespace rather than completely empty database.

The first post-fix full run passed 182/183; a test-edit replacement accidentally inserted the new phase parameter into the older policy-removal case, producing `ReferenceError: phase is not defined`. Restored that case's original OAuth hold; product behavior was unaffected. The already-started Linux copy has the same test typo and is superseded by a corrected full repeat.

Task 4 complete: the corrected post-review suite passes 183/183 tests (33 lifecycle cases) and strict Cloudflare types on Node 26/macOS and pinned Node 22.23.3/Linux. Final logs: `/tmp/xeip-cloudflare-lifecycle-final-local-corrected.log` (30.561s tests), `/tmp/xeip-cloudflare-lifecycle-final-linux-corrected.log` (64.392s tests). Both Important findings are corrected; no known scoped review findings remain. `git diff --check` passes. No shared Linux runtime code/dependencies changed in this batch; earlier organization/artifact evidence is carried forward, not reported as rerun. No cloud resources were provisioned and no production guarantee is inferred. Next: deployable private owner entrypoint/operator runner, production configuration/binding validation, then hosted route/capacity/recovery/security acceptance.
