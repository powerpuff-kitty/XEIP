# Organization action policy and ledger plan

Spec: [organization-actions.md](../organization-actions.md). Scope follows the user's instruction to continue to production readiness and the accepted human-approved internal MCP workflow. Execute inline; final fresh-context review after implementation, then fix verified findings. Existing uncommitted hardening branch remains the authorized workspace.

- [x] Build strict, immutable deny-by-default action policy with tests first: exact session/role/target/tool membership, action content digest, bounded JSON, expiry, self-approval and mutation defenses. No network execution.
- [x] Pin PostgreSQL client and test image after provenance/version checks. Implement versioned migration and transactional action/audit store. Test against an isolated real database with concurrency and crash/recovery cases.
- [x] Connect policy to authenticated and trusted principals with durable approval/revocation/claim transitions. Cover same-subject and same-entity self-approval, policy changes, stale principal, edited arguments, conflicting retries and duplicate claims.
- [x] Verify all checks and document integration contract, operational requirements and remaining gates. Perform one independent implementation review and regression fix pass.

Ruling: select PostgreSQL for the action ledger because atomic action/decision/audit changes and concurrent single-use claims require durable transactions. This does not replace the local transport log or certify database operations. Cost: an additional operated service and explicit backup/migration work.

Ruling: an ambiguous effect is never automatically retried. This prioritizes avoiding duplicate privileged actions; cost: operator reconciliation may be necessary after a crash.

Pre-flight: authentication produces immutable subject/entity/key/client/roles/expiry principals; policy consumes those fields only after the caller authenticates and validates current entity trust. The database persists canonical action bytes/digest and the policy revision; execution must compare them before acquiring a claim. No caller-provided endpoint or secret is accepted.

The user selected 500 users, 200 agents and 120 action requests/minute for workload testing on 11 October 2026. Latency/recovery SLOs and concurrent connection assumptions remain open. Do not equate the selected target with passing capacity evidence.

Initial verification: 19 policy tests pass; strict organization type checking passes. A real PostgreSQL fixture passes immutable retries, approval/digest checks, eight concurrent claims with one winner, rejected/revoked actions, atomic audit-failure rollback, a revocation/claim race and migration-checksum enforcement. The first crash drill exposed a fixture defect: Docker remapped its ephemeral host port. Database logs showed completed WAL recovery; the client kept its old port. The fixture now refreshes that port before testing recovery. Recovery and backup assertions must pass before they are credited.

Verified after fixture repair: `node conformance/postgres.mjs` exited 0 with all five assertion groups, including forced database kill/restart and `pg_dump`/`pg_restore` into a separate disposable database. A restored consumed claim remained non-replayable and its full audit event sequence matched. These are synthetic local drills, not a production recovery certification. The runtime database role and operational deployment still need explicit provisioning; this fixture uses an owner account.

`liveActionAuthorizer` composes provider revalidation and current trust for the requester and stored approving key after asynchronous provider calls. The store invokes it while holding the action lock and rechecks policy/expiry before transitions. A future transport must additionally validate signed requests, release authenticated principals and recheck before upstream effects. There is no executable HTTP service or MCP bridge in this plan's module boundary.

Ruling: consent is a short-lived explicit grant without retaining the approver's bearer; cap it at the earlier action/token expiry and require current local membership/key trust when claiming. Cost: disabling provider login alone does not revoke prior grants; explicit action, membership or key revocation is required and must be documented prominently.

## Final review and verification

One fresh-context review found no critical issue and three important integration defects: unauthorized actors could lock rows before local policy checks; expired or superseded actions lacked a read-only recovery lookup; and client-side database waits were not fully bounded. New regressions were observed failing before fixes. The store now checks local eligibility before locking/provider waits and again under the lock, adds currently authorized inspection independent of execution eligibility, requires bounded acquisition/query timeouts, destroys uncertain connections and caps authorization waits. An explicit expected digest remains mandatory on mutations.

The review's minor missing lost-commit drill was incorporated as verification of the important recovery fix. The real database fixture now commits a claim and injects loss of its response: the API reports unavailable, inspection finds `executing` without exposing a claim capability, and a second claim fails. Inspection also works after expiry and policy revision; unauthorized subjects are denied. No re-review was dispatched; the fix pass was verified by regressions and the combined suite.

Final local evidence (Node 26.8.1, macOS Docker Desktop, PostgreSQL 18.6 pinned image): `npm run coverage:organization` passed **60/60 tests** (59 unit tests plus the real database conformance file with six assertion groups), with **99.09% lines, 89.61% branches and 97.01% functions** across organization modules. Strict type checking passed. PostgreSQL backup/restore, forced kill, ambiguous commit and non-replay assertions all passed. `npm audit --audit-level=high` reported zero vulnerabilities. These claims apply to the module/test boundary, not the future HTTP/MCP service.

Supported-runtime check: **664/664** relay/tools, TypeScript SDK and organization unit tests passed on **Node 22.23.3, Alpine Linux**, in the pinned `node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402` image. The test container ran as the non-root `node` user, with a read-only source mount/root filesystem, temporary `/tmp` and no external network. This is local Linux-runtime evidence; remote CI and provider/database execution specifically on Node 22 remain separately configured checks. JavaScript syntax passed for all 87 tracked/untracked sources, changed relative documentation links and `git diff --check` passed.

Ruling on review exclusions: signed HTTP handling/MCP effects, UI, runtime least privilege, deployment durability, operator reconciliation, retention/encryption, provider internals and production capacity/security certification remain required subsequent gates. They are deliberately not credited by this module review. Cost: this foundation still cannot be deployed as a complete production service.
