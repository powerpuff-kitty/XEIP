# Signed organization service implementation plan

Spec: [organization-service.md](../organization-service.md). User authorizes continued implementation toward production readiness. Execute inline with tests first and one final fresh-context review; keep the current hardening branch and preserve uncommitted prior work.

- [x] Implement a transport-independent signed operation controller: strict envelope/body checks, bearer-to-signer binding, current trust, bounded timestamps, store operations, principal release and secret-free errors. Test real signed envelopes and mutation/revocation during asynchronous work.
- [x] Add the bounded HTTP handler with exact content type, UTF-8/duplicate-key/depth limits, request deadlines, Host/Origin policy and liveness/readiness separation. Keep public exposure in a later validated launcher; do not modify demo relay restrictions.
- [x] Verify and pin official MCP v2 client/server fixture dependencies; implement operator-pinned target configuration, discovery/auth boundaries and bounded tool results. Test a real SDK server independently of the bridge implementation.
- [x] Connect durable claims to upstream effects, record succeeded/failed/indeterminate outcomes and prove no automatic replay after disconnects or ambiguous persistence. Exercise real Keycloak/PostgreSQL/MCP end to end with exact human approval.
- [ ] Run supported runtime/static/coverage/interop checks and initial combined load measurements at the selected rollout size. Record measured limits, review/fix findings, update readiness and proceed to deployment/release/operational gates.

Ruling: keep an explicit signed organization-operation profile alongside existing envelope 0.1/experimental signing 0.2. This avoids silently reinterpreting local relay commands; cost: additional client/transport documentation and versioned compatibility checks.

Ruling: use current official MCP v2 rather than building against obsolete handshake assumptions. Upstream v2 is stable and implements protocol 2026-07-28; npm metadata currently lists client/server 2.3.1. Reverify installed APIs before implementation. Cost: new pinned dependencies and explicit interoperability limits for older peers.

Pre-flight: the controller must preserve the authenticator's exact immutable principal object because revalidation uses private token associations. The store expects that principal, an immutable ActionPolicy and `liveActionAuthorizer`; it never authenticates arbitrary caller objects. Only `claim` returns an internal execution capability; HTTP must strip it. `inspect` intentionally works after action expiry/policy revision and must not revive execution eligibility.

Ruling: construct a lightweight store facade per signed request through a trusted `createStore(authorize)` factory. Its authorization closure binds the exact authenticated principal and signed envelope deadline, and checks both again after provider waits. The store also rechecks this closure after database mutation/audit waits, immediately before initiating COMMIT. This prevents initiating a new commit after the signed window or cancellation has already become observable. A COMMIT already in flight can still have an ambiguous outcome and must be inspected. Cost: a small per-request object; the underlying database pool and immutable policy remain shared.

## Execution record

The local RSA/JWKS/introspection fixture was extracted without changing authentication behavior. Controller and HTTP tests were observed failing before implementation; additional timeout and cancellation regressions were observed RED then GREEN. The signed boundary now tests real JWTs, entity signatures/trust, wrong actor/key/session/recipient, mutation, expiry and revocation during provider waits, cancellation and principal release. HTTP bounds bodies, headers, concurrent work and readiness/operation deadlines, with real TLS verification and disconnect checks. Timed-out callbacks keep their concurrency slot until they settle. Strict organization checking passes.

Official client/server 2.3.1 dependencies are exact-pinned. The independent server fixture exercises protocol 2026-07-28, target-specific OAuth client credentials, exact resource/issuer/token endpoint pins, protocol metadata, tool errors, redirects, malformed/oversized responses, disconnects and cancellation. The connector permits only one tool POST and has no credential-refresh or interactive continuation retry. The first fixture omitted a required authorization metadata field; it was corrected without weakening production validation. All 13 connector checks pass.

Execution is connected through an internal durable claim, final identity/policy/trust gate and completion transaction. Migration 002 adds immutable bounded result storage while preserving migration 001's checksum/history. PostgreSQL RED exposed the missing stored approver; GREEN verified result persistence, immutable retry matching, lost-commit handling, abrupt database restart and backup/restore. Eight worker tests cover effect ordering, uncertain commits, revocation and failure classification.

The combined signed HTTPS/RSA-provider-fixture/PostgreSQL/official-MCP-server path passes concurrent execution (one winner), exact approvals, final-gate identity deactivation, explicit revocation, uncertain upstream outcomes and lost completion acknowledgement resolved by historical result lookup. The combined real-Keycloak/PostgreSQL/signed-HTTPS/official-MCP run subsequently passed with live provider revocation after the claim and lost completion recovery (`npm run test:organization:integration`, exit 0). The existing real Keycloak conformance test has been refactored into an owned fixture callback, adding a separate simulated approver service account. No actual human login or usability claim is made.

Ruling: retain the short, target-scoped consent grant semantics from the ledger; carry its stored approver internally to the final pre-send trust check, never in public claim authority. Result inspection uses the same current membership policy as action inspection. Cost: retained results require a production retention/encryption policy.

Ruling: classify any failed request after attempting the tool POST as indeterminate, including an auth rejection, unless a valid explicit MCP tool-error result is received. This is conservative because transport responses cannot prove whether an upstream effect happened. Cost: operators may need to reconcile some actions whose tools did not run; no automatic replay occurs.

The selected acceptance targets are now 500 users, 200 agents, 120 actions/minute, P95 machine operation latency ≤2 seconds excluding human review, restore ≤1 hour and no loss of acknowledged actions. Measurements and the final fresh-context review remain outstanding.

Verification update: Node 22.23.3 Alpine/Linux passed all 117 organization tests in an isolated non-root, read-only, network-disabled container. Organization strict checking passes. Combined unit/PostgreSQL/service coverage passed 116 test entries at 99.10% lines, 91.24% branches and 95.93% functions before two further connector regressions; all 15 connector tests now pass, including unsupported continuation and malformed UTF-8 (observed RED→GREEN). The v1→v2 upgrade fixture and 700-principal load test are running in the remaining acceptance work.

Ruling: start the single fresh-context final code review while the long disposable capacity fixture runs. Implementation and functional integration are complete; workload evidence remains explicitly pending and can prevent completion. Cost: performance changes prompted by the pending run will need their own measured regression evidence within the same final fix pass.

## Final code review and fix pass

A single fresh-context review (`organization_service_review`) found no Critical issue, one Important issue and one Minor. It independently ran 58 controller/HTTP/MCP/execution tests and verified Node 22 excess-header rejection. No second review is scheduled.

Final: fixed — authorization was not rechecked after mutation/audit SQL waits. `ActionStore` now revalidates client operations immediately before issuing COMMIT and rechecks current policy. All four mutation regressions were observed RED→GREEN. Four signed-controller cancellation/expiry regressions were additionally verified against the old behavior via a controlled temporary guard omission (4/4 failed), then against the restored fix (4/4 passed). Internal completion deliberately bypasses client authorization so attempted effects are still recorded after cancellation. A regression verifies that distinction. Real PostgreSQL now verifies rollback of both state and audit for late denial of each mutation. Cancellation after COMMIT has been issued remains ambiguous and requires inspection.

Final: minor (deferred): RELEASING.md's full local command list omits organization verification. Track this in G6 release preparation; CI and CONTRIBUTING already require the service checks.

Final: Ruling: earlier separately reviewed relay/SDK/cryptographic batches are not reopened in this review — service interfaces and regressions are covered here; cost: independent whole-product security review remains required.

Final: Ruling: this code review and zero npm advisory findings are not cryptographic or dependency certification — G1/G7 external review stays open; cost: no production security acceptance claim.

Final: Ruling: launcher, ingress, secrets, runtime roles, drain, monitoring and supported artifacts remain explicit subsequent gates — current code is a tested service library, not a deployment; cost: operators cannot yet deploy a supported release.

Final: Ruling: simulated service-account approvers do not demonstrate human PKCE login, approval display or consent usability — the human workflow remains a separate implementation/acceptance gate; cost: load success alone cannot authorize a human pilot.

Final: Ruling: the independent MCP fixture does not certify an actual organizational tool, partial-effect reconciliation or idempotency — retain no-retry semantics and require target/pilot evidence; cost: ambiguous actions need operator investigation.

Final: Ruling: local backup/kill drills do not certify production disks, restore time, exhaustion/corruption, encryption or retention — G3/G7 stay open; cost: no production durability/SLO claim.

Final: Ruling: workload results remain pending until the 700-principal run completes; the earlier run was stopped before measurement to incorporate the commit guard. The corrected upgrade fixture has now passed with real PostgreSQL. Cost: no capacity acceptance until the final report passes.

Final: Ruling: hosted CI has not run in this workspace, and the reviewer did not review the later guard fix — local regression/coverage/runtime checks provide fix evidence under the one-review workflow; cost: hosted release gates still must run before release.

Fixture correction: the new historical-schema test initially lost its password because `pg.Pool.options.password` is non-enumerable. Explicitly copying that field and preserving the original error fixed the fixture; a real PostgreSQL rerun passed upgrade, ledger and signed-service checks. No production credential or timeout validation was weakened.

Final fix verification: combined organization unit/PostgreSQL/signed-service coverage passed **127/127**, **99.12% lines, 91.47% branches, 96.00% functions**; strict organization checking passed. Root relay/tools regression suite remains **365/365**. The v1→v2 migration and all four late-denial rollback cases passed against real PostgreSQL. Post-fix Node 22/Linux passed **126/126** organization unit tests. Capacity remains in progress.

Capacity setup evidence: the second attempt exhausted its 15-minute setup deadline while Keycloak was still importing the 700 synthetic service-account clients (running, no OOM; sampled 571 MiB / 1 GiB and active CPU). No operation measurement began and no latency verdict is inferred. Ruling: allow up to 45 minutes for population fixture bootstrap, retaining 15 minutes for ordinary integration and every existing request deadline, population size, rate and P95 threshold. Cost: a longer local fixture run; this is not a claim that production startup or recovery meets its target. A third attempt is running with progress output.

Subsequent setup diagnosis supersedes the longer-bootstrap approach: after 21 minutes, a Java thread sample showed the main thread spending CPU in Hibernate `PersistentMap.equalsSnapshot`/collection pre-flush while creating the bulk-imported clients. The third attempt was stopped before measurement and its owned container removed. The fixture now imports only its small base realm and provisions the remaining 698 clients/service accounts in six-wide, separate [Keycloak Admin REST API](https://www.keycloak.org/docs-api/26.8.0/rest-api/index.html) transactions, then removes its temporary fixture-only administration client. Startup is back to 15 minutes; population setup has a separate bounded deadline. Actual identities, roles, live introspection, request rate and latency thresholds are unchanged. Fourth attempt is running; this fixes fixture setup, not an observed application bottleneck.

Capacity attempt four completed with a FAIL: 11 completed actions; successful-response P95 20.7–28.0 seconds, extensive timeouts/unavailability and pending-limit saturation. The setup successfully provisioned 200 agents/500 simulated approvers via bounded Admin API transactions, but only 302 approvers were exercised before early stop. See [durable results](../audits/2026-10-11-capacity-attempt-four.md). Diagnostic instrumentation and a comparable rerun remain required; no workload or latency acceptance claim is made.
