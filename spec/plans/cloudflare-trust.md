# Cloudflare trust implementation plan

Use executing-plans inline and TDD. Keep the existing hardening branch and accumulated uncommitted work. Spec: [cloudflare-trust.md](../cloudflare-trust.md).

## Tasks

1. [x] Share verified provisioning preparation and monotonic checkpoint merging between the filesystem and Durable Object paths. Write direct helper regressions first, extract the existing rules without changing Linux behavior, add an explicit type boundary, and update the production artifact's allowlist. Expected: shared trust, relay and organization tests pass with existing behavior; helpers import without opening filesystem state.
2. [x] Add a checked version-2 SQLite trust schema and version-1 upgrade fixture. Test wrong checksum/catalog, missing or replaced trust state, checkpoint SQL invariants and preservation of action/audit/claim history. Expected: real workerd upgrade preserves consumed claims and refuses incompatible schema.
3. [x] Implement DurableEntityTrust open/update/use-time behavior against real signed fixtures. Test rollback/forks/removal, stale reopen and refresh, mutation isolation, concurrency, SQL/sync failure quarantine, restart and ledger authorization across a trust update. Expected: no unpersisted or stale candidate authorizes an action; internal completion survives revocation.
4. [x] Wire reproducible tests and strict types, update evidence/runbooks, verify Node 22/Linux and packaging, and perform one fresh-context final review. Fix accepted findings with failing-then-passing regressions in one pass. Keep provider/ingress/hosted recovery gates open.

## Files and interfaces

- `packages/identity/trust-state.mjs` and declarations: pure preparation and checkpoint validation/merge; existing relay EntityTrustPolicy/TrustCheckpoint become consumers.
- `tools/trust-state.test.mjs`: direct shared-rule regressions using existing signed vectors.
- `services/organization/cloudflare/schema.mjs` and migration fixture: checked v1→v2 trust-state/checkpoint SQL alongside the ledger.
- `services/organization/cloudflare/trust.mjs`, declarations and type configuration: durable trust, isolated activation, use-time checks and quarantine.
- `conformance/organization-cloudflare-trust{,-worker}.mjs`: test-only real workerd fixture with actual signatures and controlled storage/provider interleavings. Public Worker ingress remains 404.
- Docker allowlist and artifact checks: include the newly shared runtime helper, exclude experimental trust code and dev tools.
- Package/CI/docs: explicit conformance command and evidence; no new dependency or deployment configuration.

## Review focus

- Removal/re-enrollment and higher-tip historical forks must preserve rollback history.
- A failed/uncertain trust write must not authorize either the candidate or stale previous state in that instance.
- Restart must distinguish missing/corrupt state from explicit first initialization and must permit safe refresh of stale signed state.
- Await interleavings and caller mutation must not let stale authority produce a claim/effect.
- The new schema migration and shared extraction must preserve prior action history and Linux trust behavior.

## Rulings and evidence

Ruling: implement the next architectural step under the standing production-readiness instruction and explicit Cloudflare exploration choice, without repeating artifact-approval ceremonies — this is reversible repository work within the agreed exploration — cost if wrong: experimental work can be discarded; production adoption and deployment still require a concrete operator decision.
Ruling: use canonical spec/plan records, inline execution and the existing branch without commits or duplicate workspaces — preserves prior uncommitted work — cost if wrong: the final reviewer needs a precise scope package.
Ruling: share the existing synchronous Node verification/merge rules instead of copying them or changing the shared controller to asynchronous verification — preserves tested Linux interfaces and avoids divergent identity policy — cost if wrong: the worker bundle must demonstrate its Node-compatibility imports do not invoke CLI/filesystem state.
Ruling: implement persistent trust before actual provider/policy/ingress composition — independently proves the missing rollback and activation boundary — cost if wrong: trust tests must not be advertised as real Keycloak or full Worker-service acceptance.
Ruling: retain maximum-observed time within an instance plus persisted acceptance time, matching the existing identity profile — whole-host clock rollback and whole-database restore require a wider recovery authority — cost if wrong: deployment must not assume this checkpoint alone supplies those guarantees.
Pre-flight: preparation produces the exact candidate/chain maps consumed by both checkpoint adapters; version-2 migration changes the catalog verified by every ledger reopen; durable trust state feeds synchronous ledger authority checks. Packaging must include the extracted helper because existing runtime trust imports it.

Task 1 complete: 22 focused shared/refresh/checkpoint tests, 370 relay/tools tests and 199 organization tests pass; organization strict types pass. The first helper run failed on its missing module. One subsequent assertion expected ordinary rather than deliberately null-prototype records; correcting that value-only assertion resolved the test mismatch without changing implementation. Prior runtime sources were extracted from the previously verified image to `/tmp/xeip-cloudflare-trust-before/` for final review. Evidence: `/tmp/xeip-cloudflare-trust-{shared-red,shared-final,relay,organization,extraction-types}.log`. Packaging allowlists now include the new shared helper; the rebuilt image is checked in Task 4.

Task 2 complete: 6/6 real workerd schema/upgrade tests pass, including an injected error after new DDL which rolls back the migration and preserves version-1 action/audit data. Existing ledger conformance remains 40/40. The initial upgrade/table tests failed before version 2 existed; the migration-fault test then exposed the missing harness injection, which was added. Evidence: `/tmp/xeip-cloudflare-trust-{schema-red,schema-final,migration-red,ledger-migration}.log`. Version 1 is frozen under conformance fixtures; its checksum/catalog are checked before migration.

Task 3 complete: 24/24 real workerd trust/schema scenarios pass and adapter types pass. Actual signed documents drive revocation, removed-entity history, same-counter/higher-tip forks, stale reopen, explicit initialization, SQL/sync failures, timeout/close gating, mutable input, corrupt state and complete runtime restart. Claim/effect interleavings use the shared ledger/executor with real signed trust and a clearly synthetic provider callback; no real identity provider or external effect is involved. Initial runtime tests failed with missing fixture operations before implementation. Expanded fault cases mostly verified the implemented boundary directly; one failure was an obsolete Miniflare stub used after disposal, corrected to use the reopened runtime stub. Evidence: `/tmp/xeip-cloudflare-trust-{runtime-red,runtime-green,runtime-types,faults,faults-final,faults-types}.log`.

Task 4 verification before review: combined real workerd suites pass 64/64 on Node 26/macOS and pinned Node 22.23.3/Linux, with Cloudflare and organization strict types passing. The corrected Linux regression fixture passes 370/370 relay/tools and 199/199 organization tests. The first broad Linux command omitted example console assets and schemas, producing four unrelated missing-file failures; a subsequent copy command referenced a nonexistent root fixtures directory and stopped before testing. Correcting the fixture input paths resolved all failures without application changes. Evidence: `/tmp/xeip-cloudflare-trust-{combined,node22,node22-complete}.log`.

The rebuilt `xeip-organization:local-cloudflare-trust-review` image is `sha256:190231a3fbc89e0bf55e1f343b2d0c54c83950b2bbb1e8a9bd62109c84fdc3c2` (67,328,623 bytes). Isolated artifact inventory/import/non-root/read-only and redacted missing-configuration checks pass; the shared helper is packaged and experimental adapters/tools remain excluded. Evidence: `/tmp/xeip-cloudflare-trust-image-{build,smoke}.log`. One fresh final review completed as `cloudflare_trust_review`, scoped by `/tmp/xeip-cloudflare-trust-review-scope.md`.

Task 4 complete: the reviewer found no Critical, Important or Minor issues and independently passed 24/24 trust tests plus strict Cloudflare types. No corrective pass or repeat review was needed. Relay strict types and the 63 tracked JavaScript syntax checks also pass; new adapter files are exercised by the test/type suites. Evidence: `/tmp/xeip-cloudflare-trust-{relay-types,js}.log`. No findings were deferred. The scoped experimental batch is complete; the broader authority/backend and production-readiness tasks remain open.

Final: Ruling: real Keycloak, protected policy/binding administration, signed ingress and MCP transport were excluded from this review — these remain explicit subsequent integration gates, and synthetic tests cannot establish them — cost if wrong: deploying the adapter alone would lack a complete authorization/transport boundary.
Final: Ruling: hosted replication, PITR, acknowledgment reconciliation and whole-database rollback were excluded — local tests cannot establish provider guarantees; require external recovery fencing and hosted drills — cost if wrong: lost acknowledged actions or replay after restore.
Final: Ruling: whole-host clock rollback was excluded — retain the documented instance/persisted acceptance-time floors and require a broader time/recovery authority before certification — cost if wrong: stale authority could appear fresh after infrastructure rollback.
Final: Ruling: throughput, retention, long rotation histories and maximum-bound capacity were excluded — count/byte/JSON structural bounds are safeguards, not measured support for the rollout; explicit workload and history-growth acceptance remains required — cost if wrong: exhaustion or latency failures under real use.
Final: Ruling: malicious full-database and metadata rewriting was excluded — checksums protect integrity consistency, not a compromised trusted owner; operational access controls and recovery authority remain necessary — cost if wrong: compromised storage ownership defeats these invariants.
Final: Ruling: multiple simultaneously live trust adapters were excluded — enforce the documented one-adapter-per-live-object ownership during composition; no cross-instance lock is claimed — cost if wrong: stale in-memory authority could survive another adapter's update.
Final: Ruling: earlier ledger/controller/provider implementations were reviewed only as context — this single review covers the trust batch, with prior batch reviews retained in their own ledgers — cost if wrong: this verdict cannot stand in for whole-product security acceptance.
Final: Ruling: retain the current branch and all uncommitted work, with no merge/push/deployment or workspace deletion — the standing production-readiness goal continues and the user has not requested integration of an incomplete product — cost if wrong: accumulated work still needs an explicit reviewed release boundary later.
