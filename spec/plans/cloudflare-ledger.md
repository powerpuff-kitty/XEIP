# Cloudflare ledger implementation plan

Execute inline using executing-plans and TDD. Spec: [cloudflare-ledger.md](../cloudflare-ledger.md). Keep the existing uncommitted hardening branch; this adds a local experimental adapter without adopting or deploying it.

## Tasks

1. [x] Add the isolated workerd/SQLite conformance harness and schema initialization. Pin tooling, bind storage to organization/schema, enforce immutable rows and a bounded action quota. Write failing scope/schema/constraint tests before implementing the schema.
2. [x] Implement the six ledger operations against synchronous transactions with late local revision/policy checks and explicit durability waits. Test the real SQLite state/audit history, idempotency, conflicts, expiry and quota.
3. [x] Verify concurrency, revocation across awaits, rollback/sync failures, lost claims and runtime restart. Exercise the shared executor with a fake effect counter to prove ambiguous claims and retries do not repeat effects.
4. [x] Wire strict type checking, a reproducible local/CI command and evidence documentation. Confirm existing organization behavior and packaging remain intact. Run one fresh-context final review, fix findings with regressions in one pass, and update the readiness record.

## Files and interfaces

`services/organization/cloudflare/schema.mjs`: explicit versioned SQL, checked initialization and storage-scope binding.
`services/organization/cloudflare/store.mjs`: `ActionLedger` implementation, local authority contract, failure quarantine and bounded asynchronous authorization.
`services/organization/cloudflare/contracts.d.ts`, `tsconfig.json`: minimal structural SQLite/storage/authority types, without hiding implementation errors behind untyped platform globals.
`conformance/organization-cloudflare-worker.mjs`: test-only Durable Object/entry point, synthetic principals/authority controls and fault injection. Never a deployment entry point.
`conformance/organization-cloudflare.mjs`: real Miniflare runner, scenario assertions, isolated persistent temp directory and deterministic cleanup.
Root package/CI: exact dev-only tooling and one explicit conformance command. The existing runtime container must exclude the experimental adapter and test dependencies.

## Review focus

- Local authority or action changes between provider checks, synchronous commit and durability return.
- A claim committed but not returned, followed by retry/restart, must not produce another effect.
- A SQL/audit/sync error must not return a successful mutation or execution capability.
- Caller mutation, malformed stored state or unexpected schema/scope must not weaken the existing policy contract.
- Synthetic harness controls must not become a deployable unsigned API; production adoption remains gated on actual trust/auth/recovery integration.

## Rulings and evidence

Ruling: proceed with the local architectural prototype under the standing production-readiness instruction and explicit Cloudflare exploration choice — no further authorization is needed for reversible repository work; adoption, hosting purchases and deployment remain undecided — cost if wrong: experimental adapter work could be discarded without changing the operating service.
Ruling: use canonical `spec/` records and inline execution on the existing branch, without commits or duplicate skill workspaces — preserves accumulated work and its evidence — cost if wrong: the final reviewer must use the explicit batch scope instead of assuming HEAD is its baseline.
Ruling: implement the storage adapter before the independently substantial signed-trust/provider/ingress port — it directly tests the new backend's riskiest transaction/claim semantics, and no API may use it as production authority yet — cost if wrong: local ledger success could be overstated as a complete Cloudflare service; documentation and packaging must prevent that claim.
Ruling: retain a bounded 10,000-action prototype with no deletion — protects replay history while retention is unresolved — cost if wrong: it cannot sustain production retention and must not be advertised as the full rollout capacity.
Pre-flight: schema and store share exact row names/version checks; the store consumes current authority callbacks from the test-only object; the runner drives interleavings/faults without a real provider or tool; no Linux runtime imports or routes change.

Task 1 complete: actual workerd/SQLite schema tests pass 4/4. Initial missing-module RED was followed by a harness-only module-root startup error, fixed by setting Miniflare modulesRoot to the temporary bundle directory. A meaningful dropped-trigger regression then failed (reopen incorrectly accepted), and schema catalog fingerprint validation made it pass. Evidence: `/tmp/xeip-cloudflare-schema-{red,green,drift-red,final}.log`. Toolchain is pinned at Miniflare 4.20260730.0 / workerd 1.20260730.1.

Task 2 complete: lifecycle implementation followed the missing-operation RED; all 12 real SQLite tests pass, including quota, immutable completion, bounded grants, mutable-principal refusal and exact audit history. Strict adapter types pass. Evidence: `/tmp/xeip-cloudflare-ledger-{red,green,lifecycle,types}.log`.

Task 3 complete: 23/23 real workerd tests pass, including actual runtime restart with persisted SQLite, concurrent decisions/claims, provider timeout, authority/row/expiry changes during awaits, SQL rollback, failed sync and completion, and at-most-one fake effect. Two initial failures exposed harness gaps (stale pre-send authority and absent terminal-audit injection); both were corrected and the scenarios passed. Evidence: `/tmp/xeip-cloudflare-ledger-faults-{red,green}.log`. This tests failure responses and local persistence, not hosted physical durability or PITR.

Task 4: Ruling: retain the tested stable Miniflare/workerd versions and use Miniflare-scoped patches for sharp 0.35.2→0.35.5 and undici 7.28.0→7.29.1 — the full npm audit found three high-severity package findings, while the registry's newer Miniflare line is a major alpha; the patch overrides minimize runtime/API churn — cost if wrong: overrides need removal when a tested stable upstream release incorporates them, and both local/Linux harness runs must verify compatibility. Sources: [Undici 7.29.1 security fixes](https://github.com/nodejs/undici/releases/tag/v7.29.1), [sharp 0.35.5 release](https://github.com/lovell/sharp/releases/tag/v0.35.5), `/tmp/xeip-cloudflare-dependencies.json`. Neither dependency belongs in the production image.

Task 4 verification before final review: patched local Node 26 and pinned Node 22.23.3/Linux each pass 23/23 ledger scenarios and strict adapter types. Existing organization suites pass 199/199 on both platforms; organization/console strict types pass. Full npm audit reports zero known vulnerabilities across the locked graph. Actionlint identified two pre-existing shell warnings (combined export assignment and unused loop variable); both were corrected and actionlint passes. The rebuilt image passes isolated non-root/read-only/network-none checks, including exclusion of the experimental adapter and Miniflare/workerd from files and SBOM. Evidence: `/tmp/xeip-cloudflare-patched-{local,node22,image-build,image-smoke,audit.json}`, `/tmp/xeip-cloudflare-{organization,node22,ci-lint-fixed}.log`. Final independent review is in progress; do not mark the batch complete until findings are resolved.

Packaging evidence: final patched local image `xeip-organization:local-cloudflare-ledger-review`, digest `sha256:941c8d4a5a28a1dc8877e1454a5053f6127f70e723341e76f19d9096dfddaced`, size 67,327,639 bytes. Pinned Node 22/Linux verification image: `node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392` (Node 22.23.3). Temporary verification containers exited and were removed; unrelated user containers were left alone.

Final review: `cloudflare_ledger_review` independently passed 23/23 workerd tests and strict adapter types. It found two Important issues, no Critical or Minor issues: SQLite replacement bypasses delete-based immutability, and scalar/canonical action/grant disagreement can permit a duplicated canonical action under another row key. Both findings are accepted at Important because they violate this adapter's promised storage invariants, despite requiring malformed/internal SQL state rather than ordinary caller operations. Fix both in one regression-backed pass; no re-review.
Final: Ruling: hosted replication, physical durability, PITR, account loss and restore fencing remain open acceptance gates — local tests cannot establish provider recovery — cost if wrong: unearned durability assurance.
Final: Ruling: production trust, provider authentication, Worker ingress and real MCP transport remain the next integration work — synthetic callbacks are not a deployable authority — cost if wrong: an incomplete backend mistaken for production.
Final: Ruling: capacity, retention and latency remain unverified — the bounded quota deliberately prevents a production-scale retention claim — cost if wrong: rollout exhausts retained-action capacity or misses the SLO.
Final: Ruling: preserve earlier hardening evidence and review only its relevant integration boundaries here — this review is scoped to the new adapter — cost if wrong: unrelated defects are not rediscovered.
Final: Ruling: accept parent packaging verification, which checks the actual rebuilt artifact — reviewer did not repeat Docker execution — cost if wrong: no second independent build-provenance check; supported release remains open.
Final: Ruling: frozen accessor/proxy principals are outside the trusted authentication-output contract; retain plain immutable provider-issued data as the integration requirement — no untrusted object becomes a principal in this prototype — cost if wrong: a future authenticator violating that requirement could expose mutable authority.
Final: Ruling: the schema is an integrity defense, not a sandbox against arbitrary code inside the owning object — fix the demonstrated SQL invariants without claiming protection against code that drops guards or rewrites all state — cost if wrong: operators overestimate protection from a compromised deployment.

Final: fixed SQLite replacement bypass — actual workerd regressions first allowed resetting approved, executing and terminal action state, audit actors and organization metadata. Replacement-resistant BEFORE INSERT guards and claim-collision checks now reject it without depending on recursive delete triggers. The claim-collision regression already passed via foreign-key protection; do not claim it failed first. New schema protections are included in the checked catalog fingerprint.
Final: fixed scalar/canonical disagreement — SQL now binds session, request ID and action/grant expiry, admits only pending initial actions, and every adapter read verifies canonical bytes/digest, row-key/expiry relationships and state/result consistency. Malformed data quarantines with StoreUnavailable before inspection or a claim. Thirteen initial regressions failed; a focused inspection run additionally demonstrated six read-integrity failures. All 40 scenarios now pass with strict types (`/tmp/xeip-cloudflare-review-{red,green}.log`, `/tmp/xeip-cloudflare-read-integrity-red.log`, `/tmp/xeip-cloudflare-reviewed-local.log`). No findings were deferred and no second review was dispatched.

Task 4 complete: final reviewed code passes 40/40 real SQLite/workerd scenarios and strict adapter types on both Node 26/macOS and pinned Node 22.23.3/Linux. The organization suite remains 199/199; its earlier Node 22/Linux run also passed 199/199. CI lint, full dependency audit and isolated image verification passed as recorded above. Review fixes affect only the excluded experiment, its tests and documentation, so the verified image is unchanged. Final logs: `/tmp/xeip-cloudflare-reviewed-{local,node22,organization}.log`. Hosted CI has not run. The experiment is complete at this scope; production identity/trust/ingress, retention, capacity/recovery and operator acceptance remain open.
