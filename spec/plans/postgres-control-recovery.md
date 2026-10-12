# PostgreSQL control recovery implementation plan

> For agentic workers: implement inline under the continuing production-readiness
> authorization, using test-first changes and scoped review. Preserve the existing
> worktree; no commit, migration of an operator database or deployment is implied.

**Goal:** prevent stale trust/configuration restored beside a current action ledger
from authorizing new work, and recover accepted control history with database WAL.

**Architecture:** PostgreSQL owns the Linux runtime's public authorization history
and current head. An immutable in-memory snapshot is usable only at that head.
Owner enrollment/configuration changes are explicit; runtime trust reloads publish
durably before activation. The loopback relay keeps its filesystem implementation.

**Stack:** existing Node 22+, PostgreSQL 18, `pg`, strict JSDoc checks and shared
identity validators. No new dependency or Cloudflare change.

**Contract:** [control recovery](../postgres-control-recovery.md),
[ADR 0018](../decisions/0018-postgres-control-history.md),
[reproduced failure](../audits/2026-10-12-linux-control-recovery.md).

## Constraints and review focus

- Preserve previous migration bytes/checksums, signed wire formats, all consumed
  claims, retained removed-entity high-water records and current runtime privilege
  restrictions. A12 is not fixed until the composed runtime refuses the stale case.
- Input ceilings: configuration 4 MiB; provisioning 8 MiB and 4096 entries;
  retained checkpoint 8 MiB; canonical combined control event 24 MiB.
- No secrets in control records, diagnostics or fixtures' retained evidence.
- No automatic enrollment from a populated legacy ledger, automatic restoration
  activation, replay of ambiguous effects or retention deletion.
- Each task's verification must exercise uncertain commits, missing/omitted state,
  stale cached authority, wrong organization/expected head and close/cancellation
  at its relevant boundary. Negative checks are mandatory, not just round trips.
- A new public-control protocol/profile change must explicitly revise the projection;
  silently ignoring a newly introduced authority field is unsafe.

## 1. Define and test canonical control state

Files: new `services/organization/control-state.mjs` and `.test.mjs`;
`services/organization/configuration.mjs`, `tsconfig.json` as needed.

Interfaces:

- `publicAuthority(configuration)` consumes validated `loadConfiguration` output
  and returns an isolated canonical public projection with a domain-separated
  SHA-256 digest. Whitelist every nested property; never spread a credentials-bearing
  object. Include `introspectionClientId` as well as provider/public client settings.
- `prepareControlState({authority, provisioning, previous, retainedRecords, operation, acceptedAt})`
  consumes the projection, complete signed input, an operation (`enroll`, `authority`
  or `trust`) and an integer UTC-second acceptance time. Enrollment requires
  `retainedRecords` and forbids `previous`; later changes require the previous
  complete canonical snapshot and forbid independent replacement records. It returns
  `{state, canonical, digest}` with immutable JSON and preserved removed identities
  and target revision mappings. Trust-only changes must preserve public authority.
- `verifyControlState(canonical)` returns the same shape after validating a bounded
  historical snapshot and its signed provisioning at original acceptance time. It
  does not prove chain continuity, independent durability or current freshness.

- [x] Write negative tests first: altered binding/session/target endpoint/revision,
      removed active entity, rollback/fork, invalid signature and oversize combined
      state must alter or reject authority as appropriate; unrelated password/TLS
      material must never appear in bytes or change the public authority digest.
- [x] Pin default values explicitly (token maximum lifetime is 300 seconds) and
      test absent/default equivalence. Preserve the policy's existing array-order
      semantics; do not normalize permission arrays differently from ActionPolicy.
- [x] Test target revision reuse with changed endpoint/OAuth settings, including
      remove/re-add and A→B→A histories; reject reused revisions for different
      execution settings. Test that `trust` cannot re-add any removed entity while
      explicit `authority` publication with the expected head can do so safely.
- [x] Implement strict projection and state validation with immutable snapshots,
      fixed redacted errors and no storage/network side effects.
- [x] Run focused tests, `npm run typecheck:organization`, `npm run test:organization`
      and shared identity regression cases; record actual scope and results.

Example required assertions against a valid configuration fixture:

```js
assert.equal(publicAuthority(rotatedSecrets).digest, publicAuthority(original).digest);
assert.notEqual(publicAuthority(changedBinding).digest, publicAuthority(original).digest);
assert.doesNotMatch(publicAuthority(original).canonical, /synthetic-secret/);
assert.throws(() => prepareControlState(olderSignedStatus), /control state/);
```

## 2. Persist immutable control history under the existing commit contract

Files: new `services/organization/control-store.mjs`, its tests and forward SQL
migration; `schema.mjs`, `database.mjs`, `store.mjs`; extract a small shared
`transactions.mjs` only to reuse the proven synchronous transaction behavior.
Conformance: new `conformance/organization-control.mjs` using `withPostgres`.

Interfaces: `ControlStore` accepts a bounded `pg.Pool`. `enroll` requires an empty
head/action/audit ledger; `open` validates organization and expected public input;
`publishTrust` requires the exact prior head/configuration and complete verified
state; `changeAuthority` is owner-only; each successful result returns an immutable
`{revision,digest}` token. `assertCurrent(client, token)` locks/checks the head in
the caller's action transaction. SQL and API representations must not silently
coerce out-of-range revision numbers.

- [x] Preserve existing action transaction behavior through extraction with current
      replication-warning/ambiguous-commit tests running before and after.
- [x] Test real SQL enrollment, mismatch/empty refusal, stale expected heads,
      concurrent publishers, immutable history, trigger/privilege restrictions,
      missing/tampered head/events, retained omitted identities and wrong scope.
- [x] Add migration and runtime privilege/readiness checks. Runtime grants permit
      trust updates only, never fresh enrollment, public-configuration replacement,
      deletion or history rewriting. Enforce this in SQL, not only JS callers.
- [x] Test cancellation/lost COMMIT notices and reopened/idempotent responses with
      synchronous standby unavailable. No success result may bypass the WAL marker.
- [x] Run real PostgreSQL, historical upgrade, organization types/tests and replication
      evidence. Confirm previous action/audit records and checksums are unchanged.

## 3. Compose asynchronous PostgreSQL trust with the Linux lifecycle

Files: new `services/organization/postgres-trust.mjs` and tests;
`main.mjs`, `lifecycle.mjs`, relevant contracts and runtime tests.

Interface: asynchronous factory `openPostgresTrust` consumes enrolled `ControlStore`,
validated public configuration/provisioning and current time. Returned trust exposes
the existing `allows`, `verify`, `status`, `updateAsync`, `close` contract plus its
current immutable control token. It must not create or clear a filesystem checkpoint.

- [x] Convert the actual stale-restore finding into a failing composed-runtime test:
      latest DB control state plus old files cannot expose an executing listener.
- [x] Prepare trust in the existing bounded worker, persist the exact full state,
      and activate only after certain durable success and current freshness checks.
- [x] Test close/cancel before, during and after commit; failures must never enable
      the old cache after a possible durable revocation. Startup/reopen must compare
      current input and durable state and emit only fixed error codes.
- [x] Test empty, removed, expired, corrupt and mismatched trust; preserve loopback
      relay behavior and shared cryptographic vectors.
- [x] Run startup/lifecycle/organization suites and semantic checks.

## 4. Fence action authorization and dispatch against control changes

Files: `store.mjs`, `authorization.mjs`, `controller.mjs`, `execution.mjs`,
contracts and tests; actual PostgreSQL integration cases.

- [x] Add failing tests that pause an authorized request, publish a revocation or
      permission change, then resume it. An old snapshot must not acknowledge a
      new claim/effect after the accepted change.
- [x] Take/check the control-head lock in each authorizing action transaction;
      recheck live provider, expiry and cancellation after waits. Define one lock
      order across control and action rows to prevent inversion/deadlocks.
- [x] Introduce the dispatch/publication barrier and connector dispatch callback
      described by the contract. Invoke the tool fetch synchronously after final
      guard checks while holding a permit. Hold exclusive publication through
      database commit and snapshot activation, or unavailability on uncertainty.
      Test a pause after successful asynchronous revision validation: publication
      winning prevents dispatch; dispatch winning precedes publication. Preserve
      single-use claims when dispatch is prevented.
- [x] Test a control change after the tool POST begins: completion still persists
      under the original consumed claim; no new authorization or automatic retry.
- [x] Run concurrent claim/reload/finish and lost-response scenarios against real
      PostgreSQL, plus signed HTTPS/MCP and real Keycloak fixture regressions.

## 5. Provide explicit owner enrollment/change commands

Files: new `services/organization/control-maintenance.mjs` and tests;
configuration helpers, package scripts, `OPERATIONS.md` and deployment templates.

- [x] Add protected owner input and exact expected-head arguments; validation must
      finish before mutation. Separate enrolling an empty organization from changing
      an enrolled one. Keep schema migration a separate operation.
- [x] Preserve complete existing filesystem records during enrollment; refuse a
      legacy populated ledger and missing/invalid history. Document the required
      reconciliation rather than inventing a migration acceptance receipt.
- [x] Enforce drained-runtime coordination for authority changes; test stale heads,
      concurrent runtime access and interrupted command results. Print only bounded
      public head identifiers and fixed result codes, never raw input/errors.
- [x] Use a dedicated bounded PostgreSQL connection for the lifetime/maintenance
      lease, not a borrowed work-pool slot (a valid max=1 work pool must not deadlock).
      Test observed lease loss, shutdown and commands racing startup. External
      fencing after unobservable partitions remains a separate acceptance gate.
- [x] Test actual restricted runtime denial of owner operations and successful owner
      workflow against disposable PostgreSQL. No operator database is touched.

## 6. Restore control and action state together

Files: `conformance/organization-archive-recovery.mjs`, replication/corruption
drills as needed, conformance README/CI and operations/readiness records.

- [ ] Extend the physical base-backup/WAL drill with a post-backup revocation,
      removed entity and owner configuration change alongside action transitions.
- [ ] Destroy the owned source, recover to the required paused target, compare exact
      action/audit/control histories, and refuse old file inputs without any tool
      call. Missing later WAL must refuse the required target.
- [ ] In the disposable promoted candidate only, verify current inputs preserve
      denial and original consumed claims; use the actual runtime path. Never make
      fixture promotion an operator activation procedure.
- [ ] Rebuild the Linux artifact and verify its full runtime inventory/startup;
      run affected suites and strict checks on native and pinned Node 22/Linux.
- [ ] Measure bounded maximum current-state startup and full offline history
      verification separately at 1, 365 and 8760 control events, recording actual
      bytes and entity count. These model daily/hourly updates over one year;
      they are test workloads, not an accepted retention policy or RTO proof.
- [ ] Obtain scoped review, address findings, preserve failures and exact evidence,
      and close A12 only when the runtime-level requirements above are demonstrated.

## Rollout and unresolved acceptance

Implementation is local first. A new schema requires explicit owner migration and
enrollment before the updated service starts. Old code lacks the new control fence
and cannot be a safe rollback after control publication; keep ingress closed and
use a reconciled supported artifact. No automatic down migration or historical
state deletion is part of this plan.

This work closes one application recovery boundary. Independent acknowledgement
evidence, accepted synchronous storage topology, external old-writer fencing,
Keycloak account/credential recovery, secret custody, history retention/sizing,
hosted 500/200/120 workload and one-hour operator recovery remain mandatory. A fully
rolled-back database cannot identify its own newer missing history unaided.

## Execution record

- 12 October 2026: current implementation inspected; initial disposable real-PG
  probe reproduced A12 with one synthetic effect and no external tool call.
- Durable evidence probe added under `spec/audits/evidence`; its result is historical
  defect evidence, not green production acceptance. Product implementation pending.
- Scoped design review identified dispatch/publication ordering, endpoint changes
  under reused target revisions, removal/re-add semantics and unbounded startup
  scans. The contract now defines a dispatch barrier, immutable target revision
  mappings, explicit owner re-addition, and bounded current-state verification with
  full offline history verification. Required regression/measurement steps added.
- Corrected design review reports no remaining important contradictions. The
  repository-relative probe repeats the original result (exit 0 asserting the
  defect); JSON result and ten source fingerprints are retained beside it. Syntax,
  local document links and whitespace checks pass. Both owned PostgreSQL fixtures
  are cleaned. No product code or deployed service changed during this investigation.
- Task 1 implemented in `services/organization/control-state.mjs`, with strict
  organization type checking enabled for the actual source. Public projection
  excludes credentials/paths, normalizes token lifetime and pins all accepted
  authority fields. Signed transitions retain removed records and immutable target
  mappings; historical reads validate exact canonical data at original time.
- Baseline stub fails the new behavior cases (`/tmp/xeip-control-state-red.log`).
  First implementation passes 9/11: two fixture endpoint changes violate the
  existing MCP same-origin metadata/token rules before reaching the intended
  assertion. Correcting only those fixture URLs gives 11/11; no endpoint policy
  was weakened. Initial JSDoc cast syntax was also corrected before the type pass.
- Scoped review found a non-string operation-tag bypass: `['trust']` passed a
  coercing enum check and skipped trust-only restrictions. Primitive-string guards
  in both preparation and historical verification fix it. A separately identified
  explicit-null token lifetime also no longer defaults silently. Both regressions
  fail before the fixes (`/tmp/xeip-control-state-enum-red.log`) and pass afterward.
- Review's coverage gaps are covered by permission-array ordering and a prepared
  state containing individually valid large sections whose combined bytes exceed
  24 MiB. A temporary 32 MiB limit makes the latter fail with the intended missing
  rejection (`/tmp/xeip-control-state-combined-limit-red.log`); exact source restored
  before final checks. The source-limit probe copy is retained in `/tmp`.
- Final native verification on Node26.8.1: 15/15 focused (7.13s), 231/231 organization (11.76s),
  385/385 root (21.96s), strict organization types and all fixture vectors pass.
  Logs: `/tmp/xeip-control-state-{final,organization,root,types-final,vectors}.log`.
  Combined command exits 0. No SQL, runtime wiring, artifact or cloud deployment
  changed; Node22/Linux verification follows the integration milestone, not this
  native-only claim. A12 is still open; task 2 is the next dependency.
  Source fingerprints: `/tmp/xeip-control-state-sources.sha256`; source syntax,
  local document links and whitespace checks pass.

- Task 2 storage implementation: `ControlStore`, migration003 and trigger/readiness
  grants now implement explicit empty-ledger enrollment, expected-head publication,
  exact-input reopen, bounded historical validation and transaction-held head locks.
  The shared `boundedPool` and `transaction` bodies are byte-identical to the saved
  pre-extraction source `/tmp/xeip-store-before-control-transactions.mjs`. Existing
  migrations001/002 SHA-256 values match `/tmp/xeip-control-migrations-before.sha256`.
- Initial actual-PG stub fails owner enrollment (`/tmp/xeip-control-store-red.log`).
  First implementation exposed an invalid aggregate JSON node budget, corrected by
  preserving each model section's limits. SQL execution then exposed JSONB operator
  precedence and an alias collision with the trigger's OLD record; both corrected.
  Temporary local diagnostics were removed and the exact transaction helper restored.
- Direct restricted-SQL cases exposed null/omitted counter bypass and then a validly
  signed alternate predecessor under increasing counters. Both regression cases
  fail before correction and pass afterward: `*-raw-sql-red.log`/`*-raw-sql-green.log`
  and `*-chain-red.log`/`*-chain-final.log`, all prefixed `/tmp/xeip-control-store`.
  SQL now requires safe integer counters and retains exact signed chain prefixes for
  entities remaining active. Final conformance stores seven events, including a
  legitimate chain extension; alternate history, owner operations, active-set
  additions, stale publishers and damaged heads are refused.
- Final native evidence: 18 control-store fault/unit cases; 249/249 organization and
  385/385 root cases; strict organization types. Actual PostgreSQL historical upgrade,
  action/service/restricted-role tests pass. Upgrade preserves original action/audit
  rows and old checksums, leaves control tables empty, and refuses enrollment over a
  populated legacy ledger. The pre-existing migration-count assertion was updated
  from two to three after its expected failure.
- Final replication evidence (`/tmp/xeip-control-store-replication-final.log`) refuses
  cancelled control publication and reopen acknowledgements, preserves acknowledged
  control events across local failover, and retains eight actions/four claims. The
  archive drill (`/tmp/xeip-control-store-archive-final.log`) with migration003 passes:
  nine actions, 23 audit events, four consumed claims, zero repeated effects;
  18,637.894595ms local recovery interval. Its control tables are empty: post-backup
  trust/configuration restoration remains task6, not proved by this existing drill.
- Pinned Node22.23.3/Linux strict types and 52/52 affected model/store/database tests
  pass (`/tmp/xeip-control-store-linux.log`). The Linux/amd64 image rebuild and isolated
  non-root inventory/integrity/startup smoke pass (`*-image-final.log`,
  `*-artifact-final.log`). The image contains migration003 and the extracted shared
  helper; the new unwired ControlStore is exercised from source, not a claimed runtime
  integration. No cloud deployment, operator database or real credentials changed.
- Scoped review began but its agent stopped under an automated cybersecurity-content
  filter before a verdict. Its preliminary chain-continuity concern was reproduced
  and fixed above; this is not a completed independent review. Root storage task stays
  in progress for review closure. Task2 implementation/verification checklist is
  satisfied locally; tasks3–6, including actual A12 regression and operator recovery,
  remain open. Production status remains NO-GO.
- Closing actual-PG check also removes the current event and its immediate
  predecessor under fixture-owner trigger bypass, verifies reopen refusal, restores
  exact rows and verifies normal reopen. Seven-event conformance passes at exit0
  (`/tmp/xeip-control-store-pg-closed.log`); no owned primary fixtures remain.
  Current source fingerprints: `/tmp/xeip-control-store-sources.sha256`. Source
  syntax, affected JS formatting, changed document links and whitespace checks pass.


### Task 3 execution evidence (2026-10-12)

- Actual launcher now composes `openPostgresTrust` and `ControlStore`. It refuses
  unenrolled/old inputs before provider readiness or TLS listeners, prepares current
  trust off-thread and reopens the exact head before activation. Publication disables
  local authority until certain durable success; late close/cancel cannot reactivate.
- Fourteen lifecycle tests pass. The actual-PG regression preserves one approved,
  unconsumed action, rejects old provisioning, and records zero synthetic effects
  after revocation. Current inputs start the real TLS listeners. Provider readiness
  and revalidation are synthetic here; real organization acceptance remains open.
- Scoped lifecycle review found full ControlStore signature validation still blocked
  the event loop. Three reproductions failed with no timer progress/missing cancellation.
  Complete validation now runs in an 8-second/128 MiB worker; 22 store plus 14 trust
  cases pass, including deadline termination before enrollment and cancellation.
- Recorded logs `/tmp/xeip-postgres-trust-{worker-focused,control-final,runtime-final,
  replication-final,organization-final,root-final,artifact-verified,linux-final}.log`
  show focused36, organization267, root385, strict types, actual SQL, replication and
  non-root Linux artifact success. Linux Node22.23.3 runs235 top-level organization
  tests, not the full267 suite. The stronger approved-action run is separately in
  `/tmp/xeip-postgres-trust-action-regression-final.log`.
- Fixture-only corrections: signed envelope omitted an unsupported critical extension;
  artifact authority uses a valid session URI; synthetic principals and roles are frozen.
  Failures are retained in the preceding logs; no validation was weakened.
- Actual-PG700-entity measurements: open855005 canonical bytes/2219.921ms,190 timer
  ticks,67.026ms largest gap; publication855004 bytes/4401.498ms,386 ticks,35.175ms
  largest gap. This establishes event-loop progress, not the selected2s hosted SLO,
  maximum accepted size, aggregate memory or whole-organization recovery.
- Task3's local contract is satisfied. SQL independent review remains incomplete;
  tasks4–6 and external acceptance keep A12 and production readiness open.

### Task 4 execution ledger

- Previous goal turn was a requested status response, with no code progress. Rechecked
  current source and recorded task3 logs, reconciled its checklist and began task4.
- Lock order: shared control head, then action row; publication takes its existing
  publication advisory lock and exclusive control head. Finish takes only action row.
  Local publication may invalidate a pending transaction, which rolls back; it cannot
  authorize under a replacement snapshot. The current asynchronous tool guard still
  needs the separate synchronous dispatch boundary.

- Implemented `ActionControlFence`/`ControlDispatchFence`: request token captured
  before acquisition, shared control-head lock before action rows, late current-state
  check before commit, durable head validation before provider revalidation, and
  synchronous dispatch around actual MCP fetch. The launcher supplies both fences.
  The reusable ledger primitive's isolated conformance mode does not claim production
  authorization. Internal outcome recording remains unfenced and never reclaims work.
- RED evidence: `/tmp/xeip-action-fence-red.log` fails eight missing transaction/fence
  cases; `/tmp/xeip-dispatch-fence-red.log` fails three dispatch-gap cases, including
  an actual official-MCP fixture receiving a call despite dispatch refusal;
  `/tmp/xeip-execution-fence-red.log` fails both executor validation cases.
- Review during implementation found provider validation preceding a potentially
  blocking durable head check. `/tmp/xeip-dispatch-provider-red.log` reproduces an
  effect after provider denial changes during that wait. Reordered head validation
  before live provider revalidation; all11 executor cases then pass.
- Restricted PostgreSQL fixture passes four-action race: publisher is observed waiting
  on the action control-head lock; invalidated claim rolls back; stale separate trust
  cache is refused despite locally valid signatures; publication-first prevents the
  effect while retaining its consumed claim; dispatch-first records success after
  revocation. Exactly two consumed claims, one synthetic effect, no replay. Evidence:
  `/tmp/xeip-action-fence-pg-first.log`. Provider/tool effects here are synthetic.
- Independent scoped reviewer found no Important/Critical findings and independently
  ran63 focused tests successfully. It read but did not rerun the PostgreSQL race.
  Task5 leases, task6 physical recovery and broader SQL review are excluded from its
  verdict, not inferred complete. Existing SQL review still lacks a final verdict.
- Native final organization285/285 and root385/385 pass; organization and Cloudflare
  strict types pass. Head-check fault cases26/26 include cancelled/lost COMMIT notice
  and failed WAL marker refusal. Full real-provider integration, Linux and rebuilt
  artifact verification are still running/pending; do not mark task4 closed yet.

- Linux/amd64 image rebuild and isolated artifact smoke pass. The smoke covers
  non-root immutable inventory, runtime/maintenance imports, identity/control workers
  and redacted CLI refusal. Manifest597d3d76…; exact hashes and log fingerprints are
  retained in `spec/audits/evidence/2026-10-12-postgres-action-fence-results.json`.
  Real-provider integration and full pinned Linux suite remain in progress.

- Real Keycloak integration completed at exit0: pinned provider JWT/JWKS/mapping,
  introspection and live revocation; actual PostgreSQL upgrade/restricted grants,
  lost responses and consumed claims; signed HTTPS exact approvals, concurrent
  single MCP effect, post-claim denial and durable result resolution. This existing
  fixture uses its separate controller composition, not the new launcher enrollment
  workflow. Final four-action fence regression passes again after provider ordering.
  Logs: `/tmp/xeip-action-fence-{integration,pg-final}.log`.

- Final actual launcher stale-startup/approved-action regression and synchronous
  replication drill also pass. Cancelled action/control COMMIT and reopen responses
  remain unavailable; eight acknowledged actions/four consumed claims survive local
  failover (1879.640732ms fixture interval, not hosted RTO). Logs:
  `/tmp/xeip-action-fence-{trust-final,replication-final}.log`.

- At this handoff only the pinned Node22/Linux full285-case suite is live: exec
  session71048, log `/tmp/xeip-action-fence-linux.log`. It uses read-only/networkless
  Node22.23.3,2 CPU/2 GiB, sequential test files; do not start a duplicate on an
  observation timeout. Integration39224, image/artifact47749 and final PG sequence48302
  are terminal exit0. Task4 stays in progress until the Linux result is inspected.
  No source change, cloud deployment, commit or operator database mutation is pending.

- Linux session71048 terminated exit1:280/285 pass; five fixture-cleanup cases
  cannot create their private Docker-shim state. Minimal same-container probe proves
  `/tmp` was implicitly mounted `noexec`; spawning a synthetic Node shebang there
  returns EACCES before any fixture create. This is the test harness mount, not a
  control-runtime failure. Preserve `/tmp/xeip-action-fence-linux.log` and
  `*-linux-exec-probe.log`. Rerun with executable temporary storage solely for the
  subprocess shim; retain network-none/read-only-root/non-root/capability restrictions.
  Do not alter the production artifact or skip the five cases.

- Corrected Node22.23.3/Linux run26503 completed exit0: strict types and285/285 full
  organization/console/fixture-cleanup cases,75852.547329ms. Only test temporary
  storage gained execute permission for the private shim; network-none, read-only
  root/source, non-root, dropped capabilities and resource limits stayed in place.
  Original280/285 result and EACCES probe remain recorded. No runtime code was changed
  to bypass the failure. Final log: `/tmp/xeip-action-fence-linux-final.log`.
- Task4 completion contract is now satisfied locally. All tool sessions from this
  task are terminal; no test process needs polling or restarting. Next: task5 dedicated
  lifetime/maintenance lease and explicit owner enrollment/change commands. A12 and
  production readiness remain open; broader SQL review is still incomplete.


### Task 5 execution ledger

- Previous goal turn made verified code/evidence progress: task4 completed with
  native285/root385, Linux285, actual PostgreSQL races/replication, real provider
  integration and rebuilt artifact. All its handles are terminal; resume task5.
- Use a dedicated `pg.Client` with bounded connect/query waits and exclusive session
  advisory key1480935760,3 for both runtime lifetime and owner maintenance. Immediate
  try-lock refusal prevents queueing an unexpected second service. Observe client
  error/end plus bounded periodic heartbeat; loss invalidates authority synchronously.
  Do not release the lease before drain/outcome recording/work-pool closure completes.
  Existing schema maintenance also must participate. This is database session
  coordination, not evidence that an old isolated infrastructure writer is fenced.

- Lease foundation implemented and tested: contention, normal close versus failure,
  client error/end, heartbeat, cancellation during acquisition and bounded close.
  Initial full-schema fixture failed because `pg.Pool.options.password` is
  non-enumerable; a unit regression confirms spreading omitted it. Explicit credential
  preservation fixes the dedicated connection without logging it. Real restricted-PG
  ownership checks pass with max1 work pool and backend termination.
- Runtime composition acquires before trust/listeners, invalidates trust synchronously
  on observed loss and signals `control_lease_lost` for supervised nonzero exit.
  It retains ownership until drain and work-pool closure. Actual launcher regression
  first failed because a maintenance-held lease did not prevent listeners; it now
  passes and observes readiness loss/shutdown after termination of the lease backend.
- Owner command implementation must bind its database mutation to the lease session,
  not merely hold a second connection while committing on a work pool: otherwise a
  terminated lease backend could permit another runtime before the owner's separate
  transaction completes. Preserve the dedicated runtime connection; select a scoped
  owner-session transaction adapter before adding the commands/schema-maintenance
  integration. This dependency remains open, not inferred from runtime lease tests.

- Continuation classification: the preceding status turn inspected and confirmed
  terminal native/Linux296 and artifact results; the independent lease reviewer
  supplied a concrete connection-cancellation finding. This turn reproduced and
  fixed that finding rather than repeating the status report.
- The real pg/TCP stalled-authentication regression initially remained pending after
  cancellation (`/tmp/xeip-control-lease-connect-red.log`). Driver inspection confirms
  intentional `end()` suppresses the pending connect callback. Both acquisition
  awaits now race the lease failure notification and then check opening state;
  late success cannot activate. Focused19/type checks passed, and the independent
  reviewer closed the P2 finding. Cancellation during the advisory-lock wait is also
  required to settle before the fixture releases its late result.
- Added `openControlMaintenance`: a bounded sequential transaction adapter over
  the locked Client. Normal transaction release retains ownership; broken release
  closes it, concurrent borrows refuse, and heartbeat skips a borrowed transaction.
  `maintainDatabase` uses it across schema migration and runtime grants; the protected
  CLI remains the configuration boundary. Shared transaction/store types accept the
  minimal connection-acquisition interface without changing runtime pool behavior.
- Actual PostgreSQL first reproduced schema maintenance succeeding while a runtime
  lease was held (`/tmp/xeip-owner-session-pg-red.log`). After wiring the adapter, the
  drill passes: maintenance refuses active runtime ownership, normal maintenance
  succeeds after drain, transaction PID equals lock-holding PID, and termination
  during an uncommitted insert rolls it back before a new runtime takes ownership.
  No replacement backend is available through the invalidated owner adapter.
- Scoped review found no important issue in the owner-session integration. Its minor
  fluent-method escape was reproduced: `client.on()` returned the raw Client. The
  adapter now returns its guarded handle when a pg method returns the original
  Client. Regression RED→GREEN, 14 lease cases and strict organization types pass.
  Full native/Linux suites, rebuilt artifact and final actual-PG launcher/lease
  checks are running against this source; no broader acceptance claim yet.

#### Remaining owner-command implementation contract

- Provide explicit `enroll --owner-config … --runtime-config … --expect-empty`
  and `change --owner-config … --runtime-config … --expected-revision …
  --expected-digest …` commands. Reject unknown/repeated arguments and malformed
  tokens before connecting. Reuse protected configuration loaders and require both
  configurations to identify the same database host/port/name. Never print either
  configuration, credentials, provisioning, or raw driver errors.
- Reuse the same-session owner adapter for every control mutation. No replacement
  pool/session may continue after loss. Prepare and verify complete signed inputs
  before publication, preserve all retained records, and recheck command/session
  cancellation. The command does not start listeners or claim that its inputs will
  remain fresh indefinitely; startup performs current freshness checks separately.
- Read legacy `trust.json` without constructing `TrustCheckpoint` (its constructor
  writes state). Coordinate any import with its existing exclusive `LOCK` convention,
  keep ownership through the database operation, preserve removed-entity records,
  and refuse missing/malformed/oversized or unsafe files. Fresh enrollment and
  existing-checkpoint import need explicit, tested handling; never interpret an
  unreadable existing directory as empty history. A populated legacy action ledger
  remains a reconciliation gate, not an automatic fresh enrollment.
- Return only a fixed result code and bounded public revision/digest. Treat interrupted
  or uncertain publication as unavailable; exact-head reinspection/reconciliation
  is required before an operator retries. Add actual-PG owner success, runtime-role
  denial, stale expected head, active-runtime exclusion and interrupted-result tests.
  Publish operations examples only once those paths are implemented and verified.

- Final verification for the runtime/schema-maintenance ownership slice: native
  organization300/300 and pinned Node22.23.3/Linux300/300 pass with no skips or
  cancellations; strict organization types pass in both environments. Actual-PG
  lease/mutation and composed-launcher drills pass. Rebuilt immutable non-root image,
  inventory, worker imports and redacted refusal checks pass. Image manifest list
  `sha256:566828850f1ae68696896d1a7db781ac39ead96f34e109eab595f1aa7ff78875`.
  All handles are terminal. Exact source/log fingerprints and scoped exclusions:
  `spec/audits/evidence/2026-10-12-postgres-owner-session-results.json`.
  The lease checklist item is complete; task5 overall remains in progress because
  explicit control enrollment/change commands and checkpoint import are not yet
  implemented. Task6, broader SQL review and external acceptance remain open.

- Continuation classification: previous goal turn made code/evidence progress,
  completing runtime/schema ownership with native300/Linux300, actual PG interruption
  and artifact checks. It left task5 owner commands as the next executable dependency.
- Implemented protected owner `enroll`, exact-head `change`, and historical `inspect`.
  Inspection deliberately requires only the owner configuration, verifies the current
  stored snapshot/adjacent head links and acknowledges through the shared durability
  transaction; it does not activate trust, verify the entire chain or establish an
  independent rollback boundary. Successful output is only fixed event/revision/digest;
  invalid CLI paths/arguments and failures produce one fixed nonzero error code.
- Legacy import now shares the existing exclusive LOCK convention, preserves complete
  records without constructing the writing TrustCheckpoint class, checks lock/directory
  identity, and removes only its own reservation. Existing incomplete/unsafe history
  refuses. Fresh absence is reserved temporarily, not materialized as invented history.
  Unit regressions cover corrupt/missing/oversized/duplicate/symlink/writable files,
  concurrent imports and replacement locks. Read helpers reuse protected configuration
  validation and strict bounded JSON parsing.
- Owner preflight validates current signed inputs before connecting, requires matching
  owner/runtime database host/port/name and separate users, and snapshots authority and
  provisioning. Publication runs on the lease session. Cancellation during final close
  initially reported success; a fault-injected regression reproduced this and a final
  cancellation check now refuses it. Both commands and worker preparation remain bounded.
- Actual PostgreSQL CLI tests pass using private protected files and verified TLS.
  Enrollment preserves a removed entity's record and leaves legacy checkpoint bytes
  unchanged. Exact-head changes succeed, stale heads and restricted SQL credentials
  refuse, active runtime ownership excludes commands, and cancellation during an
  observed blocked SQL read leaves the control head unchanged. Historical inspection
  succeeds after the provisioning file is removed. Separate fresh/legacy databases
  prove initial enrollment and refusal of an existing action/audit ledger respectively.
  Initial fixture run failed only because deepStrictEqual compared a canonical null-
  prototype record to an ordinary object; field-wise exact comparison fixes the test
  without changing production data. Preserve `/tmp/xeip-owner-command-pg-first.log`.
- Scoped owner-boundary review reports no important code findings and independently
  passes69 focused tests. Operations documentation now covers syntax, immutable target
  revisions, complete legacy import, uncertain results and historical-only inspection.
  Native322/322 and pinned Node22.23.3/Linux322/322 pass with no failures, skips or
  cancellations; strict types and rebuilt artifact checks pass. Task5 is locally
  complete. Exact results and fingerprints are recorded in
  `spec/audits/evidence/2026-10-12-postgres-owner-command-results.json`.

- Broader SQL review completed with one unresolved P2 retained-history finding.
  Restricted raw SQL can apparently replace retained counters/digests on removal;
  inactive snapshot verification then accepts an incompatible owner re-addition.
  Model acceptance is reproduced; real PostgreSQL exploit reproduction remains
  pending. Freezing inactive records alone is insufficient: invalid active metadata
  can be laundered through later removals, and invented inactive keys are accepted.
  Correction must bind retained metadata to verifiable signed history and prevent
  invalid intermediate transitions from becoming trusted history. Add direct-removal,
  multi-event laundering and invented-key regressions. Preserve applied migration
  checksums. Task2 SQL acceptance remains open; task5 workflow evidence does not close
  this finding, A12, task6 physical recovery or external production acceptance.
