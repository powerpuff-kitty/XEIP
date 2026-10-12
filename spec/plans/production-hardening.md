# Production hardening implementation plan

**Goal:** Resolve the audited correctness defects and establish measurable release gates for a self-hosted deployment serving one organization.

**Architecture:** Keep the local reference relay loopback-only. Commit durable writes before exposing messages or recording replay acceptance. Add delivery metadata to the SDK without changing base envelopes. Changes to identity binding and signed extension semantics require a new profile, never reinterpretation of signed-envelope 0.1.

**Tech stack:** Node >=22, TypeScript 5.9.3, Rust >=1.81; no new runtime dependencies for the initial repairs.

**Spec and evidence:** [Repository audit](../audits/2026-10-10-repository-and-market.md), [production readiness](../../PRODUCTION_READINESS.md), existing local profile specs.

User authorization: create the audit document and start fixing/improving all findings. Deployment target explicitly selected: self-hosted for one organization. Execution: inline on `audit/production-hardening`; no publish, merge, deployment or release is implied.

## Initial implementation batch

### Task 1 — Durable acceptance and replay consistency (A1)

Files: `services/relay/{durable,replay,relay-core}.mjs`, new combined-profile regression tests, durable/replay specs.

- [x] Write a real-filesystem regression: accept one message, make `manifest.json.tmp` a directory, send another with admission/replay/fsync always, expect non-success; remove the fault and ensure retry never returns accepted/duplicate for the failed send.
- [x] Verify failed sends are absent from retention and do not evict an earlier accepted message; close/reopen and prove recovery and retry.
- [x] Run `node --test services/relay/acceptance.test.mjs`; observe failure before implementation.
- [x] Commit replay records only after a synchronous acceptance operation succeeds. Keep `ReplayWindow.accept(message, elapsedMs)` compatibility for existing callers.
- [x] Reserve sequences before disk writes but expose/evict retained entries only after write completion. On an uncertain disk error, mark the writer degraded and refuse subsequent writes until reopen; do not compact uncertain state on close.
- [x] Report durable failure as a non-success transport outcome and expose degraded health. Do not promise exactly-once recovery.
- [x] Run relay tests and document recovery behavior.

### Task 2 — SDK delivery events and recovery (A2)

Files: `sdks/typescript/src/index.ts`, `sdks/typescript/index.test.mjs`, SDK README.

Interfaces: add `deliveryEvents(session, entity, signal?, after?)` yielding `{type:'message', message, seq?}` or `{type:'gap', session, from}`. Retain `events()` yielding envelopes, but throw a typed gap error rather than silently lose history.

- [x] Write tests for gap-before-message ordering, sequence preservation, malformed/unsafe cursors, mismatched sessions, interrupted UTF-8 and cancellation on early return/error.
- [x] Build existing SDK and run the new tests; confirm missing behavior fails.
- [x] Implement the typed iterator and compatibility wrapper; reject malformed gap/sequence data and invalid UTF-8.
- [x] Test against a real relay with retention eviction and reconnect, then run all SDK and interop tests.

### Task 3 — Maintainable boundaries and verification (A5)

- [x] Introduce focused runtime contracts for the touched acceptance/delivery interfaces; avoid an unneeded general plugin system.
- [x] Strengthen JS static verification beyond syntax for a bounded set of dependency-free policy modules, then ratchet coverage rather than suppress existing errors globally.
- [x] Run static checks and the project suites.

### Task 4 — Current truth and versioned architecture (A3, A4, A6–A8)

- [x] Reconcile README, release/security text, durable/receipts profiles and identity implementation status from source/tests.
- [x] Document a separately versioned stable-entity signing design, required conformance negatives, extension integrity, trust freshness and migration rules.
- [x] Link the audit and production gates from README/ROADMAP.
- [x] Record verified fixes separately from planned work and preserve historical audit evidence.

## Review focus

1. Storage failures after partial writes or fsync: ambiguity must not become a successful duplicate.
2. Failure with a full retention window: previous accepted records must remain recoverable.
3. A gap immediately followed by backlog: no API may silently report continuity.
4. Malformed metadata/UTF-8 and early consumer exit: fail and close the response stream.
5. Profile version compatibility: no weakening of self-certifying 0.1 signatures or implied authentication of unsigned extensions.

## Verification and rollback

Run `npm run check:js`, schema vectors, TypeScript typecheck/build, Node tests/coverage, SDK tests, Rust fmt/Clippy/tests, interoperability and local demos. Check Markdown links and whitespace. Review the complete diff with a fresh reviewer. No production designation follows merely from green unit tests.

Initial changes must not alter the durable on-disk format or base envelope schema. Revert source/API changes as a unit with matching docs/tests if needed; retain backed-up durable directories for diagnosis. New SDK APIs are additive; the old iterator's gap exception is an intentional correctness change. Publish compatibility notes before an SDK release.

## Progress and decisions

- Baseline: audit recorded at `1dcfdec`; baseline suites passed in the preceding audit.
- Decision: work on a dedicated branch in the existing clean checkout so changes remain visible in the user's workspace; no additional worktree was created. Dependencies were subsequently installed with scripts disabled to verify the updated type-only lockfile.
- Decision: ship bounded correctness repairs first. A3/A4 require coordinated protocol/SDK/Rust work and an independent review; their design and release gates are part of this batch, but the current profile will not silently change.


## Completed first batch — 10 October 2026

- **A1 repaired:** replay acceptance follows storage success; failed append does not expose/evict retained messages; storage and compaction failures stop the writer until recovery; partial writes complete before publication, zero-progress writes fail, real directory-sync errors propagate. Both explicit and automatic compaction failure paths are covered. Reserved interior/trailing sequence holes now produce a conservative gap warning before retained backlog.
- **A2 repaired:** `deliveryEvents()` exposes received cursors and gaps; `events()` raises `DeliveryGapError` on discontinuity. Invalid metadata, wrong sessions and invalid/incomplete UTF-8 fail visibly; cancellation and reader release are verified. A real HTTP reconnect regression exercises eviction and cursor resume.
- **A5 started:** strict `checkJs` contracts cover `primitives`, `replay` and `limits`, with a CI gate. Runtime package extraction, identity-module decomposition and remaining relay type coverage are still open.
- **A6 reconciled:** current locking, compaction, durable receipts, root rotation and pinned Actions are reflected in the README, security/release/roadmap and profile documents. Batch-mode power-loss/cursor limitations are explicit.
- **A3/A4, A7/A8 planned:** versioned stable-entity/extension integrity design and G1–G7 production evidence are recorded in `PRODUCTION_READINESS.md`. These are not implemented production capabilities.

### Review and decisions

One independent fresh-context review inspected the entire batch. Four important storage findings (short writes, swallowed directory-sync errors, interior gaps and compaction generation failure) were reproduced with regressions and repaired. Minor gap wording and incomplete UTF-8 EOF coverage were also addressed. The EOF test additionally caught a reader-lock cleanup omission, now fixed. No review findings were intentionally deferred within this batch; wider audit items remain tracked below.

- Ruling: preserve the current signed-envelope profile and design a successor — silently changing identity binding would break its security contract; cost is that stable parent/device identity remains a production blocker.
- Ruling: retain the existing gap wire shape and all available messages — a gap signals any missing sequence in the requested session range; `from` remains the oldest retained sequence, so applications must reconcile rather than infer the exact missing interval.
- Ruling: preserve the branch and uncommitted changes in the user's checkout — no merge, publication or deployment was requested; integration remains pending.
- Dependency decision: exact `@types/node@22.20.5` and transitive `undici-types@6.21.0` are MIT-licensed development declarations, with no package lifecycle scripts; no runtime dependency was added. `npm ci --ignore-scripts` reproduced installation and the advisory scan reported zero known vulnerabilities.

### Verification evidence

Local environment: macOS x86_64, Node 26.8.1, Rust 1.94.1 and minimum supported Rust 1.81.0. Node 22/Linux remains a CI verification requirement, not a locally observed result.

| Check | Result |
| --- | --- |
| Full relay/tools suite with coverage gates | 279 passed, zero failures; 93.70% lines, 88.23% branches, 96.41% functions |
| TypeScript SDK | 208 passed, zero failures |
| JS/TS/Rust interoperability | 32 passed, zero failures |
| Rust workspace, both 1.81.0 and 1.94.1 | 78 passed and one intentionally ignored test per toolchain |
| Rust formatting and Clippy with warnings denied | Passed |
| JS syntax, focused strict JS types, SDK typecheck/build | Passed |
| JSON Schema fixtures and shared vectors | Passed |
| All nine local demos | Passed with their required local configuration |
| npm advisory scan | Zero known vulnerabilities |
| Changed Markdown local links and diff whitespace | Passed |

Coverage is for the relay/tools/shared JavaScript measured by the existing command, not the SDK TypeScript or Rust. Tests cover injected filesystem faults and clean recovery; they do not certify arbitrary power loss, physical disk failure or a production filesystem. The initial unconfigured demo invocation failed because it requires a token and running relay; its configured rerun passed. The failed regression runs were observed before their respective fixes.

Local run logs are under `/tmp/xeip-hardening-*.log` (ephemeral); rerun the commands above for release evidence tied to an eventual commit and artifact.

## Initial implementation queue — historical

This queue records the audit's starting scope on 10 October 2026. Subsequent decisions and implementations are recorded below. Use [production readiness](../../PRODUCTION_READINESS.md) for current release gates and [the living plan](../../PLAN.md) for active work; the organization profile, Keycloak selection and workload/recovery targets have since been established.

1. **G1 / A3–A4:** accept a successor signing ADR/spec; implement stable identity, protected extensions and persisted fresh trust in JS/TS/Rust with shared negative vectors and independent review.
2. **G2 / A7:** select the organization's identity provider and action workflow; implement scoped, expiring authorization and approval binding with combined-profile adversarial tests.
3. **G3 / A8:** choose workload/SLO/recovery targets; compare the prototype with a transactional backend; certify acknowledged-write, process-kill, disk-full, partial-write, failed-truncation and backup/restore behavior. Define receipt persistence failure and duplicate-effect handling.
4. **A5 maintainability:** extract runtime crypto/validation packages from `tools`/SDK ownership, split Rust identity by responsibility, and expand strict static analysis one module boundary at a time. Keep cross-language vectors independent.
5. **G4–G5 / A7:** build the separate single-organization service with ingress, lifecycle, telemetry and operator controls; prove one real approved MCP/A2A/device workflow and independent client.
6. **G6–G7:** publish reproducible supported artifacts only after compatibility, security and recovery gates; complete operator pilot/load/restore/revocation drills and assign maintenance ownership.


## Second batch — trust enforcement and recovery boundaries

Continuation authorized by the user's “continue”. This batch repairs the existing profile contracts before introducing a successor signing protocol. No external identity provider or production backend is selected implicitly.

- [x] Trust policy: reject missing status when status enforcement is enabled; recheck configured `maxAgeSeconds` at message time; reject future/unparseable issuance and keep observed wall time nondecreasing within the process. Preserve optional age configuration for the legacy local profile, explicitly unsuitable for production without a bound. Snapshot verified provisioning input so later object mutation cannot remove revocations.
- [x] Structure: extract provisioning and status decisions from routing into a transport-independent relay trust module, keeping the current signature/profile rules and health shape.
- [x] Recovery: refuse startup if torn-tail truncation or receipt quarantine/read fails; release the store lock on failed initialization. A receipt write/compaction fault must mark health degraded and stop further writes until reopen.
- [x] Receipt acceptance: commit in-memory receipt state only after backend append succeeds; return 503 for receipt storage errors. Preserve documented advisory budget saturation behavior (memory acknowledgment can outlive bounded persistence).
- [x] Verification: deterministic clock, filesystem-failure, HTTP/WebSocket and combined-profile regressions; full Node coverage, SDK/interop, static checks; final fresh-context review required by the inline execution workflow.

Rollback: revert this batch's source/tests/docs together; no on-disk or wire schema change. New 403/503 outcomes deliberately replace unsafe successful acceptance. Signing 0.1 still binds sender to its key-derived identity; stable parent/device binding and persisted trust remain G1 work.


### Second-batch review and decisions

The fresh-context reviewer confirmed three additional defects: compaction errors
were swallowed when a full receipt append had persisted nothing, failed lock PID
writes left an owned stale lock, and failed receipt `fstat` leaked a descriptor.
All were reproduced in failing regressions and repaired. Required compaction now
restores the previous bounded ledger on error; optional maintenance after a
completed append stays best-effort. Initialization cleans up only resources it
acquired, preserving another writer's existing lock.

Ruling: keep `maxAgeSeconds` optional in the existing local profile to preserve
its explicit opt-in behavior, but enforce any configured bound on every send and
document that an unbounded policy is unsuitable for production. A future production
profile must require freshness, refresh and persisted rollback state.

Ruling: preserve advisory receipt budget saturation, which may acknowledge only
in-memory state; actual attempted persistence errors produce 503. A failed request
can still have an ambiguous disk outcome and does not promise exactly-once effects.

The new trust policy module isolates provisioning and use-time decisions from
routing. It still uses the existing cryptographic implementations under `tools/`;
package extraction and cross-language successor-profile work remain open.

One new WebSocket test initially stalled during teardown because it closed the
server before its upgraded socket. Its socket is now closed in `finally`; the
configured test rerun passed. No production socket lifecycle change was needed.


### Second-batch verification — 10 October 2026

- Full Node relay/tools suite: **297 passed**, zero failures; measured coverage
  **93.77% lines, 88.85% branches, 96.19% functions**. The existing coverage gates pass.
- SDK: **208 passed**. Cross-language interoperability: **32 passed** on the final source.
- Focused strict JS types, SDK typecheck/build, schema/shared vectors, JS syntax,
  changed Markdown links and whitespace: passed.
- Trusted-key/status, receipt and durable demos: passed. The full Node suite was
  rerun after all review fixes; those specific regressions also passed separately.
- No Rust sources or dependencies changed in this batch; the previous 1.81/1.94
  workspace results remain the recorded Rust-unit baseline. Interoperability was
  rerun against the changed relay. Node 22/Linux certification remains CI work.
- Final fresh-context review: all three reported issues repaired and covered;
  no review findings intentionally deferred. Logs: `/tmp/xeip-batch2-*.log`.

The second batch is complete. G1 remains partial: stable entity/device binding,
protected extensions, mandatory bounded freshness, refresh, persisted trust and
independent cryptographic review are still needed. G2–G7 retain their production
evidence requirements. Changes remain uncommitted on `audit/production-hardening`.

## Third batch — entity-bound signing

The user authorized continuation of the successor signing work. The [separate implementation plan](entity-signed-envelopes.md) tracks JS/TS/Rust, relay checkpoints and validation against [ADR 0011](../decisions/0011-entity-signed-envelopes.md). Historical first/second-batch results above remain unchanged. Current readiness is maintained in [PRODUCTION_READINESS.md](../../PRODUCTION_READINESS.md).

## Fourth batch — live trust and production continuation

The user requested continued work until production readiness and selected self-hosted Keycloak. The [live trust plan](live-entity-trust.md) implements owner-driven atomic refresh, durable checkpoint transitions and device-bound activity/stream revocation. The intended pilot is a human-approved agent calling an internal MCP tool. The active goal continues through G2–G7; a completed batch is not production certification.

## Fifth and sixth batches — organization identity and action ledger

The [authentication plan](organization-auth.md) records a real Keycloak 26.8.0 integration and live revocation verification. The [action plan](organization-actions.md) records exact-content approvals, deny-by-default policy and PostgreSQL single-use claims with atomic audit. Its combined unit/database suite passes 60 tests, including lost-commit, kill/restart and backup/restore drills. Review findings were fixed with regressions; these remain internal module boundaries awaiting signed HTTP and MCP execution integration.

The accepted workload is 500 users, 200 agents and 120 action requests/minute. Concurrent-connection assumptions, latency/recovery SLOs, actual combined capacity evidence and external/operator acceptance remain open. Current gate status is in [PRODUCTION_READINESS.md](../../PRODUCTION_READINESS.md).

## Seventh batch — signed HTTPS and MCP execution

The [signed organization service plan](organization-service.md) connects Keycloak/entity signatures to the PostgreSQL action ledger and official MCP 2.3.1/protocol 2026-07-28 connector. Real-provider combined integration passed, including revocation after claiming and recovery of committed results after a lost response. One final reviewer found a missing authorization guard after database waits; the regression-backed fix rechecks immediately before COMMIT while preserving internal completion after client cancellation. Final coverage passes 127 entries (99.12/91.47/96.00). The 700-principal capacity run is in progress.

Accepted SLOs now specify P95 machine operation latency ≤2 seconds (excluding human review), restoration ≤1 hour and no loss of acknowledged actions, at 500 users/200 agents/120 actions per minute. These are acceptance targets, not certified production evidence. Runtime/configuration, operations, human approval UX, release artifacts and external/operator acceptance remain subsequent gates.
