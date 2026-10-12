# Cloudflare administrative audit implementation

Spec: [administrative audit](../cloudflare-admin-audit.md). Inline execution, existing branch/worktree, preserve uncommitted changes.

1. [x] Add v5 append-only journal schema and internal adapter with native failing-then-passing persistence, corruption, bounds, pagination and capability tests. Adapter stages synchronous writes; service owns durability barriers before effects/acknowledgments.
2. [x] Integrate production owner mutations, atomic first initialization and quarantine. Add private bounded export and strict operator receipt validation. Verify real Worker separation, restart, faults and existing lifecycle behavior.
3. [x] Update operator/migration/readiness docs, run affected native suite/types on macOS and pinned Node22/Linux, build exact candidate, perform one fresh final review and regression-driven fixes.

## Review focus

- No owner mutation can occur before its attempt is durable; no successful receipt precedes durable completion.
- Initial bootstrap and migration cannot fabricate, silently discard or bypass administrative history.
- Unknown outcomes remain uncertain; no automatic replay or false completion after restart.
- Untrusted input cannot inject secrets, arbitrary fields or identities into the journal/export.
- Corruption, full capacity and synchronization failures cannot leave an apparently healthy unaudited mutation path.
- Export is bounded, read-only and private, with validated exact receipts and clear history coverage.

## Rulings and evidence

Previous goal turn: progress — Worker package review finding corrected;218/218 native cases/types pass locally and sequentially on pinned Linux. No blocking condition.
Ruling: continue local architectural implementation under standing user/developer authorization rather than repeat approval ceremonies — cost if wrong: experimental changes remain reversible, no infrastructure/credentials are touched.
Ruling: canonical spec/plans and existing uncommitted branch are the ledger; no duplicate workspace, commit or new worktree — cost if wrong: review requires saved file baselines and explicit scope.
Ruling: local durable audit does not substitute for independent recovery protection or authenticated human attribution — cost if wrong: production remains gated on those separate guarantees.
Pre-flight: task1 stages journal records synchronously and provides local tickets; task2 wraps them in shared service durability barriers and exclusively owns initialization/state transitions. Task2 emits private export receipts consumed by the operator validator; task3 must exercise the exact packaged entrypoint. No unresolved interface conflict.

Task1 complete:15/15 native workerd/SQLite tests plus strict types pass (`/tmp/xeip-admin-schema-green.log`). Initial missing module and dropped-trigger tests failed first. v4 migration preserves metadata, immutable history and uncertain attempts survive runtime restart. The adapter never creates schema itself and validates the checked catalog on every journal access. Task2 RED cases now exercise atomic bootstrap, before/after durability, conflicts and corruption quarantine through the actual service.

Ruling: run native Cloudflare functional test files sequentially by default — the previous unchanged-source concurrent Linux run had two deadline/freshness failures under host contention, while sequential execution passed original limits. Each file already exercises real asynchronous races internally; capacity tests remain a separate gate. Cost if wrong: functional suite takes longer, and passing it never certifies concurrent production workload.

Task2 complete: six service fault cases and the actual production Worker export/restart/private-boundary case pass with strict types (`/tmp/xeip-admin-integration-green.log`, `/tmp/xeip-admin-export-green.log`). Export receipt validation rejects altered hashes/fields/cursors; explicit null cursors failed a regression and were corrected to reject rather than default. Additional cross-page verification passes, bringing adapter cases to16 (`/tmp/xeip-admin-pages.log`). Indexed joins replace one start-record query per terminal row; validation remains complete and bounded by pages.
The first whole suite passed240/241; the sole failure was the old schema table-list expectation omitting xeip_owner_events. Updated that expectation and existing checked-upgrade expectations to v5. Final suite runs below use the completed source, including the indexed-join change and page-boundary test.
Ruling: the Linux service source manifest embeds package.json, so even the native-test-script change warrants a fresh artifact build/smoke; shared organization/relay runtime code and dependencies are unchanged, so broad root/organization tests are not repeated without a new concern. Cost if wrong: rely on their prior scoped results, not a claim of fresh full-platform certification.

Additional pre-review fault exploration found outer bootstrap transaction exceptions could escape as generic errors without explicit quarantine. Both before-commit and ambiguous after-commit regressions failed first (`/tmp/xeip-admin-bootstrap-transaction-red.log`); the explicit bootstrap catch now quarantines and returns StoreUnavailable. Verify reopened empty/partial states and explicit recovery without fabricated historical results. The earlier242-case local pass and Linux snapshot precede this correction; final evidence must use the corrected source and244 cases.

Pre-review evidence: corrected local source passes244/244 native cases and strict types (`/tmp/xeip-admin-corrected-local.log`). The expanded bootstrap recovery assertions also pass2/2 (`/tmp/xeip-admin-bootstrap-recovery.log`). Earlier Linux snapshot passes242/242 plus types; corrected244-case Linux run is underway. Fresh Linux image `xeip-organization:local-admin-audit-review` digest `sha256:2f4463b7867f02b73b1a128260e2e3c6bcb7b4afe62638af3ad90834b7e28da6`,67,336,192bytes passes nonroot/read-only/network-isolated SBOM/file-integrity/startup smoke (`/tmp/xeip-admin-artifact.log`). Corrected Worker candidate924,594bytes SHA256 `c235da1f19e5616af3202bd04af375a5f7d920cb871f982919b4ed37bf641f39`; seven bundled packages unchanged. No hosted resources were used.
Ruling: one fresh final review of the explicit audit increment while the independent Linux verification completes; no implementation edits during review. BASE=HEAD with accumulated uncommitted work, so use saved six-module baselines and the named scope rather than an empty Git range. Cost if wrong: the review does not certify prior accumulated changes or hosted acceptance.

Final review: one Important/P2, no Critical/Minor findings. Accept the native-proven alternate unique-key INSERT OR REPLACE defect: a next-sequence started or terminal replacement can delete prior history before subsequent validation quarantines. Fix both conflict keys in the BEFORE INSERT guard with native failing-then-passing preservation regressions. This is the single authorized fix pass; no rereview. Pre-fix corrected Linux244/244 and strict types also pass (`/tmp/xeip-admin-corrected-linux.log`), but do not cover this newly proven defect.

Reviewer declined-to-judge dispositions:
- Hosted durability/replication/PITR/independent recovery: remain unproven; local ordering cannot certify provider loss or rollback. Cost: external recovery design/drills remain release gates.
- Sustainable refresh cadence/retention/full-capacity performance: remain unproven; indexed bounded reads and hard caps are not operating capacity. Cost: size, measure and implement retention/export before production.
- Named human identity/account IAM: retain binding-capability attribution as implemented; no individual authentication claim. Cost: named operator/IAM acceptance and independent attribution remain required.
- Direct trusted adapter calls bypassing manage: retain trusted internal APIs for fixtures/composition; deployed Object exposes only the journaled manage boundary. Cost: future entrypoints must preserve that boundary and be reviewed.
- Administrator rewriting database plus hash chain: outside corruption-detection guarantee; no tamper-proof or independent witness claim. Cost: independent export/recovery controls remain required.
- Prior uncommitted work outside this increment: no global certification inferred; existing scoped evidence and independent production review still apply.
- Corrected Linux run not independently certified by reviewer: parent observed244/244 and strict types exit0; post-fix246-case run will be recorded separately. Cost: code review and platform conformance remain distinct evidence.

Final fix evidence: both alternate-unique-key replacement regressions failed with HTTP200 before the guard correction (`/tmp/xeip-admin-replace-red.log`). Explicit started/terminal existence checks now reject both replacements and preserve the exact original rows;18/18 journal tests and strict types pass (`/tmp/xeip-admin-replace-green.log`). The candidate schema v5 is unpublished; this correction changes its pre-release checksum, with no hosted database migration or organization data involved. No second review was performed.

Task3 complete: final post-review source passes246/246 native tests plus strict Cloudflare types on macOS (`/tmp/xeip-admin-reviewed-local.log`,97.45s) and pinned Node22.23.3/Linux (`/tmp/xeip-admin-reviewed-linux.log`,125.41s). Both processes exited0. The exact packaged entrypoint passes Wrangler dry-run and actual private local operator invocation within both suites. Final Worker artifact924,854bytes SHA256 `f0adf8492b9d24f84975e5fe7684fa391a3a0b0e1589b0bfa4688661a258ee90`; Wrangler config SHA256 remains `466281a224ea220926be9e16ad32457dfa27cab2a5d724760fb1ec4a4eae1a56`. Seven bundled runtime packages are unchanged. The rebuilt Linux image/smoke above remains current because the review fix changes only excluded Cloudflare code/tests; source package metadata is unchanged. git diff --check passes. No scoped findings remain; no cloud account, real credentials/data or deployment was used.

This completes the local administrative-audit increment, not the overall production goal. Next: reliable signed-status refresh, retention/export and independent recovery protection. Hosted IAM/TLS/private routing, real human PKCE/Keycloak, rollout throughput/P95, restore/no-loss drills and security/operator/pilot acceptance remain open. The requested recovery failure-boundary clarification remains unanswered; no narrower guarantee is inferred.
