# Action recovery integrity implementation plan

Use executing-plans inline, with TDD and one fresh scoped final review. Spec: [action integrity](../cloudflare-action-integrity.md).

1. [x] Add failed-then-passed native regressions for state/history mismatch and strict actor/claim validation. Extract a focused pure history checker; reconcile rows before use and after atomic action+audit mutations.
2. [x] Reconcile all persisted rows on constructor/reopen using128-key pages, reject orphan history, and verify valid multi-page recovery without reclaiming effects.
3. [x] Run full native suite/types on macOS and pinned Linux, exact Worker packaging tests, scoped review/fixes; update readiness and recovery limits.

Files: services/organization/cloudflare/store.mjs and new action-integrity.mjs; conformance/organization-cloudflare*.mjs; relevant specs/guides/readiness. No shared Linux runtime or dependencies/package changes intended.

Review focus: every mutation must validate after its matching audit insert (not reject its own transient state); identical retries still validate persisted history; corruption during an async authorization must fail before effects; constructor paging must not omit identities; expiry/policy changes must not erase historical outcomes. Version and actor validation must reflect actual writer contracts, without inventing clock monotonicity or current-policy historical authorization.

## Rulings and evidence

Previous goal turn: progress; administrative archives completed with308/308 native cases/types on both platforms and two reviewed integrity fixes. Goal and external acceptance remain open.
Ruling: user standing instruction to continue until production readiness authorizes this reversible local integrity repair; no repeated design permission gate. Cost if wrong: uncommitted changes remain reviewable, no deployed state changes.
Ruling: preserve existing isolated branch, canonical spec/plan ledger and uncommitted work; no duplicate skill workspace or commits. Cost if wrong: review must use saved scoped baselines, not the whole accumulated branch diff.
Ruling: reconcile action histories before introducing action export/recovery interfaces. Cost if wrong: full startup validation adds work and latency; this does not replace independent recovery fencing or close the no-loss gate.
Ruling: timestamps need safe integer bounds but not monotonicity because existing writer follows wall clock. Cost if wrong: backward timestamps remain visible historical evidence rather than quarantining otherwise valid prior data.
Rollback: these are local unshipped changes; restore only saved increment baselines, never reset unrelated work. No schema/data migration or deletion.

Initial eight regressions fail against prior code (`/tmp/xeip-action-integrity-red.log`). Per-operation implementation passes the live checks and old cases; combined cases still fail specifically at their constructor checks. Two dedicated reopen regressions also fail, including corruption beyond128 keys (`/tmp/xeip-action-integrity-reopen-red.log`). Ruling: tasks1/2 share end-to-end regressions; keep both active until that common gate passes. Cost if wrong: task boundaries are less independently executable, but evidence is not relabeled green.

Native iteration evidence:50/51 cases passed; sole failure was invalid orphan-test setup, rejected by SQLite foreign keys before the intended assertion. Replaced that setup with an explicitly named storage-query fault fixture. With constructor reconciliation temporarily removed, that corrected focused regression fails (`/tmp/xeip-action-integrity-orphan-red.log`); source restored in finally. This is adapter failure handling, not evidence of an actual SQLite orphan being created. Existing schema protections remain enabled.
Positive transition coverage includes every current outcome and unfinished claims; historical backward timestamps remain accepted. A test-only trigger suppressing the approval audit proves post-mutation reconciliation rolls back the row and quarantines the live adapter.

Tasks1/2 complete:53/53 native ledger cases plus strict types pass (`/tmp/xeip-action-integrity-focused.log`). Startup validates later key pages, all valid histories reopen, corruption during live authorization blocks claims, and suppressed audit inserts roll back. Full platform/packaging and final review remain pending.

Fresh offline candidate path `/tmp/xeip-action-integrity-reviewed-candidate.path`: Worker938214bytes, SHA256 `1dfbbcdddac88e865de1ababae8808faf58062a646ec15822a3c325d60c72232`. Main configuration1373bytes `adbae66e4806a886cc6c18ffdd501e11705203446ec63a7af463b067a12773a8`; scheduler685bytes `1fbd92fa87b5d59394188285ee942ac4bfca7ec0f2c175679eef055fc945530e`; scheduler config584bytes `6c1c694176a7ae88f6c4d1a67727b3a1d179d5880a325f7980b266c9fe3bd7b4`. Both Wrangler dry-runs pass. These hashes will be superseded if review requires source changes.
Ruling: no Linux application-image rebuild is needed: all runtime changes are in the excluded Cloudflare directory and package metadata/dependencies are unchanged. Cost if wrong: prior image proof only covers that unchanged artifact, not new Worker bytes; Worker tests/dry-run are required separately.

Final scoped reviewer independently ran53/53 native cases/types and reproduced one Important compatibility defect: a new256-character clientId cap rejected previously valid trusted-authority approvals and their historical records. Accepted: retain string and existing4096-byte canonical-grant checks, remove the new cap. Parent native regression failed409vs200 (`/tmp/xeip-action-integrity-client-red.log`). One Minor found: conflicting proposal retries skipped existing-key history validation; accepted under user's fix-all scope, delegate conflict handling to the already-validating #row. Regression failed StoreConflictvsStoreUnavailable (`/tmp/xeip-action-integrity-retry-red.log`). Both fixes applied in one correction pass; no re-review.

Declined-to-judge rulings and costs:
- Hosted latency/CPU/billing at10000 actions requires acceptance measurement. Cost: bounded memory does not certify affordable startup work.
- Zero-RPO/independent backup/consistent rollback/disaster recovery remain required separate work. Cost: internal consistency alone permits a consistent older snapshot.
- Mutually consistent privileged wholesale rewrites are outside this checker. Cost: independent trusted witnesses remain necessary.
- Historical policy/revoker authorization cannot be reconstructed from this audit. Cost: valid-looking historical actor metadata is not fresh authorization proof.
- Continuous arbitrary corruption detection after final validation across awaits is not provided. Cost: later corruption is caught at the next checked boundary, not by a storage monitor; detected quarantine still blocks effects via existing service guards.
- Malicious live schema triggers modifying previously read rows are outside the verified deployed schema contract. Cost: privileged schema tampering needs independent operations/security controls.
- Actual native orphan creation was prevented by foreign keys. Cost: injected read-fault coverage proves adapter handling, not an orphan recovery drill.
- Global contiguous audit sequences and monotonic timestamps are not inferred. Cost: this checker validates per-action ordered transitions and safe timestamps, not a global hash-chain history.
- Broader action shape/IdP restrictions/other adapters remain unchanged and outside this scoped review. Cost: prior evidence must not be relabeled as a new whole-system review.
- Schema migration/dependencies/deployment/credentials/retention/action export are not delivered here. Cost: those gates remain open.
- Other accumulated branch edits are outside saved baseline scope. Cost: no whole-branch release approval.

Pre-review full native runs:321/321 plus types on macOS156.53s and pinned Linux203.43s. Correction pass:55/55 focused ledger cases plus types pass (`/tmp/xeip-action-integrity-reviewed-focused.log`), including both review RED→GREEN regressions. No scoped findings remain; corrected full323-case runs and rebuilt Worker candidate are in progress.
Ruling: clarify the README's old “not deployable” opening to “experimental deployment candidate, not production-certified” so it agrees with the existing offline deployable package. Cost if wrong: wording conveys technical packaging capability only, not authorization or hosted acceptance.

Corrected exact Worker candidate:938107bytes SHA256 `7f7602c83254277e7116eebdea1c4d8e4e794a2e8701459a2a47a9103f861432`; config/scheduler files unchanged from above. `/tmp/xeip-action-integrity-final-candidate.path` records the artifact directory. Both corrected Wrangler dry-runs exit0. Action archive, independent restore fencing and replay-safe retention now have explicit open tasks in the living plan; none is redefined as complete by this integrity increment.

Final corrected macOS run:323/323 native cases in202.94s plus strict types, command exit0 (`/tmp/xeip-action-integrity-final-local.log`). Final corrected Linux run:323/323 native cases in245.66s plus strict types, command exit0 (`/tmp/xeip-action-integrity-final-linux.log`), pinned Node22.23.3.

Task3 complete: full platform/types, exact Worker/scheduler dry-runs and scoped review correction pass are verified. No scoped findings remain. Readiness/audit/operating records updated; no hosted deployment, schema migration, data deletion, or independent recovery claim. Broader production goal remains active.
