# Administrative archive implementation

Spec: [archive collection](../cloudflare-archive.md). Inline execution in the existing uncommitted isolated branch.

1. [x] Add bounded archive validation and durable fixed-head collector, with corruption, page/attempt continuity, failure/seal and prior-witness tests.
2. [x] Reuse one isolated owner connection for read-only collection, add CLI and real native/private transport integration, preserving existing owner behavior.
3. [x] Document operations and limitations, run native suite/types on macOS/Linux and exact packaging/source artifact checks, one fresh scoped final review and regression-driven fixes.

## Review focus

An archive cannot be reported complete before all data and its seal are durable. Source growth must not mix cuts; rollback/forks, cross-page metadata/timestamp mismatch and repeated/unknown terminal records must be rejected. No untrusted filenames, secrets, public administration, hidden owner mutation, output overwrite or implicit partial repair. Previous archive witnesses pin source and chain history. Resource bounds, failure/cancellation, symlink/special-file handling and cleanup preserve prior artifacts. Local archive consistency is not independent recovery, action export, sustainable retention or hosted performance acceptance.

## Rulings and evidence

Previous goal turn: progress; automatic signed refresh and reviewed scheduler isolation completed;277/277 native cases/types pass on macOS/Linux. No repeated blocker.
Ruling: standing user authorization permits reversible local tooling without repeating skill approval ceremonies; no production credentials/resources or deployment are involved. Cost if wrong: changes remain uncommitted and reviewable.
Ruling: use existing branch/canonical spec-plan ledger and saved owner/type baselines `/tmp/xeip-archive-before`; no duplicate worktree or commits. Cost if wrong: review is scoped to this increment, not accumulated unrelated changes.
Ruling: complete snapshots precede incremental retention epochs; safe export/verification is a dependency of deletion and recovery acceptance. Cost if wrong: repeated full history and source validation may be expensive; capacity is measured separately and no retention/no-loss gate is closed by this work.
Ruling: await retention and recovery-boundary clarification without blocking this independent read-only work. Cost if wrong: no destructive retention choice is inferred, and no narrower failure guarantee is claimed.
Pre-flight: archive consumes validated owner pages and pins source config; shared owner session must preserve exact parser/correlation/mode/isolation behavior. CLI emits only read-only exports; artifact verifier is offline. No unresolved interface conflict.

Task1 complete:20/20 archive tests and strict types pass (`/tmp/xeip-archive-bounded-green.log`). Missing-module RED observed; deadline and FIFO regressions failed before correction (`/tmp/xeip-archive-timeout-red-bounded.log`, `/tmp/xeip-archive-fifo-red.log`). First intentionally unbounded timeout probe was terminated by exact owned PIDs after confirming it hung; the bounded regression proves that defect. Pages, source growth, cross-page forks/timestamps/attempt metadata, prior witnesses, corruption, permissions and staged write/sync failures are covered. Offline verification certifies content, not historical flush or independent recovery.

Task2 complete:31/31 archive/owner/package tests plus strict types pass (`/tmp/xeip-archive-owner-green.log`), including actual Wrangler local-registry collection and multiple validated calls on one session. Expanded archive native/failure/CLI cases23/23 plus types pass (`/tmp/xeip-archive-native.log`); added cross-page start/result coverage for final suite. Collection leaves native journal head unchanged and verifies after restart. No public/default RPC export path exists.
Ruling: retain the existing privileged OWNER credential for manual collection, explicitly disclose its broader authority, and do not grant it to automated read-only third parties. Cost if wrong: delegated/scheduled collection needs a narrower audited capability before production use.
Ruling: rebuild the Linux artifact because package.json is embedded as source metadata; application runtime and dependencies are unchanged, so prior broad shared-service evidence remains scoped rather than rerun without cause.

Final scoped review (one reviewer, no re-review) found two Important integrity gaps and no Critical/Minor findings. Accepted both: track observed source heads independently of the fixed archive cut in collection and offline verification; preserve a UTF-8 BOM during decoding so exact canonical validation rejects it. Six focused regressions failed with missing expected rejection before correction: two BOM cases (`/tmp/xeip-archive-bom-red.log`) and rollback/fork for collection and resealed offline files (`/tmp/xeip-archive-head-red.log`). No other scoped findings remain pending implementation.

Reviewer declined-to-judge rulings, retained as explicit limits:
- Real account identity, IAM and hosted private bindings remain operating acceptance. Cost: local binding tests cannot establish actual access control.
- Maximum-history throughput and sustained export cost remain capacity work. Cost: full snapshots may be operationally expensive.
- Action export, retention deletion and independent zero-RPO recovery are separate required increments. Cost: this collector closes none of those gates.
- Hostile same-user filesystem races and wholesale archive replacement remain outside this collector threat model; independent checksum custody is required. Cost: local hashes alone cannot establish authenticity.
- Fork ancestry wholly beyond the captured cut cannot be established without fetching that suffix. Cost: monotonic observed heads detect contradictions, not all unseen forks.
- Actual power-loss persistence and filesystem durability require operator crash drills. Cost: fsync ordering tests do not certify the deployed storage.
- Wrangler setup/disposal deadlines and inherited configuration handling remain documented existing runtime behavior. Cost: the per-RPC deadline does not bound connection lifecycle.
- Unrelated accumulated branch changes were excluded from this scoped review. Cost: this is not whole-branch release approval.

Pre-review full verification:302/302 native cases and types passed on macOS (158.96s) and pinned Node22.23.3/Linux (178.49s). Fresh Linux artifact build and nonroot/read-only/integrity/startup smoke passed. Final corrected-source reruns follow below.

Review corrections pass30/30 archive cases plus strict types (`/tmp/xeip-archive-review-green.log`), including the six failed-then-passed integrity regressions. Fresh offline Worker/scheduler package comparison confirms all four deployment files are byte-identical to the reviewed refresh candidate; artifact path is recorded in `/tmp/xeip-archive-reviewed-candidate.path`. This increment changes Node operator tooling, not the deployed Worker runtime.
Linux artifact `xeip-organization:local-archive-review`: SHA256 `696c563252ddba74bfc0188b0b7b70fbb1d942fc7e59d0eb833abeb10316ceb2`,67336195bytes; build and nonroot/read-only/dependency/integrity/missing-configuration smoke pass (`/tmp/xeip-archive-image.log`, `/tmp/xeip-archive-artifact.log`). Subsequent review edits affect Cloudflare tooling/tests/docs excluded from this image; embedded package metadata is unchanged.

Final corrected macOS source:308/308 native cases pass in152.95s plus strict types (`/tmp/xeip-archive-final-local.log`). Final corrected Linux source:308/308 native cases pass in210.77s plus strict types (`/tmp/xeip-archive-final-linux.log`), pinned Node22.23.3. Both commands exited0.

Task3 complete: both review findings corrected, full native/platform/types and exact packaging checks pass, Linux image smoke passes, and operating/readiness/audit records updated. No scoped findings remain. No resources provisioned, source history deleted or production-readiness gate inferred from functional tests. Broader service integration, workload and production goal remain active.
