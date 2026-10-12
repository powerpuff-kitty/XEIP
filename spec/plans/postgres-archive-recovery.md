# PostgreSQL physical archive recovery

Close a missing G3 verification case for the Linux/PostgreSQL deployment: recover acknowledged action changes made after a physical base backup using actual archived WAL. Existing logical dumps cannot exercise this path; synchronous replication tests a different recovery mechanism.

Use only generated disposable fixtures and the existing pinned PostgreSQL 18.6 image. No operator endpoint, credentials, storage or cloud resources are accepted. Keep the ordinary PostgreSQL fixture unchanged. The new conformance driver enables archiving in its own source, verifies a native `pg_basebackup`, creates later action transitions and an explicit restore point, forces a segment switch, waits for the required archive, and copies protected recovery inputs off the source. Destroy the source before starting any restore candidate.

First restore with the required final segment absent. Require PostgreSQL to refuse reaching the target and never report a writable service. Then restore the same base with the complete archive in a separate candidate. Use a named recovery target and pause at it; compare exact acknowledged action rows, audit history and consumed claims while read-only. Resume only the disposable candidate after that comparison, verify database protections and confirm consumed claims cannot cause tool execution. The negative candidate, positive candidate and all fixture files/volumes are removed through registered cleanup.

Verification requires real archive and recovery results, not configuration presence. Preserve failed fixture runs, use bounded subprocess/readiness waits, avoid credentials in diagnostics, and retain only synthetic counts/timings in output. Review fixture isolation, target enforcement, source destruction, actual post-base changes, no replay and cleanup. Add the verified command to CI and the operator evidence guide after it passes.

This does not certify zero acknowledged-action loss for arbitrary primary failure: the drill explicitly waits until its cut is archived. Asynchronous archiving can lag. It also excludes external trust checkpoints, Keycloak, secrets, whole-organization restoration, independent storage and the one-hour hosted operator target. Those remain required production gates. Local elapsed time is diagnostic only.

Primary references: PostgreSQL 18 [continuous archiving](https://www.postgresql.org/docs/18/continuous-archiving.html), [pg_basebackup](https://www.postgresql.org/docs/18/app-pgbasebackup.html), [pg_verifybackup](https://www.postgresql.org/docs/18/app-pgverifybackup.html) and [recovery targets](https://www.postgresql.org/docs/18/runtime-config-wal.html#RUNTIME-CONFIG-WAL-RECOVERY-TARGET).

## Evidence

The local physical archive-recovery increment is complete. The new `npm run test:postgres:archive-recovery` command is included in the existing PostgreSQL CI job; hosted CI execution is unverified. The ordinary PostgreSQL fixture, application, schema and cloud deployment are unchanged.

The first run verified the base backup and reached incomplete-archive refusal, then failed its log assertion: the driver had captured only stdout from `docker logs`, while PostgreSQL diagnostics use stderr. The corrected collector preserves both streams. `/tmp/xeip-archive-recovery-first.log` retains that failure; `/tmp/xeip-archive-recovery-second.log` records the first complete pass.

Scoped review then found a candidate cleanup gap: a successful daemon-side create followed by a client timeout/lost response could leave an unregistered container/volume. Candidate names are now registered before creation, tagged with unique ownership labels and checked before removal. Missing objects are accepted only on the exact expected Docker absence response; foreign labels are never removed. Unresolved generated names are reported. A temporary Docker wrapper let the real create succeed, recorded its volume and returned exit 77 to simulate a lost response. The fixture correctly failed, and both the candidate and anonymous volume were removed. Evidence: `/tmp/xeip-archive-create-fault.py`, `/tmp/xeip-archive-recovery-create-fault.log` and `/tmp/xeip-archive-recovery-create-fault-run.log`. Review of the correction reports no remaining findings in the new drill.

Final `npm run test:postgres:archive-recovery` exits 0 (`/tmp/xeip-archive-recovery-final.log`):

- Native `pg_basebackup` and `pg_verifybackup` succeed with one baseline action.
- Eight more actions reach pending, approved, executing, succeeded, failed, indeterminate, rejected and revoked states after the backup. The archived cut contains **9 actions, 23 audit events and 4 consumed claims**.
- The original source is destroyed before either restore candidate starts.
- Omitting the target WAL segment produces PostgreSQL's required-target recovery failure, never a writable-ready log.
- The complete archive reaches the named target paused and read-only. Exact action/audit rows match the acknowledged cut, the target LSN is reached, runtime database verification refuses recovery mode, and an execution attempt reaches no connector.
- After resuming only the disposable candidate, database protection checks pass, all four consumed claims reject execution with `StoreConflict`, their original claim IDs remain present, and exact action/audit rows remain unchanged. **Zero repeated effects**.
- Candidate containers, their anonymous volumes and the original source fixture are absent after normal and injected-failure cleanup. Coordinator tests also pass **3/3** (`/tmp/xeip-archive-recovery-cleanup-tests.log`); syntax and diff checks pass.

Final driver SHA-256: `65994970f997df5382d8c328a865b0a8e97bfd8b0c96b508329366c39a368c33`. Pinned PostgreSQL image: `postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873`. The final local recovery interval is **11,040.872191 ms**, starting after source destruction and including both the negative and positive candidate paths. It excludes backup preparation, actual incident response and whole-organization recovery; it is not the hosted RTO acceptance result.

At the original review checkpoint, the analogous `withPostgres` primary-create cleanup path remained unverified. The [subsequent primary cleanup fix](postgres-fixture-cleanup.md) now reproduces and corrects that separate path, with its own actual-Docker fault evidence and a passing rerun of this archive drill. Candidate-specific evidence above is not retroactively relabeled as primary-fixture evidence. Production remains no-go for the operator, durability, storage and complete-organization reasons above.
