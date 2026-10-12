# Historical authority capture

Status: local capture and complete-history validation verified. This is a complete-control-recovery dependency, not a restore or durability guarantee.

`xeip.authority-checkpoint/1` contains the expected organization, current public configuration, revision, previous event checksum, current source checksum and a checkpoint digest covering all these fields and the format identifier. Configuration uses the existing authenticator and action-policy validation, without exporting real credentials or making provider requests. Hashes provide integrity only; authenticated provenance, whole-history rollback detection and custody belong to the independent journal/witness.

`xeip.authority-history-page/1` contains the checkpoint digest, requested exclusive `after` revision, at most 256 ordered events, `next` and `complete`. Revision zero starts from the all-zero predecessor. The caller retains its previously verified revision and checksum between pages. Each event preserves the source revision, configuration digest, predecessor and checksum. Reject gaps, forks, extras, short pages, incorrect completion claims, mismatched snapshot digests and a final configuration digest different from the checkpoint. Only validation from revision zero through the pinned head proves a complete history.

Capture requires ready authority, matching persisted/accepted state and an intact schema. Pending durability, corruption and closed/failed state refuse capture. A valid request for an older checkpoint after an authority update conflicts without quarantining healthy current authority. Each read is synchronous and immutable; changed authority requires restarting capture. No public or owner RPC is added.

Current configuration is at most 1 MiB. History pages cap records at 256; no lifetime history cap or pruning is introduced. Existing source reads validate full history in bounded SQL batches. Repeated capture pages may rescan history: this is a correctness dependency, not proof of sustainable export throughput. Event digests cannot reconstruct past configuration bodies that the source never stored.

Remaining full recovery work includes lifecycle intent, administrative attempts/results, a consistent action/control journal cut, durable receipt gating, complete fenced restoration, external execution fencing, secret/Keycloak custody and hosted acceptance. These formats do not grant current authorization and do not activate a restored organization.

Verification covers multi-page history with changed configurations, exact source preservation, tamper/gap/fork/truncation refusal, scope and secret checks, concurrent update conflicts, pending sync and corruption failures, current-authority usability after invalid requests, native regressions and strict types.

## Verification record — 11 October 2026

Eight focused cases pass on real local workerd/SQLite. The full Cloudflare suite passes **543/543** on Node26.8.1/macOS (381.10 seconds), the root suite **384/384**, and the affected authority suite **42/42** on pinned Node22.23.3/Linux (10.63 seconds). This includes extension of the existing 258-event test to read 256+2 recovery records and a case proving that an internally valid but unaccepted persisted head quarantines its old live instance while remaining valid on explicit fresh reopen. All runs exit0 with no failures/skips/cancellations; strict Cloudflare types pass on both platforms.

Linux used `node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392`, non-root/read-only execution, dropped capabilities and private ephemeral work/home tmpfs directories. No host credentials or cloud configuration were mounted. Native macOS and Linux suites ran sequentially. The complete Linux Cloudflare suite was not rerun for this increment; these durations are test timings, not SLO evidence.

Scoped review found no production-code defect. Its test limitation was corrected: the corrupt-history test now restores the exact schema trigger before invoking capture, independently proving history validation. A secret-bearing checkpoint is rejected even with both source and artifact checksums recomputed. An explicit-null cursor regression failed before default handling was corrected; malformed requests leave current authority usable. Initial static checking also exposed a readonly JSON union narrowing issue, corrected with an annotation after the runtime object guard.

Evidence files: `/tmp/xeip-authority-checkpoint-red.log`, `-cursor-red.log`, `-authority.log`, `-focused-final.log` and `-types-final.log` share that prefix. Affected source hashes are in `/tmp/xeip-authority-checkpoint-sources.sha256`. Tests use only synthetic identities/credentials; no cloud operation, real provider call, effect replay, schema migration or production acceptance is part of this increment.

Closing evidence: `/tmp/xeip-authority-checkpoint-full-local.log`, `/tmp/xeip-authority-checkpoint-root.log`, `/tmp/xeip-authority-checkpoint-linux.log`. All four affected runtime/test source hashes remain unchanged across verification. Local Markdown links and `git diff --check` pass.
