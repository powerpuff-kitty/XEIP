# Recovery bundle implementation plan

Use superpowers:executing-plans inline, TDD and one fresh scoped final review. Spec: [recovery bundles](../cloudflare-recovery-archive.md). Existing branch and canonical plan locations; standing local readiness authorization applies.

1. [x] Implement recovery-archive.mjs fixed-head read collector and offline verifier using shared protected filesystem helpers and journal validators. Write empty/multipart roundtrip and corruption/continuity tests first, observe RED then GREEN. Cover advancement, prior archive, deadlines, exclusive files, filesystem errors. Add strict types and conformance command.
2. [x] Add separate action interpretation with shared deterministic UUID derivation and exact per-action history continuity; native authenticated journal/action integration and safe private-config CLI. Cover unknown payload rejection, consumed claims, malformed histories, secret redaction and bounded config. Add operating guide and synchronize readiness/audit.
3. [x] One fresh scoped review; fix all findings in one TDD pass, no rereview. Run full macOS/Linux conformance and types, Worker/scheduler dry-runs/exact bytes and updated Linux image when root manifest changes. Record exact outcomes and complete task cards while retaining broader production gates.

## Review focus

- A sealed bundle must correspond to the captured head even when the live journal advances or returns inconsistent parts.
- Previous witnesses must constrain source identity and prefix continuity; checksums must never be represented as independent authenticity.
- Late or failed I/O must not lead to a reported successful collection, automatic retry or overwriting evidence.
- Offline action interpretation must reject omitted/forked/reordered histories and never make a consumed claim executable.
- CLI/filesystem custody must not leak credentials/payloads or accept symlinks/oversized/noncanonical archive records.

## Ledger

Previous goal turn: progress. Worker recovery configuration completed467/467 on macOS/Linux, strict types and artifacts passed, scoped review had no findings. No repeated blocker.
Ruling: this is architectural recovery tooling, designed before code; use canonical spec/plan and existing branch under standing continue-to-readiness authorization, without redundant approval/commit/deployment gates. Cost if wrong: broader recovery requirements still require explicit acceptance rather than implied production approval.
Ruling: use complete fixed-prefix read collection and separate semantic action validation rather than raw SQLite copies or partial asynchronous pages. Cost if wrong: collection/reconstruction may be expensive at retained caps, so hosted restore timing remains unearned.
Ruling: preserve all evidence on failure and make no deletion policy/provider decision. Cost if wrong: incomplete directories consume disk until an operator safely disposes of their own evidence.
Ruling: reuse existing protected archive file primitives without changing their contracts; journal archives allow24MiB record files but not larger public action inputs. Cost if wrong: maximum-record memory/CPU must be exercised independently of small fixtures.
Pre-flight: collector/verifier share exact manifest/record rules; action interpreter consumes only a fully validated archive and deterministic action UUID. New conformance filename changes root package scripts, so the Linux image source manifest must be refreshed even though runtime code remains excluded.

Task1 complete: initial5 cases failed because the module was absent; implementation then passed5/5 plus types (`/tmp/xeip-recovery-archive-{red,green}.log`). Serialized roundtrip comparisons use canonical values because strict JSON parsing deliberately returns null-prototype objects; no production parser weakening. Expanded corruption/continuity/custody/deadline/max16MiB suite26/26 plus types passed (`/tmp/xeip-recovery-archive-focused.log`).

Action interpretation and protected configuration CLI each observed missing-module/CLI-contract RED, then semantic/CLI tests passed in the expanded29/29 suite plus types (`/tmp/xeip-recovery-actions-{red,green}.log`, `/tmp/xeip-recovery-archive-cli-red.log`, `/tmp/xeip-recovery-archive-expanded.log`). Native production signed Worker flow collects via the actual authenticated client/handler and verifies four records, one succeeded action and one consumed claim, then rejects a repeated execution after restart;1/1 exit0 (`/tmp/xeip-recovery-archive-native.log`).

Ruling: action interpretation stores prior record hashes and small state/claim metadata, not all historical arguments/results, and rechecks manifest-bound file hashes on its second pass. Cost if wrong: whole-history CPU/disk work remains proportional to retained history and still needs hosted recovery timing evidence.
Ruling: archive record reads allocate the observed file size under the existing24MiB cap and reject growth, rather than allocate24MiB for every small record. Reuse no-follow/canonical/private-file validation. Cost if wrong: concurrent edits can fail verification; archives are deliberately immutable evidence, not live mutable files.

Task2 complete: focused recovery bundle + action recovery + production Worker suite76/76 plus strict types, exit0,47.24s (`/tmp/xeip-recovery-archive-focused-final.log`). Includes30 archive cases, explicit consumed-claim erasure/replacement rejection and native authenticated signed flow. Documentation and CLI complete. One fresh scoped review and final cross-platform/artifact verification follow.

Final fresh scoped review (`recovery_bundle_review`, gpt-6-astra/high) found no Critical/Important/Minor findings. No correction pass or second review needed. It checked complete fixed-prefix chain/payload capture, prior witnesses, exact semantic continuity, protected reads/writes and CLI redaction. Existing primitives were inspected as dependencies without a separate whole-branch certification.

Final: Ruling: hosted TLS/IAM/storage independence remain separate deployment gates — no provider has been selected or provisioned by this read tool — cost if wrong: local evidence could be mistaken for failure-domain protection.
Final: Ruling: source restore, trust/authority/admin recovery and retention remain required subsequent work — aggregate action checks issue no capabilities or mutations — cost if wrong: action-only evidence is insufficient to reactivate an organization safely.
Final: Ruling: sustained capacity, one-hour restore and production acceptance remain unearned — maximum-record correctness and local tests are not operational SLO evidence — cost if wrong: production recovery/latency targets can fail.
Final: Ruling: coordinated journal/all-witness replacement cannot be authenticated by hashes — independently retained evidence and accepted custody are required — cost if wrong: coherent rollback can look valid.
Final: Ruling: shared existing file primitives and other accumulated branch changes keep their prior review/evidence scope — this review does not recertify the repository — cost if wrong: unrelated defects remain outside its verdict.
Final: Ruling: cross-platform suites/artifacts are executor verification gates — reviewer did not rerun them — cost if wrong: a review verdict alone could mask platform/package failures.

Two closing tests were added after full-suite snapshots started: actual CLI verify/actions success redaction and failed final directory fsync never returning success. Both pass locally2/2 (`/tmp/xeip-recovery-archive-final-extra.log`); they are run separately in the same pinned Linux environment without changing the copied main-suite test source. No production code changed after review/full-run start. Report full-run and additional-check counts separately if a snapshot predates these cases; do not infer an unrun500-case command.

Both closing tests pass on pinned Linux2/2 (`/tmp/xeip-recovery-archive-linux-extra.log`), exit0,7.73s; macOS2/2 exit0,4.22s. One hundred deterministic UTF8 payload IDs match the pre-extraction prepare implementation (`/tmp/xeip-recovery-archive-id-compatibility.log`), confirming existing journal identity compatibility.

Exact recovery+feed package: Worker985254bytes SHA2562550e07e770cf96406d36236e665e40779f94c4da578a47d3489431ccd616416; main config1527/634676472c5e6565c22200a332b5f9494ec03887382d2fb06143f98c7796359d; scheduler685/1fbd92fa87b5d59394188285ee942ac4bfca7ec0f2c175679eef055fc945530e; scheduler config586/233bafb58a59b35abf916728df8a771da0f0ae7e29706bfb6866005cb1d56d59. Seven runtime packages unchanged; collector/semantic CLI and test fixtures remain absent from Worker imports. Exact manifest/hash/permission checks and both actual Wrangler dry-runs exit0 (`/tmp/xeip-recovery-archive-package.log`, candidate pointer `/tmp/xeip-recovery-archive-candidate.path`).

Rebuilt Linux image `xeip-organization:local-recovery-archive-review` SHA25654412bb236c934eda3c7b67722f9c1586ffb043e6a915e81f29152618caf5519,67336226bytes, includes the current root test command manifest and passes nonroot/read-only/network-none dependency inventory/file-integrity/runtime imports/redacted missing-config startup conformance, exit0 (`/tmp/xeip-recovery-archive-image.log`). Local document links91/91 and tracked diff whitespace checks pass. These are packaging checks, not hosted capacity evidence.

Final macOS run includes the two closing tests and passes500/500 plus strict types,263.43s, exit0 (`/tmp/xeip-recovery-archive-final-local.log`). Linux main snapshot predates those test-only additions; both additional cases already passed separately in the same pinned environment. Await the full Linux terminal result before recording its full count.

Final accepted platform evidence: macOS **500/500 full suite + strict types**,263.43s, exit0; pinned Node22.23.3/Linux **498/498 full-suite snapshot + strict types**,349.28s, exit0, plus the two subsequently added closing tests **2/2** in that same pinned Linux environment,7.73s, exit0. No failures/skips/cancellations. Logs `/tmp/xeip-recovery-archive-final-{local,linux}.log`, `/tmp/xeip-recovery-archive-linux-extra.log`. The Linux main command was not a500-test run; the separate closing evidence completes the same distinct500-case coverage. Product code was identical throughout these final checks. No second full run was needed for two independently verified test-only additions.

Task3 complete: scoped review clear, all platform/type checks pass, exact Worker/scheduler package dry-runs/integrity and rebuilt Linux image conformance pass, documentation updated. No deferred minor findings. Root component task complete; overall production readiness remains active. No cloud resources, real credentials or organizational data were used, no publishing/deployment occurred, and unrelated containers were untouched.

Next: complete restore/reconciliation tooling with trust/authority/admin recovery and an accepted external execution fence; separately hosted journal lifecycle/IAM/TLS/failure-domain evidence; replay-preserving retention; hosted workload, one-hour recovery, zero acknowledged-action loss and security/operator/pilot acceptance. This turn is progress, not a repeated blocker.
