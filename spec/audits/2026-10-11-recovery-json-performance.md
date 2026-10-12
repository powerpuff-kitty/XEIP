# Recovery JSON performance investigation

Status: current complete regression suites pass on both platforms, 11 October 2026. Historical maximum-size deadline failures remain evidence of shared-host variability; no hosted latency certification or new deployment.

## Failure and measurements

The corrected pre-optimization native suite finished521/524 on macOS. A16MiB payload becomes22,370,450 characters of authenticated JSON. The configured client/handler10000ms deadlines rejected the request before journal invocation. An isolated real workerd/SQLite probe instrumented transport, nesting validation, strict parsing and durable synchronization. It logged stage times and synthetic identifiers only.

| Stage                 |          Before |          After both changes |
| --------------------- | --------------: | --------------------------: |
| JSON nesting pre-scan |          8163ms |                        77ms |
| Strict JSON parse     |          4114ms |                       527ms |
| Native append result  | 503 unavailable | 200,64 parts,16777216 bytes |

These are individual diagnostic observations on a contended workstation, not comparable capacity samples or an SLO percentile. Host load varied substantially; timing differences alone cannot quantify production speedup. The causal path is independently visible: the old scan loops over every payload character; the new scan visits structural tokens. The old parser appends every unescaped character; the new parser consumes ordinary runs. The unchanged maximum-size conformance case subsequently passed, including durable storage and readback.

The first change alone reduced the nesting scan to116ms but still missed the client deadline after a successful durable append. The second change targets the measured remaining string-parsing cost. Neither change increases deadlines, caps, accepted JSON syntax or execution authority. A failed acknowledgment still needs the existing explicit reconciliation path.

## Compatibility and scope

The recovery pre-scan retains its16-level limit and ignores quoted/escaped syntax. The TypeScript strict parser retains duplicate-key, escape, control-character, Unicode surrogate and numeric checks. New cases cover long strings and escaped/unescaped Unicode boundaries;12,000 deterministic old/new input comparisons matched parsed output or exact error class/message. The reference parser and signed wire contracts are unchanged.

Focused native maximum-size/depth checks2/2 pass. SDK241/241, root relay/tools370/370, organization201/201 and interoperability33/33 pass; strict Cloudflare types pass. Full platform snapshots and subsequent corrections are recorded below; artifact checks passed. One fresh read-only review found no Critical/Important/Minor defects. It independently passed the two focused strictParse tests and411,771 exhaustive short scanner comparisons, including depth-boundary prefixes. This review covers parsing changes separately from the already completed fenced-reconstruction review.

## Other regressions

The refresh-overlap fixture used a200ms budget while scheduling its second native request through Node. Its first call could expire before the second began. The corrected fixture uses the supported10000ms budget, asserts actual overlap and releases its held response in finally; native timeout/late-update behavior still runs and passes. Production refresh behavior is unchanged.

The recovery identity-drift test now asserts successful proposal and restored lifecycle state before inspection, exposing where it fails. Instrumentation traced the failure to a recovery read during source startup, rather than to the final authenticated action request. A subsequent instrumented run passed. Subsequent diagnostics below establish a test-fixture recreation defect; it was not a client deadline failure.

## Evidence

- `/tmp/xeip-recovery-timing-detail.log`: pre-change stage observations and503.
- `/tmp/xeip-recovery-timing-optimized.log`: first change, durable append but unavailable client receipt.
- `/tmp/xeip-recovery-timing-both-optimized.log`: both changes, native200.
- `/tmp/xeip-recovery-parsing-green.log`: uninstrumented maximum-size/depth2/2.
- `/tmp/xeip-string-{sdk,root,organization,interop}-tests.log`: terminal passing regression commands.
- `/tmp/xeip-string-types.log`: strict typecheck.
- `/tmp/xeip-refresh-overlap-corrected.log`: corrected held-fetch native case.
- `/tmp/xeip-recovery-drift-{status,instrumented,http-diagnostic}.log`: preserved failures and later pass.
- `/tmp/xeip-parsing-full-{local,linux}.log`: current full verification.

The approved private Cloudflare smoke remains on its earlier reviewed artifact. Local code changes do not authorize an additional cloud deployment.

Current offline Worker artifact:988075 bytes, SHA256 `fe909801d624c89e1de0f2f0eda92c9e6642e4bf98d8bbc50559ea274249b6b2`. Configuration and scheduler hashes are unchanged from the preceding offline candidate. Seven dependency entries, file modes and manifest hashes verified; reconstruction/file-reader/test-fixture code is absent. Both Wrangler dry-runs exited0 (`/tmp/xeip-parsing-package.log`; pointer `/tmp/xeip-parsing-candidate.path`). Temporary timing/startup instrumentation was removed from the repository after terminal diagnostic runs.

First current Linux attempt ended240/241 SDK tests, exit1 because the isolated source-copy command omitted `schemas/`; the failing SDK test could not read `schemas/message.schema.json`. This is executor fixture incompleteness, not a parser regression. The chained Cloudflare suite/types did not run. Preserve `/tmp/xeip-parsing-full-linux.log`; correct the copied inputs before another Linux run. The local image rebuild started only after that container exited.

Rebuilt Linux artifact passed integrity/dependency/runtime/maintenance checks in a nonroot, read-only, network-isolated container, plus redacted missing-configuration startup: `xeip-organization:local-json-parsing-review`, image `sha256:630793d9162ec0c484a35bac8a9f97b113135f301b246e5308da3de5aeed7e38`,67,337,567 bytes (`/tmp/xeip-parsing-image.log`, exit0). The corrected Linux run includes schemas and is recorded separately in `/tmp/xeip-parsing-full-linux-corrected.log`; it must finish before making a full Linux claim.

## Journal recreation defect resolved locally

The full optimized macOS suite completed524/525, exit1 in609.65s; the only failure was recovery identity-drift restoration (`/tmp/xeip-parsing-full-local.log`). More detailed diagnostic evidence shows an HTTP500 after193ms with an active recovery deadline, and then the journal bridge reports `TypeError: this.handler is not a function` (`/tmp/xeip-startup-{response,journal}-diagnostic.log`). The HTTP journal fixture lost its memory-only handler when workerd recreated the object.

A deterministic native runtime restart reproduced the same error before the fix (`/tmp/xeip-journal-recreation-red.log`,1/1 failed). The TEST ONLY fixture now persists its synthetic configuration and reopens the existing journal through `RecoveryJournal.open` on reconstruction. It never initializes or resets journal state on this path. Synthetic credentials in fixture storage are explicitly not a production credential-custody design. The production package does not import this fixture.

The new restart regression and original identity-drift case both pass, exit0 (`/tmp/xeip-journal-recreation-green.log`,2/2). A complete rerun of both affected conformance files is in progress (`/tmp/xeip-journal-recreation-regression.log`). The current Linux full run copied the pre-fixture-correction snapshot; it remains running and must not be represented as testing the correction. Temporary diagnostic modules were removed after their terminal results. No production runtime or approved deployed artifact changed for this fixture correction.

The affected-file rerun completed59/60, exit1 in154.63s: all Worker/recreation cases passed, but the decoded-chunked success test hit its unrelated100ms fixture deadline. The recovery HTTP fixture now uses5000ms for protocol/body/receipt cases, with explicit100ms configuration for its five timeout scenarios; existing4000ms elapsed-CPU and frozen-clock review cases retain their own settings. This separates correctness assertions from deadline tests and avoids deadline failures falsely satisfying protocol rejection assertions. No production timeout changed. Full current recovery HTTP checks are running in `/tmp/xeip-recovery-http-final-fixtures.log`.

The current recovery HTTP rerun ended36/37: framing/deadline/recreation cases pass, but the maximum16MiB request again returned503 in12.10s (`/tmp/xeip-recovery-http-final-fixtures.log`). The running Linux snapshot independently passed that maximum-size case in8.07s. Preserve both observations: the optimization demonstrates improvement and prior functional passes, but does not make maximum-size completion reliable on this shared host or certify its deadline. Do not loosen production limits or call the full current macOS command green. Linux affected-file verification is queued after the ongoing full container exits, avoiding additional overlapping native workloads (`/tmp/xeip-journal-recreation-linux.log`).

## Terminal Linux follow-up

The corrected full Linux source snapshot finished SDK241/241 and Cloudflare524/525 in774.47s; its sole failure was the pre-correction journal recreation fixture described above (`/tmp/xeip-parsing-full-linux-corrected.log`, exit1). The chained typecheck did not run. The subsequent current-source Linux run passed all60 cases in both affected files in137.18s and the strict Cloudflare typecheck (`/tmp/xeip-journal-recreation-linux.log`, exit0). This includes maximum-size recovery and the deterministic recreation regression. No full-suite result is relabeled green; the intermittent maximum-size macOS failure and hosted deadline acceptance remain open.

## Current full-platform closure

After the fixture corrections, current complete conformance passes **527/527 on macOS Node 26.8.1 and 527/527 on pinned Linux Node 22.23.3**, with strict Cloudflare types on both, zero failures/skips/cancellations and terminal exit 0. The platform runs are sequential, not overlapping native workloads. The 260 captured source files remain unchanged. Logs: `/tmp/xeip-action-restore-current-full-local.log`, `/tmp/xeip-action-restore-current-types-local.log`, `/tmp/xeip-action-restore-current-full-linux-final.log`.

The isolated macOS maximum-size case passes in 4.00s; the same case within the complete Linux run passes in 6.00s. These are single case durations including fixture/readback work, not latency percentiles or an explanation that invalidates earlier failures. No limits or production deadlines changed. The full Linux suite takes 790.20s on this shared host, so the expanded CI job budget is now 25 minutes; application deadlines remain unchanged. Two failed Linux container setups preceded the accepted run and are preserved in the [reconstruction ledger](../plans/cloudflare-action-restore.md); neither ran tests.

This closes local parser/reconstruction regression verification. Hosted maximum-payload timing, selected rollout load, complete organization recovery and operator/security acceptance remain open.
