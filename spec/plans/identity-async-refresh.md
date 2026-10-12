# Keep request handling responsive during signed trust reload

The accepted 500-user/200-agent readiness target and measured 700-identity synchronous refresh motivate this bounded Node runtime change. Prior probes measured about 1.9 seconds process CPU and much larger wall times under host contention. This is a responsiveness improvement, not a capacity certificate.

Design: keep startup and the synchronous compatibility update API unchanged. Add one asynchronous preparation worker per EntityTrustPolicy, with a fixed 30-second deadline, cancellation and no queued reloads. The worker receives copied public provisioning/configuration and only performs existing signature preparation; it never owns filesystem state, provider credentials or execution capabilities. The owning thread rechecks current monotonic time, policy health and cancellation, commits the existing checkpoint, then atomically replaces active bundles. Reads overlapping preparation use the still-current verified policy and existing live provider/freshness checks; revocation becomes active at successful checkpoint commit. A failed candidate retains prior trust unless checkpoint persistence poisons the policy. Sync/async concurrent updates reject. Close cancels pending work; late results cannot activate.

The organization lifecycle awaits reload and tracks it in drain work. SIGHUP reports success only after commit. Preserve existing controller checks immediately before effects. Filesystem provisioning reads, checkpoint writes and per-request verification remain synchronous and must be reported as residual costs. No worker pool, token cache or protocol change.

Alternatives: cooperative yielding still leaves a large single chain blocking the main thread; worker-owning checkpoints complicates storage ownership and cancellation. One disposable preparation worker isolates measured CPU with a small, testable lifecycle boundary.

- [x] Record a reproducible 700-identity baseline and regressions for asynchronous refresh, cancellation, concurrent updates, revocation, expiry and rollback.
- [x] Implement worker preparation, owner-side guarded commit, awaited lifecycle/SIGHUP integration and explicit artifact files.
- [x] Compare equivalent before/after responsiveness; run root, organization, strict types and artifact checks. One fresh scoped review, repair findings and update the readiness record.

Rollback: revert async launcher integration and worker files together; existing synchronous API and unchanged checkpoint format remain usable. No data migration or external resource change. Existing authorization covers this local performance work; production acceptance and the hosting/failure-boundary decisions remain open.

Worker design reference: [Node 22 worker threads](https://nodejs.org/download/release/v22.15.0/docs/api/worker_threads.html) documents structured-clone messages, worker resource limits and asynchronous termination. Workers are an execution boundary, not a security sandbox.

## Execution evidence

Initial 700-identity probe on the shared macOS/Node26 host: synchronous reload 1186.12 ms wall, 672.22 ms process CPU, zero 10 ms timer ticks, maximum main-thread gap 1186.21 ms. The same workload using async preparation: 965.11 ms wall, 803.51 ms process CPU, 77 ticks and 84.11 ms maximum gap. These single paired observations demonstrate responsiveness, not a stable throughput or latency distribution; worker overhead increased measured process CPU. Reproduce with `node conformance/organization-trust-performance.mjs sync` and `async`. Logs: `/tmp/xeip-async-refresh-{baseline,after}.log`.

Four async-policy regressions observed missing-method RED; lifecycle regression independently observed premature reload settlement RED. First combined GREEN21/21; full expanded root377/377, organization206/206 and four strict type checks pass. Logs `/tmp/xeip-async-refresh-{red,lifecycle-red,combined,root,organization,types}.log`. New policy tests cover input snapshot isolation, overlapping sync/async updates, committed revocation and rollback, pre/during cancellation, invalid signal recovery, close, commit-time expiry, malformed signatures, and persistence failure poisoning. Lifecycle waits for completion and cancels during bounded drain.

The capacity harness now awaits the same async update API, prevents overlapping timer reloads and drains an outstanding refresh on cleanup. No full capacity rerun was attempted on the shared host. Startup, protected provisioning reads, worker message cloning, checkpoint commits and per-request trust verification remain synchronous costs. Full host acceptance remains open.

One fresh read-only scoped review found no confirmed defects; reviewer inspected code/tests and did not rerun them or certify performance. No second review or unrelated audit claim. Linux verification is recorded below when terminal.

Final supported-runtime evidence: Node22.23.3/Linux, non-root/read-only/network-disabled container, affected refresh and lifecycle files **23/23**, exit0 (`/tmp/xeip-async-refresh-linux.log`). A later additional monotonic-deadline case passes **1/1 on macOS and Linux**; temporarily removing the response-time deadline check makes it fail with missing expected rejection, then the original implementation was restored and passes again. `/tmp/xeip-async-refresh-deadline{,-mutation,-restored,-linux}.log`. This supplementary test was added after review and the full377-case run; no production change followed review. Do not call it a378-case full-suite run.

Final Linux image `xeip-organization:local-async-trust-review`, ID `sha256:fba93ce780fea9b282be696d5d564a55d5aed29c109a418dcc87b3a2ec0e3b19`, 67,338,622 bytes. Build and isolated artifact verification exit0, including actual worker creation/preparation, file integrity, dependency inventory, no CLI wrappers, non-root/read-only/network-none runtime and maintenance imports, and redacted missing-configuration failure. `/tmp/xeip-async-refresh-image.log`. Whitespace/syntax checks pass. No cloud mutation, commit or release.

This increment is complete. It does not certify the two-second machine-operation target, repair the previously recorded controlled-browser/maximum recovery HTTP timing failures, provide full source recovery, or resolve the hosting, retention, independent security and operator acceptance gates. Those remain explicit production blockers.
