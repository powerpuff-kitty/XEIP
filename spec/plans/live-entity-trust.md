# Live entity trust implementation plan

Use the established inline executing-plans workflow with one final fresh-context review. Authorized by the user's instruction to continue until production readiness.

**Goal:** durably refresh verified trust without restart and enforce device revocation/expiry on active and future connections.
**Spec:** [live-entity-trust.md](../live-entity-trust.md).
**Architecture:** checkpoint owns durable transitions; entity policy owns validated snapshots and use-time eligibility; admission binds credentials; relay owns transport cleanup.
**Constraints:** Node >=22, Rust >=1.81, legacy profile unchanged, no public exposure or administration endpoint, no new dependency for this batch.

- [x] Checkpoint update: failing update/restart/failure tests in `trust-checkpoint.test.mjs`; implement reusable locked commit and poisoned-I/O state in `trust-checkpoint.mjs`; verify rejection preserves old state and failure disables subsequent updates.
- [x] Entity policy: failing replacement/removal/revocation/expiry/failure tests in `entity-refresh.test.mjs`; separate pure provisioning validation from mutation, add `update`, `allows` and aggregate `status`; checkpoint before publish.
- [x] Credential and transports: failing HTTP/SSE/WS tests for bound key, fresh-status admission, live revocation, idle expiry, and failed update; add optional credential kid and rotation preservation, shared use-time checks, owner update method and lifetime-managed sweep timer.
- [x] Document migration/API/recovery constraints, update readiness, run full relay coverage/SDK/interop and static checks; complete final fresh review and regressions.

Review focus: a valid replacement must never unlock checkpoint between writes; poisoned persistence must never continue authorizing from old memory; subscriptions and idle WebSockets must be rechecked; omitted entities retain rollback history; invalid preflight cannot advance persisted state.

Ruling: implement in the existing uncommitted audit branch to preserve all earlier work. Changes remain reviewable before integration; no publish/deploy/merge is implied.
Ruling: treat the user's workflow answer “yes” as accepting the suggested human-approved internal MCP workflow. Capacity and pilot SLOs remain unconfirmed and cannot be certified from that answer.
Ruling: key binding is required only for experimental entity-signing mode. Existing users of that opt-in mode must provision `kid`; legacy profiles retain their authentication contract.

## Implementation and review record — 11 October 2026

Checkpoint update tests were observed failing before implementation. Policy replacement/revocation/expiry/failure tests and transport update/key-binding tests also failed against the earlier implementation. Idle-expiry regressions were additionally verified by disabling the sweep, observing both failures, then restoring it.

The fresh-context review found no confirmed defect but requested stronger persistence and asynchronous authorization evidence. Added file-write/file-sync/rename/directory-sync failure tests; paused request bodies during revocation, expiry and storage failure for both messages and receipts; active SSE/subscribed and idle WebSocket preservation/closure checks; and device removal followed by explicit credential rotation. All 28 expanded policy/transport tests passed. No review findings intentionally deferred.

The full suite detected a legacy WebSocket response regression: immediate closure had accidentally applied outside entity mode. Restored the legacy response path by gating the new connection behavior on entity trust. Its existing failing test then passed; a final full coverage run is in progress.

Ruling: retain the on-disk checkpoint version and compare validated candidate histories under the same writer lock — no migration is necessary — cost: ambiguous I/O failures intentionally require reopen with same-or-newer provisioning.

Source/docs updated. Final coverage and interoperability checks passed; detailed evidence follows. The next plan is [organization-auth.md](organization-auth.md); G1 still requires automated distribution, recovery certification and external review.

## Final evidence

- Full relay/tools coverage suite: 365 passed, zero failures; 94.39% lines, 88.81% branches, 96.58% functions (existing gates pass).
- TypeScript SDK: 240 passed. Rust/TypeScript transport interoperability: 32 passed on the final relay source.
- SDK and focused relay typechecks, build, schema/shared fixtures, syntax of 76 tracked/new JS files, Markdown local links and whitespace passed. Rust source is unchanged in this batch; the prior Rust 1.81/1.94 80-pass baseline remains, and transport interop was rerun.
- The initial full suite's single legacy WebSocket regression was fixed and its test rerun before the final full suite. All review-requested coverage was added; no reported finding was deferred.
- macOS/Node 26.8.1 evidence only; Node 22/Linux and independent production/security certification remain release gates. Logs: `/tmp/xeip-refresh-final-coverage.log`, `/tmp/xeip-refresh-final-interop.log`, `/tmp/xeip-refresh-sdk.log`, `/tmp/xeip-refresh-review-coverage.log`.

This batch is complete. The production-readiness goal remains active; implementation now proceeds to Keycloak authentication and action policy.
