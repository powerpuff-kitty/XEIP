# Experimental Durable Object action ledger

Status: local implementation contract within the user-selected Cloudflare exploration. This is a separate storage adapter, not a selected production backend or deployable organization service. Preserve the Linux/PostgreSQL path and all existing acceptance targets.

## Purpose and boundary

Implement the existing `ActionLedger` contract against a SQLite-backed Durable Object: propose, inspect, decide, revoke, claim and internal finish. Reuse `ActionPolicy`, shared errors and the existing executor. The prototype must establish real workerd/SQLite transaction behavior, persistence across local runtime restart, and failure semantics before provider/trust/transport integration proceeds.

One configured organization owns each object. Initialization binds its storage to an explicit organization ID and schema checksum; reopening under another ID or incompatible schema fails closed. No public Worker ingress, bearer authentication shortcut, deployment configuration, cloud resource creation or real MCP effects belongs in this batch. The conformance entry point contains synthetic controls and must never be deployed.

## State and invariants

Use a versioned schema with actions keyed by `(session_id, request_id)`, immutable canonical action bytes/digest/expiry, bounded state revision, immutable single-use claim ID, optional approver grant and canonical result. Audit rows append atomically with transitions and retain the action digest and bounded actor identity, never bearer tokens. SQL constraints and triggers reject action/audit deletion, content replacement (including SQLite `OR REPLACE`), invalid transitions and terminal result mutation. New actions enter only as pending. Index audit inspection by action and sequence.

Bind SQL session/request IDs and expiry to the canonical action, and SQL approval expiry to the serialized grant. Validate these relationships and canonical bytes/digest on every row read, including internal completion; malformed persisted data quarantines the adapter with a redacted unavailable error. SQL checks enforce the same scalar/JSON relationships. These guards protect storage invariants, not arbitrary hostile code that can drop protections inside the owning object.

Preserve existing behavior: exact idempotent propose; conflicting reused ID rejected; pending-only approve/reject; pending/approved revoke; one approved→executing claim; terminal finish idempotent only for the same claim/outcome/result. Inspection excludes claim IDs and remains available after expiry under current membership. Self-approval is denied by subject or entity. Approval expires at the earlier of token/action expiry. Internal completion must remain recordable after caller authorization disappears. An ambiguous claim never authorizes an effect; no automatic retry or recovery execution exists.

Bound the prototype at 10,000 retained actions per object, with a smaller configurable test quota. Capacity exhaustion rejects new proposals while preserving existing inspection, decisions and completion. There is no deletion/retention API. This bound is a safety limit for local feasibility, not a retention or scaling solution for the requested workload.

## Authorization across awaits

The adapter requires a trusted local authority interface: synchronous `revision()`, `policy()` and `allows(principal)` plus the existing asynchronous `authorize(principal, context)` gate. `revision` must change atomically with every change to local trust, policy, membership or identity bindings. `allows` must check current local identity/key eligibility; `policy` returns current `ActionPolicy`. These callbacks are internal dependencies, not client input.

Capture the authority revision and immutable row version before the provider check. Await a bounded live authorization check outside SQL transactions. Then synchronously reread the revision, local eligibility, current policy, action row version and expiry inside `transactionSync`. Reject any stale snapshot; do not retry automatically. Consume SQL cursors fully before any await. Never perform network work inside a transaction callback.

Mutate state and append its audit event in one synchronous transaction, then await `storage.sync()` before returning. After that await, recheck local authority and time before returning client results or a claim. A revocation during this wait may leave an already committed transition with a denied response; inspection resolves that ambiguity. A storage/sync failure quarantines the adapter instance and yields `StoreUnavailable`, with no claim capability. A reopened instance may inspect persisted state but cannot reclaim executing/terminal actions. The caller still needs the existing live pre-send check after a successful claim.

The local authority implementation in the conformance harness is deliberately synthetic. Verified signed trust persistence, rollback checkpoints, provider revalidation and real binding configuration must be integrated in a later batch before a Worker service can be used. Passing a callback contract does not certify that future implementation.

## Durability and recovery limits

Use explicit synchronous transactions and durability waits; injected failures verify caller behavior, not physical disk failure. Local Miniflare persistence/restart proves only the tested local engine path. Cloudflare's hosted replication/PITR, account loss, external restore fencing and reconciliation of acknowledged actions are not established here. Restoring an older database can resurrect consumed claims; do not offer a restore/unfence command before the independent acknowledgment journal and recovery authority are designed and tested.

The unchanged acceptance targets remain 500 users, 200 agents, 120 actions/minute, machine P95 ≤2 seconds, restore ≤1 hour and no loss of acknowledged actions. Retention/partitioning and the precise failure model remain release gates.

## Verification

Run the adapter in actual local workerd through pinned Miniflare 4.20260730.0 / workerd 1.20260730.1, compatibility date `2026-07-30`, with `nodejs_compat`. Test schema/scope refusal, exact state/audit transitions, concurrent decisions/claims, authorization and row changes during awaits, token/action expiry, quota, injected transaction rollback, failed synchronization, lost claim response, immutable completion, restart persistence and at-most-one fake effect through the shared executor. No external network is required after dependency installation.

Source: [Cloudflare SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/), checked 11 October 2026. The platform documents synchronous transactional SQL and a durability synchronization API; hosted behavior still requires platform acceptance tests.
