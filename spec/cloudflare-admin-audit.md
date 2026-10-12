# Durable Cloudflare administrative audit

Status: implementation under authorized local Cloudflare-native exploration; no hosted deployment or production acceptance. Keep Keycloak and all workload/recovery targets.

## Contract

Administrative initialization, signed trust replacement and authority changes must have a durable attempt record before they mutate state and a durable terminal record before successful acknowledgment. Store only validated binding operator label, request UUID, internally generated attempt UUID, operation, SHA-256 digest of the validated canonical command, timestamp and compact before/after revision summaries. Never store raw commands, tokens, secrets, provisioning documents, policy contents or arbitrary errors. The binding label attributes a capability; named human authentication/IAM remains an operator acceptance gate.

Use an append-only SQLite journal in schema v5. Each row has a monotonic contiguous sequence, canonical bounded event JSON, previous checksum and a domain-separated SHA-256 checksum. SQL constraints/triggers forbid update/delete/replacement and mismatched scalar fields. Validate full history in bounded pages on open and before mutation/export; corruption or persistence uncertainty quarantines the service. Checksums detect corruption; they do not defend against an administrator rewriting the database and chain together.

An attempt has one started record and at most one terminal record (completed, conflict, invalid_request or unavailable). Reserve capacity for the result before beginning. Local opaque completion tickets cannot be forged, reused, or restored after restart. A crash can leave only started: its outcome is unknown, may already have changed state, and must be reconciled against current revisions. Never infer no mutation, replay an operation or fabricate a terminal record. Request IDs are correlation only; separate attempts have separate UUIDs.

First initialization installs lifecycle intent and its journal attempt in the same transaction before synchronization. Existing v4 state upgrades forward without inventing historical attribution. Empty public open still creates no tables. All production owner mutations use the journal; low-level service fixtures remain trusted adapter APIs. A successful underlying mutation followed by journal failure returns unavailable and quarantines public effects. Current persisted authority remains the source of truth after validated reopen.

Private auditExport accepts an exclusive after sequence and limit 1..16 (default16), plus requestId. Export returns bounded verified rows, next cursor and captured head sequence/checksum; no public HTTP/default RPC export. Export does not mutate or recursively log itself. Unknown/malformed input and status probes are not journaled to avoid unauthenticated write amplification. Before initialization, export is an empty page with head0. The operator client validates exact export receipts before printing.

## Limits and recovery

Each event is at most2048 UTF-8 bytes; journal cap100000 records, with fail-closed mutation refusal before exhaustion. No deletion/pruning/archive acknowledgment is introduced. Retention and sustainable refresh cadence remain production requirements. Use bounded pages of256 for validation and at most16 for export (well below the64KiB receipt cap). Timestamps are nondecreasing wall-clock observations, not proof of real-world order beyond sequence.

The journal shares the organization's database and recovery domain. It cannot establish no acknowledged-action loss, prevent database/PITR rollback, or survive account/provider loss independently. A separate recovery journal/fence remains required; its failure boundary is awaiting user clarification.

## Verification

Native workerd/SQLite tests must cover append and immutable constraints, corruption/history gaps, pagination/head continuity, size/capacity bounds, opaque tickets, sync faults/late completion and real restart. Service integration must show initialization attempt atomicity, before-effect/after-result durability, conflict/rejection recording, no secret leakage, public/private separation, v4 migration and existing signed-action/revocation/no-replay behavior. Preserve all existing conformance and strict types on macOS and Node22/Linux. One fresh scoped final review; fix accepted findings with regressions.

## Alternatives and rollout

Diagnostic logs alone cannot prove durable ordering. An external collector alone would add an unprovisioned network dependency and leave local mutation attribution incomplete; implement local durable audit now, then export to an independently operated destination as part of accepted recovery/retention design. Never claim this local journal supplies that independent guarantee. Schema migration is forward only: older binaries reject v5; rollback requires a reviewed forward fix, never restoring an older database and replaying consumed actions.
