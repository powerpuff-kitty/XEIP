# Experimental administrative audit

The deployed private owner path journals initialization, signed trust replacement and authority updates. Each accepted attempt is persisted before mutation; successful acknowledgment waits for a persisted completed record. A stale revision is recorded as conflict. Refusals before admission (malformed input, missing binding capability, busy service, full journal or invalid first setup) do not create an attempt and cannot mutate authority. Status and export are read-only.

Records contain only the validated binding operator label, request UUID, generated attempt UUID, operation, canonical-command SHA-256 digest, timestamp, outcome and compact lifecycle/trust/authority revision summaries. Raw commands, secrets, policies, tokens and provisioning documents are excluded. The operator label identifies the privileged binding; it does not authenticate a human. Accept account IAM and named operator ownership separately.

## Export

Use the same protected operator configuration and explicit local/remote mode described in [the Worker guide](WORKER.md). Prepare a protected command file with a fresh request UUID:

```json
{"operation":"auditExport","requestId":"369a98d2-d5db-4365-a101-0bbf79ae33d1","after":0,"limit":16}
```

```sh
npm run cloudflare:owner -- /protected/operator.json /protected/audit-command.json --local
```

The private receipt has `audit.records`, `audit.next`, `audit.headSequence` and `audit.headChecksum`. Continue from `next`, using a new request UUID. Each page captures the current head; concurrent administrative changes can advance it between pages. For a fixed cut, retain the first head and request only the remaining entries up to it. Verify each page's first `previous` checksum against the preceding page's last checksum. The client validates exact schemas, record checksums, contiguous sequence numbers, page bounds and correlated receipt metadata before printing. An empty uninitialized export does not create any tables. Public HTTP/default RPC cannot export.

Persist exported pages and their head checksums in an independently controlled destination once one is selected and accepted. A [manual archive collector](ARCHIVE.md) now verifies fixed-head complete snapshots and optional prior witnesses, using the existing privileged operator binding. Independent storage, automated scheduling and retention acknowledgments are not configured. Local hash chains detect corruption; they do not protect against an administrator rewriting an entire database and its checksums.

For internal recovery composition, `OwnerJournal.checkpoint()` and `historyPage(checkpoint, cursor)` provide [historical administrative capture](../../../spec/cloudflare-admin-checkpoint.md). These methods require a settled journal and an unchanged scoped head. The platform-neutral verifier checks complete continuity and matches results to starts across page boundaries, retaining unresolved counts. They introduce no new owner RPC and do not replace the manual archive collector or authorize retrying an unresolved operation.

`historyPageAt(checkpoint, cursor)` additionally permits an earlier captured head after later commands, while preserving the original `historyPage` behavior. It verifies current source integrity and the captured head's retained checksum, then restricts reads to that sequence. A captured empty head stays empty; retained unresolved attempts remain unresolved in that cut. Foreign or unmatched checkpoints cannot modify healthy state, and source corruption fails closed. Full-history scans still occur on reads; practical maximum-history cost and the [complete private operator export](../../../spec/plans/cloudflare-organization-export.md) remain unfinished.

For internal streaming, `historyReaderAt(checkpoint)` verifies complete source history and the retained cut once, then returns `page(cursor)` and `close()`. Each page checks schema, organization, the same live journal instance's accepted tail, the captured anchor, predecessor and selected records. Later commands on that instance may advance the live tail; unrelated instance advancement, damaged selected data or storage faults fail closed. Pending administration conflicts, and a closed reader cannot resume. This is selected-history evidence, not continuous integrity attestation of every source row on every read. Complete bundle collection must validate all pages from genesis to the captured head before sealing. The standalone page APIs and live mutations keep their full scans. Local row-work measurements are in the export plan; full initial capture cost, private transport and hosted acceptance remain open.

`captureHistoryReader()` captures the fully verified current checkpoint and a scoped reader in the same synchronous pass. It accepts no external checkpoint or verification proof. Organization export uses this factory during its confirmed post-sync capture, retaining the full pre/post manifest comparison while avoiding a third complete history scan. The checkpoint is immutable, and callers must close the reader on completion or failure. This internal method adds no durability receipt or activation permission.


## Uncertain outcomes

`started` without a later terminal record means the attempt is unresolved. It may already have applied. Inspect current revisions and reconcile the intended change; never automatically replay or interpret the missing result as failure to apply. Terminal `unavailable` likewise does not prove an operation had no effect. Request IDs correlate calls and are not idempotency keys; separate attempts have separate generated IDs.

A lost response or failed synchronization can return unavailable even if data reached storage. Persistence/corruption failures quarantine the service, preventing further public effects until a fresh instance validates persisted state. A successfully completed record describes a completed mutation, not proof that its caller received the receipt. No reset/delete/repair operation is exposed.

## Migration and capacity

Schema v5 upgrades existing checked v1–v4 state forward. Existing action, trust, authority and lifecycle data remains intact. The journal begins with new managed operations after this upgrade; it does not invent historical operator attribution. Older binaries reject v5. Roll back with a reviewed forward fix; restoring an old database or creating a new namespace is not safe effect recovery.

Records are at most 2 KiB; exports contain at most 16 records under the 64 KiB receipt limit. Journal capacity is 100,000 records. New attempts reserve room for their terminal record and fail closed when capacity is insufficient. Unresolved attempts remain in history. No automatic deletion/pruning is implemented. Establish retention/export policy and capacity alerts before production; automated refresh adds administrative records and must be included in that sizing. Validation reads bounded pages and uses indexed attempt/result joins. Growth performance is not yet certified on hosted infrastructure.

This journal shares the action database and cannot survive its rollback/loss independently. It does not meet the no-acknowledged-action-loss requirement by itself. Independent recovery fencing/journaling, restore drills, hosted workload tests, real operator/IAM/browser acceptance and security review remain production gates.

Contract: [administrative audit design](../../../spec/cloudflare-admin-audit.md). Evidence: [execution ledger](../../../spec/plans/cloudflare-admin-audit.md).
