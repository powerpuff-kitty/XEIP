# Fenced action reconstruction

`StagedActionRestore` reconstructs action rows and their complete audit history from a verified recovery bundle into a **separate empty SQLite database**. The candidate remains unavailable for execution, even after successful verification. This is an internal recovery building block, not a complete restore command or a production activation route.

The production Worker does not expose this module. Never deploy the conformance Worker: its private fixture includes arbitrary SQL and fault controls. No organization database is overwritten, no tool is called and no consumed claim becomes executable.

## Internal storage API

First use the [bundle verifier and semantic action checks](RECOVERY_ARCHIVE.md) on retained evidence. Supply its exact manifest and canonical numbered records to the internal storage capability:

```js
const candidate = await StagedActionRestore.initialize(emptyStorage, manifest);
for await (const record of recordsInSequence) await candidate.apply(record);
const receipt = await candidate.verify();
// receipt.phase === 'verified'; receipt.blocked === true
candidate.close();
```

Stream bounded records rather than load the entire bundle. `initialize` refuses all existing application tables, including an already initialized empty XEIP ledger. It creates the current schema9, immutable recovery enrollment and a permanent restore intent atomically, then synchronizes. `open(storage, manifest)` resumes only that exact manifest after reconciling the entire persisted prefix; it never initializes or repairs application data. A valid schema8 staged candidate is explicitly upgraded inside the same transaction as full-prefix reconciliation; failure rolls back the schema change and the fence is never removed.

`apply` validates scope, sequence, payload hash, deterministic ID, canonical data, history and prior action projection. The action change, original audit event and progress share a transaction. Existing SQL constraints remain enabled. Success follows synchronization and checks of the committed record. An exact current-tail retry is idempotent; old or out-of-order records cannot overwrite data. A blocked progress receipt is not full bundle verification: the final head, complete files checksum and prior witness are checked by `verify` and full-prefix reconciliation.

`verify` regenerates each journal entry from the actual SQL history and checks the target head, bytes, exact file checksum and prior witness. It persists `verified` only after these checks and synchronizes before success. Pending, approved, rejected, revoked, executing, succeeded, failed and indeterminate states retain their original rows, audit, approvals and claims. This module supplies no execution capability.

`status()` performs full prefix reconciliation. Receipts expose manifest identity, phase, head, byte/action counts and `blocked:true`; they contain no arguments, results or credentials. `close()` invalidates the instance. One operation runs at a time; concurrent calls conflict. The synchronization timeout is 100–10000 ms, default 10000 ms. Uncertain writes, storage faults, timeouts and corruption quarantine the instance. After investigation, a fresh `open` must validate persisted evidence and perform its own synchronization; it may do so while an earlier sync promise remains pending. The quarantined operation has no remaining mutation continuation. Do not retry a tool effect.

## Durable activation fence

Schema 8 adds a singleton restore intent with checked contiguous progress and immutable manifest. SQL guards prevent replacement, deletion, intent changes and phase reversal. Normal schema initialization and verification reject any restore row, including malformed or fully verified rows. Schema9 additionally fences complete organization restores; prior executables reject the newer schema. Downgrading code is not a supported schema rollback.

The candidate requires control-plane tables to remain empty. It is intentionally unsuitable for service activation: trust, authority, administrative history and external execution fencing have not been recovered. There is no reset, delete, activation or namespace-selection API. Do not alter SQL guards or remove the restore row to turn this candidate into a live service.

## Evidence and remaining gates

Native tests cover every action outcome, interrupted/ambiguous commits, synchronization failures, timeout, close, restart, exact-tail retry, schema 7 data preservation, corruption and malformed/forked evidence. An actual signed Worker→authenticated journal→bundle workflow reconstructs its completed action and consumed claim in another native database, leaves normal store/service activation blocked, and suppresses repeated source execution after restart. See [the verification ledger](../../../spec/plans/cloudflare-action-restore.md).

Current complete regression suites pass 527/527 on each of macOS Node 26.8.1 and pinned Linux Node 22.23.3, with strict Cloudflare types on both. Earlier fixture/setup failures remain in the ledger. These local results complete implementation verification for this module; they do not authorize activation or certify hosted deadlines.

The bound remains 10,000 actions/40,000 transitions; full history reconciliation cost is proportional to retained history and is not certified against the one-hour restore target. Checksums prove consistency, not freshness or independent authenticity. A bundle cut excludes later acknowledgements. Complete organization reconstruction is now provided by the separate [organization restore library](ORGANIZATION_RESTORE.md). Coordinated current-journal reconciliation and external execution fencing, independent hosting/IAM/TLS, retention and hosted workload/recovery/security/operator acceptance remain required.

See [design](../../../spec/cloudflare-action-restore.md), [action acknowledgement gate](ACTION_RECOVERY.md), [readiness](../../../PRODUCTION_READINESS.md).
