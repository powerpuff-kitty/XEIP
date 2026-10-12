# Ordered recovery journal storage core

Purpose: supply the durable append boundary needed before source mutations can be acknowledged or external effects can execute safely after database restoration. The application must eventually publish complete recoverable mutation data here before acknowledging it, and reconcile its local history against this journal before use. This increment implements the storage core only, in a separate database. It exposes no public or production Worker entrypoint, performs no source mutations/restores, and does not yet meet the no-acknowledged-action-loss requirement.

## Scope and identity

One explicitly configured organization and immutable random UUID stream per database. Initialization is explicit and requires no existing XEIP schema; opening empty/mismatched/corrupt storage fails without bootstrapping. The source action database must not be reused. Stored metadata binds schema version, organization, stream, entry/byte caps and catalog. No migration, reset or deletion API. The owner of namespace/database access is trusted. Hashes detect corruption and continuity changes; they do not authenticate a cloud account or prevent a privileged complete rewrite.

A local separate SQLite database is useful conformance evidence, not an independent production failure domain. A journal restored or lost with the source cannot establish rollback detection. Same-provider separate storage cannot cover loss of that provider/account. User failure-boundary clarification, hosting/IAM/credential choice and operator acceptance remain open; no narrower guarantee is inferred.

## Append and read contract

`RecoveryJournal.initialize(storage, options)` creates a new journal and synchronizes before returning it. `open(storage, options)` requires existing exact metadata/catalog and reconciles all retained entries/chunks before returning a ready instance. Options: organization, stream UUID, optional maxEntries (default/ceiling 1000000), maxBytes (default/ceiling 1073741824), timeoutMs (100–10000; default5000). Caps persist and must match on reopen; timeout is runtime-only. Genesis checksum binds identity/caps with a versioned domain.

`healthy()` checks ready state, catalog and the cached tail header; it does not continuously rescan historical payloads. Full open and selected reads perform payload integrity validation. Future source integration must not use health alone as a complete reconciliation attestation.

`head()` returns `{organization,stream,sequence,checksum}`. Empty sequence0 uses the genesis checksum. `append({expected,id,bytes,payloadDigest,chunks})` requires exact current head, a UUID id, 1–16777216 payload bytes, SHA256 digest, and 1–64 canonical base64 chunks of at most262144 decoded bytes each. Every non-final chunk has exactly262144 bytes; final length, count and whole-payload hash must match. The journal does not parse or execute opaque payloads: the future source/restore adapter must define and validate their versioned semantic format. No secret/body logging.

One synchronous transaction inserts an immutable entry header and all parts. The header binds schema `xeip.recovery-entry/1`, organization, stream, contiguous sequence, id, previous checksum, payloadDigest, bytes, parts and cumulative totalBytes. Its checksum uses domain `XEIP recovery entry v1\n` plus canonical header without checksum. A receipt is that exact header including checksum, returned only after storage synchronization and revalidation. Busy writes reject overlap; reads cannot advertise a not-yet-synchronized head. Closing or a storage/sync failure prevents later activation; uncertain outcomes require a fresh validated instance.

Stale/forked expected heads, duplicate historical IDs and capacity exhaustion return conflict without poisoning a healthy journal. The exact current-tail retry is idempotent only when expected predecessor, id, metadata and payload match; it still synchronizes/revalidates before returning the original receipt. An older repeated entry after the head advanced is a conflict, not permission to resume stale state. There are no automatic retries or effect capabilities.

`entry(sequence)` returns validated metadata and `part(sequence,index)` returns `{entry,part,data}` for bounded reconstruction. Positive integer sequences must exist; indexes must be in range. Validate the selected entry's payload and adjacent chain links. Opening validates complete sequence/hash/cumulative/count continuity plus no orphan/missing/extra parts. No page offsets, raw SQL, caller-supplied filenames or arbitrary limits. Reads during write/failed/closed state fail closed.

## SQL invariants and bounds

Separate immutable metadata, entries and chunks tables, protected from update/delete/INSERT OR REPLACE. Entry sequence/predecessor/cumulative totals/caps and UUID uniqueness are enforced in SQL and application validation. Chunks require an existing entry and legal part index; insertion cannot replace a prior part. Each base64 row is at most349528 bytes, below the provider row limit. Writes are atomic; partial insertion/transaction faults cannot leave a successful partial record.

Scan metadata in bounded128-entry pages and payload one chunk at a time. Retained raw bytes are capped at1 GiB; base64/index overhead is additional. These are prototype safety caps, not sustainable120-action/min capacity. Full reconciliation and validating an entire entry before each part read can be expensive; segmentation, admission/streaming transport, startup cost and hosted CPU/memory/latency acceptance remain required. The 16 MiB append envelope is an internal trusted adapter contract, not an expanded public API/body limit.

## Completion and recovery limits

Prove explicit initialization, independent namespaces, scope/caps, atomic multi-part append, head conflicts/idempotency/concurrency, durable acknowledgment ordering, lost-sync reopen, late close/timeout, corruption/catalog/SQL replacement guards, capacity and bounded export through real local workerd/SQLite. No source acknowledgment gate, independent provider storage, recovery fence, replay/restore engine, archival/retention or hosted SLA is completed by this core. Never infer that a journaled byte payload is an approved action.
