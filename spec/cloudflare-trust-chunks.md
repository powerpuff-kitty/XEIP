# Bounded persistence for large signed trust bundles

The existing trust adapter accepts up to 8 MiB canonical provisioning data and 4096 retained identity checkpoints, but writes the entire bundle into one SQLite row. Cloudflare documents a [2 MB maximum string/BLOB/table row](https://developers.cloudflare.com/durable-objects/platform/limits/) (checked 2026-10-11). Preserve the existing logical bound without relying on oversized provider rows. No change to identity signatures, freshness, authority, public/private request sizes or effect semantics.

## Storage contract

Add schema version 6 with `xeip_trust_chunks(revision,part,data)`; each part is canonical base64 of at most 262144 raw UTF-8 bytes. At most 32 parts represent the current 8 MiB bundle. The existing state row stores either its legacy exact canonical provisioning string or an exact canonical descriptor `{schema:'xeip.trust-chunks/1',bytes,parts,digest}`. Use chunks for bundles larger than 262144 bytes; small updates stay inline. SHA256 covers the complete raw canonical bytes. Revision is bound by the state row and each chunk. The existing state checksum continues to cover the resolved canonical provisioning string, preserving logical state checksums and trust behavior.

Read requires exact descriptor fields, canonical bytes, integer bounds, matching revision, consecutive parts, canonical base64, exact part sizes/count, total bytes/hash and valid UTF-8. Any extra/orphan/missing/changed chunk fails closed. Inline state requires no chunks. Resolve before existing canonical/signature/checkpoint checks; never repair corrupt input. No chunks can authorize before complete validation and storage sync.

Update state, replace its previous chunk representation and update rollback checkpoints within the existing single synchronous transaction. Delete only obsolete representation chunks after the state revision advances, never checkpoint/history records. Chunk insertion requires the current state revision/descriptor/part range, and rejects replacement; updates and current-revision deletion fail. Completed updates retain only the current bundle representation. A failed write rolls back the whole transaction; ambiguous sync quarantines the live adapter and a fresh instance validates persisted state before use. Closed/failed state cannot reactivate.

## Migration and compatibility

The additive v5→v6 migration preserves all existing rows, checksums, constraints and consumed action history. Existing small/large inline rows remain readable. No current trust bundle is rewritten on migration/open. Later updates may switch between inline and chunked representations atomically. Partial bootstrap rejects orphan chunks as well as existing trust/checkpoint state. All owner/audit schema checks recognize version 6; old v1–v5 migration/catalog checks remain exact. A v5 executable must reject v6 rather than downgrade. Reverting code after a data migration requires a reviewed forward compatibility/restore procedure, not table deletion.

## Verification and limits

Use native workerd/SQLite tests for signed >2 MB update/reopen, bounded rows, chunk↔inline transitions, mutation/replace constraints, rollback/sync ambiguity, missing/extra/wrong revision/content, exact v5 migration preservation and bootstrap refusal. Test the 8 MiB boundary and malformed descriptor/base64/UTF-8 with bounded helpers; public 2 MiB provisioning commands remain unchanged. This fixes storage representation only: supported population, maximum-size CPU/memory/head-of-line latency, hosted SQL limits, recovery fencing and operational acceptance still require evidence. No cloud resources or source history deletion.
