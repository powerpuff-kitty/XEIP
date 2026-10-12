# Verifiable recovery-journal bundles

The accepted no-acknowledged-action-loss and one-hour restore targets require recovering complete acknowledged histories, including consumed execution claims. The HTTPS client can retrieve journal headers/parts but no operating tool currently produces a durable, independently checkable complete bundle. Implement this prerequisite without changing the accepted failure boundary or issuing restore/replay operations. Keycloak and both existing runtime profiles remain.

## Approach

Collect a fixed initial head through the existing authenticated client, using only head/entry/part. Download entries1..head in order, validating scope, sequence, predecessor checksum, cumulative bytes, unique entry IDs, every canonical base64 part and the complete payload digest. A later append may advance the live head; never include it in the fixed bundle. Recheck live head has not regressed and re-read the captured head entry before sealing. A coherent rollback of all witnesses remains undetectable; an independently retained previous verified bundle constrains current prefix continuity.

A raw database export would bind operators to storage internals and bypass transport validation. Asynchronous partial snapshots would not contain all journal records. Choose provider-neutral bounded sequential collection of complete records through the existing read protocol.

## Format and custody

New directory0700; files0600 with exclusive no-follow creation. Files0000001.json onward contain exact canonical `{entry,chunks}` records, at most24MiB each. Preserve opaque bytes; the journal's16MiB record/1GiB total/1million entry limits remain. Process one record at a time rather than buffering the full journal. Manifest `xeip.recovery-archive/1` binds normalized public source `{url,options:{organization,stream,maxEntries,maxBytes}}`, fixed head, totalBytes, filesChecksum and optional prior `{head,manifestChecksum}`. Domain-separated manifest/file hashes bind exact canonical bytes. Write and sync data first, manifest last, then sync directory and parent. Failure leaves an incomplete directory and fixed redacted error; never overwrite, retry automatically or delete evidence.

Offline verification requires a private real directory, exact expected regular-file set, no symlinks, canonical strict JSON, bounded sizes, complete chain/payload consistency and exact manifest checksum. Optional independently supplied prior archive must match the manifest's prior witness, source identity and prefix. Hashes establish content consistency, not independent authenticity or historic fsync. Source URL is provenance, not account/IAM attestation.

Collection reads may continue after initial capture only within that prefix. Every injected client call has a bounded deadline (default30s,100..30000ms); late resolution cannot write or seal a bundle. The real HTTP client applies its own shorter transport timeout. Filesystem failures must not return success. A manifest present after a final fsync failure is unacknowledged evidence, not proof of a durable receipt.

## Action interpretation

Separate `verifyRecoveryActions` first validates the complete bundle, then decodes each payload as strict canonical `xeip.action-recovery/1`. Validate exact organization and contiguous journal/source sequence, deterministic action-recovery UUID, valid action evidence and exact historical continuity for each session/request pair. Re-project each subsequent record at its previous sequence and compare the prior record byte-for-byte. New actions begin with one proposal; consumed claims can never disappear or become reusable. Return only aggregate action/state/consumed-claim counts and manifest/head identifiers, not sensitive arguments/results. No trusted action state is returned before complete verification; unknown record types fail action interpretation while remaining valid opaque journal bytes.

## Operator interface and scope

Library collector accepts validated public source plus a read capability. CLI `collect CONFIG NEW_DIRECTORY [PREVIOUS_ARCHIVE]`, `verify DIRECTORY [PREVIOUS_ARCHIVE]`, and `actions DIRECTORY [PREVIOUS_ARCHIVE]`. CONFIG is a private regular nonsymlink strict JSON file≤8KiB containing exactly the existing `{url,token,options}` transport configuration; no environment fallback or token CLI parameter. Success prints identifiers/counts only. Failure prints fixed usage/error text with no cause, path, endpoint, credentials or payload. The real credential currently grants journal read and append; the collector only invokes reads and does not create a least-privilege role.

Full source restore, trust/authority/admin recovery, hosted journal lifecycle/IAM/independent storage, retention, sustained capacity and latency/recovery/security/operator acceptance remain required. A periodic bundle does not protect acknowledgments after its captured head. No deployment or purchase occurs.

## Verification

RED→GREEN focused empty/nonempty/multipart archive roundtrip; advancing journal/fixed cut, full payload corruption, scope/chain/byte/ID mismatch, malformed JSON/extra/missing/symlink/world-readable files, prior rollback/fork, exclusive directory, injected sync failure, delayed client response; CLI redaction/private config. Native separate journal with authenticated HTTP client collects real payloads; source signed action flow verifies consumed claims/outcomes. Full macOS/Linux Cloudflare suites/types, exact Worker/scheduler artifact checks and applicable Linux image verification required. No new dependencies.
