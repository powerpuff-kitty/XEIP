# Collect and verify action archives

The manual operator tool preserves exact action requests, approvals, consumed claims, results and transition history at one fixed action-audit sequence. It complements the [administrative archive](ARCHIVE.md). It does not export historical policy/trust configuration, restore a database, delete history or grant permission to execute archived work.

## Collect and verify

Use the protected, explicit [OWNER binding configuration](WORKER.md) and an initialized organization. Export remains available independently of live user authentication or expired action grants; it requires the existing privileged owner capability. That credential also permits administration, so do not grant it to an automated read-only third party.

```sh
node services/organization/cloudflare/action-archive.mjs collect OPERATOR_CONFIG.json NEW_DIRECTORY --local
node services/organization/cloudflare/action-archive.mjs verify NEW_DIRECTORY
```

Use `--remote` only with a matching explicit remote binding and authorized account. The collector uses one isolated Wrangler connection and emits only `actionSnapshot` and `actionPage`; each read has a 30-second deadline and no retry. Connection setup/disposal follows the existing Wrangler runtime. The source configuration is an operator assertion, not independent account attestation. Confirm real account/service/IAM before treating remote evidence as authoritative.

The first capture computes a checksum over the complete fixed-cut snapshot. Later pages reconstruct that historical state even if approvals, effects or new proposals occur meanwhile. Collection validates every record, exact count, final empty page and initial checksum. It fails if records are missing, duplicated or changed. Capturing a full checksum performs synchronous ledger reads and hashing; it can delay other object requests. Maximum-history CPU, database reads, cost and latency still need hosted acceptance.

The destination must not exist. Numbered canonical record files are created with 0600 permissions in a 0700 directory. Data and directory flushes precede the final manifest seal; the seal/directories are flushed before success. Zero-action archives have only a manifest. CLI output contains snapshot/count/checksum metadata, not payloads. Retain a trusted manifest checksum independently: local hashes detect corruption but not replacement of all bytes and hashes by a privileged writer.

**Record files contain sensitive tool arguments/results and principal metadata.** Preserve permissions and protect storage, access and transfer. Separate provider credentials and bearer tokens are not copied from runtime state, but any sensitive values embedded in arguments/results are retained exactly. Raw owner inspection can print privileged export records; use the collector for metadata-only stdout.

For a later archive:

```sh
node services/organization/cloudflare/action-archive.mjs collect OPERATOR_CONFIG.json NEW_DIRECTORY --remote PREVIOUS_ARCHIVE
```

The previous archive must verify, with the same public source configuration and organization. The source must reproduce its earlier snapshot. The new archive must not move backward, and offline verification reconstructs the prior cut from the new records and checks the prior digest/count. Changing operator/service labels requires explicit source handling; no implicit archive merging occurs.

## Failure and verification

Verification is offline/read-only and checks canonical bytes, exact manifest/record schemas, action/history consistency, unique ordered identities/sequences, complete snapshot digest, optional previous witness, permissions and exact filenames/counts. Missing/extra files, symlinks/special files, BOM prefixes, corruption or truncation fail with a fixed error. Files are bounded to 480 KiB; record count is bounded to the current 10000-action cap. The collector retains bounded identity/sequence sets and one payload at a time.

A failed collection leaves partial files for diagnosis and never overwrites or repairs them. Retry to a new destination. Missing/invalid seals are incomplete. Failure after seal creation may leave structurally valid files with uncertain durability: offline verification cannot prove that a failed collector reached its final fsync. The parent directory tree and operator account are trusted; this is not a hostile same-user filesystem sandbox. Real filesystem/power-loss behavior needs an operator drill.

## Recovery limits

A snapshot may include transitions that were persisted locally but whose original caller never received an acknowledgment. It does not prove acknowledgment status or tool outcome beyond the recorded state. Executing/indeterminate claims remain consumed and uncertain; collection never completes or retries them.

A periodic snapshot has a gap after its cut. It cannot meet no-acknowledged-action-loss, detect a consistent rollback before its first independently witnessed capture, or authorize replay after point-in-time restore. Independent recovery journaling/fencing, authoritative policy/trust recovery, replay-preserving retention and hosted workload/restore/security/operator acceptance remain required. No automatic schedule, independent destination or deletion policy is configured.
