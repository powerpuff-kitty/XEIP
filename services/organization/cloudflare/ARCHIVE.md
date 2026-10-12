# Collect and verify administrative archives

The Node operator collector saves a complete fixed-head copy of the [administrative journal](ADMIN_AUDIT.md). It verifies sequence/hash/timestamp continuity, matching attempt/results and an optional previous archive witness. It does not archive action payloads, remove source rows, restore an organization, or satisfy zero-loss recovery.

## Collect

Use a protected operator-controlled filesystem and the exact [operator binding configuration](WORKER.md). This is a manual privileged operator tool: it uses the existing OWNER binding, which also has administrative authority. Do not give that credential to a read-only third party or assume the collector supplies a narrower access role.

```sh
node services/organization/cloudflare/archive.mjs collect OPERATOR_CONFIG.json NEW_ARCHIVE_DIRECTORY --local
```

Use `--remote` only with a matching explicit remote binding and an authorized target account. The collector reuses one isolated Wrangler connection, loads no adjacent environment files, and sends only `auditExport` with fresh request IDs. There is no local fallback or automatic request retry. Each read RPC has a 30-second deadline; normal Wrangler setup/disposal still has its own runtime behavior. The public operator config is stored in the archive; credentials are not. That config identifies the intended service/binding, not independently attested account identity. Verify the real account/service/IAM before using a remote archive as evidence.

The destination must not exist. Files are created exclusively with 0600 permissions in a 0700 directory. Successful output contains only the fixed head, counts and manifest checksum. Copy that checksum to an independently controlled record, then protect the archive against modification and loss. Local hashes detect corruption but cannot detect an attacker replacing every byte and its checksum without an independent witness.

For a later complete snapshot, supply a prior verified archive:

```sh
node services/organization/cloudflare/archive.mjs collect OPERATOR_CONFIG.json NEW_ARCHIVE_DIRECTORY --remote PREVIOUS_ARCHIVE_DIRECTORY
```

The source config must match exactly. The new snapshot cannot move behind the previous head or change its historical checksum. Operator label/proxy-name/config changes require explicit handling rather than silently combining different sources. Each run captures the first exported head and stops there even if new events arrive. Collection and offline verification also reject a later observed head moving backward or reporting a conflicting checksum at the same sequence, including above that fixed cut. They do not establish ancestry of an unexported suffix without an observed contradiction. Unfinished attempts remain unfinished; the collector cannot convert them to success.

## Verify and handle failure

```sh
node services/organization/cloudflare/archive.mjs verify ARCHIVE_DIRECTORY
```

Verification is offline and read-only. It rejects missing/extra files, symlinks/special files, permissive file modes, noncanonical data (including prepended UTF-8 BOM bytes), broken chains, malformed attempts, altered seals and truncated pages. It reads bounded files and retains bounded attempt digests. Preserve directory/file permissions when copying archives. The parent directory tree and local operator account are trusted; this is not protection against a hostile same-user process racing filesystem changes.

Page data and directory entries are flushed before the manifest seal. The seal and directories are flushed before collection reports success. A failed collection leaves partial files for diagnosis and prints a fixed error. Never overwrite or silently repair that directory. Retry into a new directory. An absent/invalid seal is incomplete. Failure after writing a seal can leave structurally valid content with an uncertain durability outcome: offline verification checks consistency, not whether the failed collector reached its final flush. A new successful complete snapshot can establish a newly flushed copy.

## Operating limits

Pages contain at most 16 records under 64 KiB; source history is bounded at 100000 records. Every collection currently copies full history, and source export revalidates history. Maximum-size export duration, sustained cost and scheduling are not certified. This is a retention prerequisite, not indefinite-storage support. No automated collector schedule or deletion policy is enabled.

Keep archives in an accepted independent failure domain, with an owner, monitoring and restore practice. A periodic administrative snapshot has a gap after its captured head and contains no action payloads. It cannot meet no-acknowledged-action-loss, authorize replay after PITR, or replace synchronous independent recovery fencing/journaling. Retention policy, action export/tombstones, hosted capacity/recovery and security/operator acceptance remain production gates.
