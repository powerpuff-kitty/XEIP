# Recovery journal bundles and offline action checks

The collector produces a complete, fixed-head copy of an already initialized recovery journal through the authenticated HTTPS client. It never appends, initializes, resets, deletes, restores a source database or calls a tool. No journal host has been deployed.

A bundle contains sensitive action arguments, approvals and results. Keep it outside the source failure boundary under accepted access and retention controls. The journal credential currently grants both reads and appends; this collector only uses reads, but it is not a separately delegated read-only credential.

## Collect through protected configuration

Create a private regular file with mode `0600` containing the existing transport configuration. JSON may be pretty-printed; the file must not exceed 8 KiB or be a symlink. Use the exact enrolled URL, organization, stream and capacity settings. Supply the existing 32-byte lowercase-hex credential from protected secret custody; the placeholder below is intentionally invalid.

```json
{
  "url": "https://journal.example/v1/recovery",
  "token": "REPLACE_FROM_PROTECTED_SECRET_CUSTODY",
  "options": {
    "organization": "example-org",
    "stream": "8f310e3a-c4c8-4ef2-b42c-4660251c89aa",
    "maxEntries": 1000000,
    "maxBytes": 1073741824,
    "timeoutMs": 5000
  }
}
```

Use Node 22.23.3 and the repository lockfile/build. Commands do not load credentials from environment variables or accept the token as an argument:

```sh
node services/organization/cloudflare/recovery-archive-command.mjs collect /protected/journal.json /protected/new-bundle
node services/organization/cloudflare/recovery-archive-command.mjs verify /protected/new-bundle
node services/organization/cloudflare/recovery-archive-command.mjs actions /protected/new-bundle
```

For subsequent collection, pass a previously retained verified bundle as the last argument. The collector checks the same normalized public source and journal prefix. Pass that same previous directory when verifying the new bundle to check its recorded witness against the independently supplied evidence:

```sh
node services/organization/cloudflare/recovery-archive-command.mjs collect /protected/journal.json /protected/next-bundle /protected/new-bundle
node services/organization/cloudflare/recovery-archive-command.mjs verify /protected/next-bundle /protected/new-bundle
```

Success prints only operation, head/checksum and counts. Errors use fixed text without configuration, paths or payloads. A failed command is not permission to overwrite evidence or retry a tool effect. Collection may be rerun into a different new directory after investigating the error; it never automatically retries a read.

## What is verified

The initial head fixes the bundle cut. Later journal appends may continue, but they do not enter this bundle. Collection checks every contiguous entry, unique ID, scope, predecessor, cumulative bytes, canonical base64 part and full payload SHA256. Before sealing, it checks that the live head has not regressed and that the captured tail still matches. Each read has a bounded deadline; a late response cannot resume writes or seal the bundle.

The new directory is `0700` and its exclusive files are `0600`. Numbered files contain canonical `{entry,chunks}` records. The manifest `xeip.recovery-archive/1` binds the public source, fixed head, retained raw byte count, exact file hashes and optional previous witness. Data files are synchronized before the manifest is written; directory and parent synchronization precede reported success. Failures preserve incomplete evidence. A manifest left after a failed final synchronization does not prove that a successful durable receipt was returned.

Offline `verify` requires the exact regular-file set, protected modes, no symlinks, strict canonical JSON and complete chain/payload consistency. It processes one record at a time, bounded by the existing 16 MiB record/24 MiB JSON file limit. Retained entry and raw-byte caps remain 1 million and 1 GiB; base64, headers, files and filesystem metadata add overhead. Full-prefix collection and verification are not certified against the one-hour restore target.

`actions` adds semantic verification: exact `xeip.action-recovery/1` payloads, organization/sequence, deterministic journal IDs, valid per-action transitions and byte-equivalent continuity between versions. It tracks hashes and small metadata for at most the source’s 10,000 actions, rather than retaining all argument/result bodies in memory. It rejects removed or replaced claims, omitted transitions and unknown record types. The result is aggregate state/action/consumed-claim counts. Executing or indeterminate actions remain consumed; these checks never issue an execution capability.

## Limits and next gates

Hashes establish content consistency, not authenticity against a privileged journal/filesystem operator or proof of historical synchronization. A prior witness must be retained independently to constrain rollback; a consistent rollback of the journal and every witness cannot be detected by this tool. Records establish committed journal content, not proof that a particular caller received its acknowledgement.

A periodic bundle does not protect acknowledgements after its cut. The separate [fenced reconstruction module](ACTION_RESTORE.md) can rebuild action rows/audit in an isolated unavailable candidate; the collector does not activate it, recover trust/authority/admin state, implement retention, select a failure boundary or certify hosted TLS/IAM/storage independence. Complete restore and representative 500-user/200-agent/120-action-per-minute, P95≤2s, restore≤1h, no-acknowledged-action-loss and security/operator acceptance remain required.

See [journal](RECOVERY_JOURNAL.md), [HTTPS transport](RECOVERY_HTTP.md), [action gate](ACTION_RECOVERY.md), [design](../../../spec/cloudflare-recovery-archive.md), and [verification ledger](../../../spec/plans/cloudflare-recovery-archive.md).
