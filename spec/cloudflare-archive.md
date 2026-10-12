# Administrative archive collection

Experimental local operator tooling, prerequisite to retention/export operations. Preserve all production workload/recovery targets. This increment archives the administrative journal only; it does not export action payloads, restore authority, prune source rows or satisfy no acknowledged-action loss.

## Collection contract

`archive.mjs collect OPERATOR_CONFIG.json NEW_DIRECTORY --local|--remote [PREVIOUS_ARCHIVE]` uses the existing explicit private named OWNER binding and validates every correlated receipt. One isolated Wrangler connection serves all read-only `auditExport` calls; no owner mutation or automatic retries. Configuration is exact and source-pinned; a previous archive must have the same canonical public operator configuration. Remote credentials/account context are supplied through the existing operator environment, never stored in an archive. The source label/config is an operator assertion, not independent proof of account or organization identity; real account/IAM acceptance remains required.

The first page captures head sequence/checksum. Subsequent requests use fresh UUIDs and limit<=16, stop exactly at that head even when new records arrive, reject observed head rollback/fork (including above the fixed cut) and verify continuous sequences/hash links/nondecreasing timestamps across pages. Validate each terminal event against its unique prior start (metadata, attempt ID and before state); preserve unfinished attempts as unknown. Bound by the existing 100000-record cap. If a previous complete archive is supplied, the new snapshot must include its head with the identical checksum and may not shrink below it.

Collect a complete snapshot from sequence 1 each time. This deliberately gives each archive a self-contained history and allows checking terminal records against starts across page boundaries. It does not implement incremental retention epochs. Full-history source validation per page is potentially expensive; sustained/maximum-size export duration must be measured before operating acceptance. This functional tool is not a capacity certification.

## Durable artifact

Create a new private 0700 directory; never overwrite an existing destination. Parent directories are trusted operator-controlled local filesystem paths. Fixed numbered page filenames cannot be supplied by the source. Files are 0600 and exclusively created. Flush page contents, then directory entries; write a canonical exact-schema manifest/seal last, flush it and the directory and parent before reporting success. A bounded manifest identifies source, fixed head, page/record counts, aggregate page checksum, optional prior archive witness and its own domain-separated checksum. No secret, raw command, action arguments or arbitrary error enters the artifact or stdout.

Failure leaves partial files for diagnosis; it cannot alter the source or a prior archive. An absent/invalid seal means incomplete. Failure after a seal write can be an uncertain local durability outcome: never claim success. Collection retry uses a new directory and a new current cut; no partial-directory overwrite or silent repair. A verifier performs no network access or mutations and certifies content consistency only, not prior filesystem flush guarantees or malicious whole-archive rewriting.

`archive.mjs verify DIRECTORY` validates exact canonical manifest/page schemas, sizes, filenames/counts, hash chain, sequence/timestamp continuity, attempt/result consistency and fixed head. Reject symlink files/directories, special files, permissive access modes, truncation, extra files and altered page/seal bytes. Read bounded pages; keep only bounded attempt digests in memory. Independently retain a trusted manifest checksum to detect replacement of all local archive bytes. Protect local filesystem ownership; checks are not a hostile-same-user filesystem sandbox.

## Security and recovery limits

Only named owner bindings can export; ordinary public HTTP/default RPC remains denied. The collector has no root/status signing keys. Privileged operator/deployment code may already administer, but this tool emits only auditExport. Returned errors are fixed/redacted. Deadline each read-only RPC at 30 seconds; late results cannot become an acknowledged archive. Dispose the isolated connection and remove only its own temporary Wrangler configuration.

A periodic archive has a gap after its captured head and shares whatever failure domain its destination uses. It neither proves zero-RPO action durability nor prevents automatic replay after database restore. Independent synchronous recovery fencing/journaling and operator restore acceptance remain required. Source deletion and archive retention are excluded until policy and a safe replay-preserving retention design are accepted. User retention preference and failure boundary remain pending; no destructive default is inferred.
