# Experimental persistent trust

`DurableEntityTrust` provides the signed identity portion of the experimental object-local authority. It reuses the same provisioning verification and rollback rules as the Linux filesystem implementation. It does not supply provider login, membership/policy administration or a public Worker API.

Run `npm run test:cloudflare` for the ledger and persistent-trust suites, followed by `npm run typecheck:cloudflare`. The trust fixture uses real Ed25519 key/status documents and the shared ledger/executor; provider responses and effects are synthetic. Its privileged SQL/control interface must never be deployed.

## Lifecycle

The trusted object owner calls `await DurableEntityTrust.open(storage, {organization, configuration, initialize})`. Configuration supplies `maxAgeSeconds` (1–86400) and optional understood critical extensions. Set `initialize: true` only for explicit first initialization; it refuses an existing snapshot or orphaned checkpoint history. Ordinary reopen requires valid existing state and the same normalized configuration. Empty trust authorizes nobody.

Call `await trust.update({keyDocuments,statusDocuments})` with complete owner-provisioned signed data. Initial/new identities require explicit anchors. Invalid signatures, rollback, forks and anchor changes are rejected without replacing usable authority. Removed identities lose access while their checkpoint rows remain. Once persistence starts, all trust-authorized use is gated until state and checkpoints commit and synchronize. Concurrent updates are rejected. A storage failure, synchronization timeout or corrupt stored snapshot disables that adapter; investigate and reopen against verified persisted state. Do not delete checkpoints to clear an error.

`trust.allows(principal)` checks current endorsed/unrevoked keys and freshness; `trust.verify(envelope)` also verifies its signature and critical extensions. `trust.revision()` changes when an update starts and after it commits, so in-flight authorization tickets become stale. The complete `LocalAuthority` must also incorporate every policy, membership and provider-binding change. A caller must still perform live provider authorization and the final pre-send check. The test fixture demonstrates that composition only with a synthetic provider.

`trust.status()` reports ready, empty, stale, opening/updating, failed or closed state. Expired persisted provisioning can reopen in stale state for owner refresh, but cannot authorize. `close()` disables the instance and prevents a pending write from activating authority later; it does not delete storage or undo a committed update.

## Schema and recovery

The checked version-1→version-2 migration adds a trust snapshot and retained checkpoint table in one transaction. It verifies the prior schema checksum/catalog first and preserves existing action/audit rows and consumed claims. Older version-1 code refuses the newer schema; there is no downgrade/reset command. The conformance fixture tests forward migration and rollback after an injected migration error.

Schema 6 adds bounded storage for large bundles. Provisioning up to 256 KiB stays inline; larger canonical bundles use a descriptor and at most 32 base64 chunks, each containing at most 256 KiB of raw bytes. Each stored chunk is below 350 KiB. Reads validate exact count, order, revision, bytes, checksum and UTF-8 before the existing signature/checkpoint checks. This avoids the provider's [2 MB SQL row/value limit](https://developers.cloudflare.com/durable-objects/platform/limits/) while retaining the logical 8 MiB bound. Public owner requests retain their separate 2 MiB transport cap.

The additive v5→v6 migration preserves existing inline rows, logical checksums, checkpoints and action history. It does not rewrite the active bundle. Subsequent updates atomically replace only the current representation chunks together with state/checkpoints; missing or corrupt chunks quarantine the adapter. No checkpoint or audit history is pruned. Older executables reject schema 6; reverting code is not a supported database downgrade. See the [storage contract](../../../spec/cloudflare-trust-chunks.md) and [migration/test evidence](../../../spec/plans/cloudflare-trust-chunks.md).

Snapshot checksums bind active canonical provisioning, configuration, accepted-at time, revision and the retained checkpoint set. Reopen re-verifies signatures at the recorded acceptance time, checks active candidates against retained history, and applies current freshness before use. SQL protects against replacement, deletion, counter rollback and same-counter content changes. Checksums are integrity checks, not protection from malicious code able to rewrite the entire owning database.

Limits remain 4096 retained identity checkpoints, 4096 key documents per active replacement, and 8 MiB provisioning/checkpoint state. Capacity beyond those bounds, rotation-history growth, retention and administrative audit/export workflows need production design and acceptance. The clock floor is monotonic within a live instance and starts no earlier than the persisted acceptance time. This does not establish protection against whole-host clock rollback or restoration of all database copies to an older version. Hosted PITR requires an external recovery fence and acknowledgment reconciliation before execution can resume.

The Linux artifact includes the newly shared identity helper; it excludes this experimental adapter. No private signing key or bearer token is stored by the trust adapter. See the [specification](../../../spec/cloudflare-trust.md), [implementation evidence and decisions](../../../spec/plans/cloudflare-trust.md), and [production gates](../../../PRODUCTION_READINESS.md).

Provisioning snapshots permit at most 262,144 JSON nodes and depth 32 so the 700-identity rollout fixture fits within the existing byte/checkpoint caps. Individual action snapshots keep the default 8,192-node limit. The Worker owner boundary adds a stricter 2 MiB transport cap; these are bounds, not hosted throughput certification.
