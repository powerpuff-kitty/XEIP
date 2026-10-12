# Experimental complete organization restoration

`StagedOrganizationRestore` reconstructs the complete [organization bundle](ORGANIZATION_BUNDLE.md) in a new isolated SQLite Durable Object database. It is an internal library, not a deployed owner command or remote import CLI. It performs no provider request, administrative command replay or MCP call. Every returned receipt has `blocked: true`, including a verified receipt.

The caller supplies a checkpoint assembled from the bundle's four component files and its checkpoint manifest, the complete bundle manifest, and the explicitly expected organization. First verify the protected source bundle with `verifyOrganizationBundle`, using a separately retained digest when available. Do not infer authenticity, freshness or acknowledged-action durability from self-consistent files alone.

```js
import { StagedOrganizationRestore } from './organization-restore.mjs';

const restore = await StagedOrganizationRestore.initialize(
  isolatedStorage,
  checkpoint,
  bundleManifest,
  { organization: 'my-organization' },
);

// Apply the exact bundle files in order, with one-based page sequence:
// actions-*.json, authority-*.json, administration-*.json.
await restore.apply(1, firstPage);
// ...remaining bounded pages...
const receipt = await restore.verify(); // still blocked; no activation API
restore.close();
```

Initialization refuses any existing application tables. It validates all component bodies and their cross-state commitments, installs a permanent restore fence and the control rows in one synchronous transaction, synchronizes and reconciles before returning. Trust is validated at its original acceptance time, not made fresh by restoration. Removed-entity rollback records, original trust revision, chunked provisioning, lifecycle intent, current authority configuration and recovery binding are preserved. Credentials remain separately provisioned and are excluded from these files.

Apply one action file at a time, followed by authority pages of128 records and administrative pages of16 records. Even an empty administrative history has one page. Actions are projected through their original transitions under the normal SQL action constraints. Original audit sequence numbers, approvals, results and consumed claims are preserved, including interleaved action histories. Administrative events are records only: unresolved attempts are not retried or completed.

Each page and its progress commitment commit in the same transaction and synchronize before acknowledgement. Only an identical retry of the last applied page is accepted without rewriting; older or out-of-order pages conflict. Invalid content, storage faults, uncertain commits, synchronization failure or timeout quarantine the instance. Reopen explicitly with `StagedOrganizationRestore.open(storage, checkpoint, manifest, settings)` to reconcile the entire saved prefix before resuming at the returned `sequence + 1`. A closed or failed instance cannot be revived by a late synchronization.

`status()` checks the full persisted prefix. `verify()` requires all expected pages, exact control rows, complete authority/admin histories, each original action audit sequence exactly once, and the ordered checksum of every reconstructed bundle file. It synchronizes and rereads before reporting verified. These checks reconstruct data from SQL rows rather than trusting a saved copy of the input files. Whole-database/bundle rollback still needs independently retained current evidence.

Schema9 adds the immutable organization fence and progress table while preserving migration1–8 bytes. Normal runtime refuses either restore fence, even when its intent is corrupt. Older executables reject schema9; there is no supported schema downgrade. The existing action-only restore can explicitly upgrade a valid schema8 fenced candidate inside its reconciliation transaction without removing the fence. A failed migration/reconciliation rolls back the upgrade.

Historical authority configurations cannot be replayed because the source stored only past configuration digests. During historical control insertion, the restore implementation suspends only the specific insertion trigger that rejects nonzero historical revisions (and the authority event/current-state restriction), inside a synchronous fenced transaction. It recreates the exact verified trigger SQL and verifies the schema catalog before commit. There is no `await`, externally supplied callback or live operation inside this window; failures roll back both rows and DDL. All live schema protections are present at transaction boundaries.

This candidate cannot become a live service. The remaining recovery work includes independent action/control receipt gating, reconciliation of acknowledgements after the captured cut, external execution fencing, accepted backup custody/failure boundaries, bounded operator transport and a real restore drill. Keycloak state, secrets and actual MCP-side effects require separate operator recovery procedures. No hosted deployment or recovery guarantee follows from local reconstruction tests.

Run `npm run test:cloudflare` and `npm run typecheck:cloudflare`. See the [implementation and evidence record](../../../spec/plans/cloudflare-organization-restore.md) and [production gates](../../../PRODUCTION_READINESS.md).
