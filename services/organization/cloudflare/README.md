# Experimental Cloudflare adapters

These are local feasibility adapters for a SQLite-backed Durable Object. The Worker package is an experimental deployment candidate, **not a production-certified backend**. The existing Linux/PostgreSQL service does not import it, and its runtime image excludes both this directory and the Miniflare/workerd development dependencies.

From the repository root, with Node 22 or later:

```sh
npm ci --ignore-scripts --no-audit
npm run test:cloudflare
npm run typecheck:cloudflare
```

The harnesses bundle test-only Durable Objects, start pinned Miniflare 4.20260730.0 / workerd 1.20260730.1 on ephemeral loopback ports, and use unique temporary SQLite directories. They dispose the runtime and remove only their own directory on completion. They need no Cloudflare account, secrets, Keycloak instance, Docker daemon or external tool. Dependency installation needs network access; the ledger fixture uses synthetic identity/provider controls, while the trust fixture uses actual signed identity documents. Ledger/trust/authority effects remain fake counters. The transport fixture adds a real local official-SDK MCP server and signed public Fetch routing; its setup/SQL controls remain reachable only through Miniflare's private object interface. **Never deploy the conformance workers**, which include privileged SQL and fault controls.

`DurableActionStore` implements the six shared `ActionLedger` operations. `schema.mjs` installs the organization-bound schema and checks its version and catalog on reopen. Replacement-resistant insertion guards preserve action, audit and organization rows. SQL and read-time checks bind row identifiers/expiry to canonical action/grant data. State changes and their audit entries share one synchronous transaction. The adapter waits for storage synchronization before returning, then rechecks local authority and expiry. Storage faults or malformed rows quarantine the adapter; recovery creates a fresh instance after validating persisted storage. An executing action is never automatically reclaimed, even when its original response was lost.

One adapter instance belongs to one live object. Its trusted `LocalAuthority` callbacks must supply an atomically updated revision, current policy, local identity/key eligibility and bounded live authorization. Revisions must change for every local trust, membership, policy or binding change. The harness demonstrates this contract with synthetic state; it does not implement the production authority. Effects also require the existing live pre-send check after a successful claim.

The prototype retains at most 10,000 actions and has no deletion API. It rejects new proposals at the limit while preserving existing work. This is not the retention design for 120 actions/minute. Local restart and injected failures do not establish hosted replication, point-in-time restore, disaster recovery or latency guarantees.

The [persistent trust adapter](TRUST.md) implements signed provisioning, monotonic checkpoints and gated activation in the same object database, using the existing shared identity rules. The [organization authority](AUTHORITY.md) composes it with the existing Keycloak verifier and owner-only durable policy/binding updates; its signed controller integration is exercised through private conformance interfaces. The [Fetch/MCP transport](TRANSPORT.md) now exercises the signed workflow against a local official-SDK server. The [service lifecycle](LIFECYCLE.md) adds explicit resumable initialization and owner-only signed refresh. The [Worker package](WORKER.md), [durable administrative audit](ADMIN_AUDIT.md) and opt-in [automatic signed refresh](REFRESH.md) are verified locally. Before adoption, establish the real private network route, and complete retention, independent recovery fencing and acknowledgment reconciliation. Run hosted capacity/recovery/security acceptance against the unchanged requirements. Keep self-hosted Keycloak until an explicit identity decision replaces it.

See the [contract](../../../spec/cloudflare-ledger.md), [implementation evidence](../../../spec/plans/cloudflare-ledger.md), [hosting assessment](../../../spec/audits/2026-10-11-cloudflare-feasibility.md) and [readiness gates](../../../PRODUCTION_READINESS.md).

The root manifest temporarily overrides only Miniflare's `sharp` and `undici` dependencies to 0.35.5 and 7.29.1 for published security fixes. Keep these exact versions in the lockfile; remove the overrides when a tested stable Miniflare release includes patched dependencies. See the [dependency decision and sources](../../../spec/plans/cloudflare-ledger.md).

The [Worker/operator guide](WORKER.md) covers strict production profiles, private named-binding administration, offline artifacts and the local operator client. No hosted deployment or production certification has occurred.

Administrative mutations now have a [durable private journal and bounded export](ADMIN_AUDIT.md). This audit shares the object database and does not replace independent recovery protection.

The [manual administrative archive collector](ARCHIVE.md) verifies and flushes complete fixed-head snapshots through the private binding. It does not archive actions, delete source history or close the independent recovery/retention gates.


Before use or reopen, the ledger now [reconciles each action with its audit history](../../../spec/cloudflare-action-integrity.md). Startup walks at most 128 keys per page and loads one bounded action/history at a time. Each existing-row operation validates the history, and each mutation reconciles its new row plus audit inside the same transaction. Inconsistent state, actors, claims or transitions quarantine the adapter; no repair or effect retry occurs. This adds startup/read work that still needs hosted cost and latency acceptance. It detects internal inconsistency, not a consistent database rollback or wholesale privileged rewrite.

The [manual action archive collector](ACTION_ARCHIVE.md) captures exact requests, grants, claims, results and history at a fixed audit cut while writes continue between pages. It preserves sensitive payloads in protected operator files and verifies complete snapshot/prior-witness checksums. It does not restore or prune data and does not close independent recovery acceptance.

The [experimental recovery journal core](RECOVERY_JOURNAL.md) stores ordered immutable payloads in a separate database and acknowledges only after synchronization. It remains unexported by the production Worker; the configured action integration below now uses its receipt boundary. No hosted recovery guarantee follows from the storage core alone.

The [action recovery integration](ACTION_RECOVERY.md) can now gate action acknowledgements and execution claims on a separately injected journal, with immutable source enrollment and startup rollback detection. The [optional Worker profile](WORKER.md#configure-action-recovery-before-initialization) now constructs an HTTPS client and pins its endpoint/enrollment before activation. Hosted journal deployment, complete restore and accepted failure-domain protection remain open.

The [authenticated recovery HTTPS boundary](RECOVERY_HTTP.md) provides a provider-neutral client and handler around an explicitly opened journal, with separate credentials, bounded records/deadlines and no automatic retries. Native tests exercise full-size payloads and lost-response action reconciliation. Worker/profile wiring has local integration evidence; journal hosting, isolation/IAM, complete restore and production acceptance remain open.

The [recovery bundle collector](RECOVERY_ARCHIVE.md) now reads a fixed complete journal prefix into private durable files and verifies payloads, chained history and prior witnesses offline. Separate action interpretation checks exact transition continuity and consumed claims. It performs no restore or replay and does not certify independent hosting or zero-loss recovery.

The [fenced reconstruction module](ACTION_RESTORE.md) now rebuilds exact action rows/audit into a separate empty native database. Verified candidates remain durably blocked; no production activation or restore entrypoint is exposed. Complete control-plane recovery and external execution fencing remain required.

The [complete organization restore library](ORGANIZATION_RESTORE.md) reconstructs lifecycle, signed trust and rollback records, authority/admin history and actions from a coordinated bundle into a permanently fenced candidate. It preserves consumed claims and original audit sequences and verifies the complete persisted content before reporting a blocked receipt. It is not an activation route or deployed import command; independent receipt gating, current-journal reconciliation and external execution fencing remain mandatory.
