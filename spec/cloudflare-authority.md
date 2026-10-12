# Cloudflare organization authority

Status: experimental integration within the approved Cloudflare exploration; no backend adoption or deployment.

## Outcome and boundaries

Compose the existing KeycloakAuthenticator, DurableEntityTrust, ActionPolicy and DurableActionStore into one authority owned by one live Durable Object. A provider-authenticated subject must match explicit current entity/key bindings and signed trust before it can authorize an action. Policy supplies session membership and target/tool access. All checks remain deny-by-default. Keep the Linux implementation unchanged.

Expose owner-only open/update/close plus Authentication and LocalAuthority interfaces; no public enrollment or administration route. The public Worker fixture stays 404. Signed request orchestration uses the existing OrganizationController with a request-specific store facade sharing the durable database and full authority revision. The test connector sends no real effect. Worker HTTP ingress and actual internal MCP networking remain separate requirements.

## Durable configuration

A checked v2→v3 migration adds one authority snapshot and an append-only configuration event table. Preserve action, audit, trust and consumed-claim history; verify the previous catalog/checksum before migration. Snapshot contains revision, canonical public configuration and checksum. Events bind each revision, configuration digest and previous event checksum into a chain anchored by the current snapshot; no bearer, introspection secret or signing key enters these rows.

Public configuration contains exactly authentication (issuer, audience, allowed client IDs, explicit subject/entity/key bindings, introspection client ID, bounded timeout/token lifetime and the explicitly named local-fixture transport option) and policy (targets/sessions). Reuse existing strict validators. Reject introspectionClientSecret in public configuration; supply it separately from the object's secret binding. Pin issuer, API audience and introspection client ID for the life of this database; replacing the identity domain requires a separate migration. Other owner-controlled configuration can change through update with expectedRevision to prevent lost updates.

Initialization requires explicit initial configuration; ordinary reopen requires an existing valid snapshot. Never silently initialize/reset on missing or corrupt state. Append a configuration event atomically with each snapshot write, including initialization. Validate canonical bytes, revision/checksum and the complete event chain on reopen and update, reading ordered batches of at most 256 rows. Invalid input leaves old authority usable. Once writing starts, gate authentication, eligibility and policy access; synchronize before activation. SQL/sync failure or timeout quarantines the authority until validated reopen. Concurrent updates conflict. Close cannot be undone by a pending operation.

## Use-time authorization

The revision token incorporates an instance nonce, persisted configuration revision, lifecycle state and live trust revision. The nonce prevents reuse of a ticket across a same-version reopen. Authentication captures that token and the concrete provider instance before awaiting JWT/JWKS/introspection, and releases any returned principal if either changed. Retain the issuing provider privately for request cleanup; never persist tokens. Revalidation requires the exact issued principal object, current bindings and trust before and after the await. Current approver bindings/trust must also pass when checking an existing approval. Provider login revocation alone does not revoke an already issued approval; preserve the shared grant contract.

The authorizer snapshots the proposal/approver before await, checks current policy for the requested phase, and rechecks revision, requester and approver after provider revalidation. Begin each execution with the current policy, allowing fresh work after legitimate updates. At effect time require both current execution and approval eligibility, even if an executor captured an older policy object. All relevant local changes invalidate pending authorization. Restoring identical policy/membership later is an explicit owner action, not automatic revocation undo; explicit action revocation remains the way to permanently revoke an existing grant. Current signed key revocation independently denies that key. Internal result completion remains independent of caller eligibility.

## Evidence required

Use real local workerd/SQLite and actual RS256 tokens over a controlled HTTP JWKS/introspection fixture for failure/interleaving tests. Cover missing/corrupt initialization, v2 migration, secret exclusion, forbidden identity-domain change, expected-revision conflict, malformed candidate isolation, SQL/sync failure quarantine, restart, provider inactive/outage, cloned/released principals, provider await concurrent with policy/binding/trust update, exact signed controller lifecycle and post-claim revocation without effect. Also run an isolated real Keycloak fixture against the actual workerd adapter; distinguish machine-issued approver fixture tokens from human browser login acceptance.

Keep existing ledger/trust tests, strict types and affected organization tests passing. Review the full batch once in a fresh context and fix accepted findings with regressions. Local checks do not certify hosted persistence, rollback recovery, throughput, retention or operator/security acceptance.
