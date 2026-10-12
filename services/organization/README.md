# Organization service — experimental

This directory contains the single-organization service and its experimental executable. The launcher and Linux artifact exist; production capacity, recovery and operator acceptance remain open. The loopback demonstration relay remains separate.

## Adapter boundaries

The signed controller and execution coordinator consume the structural contracts in `contracts.d.ts`. Shared error classes live in `errors.mjs`; existing exports from `store.mjs` and `mcp.mjs` refer to the same classes. Importing orchestration does not load PostgreSQL migrations or the MCP implementation. See the [adapter contract](../../spec/organization-adapters.md).

The composed runtime still uses Keycloak, PostgreSQL and the official MCP connector. Replacing an adapter requires its authorization, durability, ambiguous-outcome and recovery guarantees to pass the same acceptance gates; structural type compatibility alone is insufficient.

## Keycloak authentication adapter

`KeycloakAuthenticator` verifies RS256 JWT access tokens against one pinned Keycloak realm and then checks active status through confidential-client introspection. Explicit operator-provisioned subject mappings determine the entity and signing key. The returned principal contains API-client roles, but authentication alone grants no action or session permission.

```js
import { KeycloakAuthenticator } from './auth.mjs';

const auth = new KeycloakAuthenticator({
  issuer: 'https://identity.example.org/realms/organization',
  audience: 'xeip-api',
  clientIds: ['xeip-console', 'xeip-agent'],
  bindings: [{ subject: keycloakSubject, entity: entityUrn, kid: signingKeyId }],
  introspectionClientId: 'xeip-introspection',
  introspectionClientSecret: secretFromProtectedConfiguration
});
const principal = await auth.authenticate(authorizationHeader);
// null means unauthenticated. IdentityProviderUnavailable means fail closed (503).
// Next: validate entity trust, session membership and permission for this exact action.
```

Set Keycloak audience mappers for **both the API and the confidential introspection client** (for example `aud: ["xeip-api", "xeip-introspection"]`), and provision API-client roles under `resource_access["xeip-api"].roles`. Current Keycloak enforces the introspecting client's audience; do not enable its audience-check bypass. Tokens require `typ: "Bearer"`, `sub`, `azp`, `jti`, `iat` and `exp`. Default maximum lifetime is 300 seconds (configurable 30–900); no expiration grace is accepted. The JWT header must identify RS256 and type JWT. ID tokens, unknown subjects, other authorized clients and inactive tokens are denied.

JWKS requests use a 60-second cache and a 30-second unknown-key fetch cooldown; newly rotated signing keys may be rejected during that cooldown. Introspection active status is not cached. The default provider request deadline is 3 seconds (configurable 100–10000 ms); responses are bounded to 64 KiB and redirects are rejected. Provider failures never produce an authenticated result.

`await auth.revalidate(principal)` checks a principal previously issued by this adapter against current token status; copied/fabricated principals fail. Tokens remain private to the adapter's weakly held principal associations. Call `auth.release(principal)` when a request completes or a connection closes. Expired, inactive or failed revalidation also releases the stored token, and release during an in-flight revalidation cannot reactivate the principal. The signed organization controller rechecks at the store boundary and before the tool effect, then releases the principal. Streaming organization operations are not supported.

Use HTTPS in production. `allowInsecureLoopback: true` exists only for literal-loopback integration fixtures and must be prohibited by the production launcher. Human login should use authorization code with PKCE; service agents use client credentials. Do not use password grants or embed client secrets in browser code.

From repository root:

```sh
npm ci --ignore-scripts
npm run build:ts
npm run typecheck:organization
npm run test:organization
# Docker is required only for the real provider test:
docker pull quay.io/keycloak/keycloak:26.8.0@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741
npm run test:keycloak
```

The provider fixture uses a temporary realm, random client secrets, a private temporary directory, a non-root container, a random loopback port and automatic cleanup. Keycloak runs in development mode solely for this test; do not use it as a production deployment template. See the [authentication contract](../../spec/organization-auth.md) and [production gates](../../PRODUCTION_READINESS.md).

## PostgreSQL runtime trust

The Linux launcher now requires explicitly enrolled PostgreSQL control history.
It compares current public configuration and signed provisioning before opening
listeners; it no longer creates or accepts a filesystem trust checkpoint. Reloads
publish a complete verified trust update before activation, and uncertain commit or
cancellation leaves authorization unavailable until reopen. Complete signature
validation runs in bounded workers, including the storage boundary.

The launcher fences action transactions with the captured PostgreSQL control head
and wraps actual tool dispatch in a synchronous trust-revision check. Publication
blocks old-snapshot dispatch; outcomes of already-started calls remain recordable.
Runtime startup and schema maintenance now share an exclusive PostgreSQL session
lock. Runtime uses a dedicated connection so a one-slot work pool remains usable;
owner schema transactions use the locked connection itself. Observed lease loss
invalidates runtime authority and triggers shutdown. This coordinates one database,
not separately restored writers or unobserved infrastructure partitions.
Explicit owner `enroll`, exact-head `change`, and historical `inspect` commands are
available through `npm run organization:control -- …`. Enrollment preserves complete
legacy checkpoint records and refuses populated legacy action ledgers. Migration
alone cannot start a new organization. Combined recovery and operator acceptance
remain open; this local artifact is not a certified production upgrade. See the
[control recovery contract](../../spec/postgres-control-recovery.md) and
[operations guide](OPERATIONS.md).

## Action policy and durable ledger

`ActionPolicy` accepts explicit session agent/approver subjects and allowed target/tool IDs. It snapshots bounded JSON and computes a digest binding actor/key, session, target deployment revision, arguments, expiry and policy revision. A different subject and entity must approve; roles alone do not grant permission.

`ActionStore` uses PostgreSQL for action state and atomic audit events. Construct it with a bounded `pg.Pool`, the policy and `liveActionAuthorizer(auth, entityTrust)`. Both `connectionTimeoutMillis` and `query_timeout` are required, from 100 through 10000 ms; the store also bounds server waits and its authorization callback. Apply migrations and provision the restricted runtime role with the separate owner maintenance command described in [operations](OPERATIONS.md). Startup verifies that role's effective privileges; fixture credentials and owner credentials are not runtime deployment credentials.

The internal API is `propose(principal, request)`, `decide(principal, session, id, expectedDigest, 'approve'|'reject')`, `revoke(...)`, `claim(...)` and read-only `inspect(principal, session, id)`. The internal worker records `finish(session, id, claimId, outcome, result)` after an effect. Migration 002 adds a canonical result bounded to 128 KiB; terminal results are immutable and inspection returns them under current membership rules. Repeating completion requires the same outcome and result. Only a newly committed claim may initiate an effect. Never retry an ambiguous effect; inspection reports state after expiry or policy changes without returning a claim capability. Never expose `finish` or claim capabilities as public client authority.

An approver's consent expires by both the action deadline and their token deadline. Their bearer is not persisted. Disabling provider login alone does not revoke prior consent: explicitly revoke the action, local membership or key. The executing agent's provider status and both actors' local membership/key trust are checked when claiming.

The signed controller binds bearer, signing key, entity, recipient, session and operation. Its per-request store authorization rechecks the signed deadline after provider waits; the execution worker rechecks identity, both keys and policy immediately before the tool POST. See the [action contract](../../spec/organization-actions.md) and [ledger decision](../../spec/decisions/0014-organization-action-ledger.md).

```sh
docker pull postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873
npm run test:postgres
# Combined unit/database coverage requires Docker and the image above:
npm run coverage:organization
```

The PostgreSQL fixture creates a disposable database on a random loopback port with temporary credentials, kills/restarts only its own container, and restores its own dump into another disposable database. It removes the container, its volume and credentials afterward. These synthetic checks do not certify an operator's disks, backups or workload.

## Signed HTTPS and MCP adapter

`OrganizationController`, `createOrganizationServer`, `createActionExecutor` and `McpConnector` compose the [signed organization service contract](../../spec/organization-service.md). `POST /v1/actions` accepts a signed envelope up to 96 KiB. Direct TLS is required; a literal-loopback HTTP exception exists only for fixtures. Exact Host/Origin checks apply. `/live` reports process liveness; `/ready` runs a bounded dependency check. Timed-out work keeps its concurrency slot until it settles, and cancellation prevents a later pre-send authorization from reviving an effect.

The MCP adapter pins protocol 2026-07-28 and official SDK 2.3.1. Each target config includes `id`, `revision`, `recipient`, `tools`, HTTPS `endpoint`, `resourceMetadataUrl`, `issuer`, `tokenEndpoint`, confidential `clientId`/`clientSecret`, and explicit `scope`. Resource metadata must name exactly that endpoint and issuer; the token endpoint must match its configured pin. It uses OAuth client credentials for that target and never receives the incoming XEIP bearer. Older protocols, interactive continuation, extra tool calls and automatic retries are unsupported. Redirects, invalid UTF-8, oversized output and unexpected endpoints fail closed.

Only a committed new claim can reach the connector. A failure before attempting the tool POST records `failed`; an uncertain attempted POST records `indeterminate`. A valid MCP tool-error result records `failed` with that result; it does not prove the tool had no partial effects. No state permits automatic re-execution of a consumed claim. Failed completion persistence returns unavailable; inspect the action to distinguish a committed result from an unresolved execution.

```sh
# Requires both pinned Docker images above; isolated real Keycloak + PostgreSQL + MCP fixture:
npm run test:organization:integration
# Five-minute 120-action/minute workload, 200 agents and 500 simulated approvers:
XEIP_LOAD_REPORT=/tmp/xeip-load.json npm run test:organization:load
```

The load fixture provisions separate Keycloak service accounts for simulated users and agents; it does not implement or assess human login/approval UX. Its pass thresholds are P95 ≤2 seconds for each machine operation, no request failures and at least 95% of the scheduled 120-action/minute completion rate. Token issuance/signing and simulated human review are excluded from operation latency. Results remain local test evidence until repeated on supported deployment hardware with the operator's actual tool, storage and network.

The experimental dedicated launcher now loads protected configuration, verifies restricted runtime database privileges, probes dependencies, drains actual workers and exposes redacted logs/private metrics. Start with the [reserved Linux staging procedure](../../deploy/STAGING.md), [operations guide](OPERATIONS.md) and [configuration templates](../../deploy/organization.example.json). Owner migration is a separate command. Full operator reconciliation tooling, retention/encryption, human PKCE UI, supported artifacts and independent security/pilot acceptance remain open. Do not deploy fixture keys, development Keycloak configuration or database owner credentials.

## Human approval console

An opt-in browser console now provides Keycloak code/PKCE login, explicit device-key enrollment, signed inspection, exact-action approval/rejection and revocation. See the [console operator guide](CONSOLE.md) for configuration and remaining acceptance gates. Build it with `npm run build:console`; it is included in the organization image and disabled unless `console.clientId` is configured.
