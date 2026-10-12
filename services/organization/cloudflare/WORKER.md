# Experimental Worker package and private operator access

This is a locally verified Cloudflare-native candidate. It retains the chosen Keycloak identity provider and signed approval workflow. It is not production certified, has not been deployed, and does not eliminate the need to host Keycloak or connect the private MCP service. The Linux/PostgreSQL profile remains available.

## Build without a cloud account

Use the lockfile and Node 22.23.3 (also verified on local Node 26). No deployment command runs during packaging:

```sh
npm ci --ignore-scripts
npm run build:cloudflare -- deploy/cloudflare/profile.example.json xeip-staging /tmp/xeip-worker-artifact
```

The output directory must not exist. Replace the example organization, gateway, origin, target entity and endpoints with reviewed deployment values before a real candidate. The example key IDs and domains are illustrative, not enrolled organization identities. The artifact contains `worker.mjs`, `wrangler.json` and `manifest.json`. The manifest records hashes of the exact module/configuration and the bundled package versions/integrity. Keep the artifact immutable; configuration edits create a new candidate and invalidate its recorded configuration hash.

The generated configuration has no routes, workers.dev exposure or preview URLs. Its SQLite migration creates `OrganizationObject`; the binding is `ORGANIZATION`. Do not rename that class/binding/namespace or change the fixed object name `xeip-organization-v1` to bypass existing state. A new namespace is an empty organization, not recovery. Public runtime configuration drift is rejected against persisted lifecycle intent. Credential rotation with identical public settings is supported on a fresh instance.

The offline validation command is:

```sh
WRANGLER_SEND_METRICS=false npx --no-install wrangler deploy --dry-run --config /tmp/xeip-worker-artifact/wrangler.json
```

This checks bundling/configuration, not account IAM, routes, durability, private connectivity or production SLOs. The pinned Wrangler/runtime generation is recorded in the lockfile. The module reuses shared reference verification helpers, including their dormant Node CLI code; workerd artifact startup and private RPC are tested. No conformance classes, SQL fault controls, organization CLI, PostgreSQL runtime or test credentials are included.

## Credentials and first setup

`XEIP_PROFILE` is the public JSON profile embedded in the generated config. `XEIP_CREDENTIALS` must be provisioned separately as a Cloudflare secret binding containing exactly:

```json
{"introspectionClientSecret":"REAL_PROVIDER_SECRET","targets":{"internal":"REAL_MCP_CLIENT_SECRET"}}
```

Do not place real values in Git, shell arguments, generated public manifests or command receipts. Each binding is limited to 5 KiB; the target-secret keys must exactly match the profile's target IDs. Public profiles and owner authority updates reject insecure-loopback flags and HTTP endpoints. Fixture allowances in lower-level adapters do not enable them here. Larger deployment profiles need a separately reviewed configuration mechanism.

First owner commands are `initialize` with public `{authentication,policy}` configuration, then `refreshTrust` with the complete signed `{keyDocuments,statusDocuments}` replacement and `expectedRevision:0`. Empty trust authorizes nobody. Every command includes a fresh UUID `requestId`. See the [authority guide](AUTHORITY.md) for the provider/device/policy contract and [lifecycle guide](LIFECYCLE.md) for retry and state semantics. Owner payloads are strict JSON limited to 2 MiB, 262,144 nodes and depth 32; the trust adapter's storage limit remains 8 MiB/4096 checkpoints. The larger provisioning budget supports the 700-identity fixture; individual action JSON retains its 8,192-node limit. This is provisioning evidence, not capacity certification.

`updateAuthority` and `refreshTrust` require the current expected revision. `initialize` retries require the exact original configuration and never overwrite later policy updates. Request IDs correlate attempts; they do not make arbitrary commands idempotent. After an uncertain result, inspect status/revisions and reconcile before retrying. There is no reset, delete, automatic retry or automatic effect replay.

## Configure action recovery before initialization

Use [profile.recovery.example.json](../../../deploy/cloudflare/profile.recovery.example.json) as a public configuration example. Replace its illustrative stream UUID, organization and endpoint with the separately initialized journal's exact settings. The organization is inherited from the profile; it cannot be overridden inside recovery.

```json
"recovery": {
  "url": "https://journal.example/v1/recovery",
  "stream": "8f310e3a-c4c8-4ef2-b42c-4660251c89aa",
  "maxEntries": 1000000,
  "maxBytes": 1073741824,
  "timeoutMs": 5000
}
```

When this field is present, add `recoveryToken` to the separate `XEIP_CREDENTIALS` secret: 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters. A missing/malformed token, a token without recovery settings, or credentials embedded in the public profile are rejected. Packaging never creates or prints this credential. Capacity defaults are the values shown; timeout is 100–10000 ms, default 5000. These storage caps are safety bounds, not a retention or rollout capacity plan.

Initialize/open the journal separately using the [journal contract](RECOVERY_JOURNAL.md) and expose its [authenticated handler](RECOVERY_HTTP.md) through an accepted HTTPS runtime. This repository does not yet package or deploy that host. It must be empty for first source enrollment. Then build the organization artifact with the recovery profile, deliver its secret, and explicitly invoke the existing private owner `initialize`. Public traffic and owner status on empty storage neither enroll nor contact the journal. The source cannot initialize/reset the remote journal.

Lifecycle intent pins the exact HTTPS URL and normalized organization/stream/capacity/genesis. Removing or changing them, or adding recovery to an already initialized unconfigured source, fails closed. Do not change the object namespace to bypass this restriction. Credential and timeout remain runtime-only: coordinate credential rotation at both endpoints, drain/reconcile in-flight work, then open a fresh instance with the same public identity. An interrupted initial setup caused by a wrong secret can resume on a fresh instance with the corrected secret and an explicit exact initialization retry.

Every configured action transition waits for its recovery receipt. A claim must be confirmed before the MCP call. Lost receipts and unavailable or divergent journal state stop processing and require reconciliation on fresh open; they never authorize repeating a tool effect. See [action recovery](ACTION_RECOVERY.md). Native tests cover the exact packaged Worker, private initialization, four durable transitions, restart and single execution. Actual local Wrangler also verifies configured startup/private status; fixture URL translation does not certify hosted TLS, network isolation or provider durability.

This is opt-in source integration, not production zero-loss certification. Complete restore, trust/authority/admin recovery, accepted failure domains, retention and hosted workload/recovery/security acceptance remain required.

## Invoke the private owner binding

Copy and review [the operator configuration](../../../deploy/cloudflare/operator.example.json). It must contain exactly one `OWNER` service binding targeting `OwnerEntrypoint`, an explicit local/remote boolean and a bounded `props.operator` identifier. The private binding is the authorization capability. The operator property labels that deployment capability; it is not proof of a human's identity. Account permissions to create bindings, deploy code or access the object namespace are administrator privileges.

Create a protected command JSON file, for example a status command with a newly generated UUID:

```json
{"operation":"status","requestId":"7f2a9ab0-0ee7-49ea-8fd8-24c8fbc72d98"}
```

Local Wrangler may report startup before service-binding registration completes. Use a read-only status probe to confirm availability; do not retry an uncertain mutation. For a deliberately running local Wrangler development service, set the binding's `remote` to false and invoke:

```sh
npm run cloudflare:owner -- /protected/operator.json /protected/command.json --local
```

After a separately authorized hosted deployment and Cloudflare authentication, the corresponding invocation uses `remote:true` and `--remote`. The command and binding modes must agree; the client never substitutes a local database for a remote target. Remote binding behavior remains a hosted acceptance gate. This work has only invoked local bindings.

The client uses Wrangler's platform proxy, not an HTTP admin bridge. It validates and copies only the named service-binding configuration into an isolated temporary directory; adjacent .env/.dev.vars and unrelated bindings cannot alter the target. It validates command shape before contacting a binding, makes one RPC attempt, validates exact bounded receipt variants and success/failure correlation before printing, disposes the proxy and removes only its own temporary directory. Unexpected fields, incomplete success, unknown error codes or mismatched metadata fail without printing the response. Nonzero exit means failure or an uncertain result, not permission to retry blindly.

Public HTTP supports only the signed action and health routes. The default Worker RPC surface cannot administer; the named owner's HTTP fetch always returns 404. Do not expose the owner binding from another public Worker. Structured owner logs contain only operator/request ID/operation/outcome. They remain diagnostic logs. Mutating owner commands now also use the [durable administrative journal](ADMIN_AUDIT.md): persist an attempt before mutation and a terminal record before acknowledgment, with private bounded export. Binding attribution still does not authenticate a human. A complete production control plane needs accepted IAM, named operator ownership, independent export/retention and accepted operations for the [automatic signed-status feed](REFRESH.md).

## Verification and remaining acceptance

`npm run test:cloudflare` runs native workerd/SQLite and actual private-binding cases, including the packaged artifact's Wrangler dry-run and local operator invocation. Integration fixtures translate pinned HTTPS URLs to local provider/MCP servers; they do not verify hosted TLS or private routing. Public requests cannot initialize storage, missing configuration fails closed, wrong organization configuration cannot select a new object, and consumed effects survive a local restart.

Before production: accept the provider-specific operating model; review IAM and secret delivery; configure and test the exact public origin/private MCP path; accept administrative audit/export operations, accept the automatic signed publisher/refresh operation and implement retention; certify 120 requests/minute with the 500-user/200-agent population; demonstrate P95 ≤2 seconds, restore ≤1 hour and no acknowledged-action loss with an independent recovery fence/journal; complete security/operator/pilot sign-off. Never use PITR or a new namespace as automatic effect recovery.

Contract: [Worker design/threat model](../../../spec/cloudflare-worker.md). Evidence: [implementation ledger](../../../spec/plans/cloudflare-worker.md). Overall status: [production readiness](../../../PRODUCTION_READINESS.md).

Optional minute Cron refresh is configured before initialization through `trustFeed` and a separate `trustFeedToken` credential. See [REFRESH.md](REFRESH.md) for the publisher contract, immutable source, existing-roster restriction, failure behavior and journal growth.

A feed-enabled package additionally contains a separately configured scheduler Worker. Its default binding is privileged; the organization Worker’s default remains fetch-only. Deploying the main config alone does not activate scheduled refresh. See [REFRESH.md](REFRESH.md) for the separate configs and rollout order.

For complete offline-verifiable administrative snapshots through one reusable operator session, see [ARCHIVE.md](ARCHIVE.md). The collector sends only exports but holds the same privileged owner binding; it is not a separately delegated read-only role.

Private `actionSnapshot`/`actionPage` support the [action archive collector](ACTION_ARCHIVE.md). The initialized ledger can export without refreshing expired user grants. Only actionPage receipts permit up to 512 KiB; other owner receipts retain 64 KiB. Action arguments/results stay out of Worker logs but are intentionally present in privileged export data.
