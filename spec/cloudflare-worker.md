# Deployable experimental organization Worker

Status: local implementation under the approved Cloudflare-native exploration. This does not accept production adoption or provision resources. Keep Keycloak, 500 users/200 agents/120 actions per minute, P95 ≤2 seconds, restore ≤1 hour and zero acknowledged-action loss as unproven acceptance targets.

## Boundary and behavior

Export a public default Worker with fetch only, a named `OwnerEntrypoint` with private service-bound `manage(serializedCommand)`, and `OrganizationObject` backed by SQLite. Every path selects the same constant object name `xeip-organization-v1`; no request or organization configuration chooses another object. This prevents configuration drift from silently creating an empty replacement ledger. Separate deployments/environments must use separate namespaces. Namespace/class/name changes require explicit migration, never an automatic reset.

The object opens one OrganizationService behind constructor concurrency gating. Invalid configuration yields redacted unavailability and cannot write storage. Public requests forward only to the existing bounded signed Fetch handler; public URLs, headers and bodies cannot select owner methods. The owner entrypoint's HTTP fetch always returns 404. Only holders of the named binding (and direct object namespace capabilities) may administer. No capabilities, storage handles, credentials or configuration are returned.

Owner RPC accepts a strict JSON string, at most 2 MiB/262,144 nodes/depth 32, with exact fields: `operation`, `requestId`, and operation-specific `configuration` (initialize/updateAuthority), `provisioning` (refreshTrust), `expectedRevision` (updateAuthority/refreshTrust). Operations are status, initialize, refreshTrust and updateAuthority. Status is local state, not a network readiness probe. UUID request IDs correlate attempts; they are not deduplication keys. Expected revisions and exact initialization intent govern retries. No automatic retries; ambiguous writes require inspection/reconciliation.

A binding-supplied `operator` property is required and validated (1–128 ASCII identifier characters). It identifies the deployment capability, not a cryptographically verified individual. Request bodies cannot supply or override it. Record redacted structured start/result events containing operator, requestId, operation and outcome only; return bounded plain receipts. The operator client accepts only exact success/failure schemas: success requires correlated operator/request/operation and bounded state/counter fields; correlated failures must match the attempt, and boundary failures use fixed error codes. Unknown fields and incomplete or mismatched receipts fail without printing target content. These logs are diagnostic, not a durable administrative audit. Durable actor attribution/export, Cloudflare IAM acceptance and named operators remain required before production.

## Production configuration

`XEIP_PROFILE` is strict public JSON limited to 5 KiB: organization, exact HTTPS origin, gateway, trust settings, target definitions and optional synchronization timeout. It must not contain credentials, insecure-loopback flags, HTTP URLs or unknown fields. Targets use the existing pinned resource/issuer/token endpoints and exact revision/recipient/tool policy. `XEIP_CREDENTIALS` is a secret JSON binding limited to 5 KiB with introspectionClientSecret and an exact map of target IDs to client secrets. Missing, extra, malformed or unknown secrets/configuration fail before opening storage. Initial/updated authority authentication must also use HTTPS and cannot enable fixture allowances. Existing shared fixture allowances remain available only outside this production wrapper.

Package a prebundled module plus a Wrangler manifest with a SQLite class migration, fixed compatibility date/nodejs_compat, workers_dev=false, preview_urls=false, routes=[], observability invocation logging disabled. A public profile is embedded; secrets are never accepted by the packaging command. Default packaging grants no public route and cannot publish. Operators explicitly configure routes and secrets later. Pin Wrangler to the existing verified Miniflare/workerd generation and verify its dry-run. Do not silently upgrade the runtime during packaging.

Provide a local operator invocation path using the supported Wrangler binding API where available; verify real local service-binding RPC without an HTTP admin bridge. Any remote binding usage requires Cloudflare authentication and a separately authorized target; do not contact or mutate a hosted account during this work. Fail closed if the pinned tool cannot provide that path; document the verified alternative rather than inventing hosted behavior.

## Threats and verification

| Threat | Control | Evidence / residual |
| --- | --- | --- |
| Internet caller initializes or rewrites trust | Public export has fetch only; owner HTTP always 404; named binding required | Actual workerd public/default/named-binding separation tests |
| Object selector bypasses prior claims | Constant namespace key independent of all caller/config input | Restart and configuration-drift tests |
| Credentials enter artifact or diagnostics | Separate exact secret binding, bounded fixed errors, public-only package | Inspect packaged bytes and RPC errors with sentinel credentials |
| Owner floods or malformed input enters adapters | Strict bounded string/exact command fields; one mutation at a time inherited from lifecycle | Oversize/duplicate/unknown-operation/revision tests |
| Insecure fixture profile reaches deployment | Strict HTTPS public and authority profiles | Reject loopback flags and HTTP before mutation |
| Owner or account capability compromised | Binding is privileged; operator property is deployment attribution only | IAM/human attribution review remains open |
| Restore or redeploy loses acknowledged work | Preserve object identity and existing lifecycle; no reset or effect replay | Local restart only; independent recovery fence and hosted drill remain open |

Sources: [RPC visibility](https://developers.cloudflare.com/workers/runtime-apis/rpc/visibility/), [named entrypoints](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/), [object constructor gating](https://developers.cloudflare.com/durable-objects/api/state/), [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/), [binding API](https://developers.cloudflare.com/workers/wrangler/api/). Platform evidence is not hosted acceptance.

## Optional scheduler separation

The [automatic refresh contract](cloudflare-refresh.md) adds a named `RefreshEntrypoint`, accepting only a fixed-purpose private binding (`purpose: trust-refresh`) and exposing no HTTP administration. An opt-in separate Cron Worker receives that capability. The main default export remains fetch-only; its ordinary service binding cannot call scheduled refresh. A scheduler default binding is itself privileged because service bindings can call scheduled handlers directly. Its artifact/config are separate, hashed, route-free and explicitly deployed after organization initialization; no scheduler is packaged when a feed is absent.
