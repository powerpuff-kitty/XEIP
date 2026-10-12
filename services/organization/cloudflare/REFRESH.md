# Automatic signed trust refresh

Experimental, opt-in. A dedicated Cron Worker can trigger the organization Worker to poll an authenticated feed each minute for complete signed key/status documents. Signing keys stay with the external publisher. The owner provisions the initial roster; the feed may update its signed keys/status but cannot add, remove or restore identities. Manual roster changes remain owner operations.

## Configure a new candidate

Add this public field before initial organization setup:

```json
"trustFeed": {
  "url": "https://trust.example.org/xeip/current",
  "timeoutMs": 5000
}
```

The URL must be canonical HTTPS without credentials, query or fragment. Set `trust.maxAgeSeconds` to at least 180; choose a value and publishing cadence appropriate to the required revocation window. Add `trustFeedToken` to the separate `XEIP_CREDENTIALS` JSON secret. It must use bearer-token characters, at most 4096 bytes, and fit the existing 5120-byte credential binding budget. Do not put it into a profile, command, repository, artifact or logs. The publisher receives `Authorization: Bearer …`; redirects are rejected. Rotate this token by replacing the secret binding.

Build using [WORKER.md](WORKER.md). The main `wrangler.json` always has an empty cron list and a fetch-only default entrypoint. When configured, two additional hashed files appear: `scheduler.mjs` and `scheduler.wrangler.json`. The latter names `<main-name>-refresh`, configures `triggers.crons: ["* * * * *"]`, and binds privately to `RefreshEntrypoint` with `purpose: trust-refresh`. Feed-enabled main Worker names are limited to 55 characters to leave room for that suffix. Reserve both names in the target account and check for existing services before any authorized rollout; the offline builder cannot check account-wide naming conflicts. No resources are created by building. A future authorized rollout must deploy the organization Worker, install its credentials and initialize/provision it, then deploy the scheduler using its separate config. Dry-run each config first. Both disable workers.dev/preview URLs; the scheduler has no public routes and HTTP returns404. Never grant a scheduler default binding to ordinary clients: scheduled handlers are directly callable through service bindings. Only the organization Worker’s default binding is intended for ordinary fetch access. Disabling/removing the scheduler trigger stops polling without deleting organization state; trust still expires. Do not deploy only one config and assume cron is active. The feed source and timeout are immutable organization intent; adding/changing/removing them after initialization fails closed. Existing deployments need an explicit future migration; never delete live state to enable this feature.

Initialize authority and provision signed trust through the private owner commands first. An empty organization or empty roster never bootstraps from the feed. Publish exactly `{ "keyDocuments": [...], "statusDocuments": [...] }`, using the same complete document format as manual `refreshTrust`. Keep the exact active roster synchronized with owner changes. Response: HTTP 200, `application/json` (optional `charset=utf-8`), identity/no content encoding, <=2,000,000 decoded bytes, strict duplicate-free JSON. Deadlines cover headers and body; no immediate network retries occur.

## Observe and recover

Each poll emits a redacted `xeip.trust-refresh` outcome: `disabled`, `not_ready`, `busy`, `unchanged`, `updated` or `failed`. Failed/not-ready/overlapping polls fail the native scheduled event. Alert on failures, readiness and signed-document age; liveness alone is insufficient. Identical valid data writes nothing and does not extend its freshness. Fresh changed data uses the durable [administrative journal](ADMIN_AUDIT.md), with actor `automation:trust-feed` and a new request UUID. Fetch and validation failures are diagnostic only, not admitted mutations in that journal.

Invalid, stale, rolled-back or conflicting data preserves the previous trust, which still expires normally. If an owner changes trust while a fetch is pending, that fetched data is discarded. Fix the publisher or secret for network/validation failures; the next schedule can try current data again. Storage uncertainty quarantines the object. Follow the existing incident/reopen procedure; an unfinished journal attempt remains uncertain, even when a later duplicate confirms that the candidate is present. No action execution or administrative result is replayed or fabricated.

The minute schedule is not a latency guarantee. Signing plus publishing plus polling plus network and scheduling delay must fit the freshness window. See [Cloudflare's scheduled handler](https://developers.cloudflare.com/workers/runtime-apis/handlers/scheduled/) and [Cron documentation](https://developers.cloudflare.com/workers/configuration/cron-triggers/). Local workerd tests cover actual event dispatch, 700 identities, restart, malformed feeds, late responses, roster/owner races and durability failures; they do not establish hosted TLS, scheduling availability, network routing or capacity.

One changed poll/minute consumes 2880 journal records/day, before manual administration. The 100000-record cap therefore cannot support indefinite operation without accepted retention/export. Publisher custody and uptime, monitoring, retention, independent recovery protection, real human Keycloak/MCP flows and hosted workload/recovery/security acceptance remain production gates.
