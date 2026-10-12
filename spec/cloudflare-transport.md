# Cloudflare request and MCP transport boundaries

Status: experimental transport work within the approved native exploration. This is a dependency of the complete Worker service, not production adoption or deployment.

## Intent

Reuse the existing signed controller, durable authority/ledger and MCP SDK while providing the Workers Fetch API boundary. Establish native-runtime behavior before adding a deployable object lifecycle. The organization still targets 500 users, 200 agents, 120 actions/minute, machine-operation P95 ≤2 seconds, restore ≤1 hour and no acknowledged-action loss; local conformance does not certify those targets.

## MCP egress

Run the existing McpConnector in real workerd against an independent official-SDK MCP server and OAuth fixture. Keep exact configured target/revision/recipient/tool checks, pinned HTTPS discovery/resource/issuer/token endpoints, target-scoped OAuth credentials, bounded response sizes/time/request count, one pre-send live guard and no retry after an uncertain effect. Replace unsupported redirect behavior only if runtime evidence requires it; explicitly reject all redirect statuses so neither credentials nor effects follow a Location header. Do not add a less strict Workers connector or fall back to unsigned/unscoped requests. Private networking still requires an operator-provided route to the pinned HTTPS endpoints; this batch proves protocol transport, not a real organization's private route.

## Fetch ingress

Expose `createWorkerHttp({controller, origin, ready, bodyTimeoutMs?, operationTimeoutMs?, readinessTimeoutMs?, maxConcurrent?})`, returning a request handler. Defaults/ranges match the existing organization HTTP profile: 96 KiB streamed body limit, 256 KiB encoded response limit, body timeout 5000 ms (100–30000), operation timeout 30000 ms (100–60000), readiness timeout 2000 ms (100–10000), and 32 concurrent work slots (1–256).

Pin an exact HTTPS origin and reject mismatched URL/Host/Origin, credentials, query fragments, compressed payloads, ambiguous length/authorization/content-type values and malformed UTF-8 before invoking the controller. Forwarded identity/proxy headers never establish authority. Fetch headers can normalize repeated fields, so reject malformed combined sensitive values; hosted raw-header behavior remains an acceptance check. Only POST /v1/actions invokes the controller; GET /live and GET /ready have distinct meanings. Other paths/methods are denied. No public administration, bootstrap, console or unsigned command route is introduced.

Read incrementally and enforce byte/time bounds before parsing. Abort work on request cancellation or deadlines. An operation timeout returns a redacted error but retains its slot until the actual underlying task settles; late completion must not start another effect or report an unrecorded success. Provide an explicit owner-supplied `waitUntil` hook for pending work, including internal result recording, without treating runtime background-work support as durability. Durable claims and indeterminate outcomes remain the crash boundary. Liveness remains available when action slots are busy. Readiness is separately bounded, shares admission slots and does not mutate storage.

Responses use fixed safe errors, no-store, nosniff, bounded JSON, a generated request ID and Retry-After for overload. A trusted controller's unexpected exception cannot leak message/stack/credentials. Expose only fixed operation-error mappings, never arbitrary exception fields. No browser CORS grant is added; same-origin browser clients remain the intended profile.

## Composition evidence

Use the real local workerd engine. First test the ingress with controlled controller delays/errors/streams to isolate size, cancellation, deadline and slot semantics. Then route signed requests through the existing real authority, trust, ledger and executor to the official MCP server fixture with actual OAuth discovery/token flow; assert a single tool call and durable outcome, redirection refusal, authority changes during OAuth/pre-send work, terminal failures and restart without replay. Credential separation must be observable at the receiving fixture.

A test Worker may expose privileged setup through a private Miniflare object interface only; its public route uses the new handler and must not expose SQL/fault controls. It is never the deployment artifact. The production object's explicit initialization, protection of owner administration, signed trust refresh, lifecycle/readiness composition, binding/secret configuration and deployable packaging remain subsequent required work. No resource or DNS changes occur here.

## Platform evidence

Cloudflare documents Fetch request behavior and execution-context lifetime in [Request](https://developers.cloudflare.com/workers/runtime-apis/request/) and [Context](https://developers.cloudflare.com/workers/runtime-apis/context/). Durable object in-memory state is lost on eviction/deployment, so persistent state must remain authoritative: [storage guidance](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/). Local runtime checks establish compatibility, not hosted recovery or lifecycle assurances.
