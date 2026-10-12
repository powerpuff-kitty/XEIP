# Signed organization action service

Implementation contract following the [authentication](organization-auth.md) and [action ledger](organization-actions.md) modules. Target: one organization, self-hosted Keycloak/PostgreSQL, human-approved internal MCP tool invocation. This design is not yet a deployed or production-certified service.

## Request boundary

Expose one versioned command endpoint, `POST /v1/actions`, accepting strict UTF-8 JSON containing an entity-signed XEIP envelope. Require `Content-Type: application/json`, a Keycloak bearer token and the explicitly selected entity-signature profile 0.2. Reject duplicate keys, malformed UTF-8, excessive nesting, unsupported fields, body sizes over 96 KiB and compression. No bearer in query strings, no unsigned fallback, and no trusting a caller-provided upstream URL.

The envelope must pass the base schema and current cryptographic trust policy. Its sender and proof key must equal the authenticated principal; its recipient must equal the configured gateway entity. Require `kind: command`, content type `application/vnd.xeip.organization-action+json`, a whole-second UTC timestamp no more than 60 seconds old and no future timestamp, and a future whole-second expiry no more than 60 seconds away. The signed body must bind operation, session, action ID and exact arguments or expected digest. Snapshot input before asynchronous provider/store calls. Revalidate identity and trust after request reads and at the store boundary.

Supported body forms:

| Operation | Exact body fields |
| --- | --- |
| `propose` | `operation`, `request` (the action request from the action contract) |
| `approve`, `reject`, `revoke`, `execute` | `operation`, `session`, `id`, `digest` |
| `inspect` | `operation`, `session`, `id` |

The body's session must equal the envelope session. A proposal's request ID must equal the envelope ID. Other envelope IDs identify their signed operation; state transitions and execution claims remain replay-safe through the ledger, not an in-memory HTTP cache. Status inspection grants no ability to execute or finish a claim. Do not return internal claim IDs to clients.

After mutation/audit database waits, revalidate the request immediately before initiating COMMIT. Cancellation or signed expiry already observed at that point must roll the transaction back. Once COMMIT has been issued, a timeout/disconnect cannot prove whether the database committed; use authorized inspection to resolve it. Internal completion persistence after an attempted tool effect must proceed independently of caller cancellation or expiry.

Successful requests return JSON with the proposal digest/content and state; execution also returns a bounded MCP result when available. Approval/rejection/revocation responses confirm only durable state. Use 400 for invalid structure, 401 for unauthenticated bearer, 403 for identity/policy denial, 409 for state/digest conflicts and 503 for provider/store/target unavailability or ambiguous persistence. Never expose bearer/client secrets, raw database/provider errors or argument contents in logs. Exact response status does not replace the durable status lookup after connection loss.

The library handler must bound body-read time, concurrent requests, queued output and header sizes. Bind network exposure in a separate production launcher: require TLS directly or an explicitly configured private TLS ingress, exact Host/Origin allowlists, protected configuration, no insecure-issuer option, and no public demo relay. Liveness and dependency readiness are separate endpoints. Request IDs/logs must not contain credentials or application arguments.

## Execution boundary

The worker acquires one durable approved claim, revalidates the agent token and both actor/key trust relationships immediately before upstream I/O, then calls an operator-configured connector. It must never retry an effect automatically after sending a tool call, including on a timeout, disconnect or ambiguous upstream result. A pre-send denial can finish as `failed`; an uncertain post-send effect is `indeterminate`. Completion persistence failure must be surfaced as unavailable with status inspection/reconciliation instructions; do not claim that a returned result was durably recorded if commit failed.

The connector target ID/revision/recipient must match the approved action and immutable policy configuration. MCP tool names and arguments come only from the approved stored proposal. Limit result size and deadline; close resources on timeout/client cancellation. Upstream results are untrusted data. Do not interpret instructions in tool output as new approvals or actions.

For the MCP adapter, use the current official v2 client and a separately implemented official-server fixture. Verify exact installed API and version. Preserve MCP request metadata, tool error semantics and required authorization discovery; reject unsupported interactive continuation instead of executing extra calls. Use target-scoped upstream credentials and resource/audience restrictions, never pass the incoming XEIP bearer to the tool server. Pin trusted endpoint/issuer origins and bound metadata requests; redirects and metadata must not expand the configured network trust boundary.

Current upstream references: [MCP transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), [authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and the [official TypeScript SDK v2](https://ts.sdk.modelcontextprotocol.io/v2/). This revision uses per-request protocol metadata; do not assume the older initialize/session model is the current protocol.

## Verification and release limits

Exercise the signed HTTP boundary with real signatures, real entity trust and a local JWT/provider fixture, then combine with real Keycloak/PostgreSQL and an independently implemented MCP server fixture. Negative cases include changed arguments/digest, wrong actor/key/session/recipient, revoked keys/tokens during body reads or provider waits, duplicate execution, expired approval, unavailable storage, denied upstream auth, oversized/invalid output and lost completion commit.

Measure the accepted 500-user/200-agent/120-action-per-minute workload through the complete provider/database/connector path. Human approval timing must be reported separately from machine latency; simulated approvals do not demonstrate human usability. Operator-approved latency/recovery targets, runtime least privilege, storage fault/restore acceptance, supported artifacts, independent security review and pilot sign-off remain production gates.
