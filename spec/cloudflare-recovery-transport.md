# Recovery HTTPS boundary

Architectural increment toward the approved Cloudflare exploration and original no-acknowledged-action-loss requirement. Hosting, failure boundary and production adoption remain undecided. Preserve self-hosted Keycloak and the existing Linux deployment.

## Decision

Use a provider-neutral Fetch client and handler around the existing journal, rather than a Cloudflare-only service binding or unauthenticated injected production capability. HTTPS permits a separately operated endpoint; it does not prove provider/account independence. A private service binding could avoid bearer management but would constrain placement. A staged upload protocol would reduce peak memory but adds persistent upload lifecycle and cleanup; this version uses one bounded atomic append carrying the existing maximum 16 MiB payload, and must pass a native maximum-size test. Hosted memory/CPU/latency acceptance remains required.

## Contract

`createRecoveryClient({url,token,options}, fetchImpl=fetch)` supplies asynchronous head(), entry(sequence), part(sequence,index), append(value). Configuration pins a canonical HTTPS URL (no credentials/query/fragment) and the journal options. Token is exactly 32 random bytes encoded as 64 lowercase hexadecimal characters, runtime-only. A dedicated token grants read/append authority only to this organization/stream; never reuse Keycloak, owner or application credentials. Rotation requires replacing both endpoint and client configuration; deployment automation is separate.

`createRecoveryHandler({url,token,options,journal})` returns a Fetch handler. Journal is already explicitly initialized/opened in isolated storage; handler cannot create, reset, close, delete or select a namespace. Authenticate before reading the body or accessing the journal. Compare fixed-size token hashes without early byte mismatch. Reject browser Origin, cookies, incorrect Host/URL/method and encoded/compressed requests. All responses are no-store JSON with generic fixed errors, no reflected credentials or payloads. No CORS.

Single POST envelope: `{schema:"xeip.recovery-http/1",organization,stream,operation,args}`. Exact keys and strict JSON (duplicate keys/BOM/invalid UTF8 rejected), max depth 16. Operations: head args{}, entry args{sequence}, part args{sequence,part}, append args equal the existing validateAppend contract. Head/entry/append success is the existing exact head/entry; part is {entry,part,data}. Response validation binds requested cursor, scope and append predecessor/id/bytes/digest/part count; action coordinator additionally checks cumulative bytes and full chain. Genesis heads must match pinned options.

Request cap 24 MiB covers64 canonical base64 parts; response cap 384 KiB covers one full part plus header. Declared lengths must match bytes actually received; stream limits apply without Content-Length. Entire request/fetch/body/operation deadline uses options.timeoutMs (100..10000ms). One admitted request per handler/client prevents unbounded buffered concurrency; overlapping requests fail unavailable. A timed-out underlying operation retains its slot until settled, and cannot later return success or invoke a not-yet-started journal call. Append may have committed after a lost response: no automatic retry and caller reconciliation/quarantine semantics remain mandatory. No automatic redirect, credential forwarding, cookies, transport cache, response decompression or effect retry. Synchronous CPU work cannot be interrupted by timers; yield to pending timers before starting outbound/journal work and before accepting success, including when deployed clocks remain frozen until I/O.

Only exact HTTP 200 success. Client treats every failure status/malformed response/timeout as StoreUnavailable, so even an ambiguous409 cannot be mistaken for safe source admission. Server uses 401 unauthenticated,400 invalid_request,409 conflict,429 busy,503 unavailable; TypeError from request validation is400, but errors or malformed results from the journal are503. Failed authentication does not reveal journal state.

## Evidence and limits

Tests: real local workerd/SQLite journal and Fetch client/handler round-trip, multipart and16 MiB max, restart, claim-free append, sync-before-response, lost receipt reconciliation, missing/wrong credentials before body read, malformed/cross-scope/cursor/receipt responses, forbidden administration, redirects, body/header/UTF8/JSON limits, never-settling fetch/body/operation, cancellation, concurrent admission, late completion and error redaction. No real cloud resources or secrets.

The [Worker recovery configuration](cloudflare-worker-recovery.md) now wires the source client into the organization Worker/profile. A journal hosting package remains open. Those require explicit enrollment, secret custody, network/IAM/failure-domain evidence and full restore/retention tests. Transport authentication cannot establish integrity against an endpoint operator or a coherent rollback of all witnesses.

Platform references checked 11 October 2026: [Request redirect semantics](https://developers.cloudflare.com/workers/runtime-apis/request/), [Fetch](https://developers.cloudflare.com/workers/runtime-apis/fetch/), [Workers limits](https://developers.cloudflare.com/workers/platform/limits/). These motivate manual redirects and bounded buffering; local maximum-size success is not hosted capacity certification.

Response compatibility: decoded chunked Fetch responses without Content-Length are accepted. Transfer-Encoding plus Content-Length and unsupported coding chains remain invalid, as do transfer-encoded handler requests. All existing decoded byte/deadline/JSON bounds apply. See [RFC9112 section7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).
