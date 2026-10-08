# HTTP + SSE development transport — XEIP draft 0.1

**Experimental reference transport only.** Intended for loopback demonstrations, not untrusted or public deployment.

A sibling [WebSocket transport](websocket.md) carries the same envelopes, validation, admission and replay path over `GET /ws`. Both transports share one routing table, so a message can be delivered to a mix of HTTP/SSE and WebSocket subscribers in one acceptance.

The contract below describes the shared-token CLI mode. The opt-in [local admission profile](../local-admission.md) uses the same routes and XEIP 0.1 envelopes, with separate entity credentials, owner-provisioned memberships, generic authorization denials and subscription quotas. It must be selected explicitly through `createRelay({ admission })`; authentication failures never fall back to shared-token mode.

Admission may additionally select the [local replay profile](../local-replay.md) using `replay: { windowMs, maxEntries }`. It adds an optional boolean `duplicate` to HTTP acceptance responses, rejects conflicting reuse with 409, and refuses new scopes with 503/Retry-After when its bounded ledger is full. `duplicate: true` means no new stream writes; acceptance is still not recipient acknowledgment. Neither profile changes the base envelope version.

- `GET /health`: returns JSON health status.
- `GET /events?session=<encoded-session-URI>&entity=<encoded-entity-URI>`: returns HTTP 200 with a text/event-stream. Both selectors are required. Header `Authorization: Bearer <XEIP_DEV_TOKEN>` required. Send via `fetch()`; standard `EventSource` does not allow custom bearer headers.
- `POST /messages`: accepts a JSON XEIP message, requires the same bearer token and the exact `application/json` media type (case-insensitive, parameters permitted), validates its structure and broadcasts to current subscribers for that session. A `Content-Type` prefix such as `application/jsonp` is rejected.
- SSE event type is `xeip.message`. Each event's joined data is a JSON envelope; multiple data lines are joined with newlines. Heartbeat lines begin with `:`.
- Accepted messages return HTTP 202 and JSON `{ accepted: true, delivered: number }`. `delivered` is an integer from 0 through 9007199254740991. This only counts **writes to active SSE connections**, not consumption or durability; zero is a successful acceptance when no matching connections exist. SDKs must not treat another 2xx status or a negative, fractional, or unsafe-integer count as this acceptance response.
- Request bodies are limited to 64 KiB and 64 nested JSON containers, counting the root envelope and each containing object/array. The reserialized SSE frame is also limited to 128 KiB of UTF-8 bytes, including framing; compact numeric notation can expand during JSON serialization, so this limit is checked before any stream write. These are transport resource limits, not extra core-schema constraints. For example, `body.data` may contain at most 62 nested arrays under the root envelope and body object. Each subscriber's pending output is limited to 256 KiB; the relay disconnects that subscriber before a write would exceed the limit. Other subscribers continue receiving messages. A queued write is counted as a write even if that stream later disconnects.
- The TypeScript, console and Node demo readers support LF, CRLF, and CR delimiters across chunk boundaries and limit each unfinished frame to 128 Ki UTF-16 code units. The Rust example uses a 128 KiB frame-content limit with CRLF treated as one line ending and rejects malformed UTF-8; JavaScript's text decoder replaces malformed sequences. Readers discard incomplete final events when a stream ends. No reconnect or replay is implemented.

Every route checks the socket peer and requires exactly one literal loopback `Host`: `localhost`, `127.0.0.1`, or `[::1]`, optionally followed by a port from 1 through 65535. DNS names resolving to loopback, proxy hostnames and duplicate Host headers are rejected. If `Origin` is present it must exactly match the serialized `http://` origin of the Host header, including its effective port; `null`, remote origins and different loopback origins are rejected. Native clients may omit Origin. Only origin-form request targets (paths beginning with a single `/`) are supported. These browser/authority gates also apply to public health/static routes; they do not bind participant identities.

Routing uses exact session/entity URI strings, without URI normalization. In shared-token mode, an explicit recipient selects every matching connection, while omission broadcasts to every active connection in the session, including the sender's connections. Admission mode additionally requires current credential records and membership for each eligible stream. Duplicate message IDs are forwarded repeatedly unless the local replay extension was explicitly enabled; that extension scopes equality by authenticated sender, session and ID. The relay has no HTTP session descriptor/admission endpoint and no `replyTo` lookup. See [../core.md](../core.md) for these baseline semantics.

`expiresAt` is checked once at POST acceptance against the relay's local `Date.now()` clock; expiry at or before that sampled millisecond is rejected. Fractional digits beyond milliseconds are conservatively truncated, and a structurally valid `23:59:60` is mapped to the following second without verifying an actual leap-second insertion. `timestamp` is not used for freshness or ordering. Nothing removes an already queued message when it expires, and client structural validation does not perform a live expiry check.

## Error responses

Errors return JSON `{ error: string }` with a transport status; the text is diagnostic and is not a stable typed error code.

| Status | Condition |
| --- | --- |
| 400 | Invalid request target/URL, malformed UTF-8/JSON or invalid event selectors |
| 401 | Missing/incorrect bearer token, or revoked credential in admission mode |
| 403 | Non-loopback socket peer, disallowed Host or mismatching Origin; generic authorization denial in admission mode |
| 404 | Unknown route or unsupported method |
| 409 | Local replay profile: an accepted scope was retried with different content |
| 413 | Request body exceeds the byte/nesting limit or its serialized SSE frame exceeds 128 KiB |
| 415 | POST media type is not `application/json` |
| 422 | Structurally invalid envelope or expired message |
| 429 | Admission mode's total or per-entity subscription limit is reached |
| 503 | Local replay profile: new scope cannot fit without evicting a live record; Retry-After advises earliest expiry |

Authority/Origin checks happen before protected-route authentication. No production `unknown-session`, membership, rate-limit or negotiated version error contract is implemented.

Shared-token restrictions: local loopback bind, request-body limit, no store-and-forward, no independent sender authentication, no verified session membership, no offline queues, no federation, no E2EE, and no per-entity permissions. The local admission profile adds local credential binding and membership enforcement. For production, a complete identity/admission design, transport encryption and replay protection remain required.

The scoped review and remaining risks are recorded in [../threat-model.md](../threat-model.md).

## Local test console

The reference relay also serves `GET /console`, `/console.js`, `/console.css`, `/sse.js` and `/validation.js` on loopback. These static files require no token to load, but streaming and posting require the selected mode's bearer credential. The shared-token CLI permits simulated entities to use the same token/session. Admission mode requires each selected entity's provisioned token and an admitted session; the console does not enumerate that configuration. The console deliberately does **not** persist its entered token.
