# Local rate and connection limits profile — xeip.local-limits/0.1

Experimental, opt-in **advisory** local bounds for the [HTTP + SSE](transports/http-sse.md) and [WebSocket](transports/websocket.md) development relays. It adds a per-key token bucket and global connection/subscription counters that reject excess work with `429`. [ADR 0008](decisions/0008-local-limits.md) records the decision. It carries unchanged XEIP `"0.1"` envelopes and is **not** production rate limiting, fair scheduling, a traffic shaper or a durable quota.

## Selection and limits

Enable explicitly through `createRelay({ token | admission, limits: { requestsPerSecond, burst, maxConnections, maxSubscriptions, keyBy } })`. Every field is optional; `limits: {}` uses the defaults below. Null, an array, unknown option keys, non-integers and out-of-range values are errors. Configuration is copied, so later caller mutations do not change the running policy.

| Field | Default | Range | Meaning |
| --- | --- | --- | --- |
| `requestsPerSecond` | 50 | 1–100000 | Token refill rate per key |
| `burst` | 100 | 1–100000 | Bucket capacity per key |
| `maxConnections` | 256 | 1–100000 | Concurrent long-lived transports relay-wide |
| `maxSubscriptions` | 256 | 1–100000 | Concurrent subscriptions relay-wide |
| `keyBy` | `"principal"` | `"principal"` or `"peer"` | How the rate-limit key is derived |

`keyBy: "peer"` keys shared-token/native mode by the socket peer. `keyBy: "principal"` keys admission mode by the authenticated entity; when no authenticated principal is present (shared-token mode) it falls back to the peer rather than sharing one `null` bucket. A peer on a loopback relay is the loopback address, so all shared-token clients from one address share one bucket.

The profile composes with the [admission](local-admission.md), [replay](local-replay.md), [delivery](local-delivery.md), [receipts](local-receipts.md) and dynamic durable profiles. It does not change their errors and does not require admission.

Run `npm run demo:limits` for a self-contained simulated burst, `429` handling, per-principal isolation, refill and a subscription-cap release. It generates temporary credentials without printing them and cleans up its relay/streams.

## Token bucket

Each key owns one token bucket on a **process-monotonic** clock:

- A new key starts full (`burst` tokens).
- A request consumes one token. If at least one token is available it is allowed; otherwise it is denied.
- Tokens refill continuously at `requestsPerSecond` and are capped at `burst`.
- The clock is a high-water mark: a caller-reported time that goes backwards never refills a bucket or resurrects spent tokens.
- Distinct rate-limit keys retained at once are bounded (4096) and the **least-recently-used** key is evicted; a denied request still counts as activity for recency. An evicted key that returns starts with a fresh full bucket.

The bucket is keyed only by the selector above. It is not fair: a key that sends in a burst can exhaust its own bucket, but keys do not share tokens, and there is no cross-key scheduling, priority or weighted fairness.

`Retry-After` is the whole number of seconds until one more token is available, rounded up and never less than `1`. Because `requestsPerSecond` is at least one, it is always at least one second; it is a lower-bound advisory, not a schedule.

## Connections and subscriptions

`maxConnections` and `maxSubscriptions` are **global** counters for the relay process, not per-key quotas:

- An SSE `GET /events` stream consumes one connection and one subscription.
- A successful WebSocket upgrade consumes one connection; each distinct, currently held WebSocket subscription consumes one subscription. Re-subscribing the same session on one connection replaces the prior subscription and does not consume another.
- Both counters are released when the stream closes, the WebSocket connection closes, or the subscription is replaced/removed.

These complement the admission profile's existing total/per-entity subscription quota; both can reject a subscription, with the first applicable check returning `429`.

## Where limits apply

Limits apply only to authenticated protected routes. **`GET /health` and the static console assets (`/console`, `/console.js`, `/console.css`, `/sse.js`, `/validation.js`) are never rate-limited or counted.**

| Transport surface | Rate bucket | Connection | Subscription |
| --- | --- | --- | --- |
| `POST /messages` | yes | — | — |
| `POST /receipts` | yes | — | — |
| `GET /events` | yes | acquire/release | acquire/release |
| WebSocket upgrade (`GET /ws`) | yes | acquire/release | — |
| WebSocket `send` | yes | — | — |
| WebSocket `receipt` | yes | — | — |
| WebSocket `subscribe` | yes | — | acquire/release |

`429` responses:

- Rate exceeded (HTTP): `{ "error": "rate limit exceeded" }` with a `Retry-After` header. (WebSocket controls instead receive `{ "type": "error", "status": 429, "error": "rate limit exceeded" }`.)
- Connection cap (HTTP/SSE and WebSocket upgrade): `{ "error": "connection limit exceeded" }`.
- Subscription cap (HTTP/SSE and WebSocket control): `{ "error": "subscription limit exceeded" }` / `{ "type": "error", "status": 429, "error": "subscription limit exceeded" }`.

A denied WebSocket upgrade returns an ordinary HTTP `429` and closes the socket, like other upgrade failures. A denied WebSocket control keeps the connection open and reports the error only to that connection.

## Health

Health adds `limitsProfile: "xeip.local-limits/0.1"` and `limits: { requestsPerSecond, burst, maxConnections, maxSubscriptions, keyBy }` to the existing mode-specific health body. It exposes the configured limits only — never per-key buckets, peer addresses, principal entities or live counts. Health and static assets remain available after any bucket is exhausted.

## Honest scope and non-goals

This profile is a local prototype and deliberately limited:

- It is **advisory** and in-memory. Buckets and counters reset on restart and are lost on a new factory; they are not a durable quota.
- It is **not production rate limiting** or traffic shaping. It does not smooth bursts beyond the bucket, does not coordinate across processes/relays, and does not implement token-bucket fairness, priority or weighted scheduling.
- It is **not an identity or admission control**. In shared-token mode the rate key collapses to the peer address and cannot distinguish token holders.
- It does **not** bound total memory, per-message size, request bodies, JSON depth, pending write queues, replay/delivery/receipt records or console state; those keep their own limits. Connection and subscription counters bound counts, not bytes or work.
- Limits are evaluated per request/control; they do not replace envelope validation, expiry checks, admission or the replay/delivery/receipt profiles.
- No production `429`/retry contract, metrics, distributed enforcement, fairness guarantee or independent review is added.

## Migration and rollback

Adding `limits` is additive and explicit. Without it, no route is limited or counted, health omits the `limitsProfile`/`limits` fields, and all modes, schemas and fixtures behave exactly as before. Removing it drops the in-memory buckets and counters and restores the prior behavior; there is no persistent state or migration. The [threat model](threat-model.md) T4 residual risk (broader per-principal quotas and fair scheduling) is reduced but not eliminated, and is recorded as such.
