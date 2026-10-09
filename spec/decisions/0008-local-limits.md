# ADR 0008: Opt-in advisory local rate and connection limits

Status: Accepted for local prototype (implemented in `services/relay/limits.mjs`). Date: 2026-10-09. This decision advances [issue 6](https://github.com/powerpuff-kitty/XEIP/issues/6) (rate-limit/error taxonomy) and addresses the repeatedly-noted residual risk in [threat-model.md](../threat-model.md) T4 that "global/per-principal request quotas and fair scheduling" are missing. It is an opt-in, in-memory local prototype and does not approve production rate limiting, fairness or a durable quota.

## Context

[threat-model.md](../threat-model.md) T4 rates resource exhaustion by a hostile authenticated peer as likely/high and states that neither relay mode bounds all HTTP connections, request rates or total client memory. [local-replay.md](../local-replay.md) records that a member can fill the shared ledger and temporarily deny new admissions, and that its entry cap "is not fair scheduling or rate limiting." [local-receipts.md](../local-receipts.md) lists "per-principal request quotas, fairness or rate limiting beyond the ledger bounds" as an explicit non-goal. [security.md](../security.md) and the transport profiles describe the relay as a loopback-only development tool with no production error contract.

Existing profiles bound individual dimensions — body size, JSON depth, pending output, replay entries, delivery entries, receipt digests, and admission subscription counts — but nothing bounds request rate, total connections or total subscriptions across the relay, and there is no `429` taxonomy for them. The missing control is small and local, so it can be added without touching the envelope, routing, admission or the persistence profiles.

## Decision

Adopt the design in [../local-limits.md](../local-limits.md). In summary:

1. Add `xeip.local-limits/0.1`, enabled explicitly with `createRelay({ token | admission, limits: { requestsPerSecond, burst, maxConnections, maxSubscriptions, keyBy } })`. All fields are optional with documented defaults; null, unknown keys, non-integers and out-of-range values are errors; configuration is copied. It works in shared-token and admission modes and composes with every other opt-in profile.
2. Use a **per-key token bucket** on a process-monotonic clock for request rate, with a bounded, least-recently-used key store and a `Retry-After` in whole seconds. Keys are selected by `keyBy`: the authenticated principal (default, rising to peer without a principal) or the socket peer for shared-token/native mode.
3. Use **global connection and subscription counters** with explicit acquire/release, released on stream/socket/subscription close. An SSE stream and a WebSocket upgrade each hold a connection; an SSE stream and each held WebSocket subscription hold a subscription.
4. Apply limits only to authenticated protected routes and the WebSocket upgrade/controls; **never** to `GET /health` or static console assets. Exceeded rate returns `429 { error: "rate limit exceeded" }` with `Retry-After`; exceeded connection/subscription caps return `429` with a distinct diagnostic.
5. Advertise `limitsProfile` and the configured limits in health, never per-key buckets, peers, principals or live counts.
6. State the guarantee honestly: advisory, in-memory, per-process, non-durable, and not fair scheduling or production rate limiting.

## Alternatives

- **Add a dependency (e.g. a token-bucket/rate-limit package).** Rejected: the relay is deliberately dependency-free, and the algorithm is a few lines.
- **One global rate bucket instead of per-key.** Rejected: it lets one principal deny every other principal, recreating part of the T4 concern; per-principal sharing is the point.
- **Per-key connection/subscription counters instead of global.** Rejected for 0.1: the reported gap is relay-wide connection/subscription exhaustion, and a global counter is the direct, auditable bound; per-key fairness is deferred as future work.
- **Refill using wall-clock time.** Rejected: wall clock skew/rollback makes refill non-monotonic; the bucket uses the same process-monotonic convention as replay, delivery and receipts, and the tests inject elapsed time.
- **Reject with a stable typed error code and a full `Retry-After` schedule.** Rejected for 0.1: consistent with the existing profiles, the diagnostic is not a stable code and the whole-second `Retry-After` is a lower-bound advisory. A production error taxonomy remains [issue 6](https://github.com/powerpuff-kitty/XEIP/issues/6).
- **Persist buckets/counters or enforce across processes.** Deferred: it introduces storage, coordination and confidentiality decisions that belong with durable delivery and federation, and would invite a durable-quota overclaim.
- **Bound memory/bytes rather than counts, or shape traffic.** Rejected as out of scope: existing profiles bound their own entries, and fair/weighted scheduling is future work, not this prototype.
- **Rate-limit health and static assets too.** Rejected: it would make liveness checks and console loading fail under load, and those routes carry no protected work.

## Consequences

Positive: issue 6 gains an implemented `429` taxonomy for rate and connection/subscription caps; the T4 residual risk has a concrete, documented local mitigation; and the relay gains per-principal and relay-wide bounds without changing any envelope, transport framing, existing profile or default behavior. It reuses the monotonic-clock, bounded-map and copy-configuration conventions of the other profiles.

Negative and limiting: the bounds are advisory and in-memory, reset on restart, collapse to the peer address in shared-token mode, and are not fair scheduling or a durable quota. Evicting a least-recently-used rate key lets that key resume with a full bucket, so the bound is not a precise long-run rate for very many distinct keys. Connection/subscription counts bound counts, not bytes or work, so a hostile peer can still consume memory within those counts. Multi-process, cross-relay and durable enforcement, weighted fairness, metrics and a production error/backoff contract remain future work, as does independent security review. See [../local-limits.md](../local-limits.md) for the contract and [../threat-model.md](../threat-model.md) T4 for the residual risk.
