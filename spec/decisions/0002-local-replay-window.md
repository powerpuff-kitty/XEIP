# ADR 0002: Opt-in bounded suppression of authenticated retries

Status: accepted for the experimental local implementation under the ongoing implementation task. Date: 2026-10-09. This is a first slice of [issue 4](https://github.com/powerpuff-kitty/XEIP/issues/4), not approval of durable delivery or exactly-once execution.

## Context

The shared-token and admission relays forward repeated IDs. After a lost HTTP acceptance response, an authorized sender cannot retry without another stream write. The admission profile now supplies a trustworthy local sender/session scope; the relay remains an in-memory loopback example with no recipient acknowledgment or persistence.

## Decision

Add `xeip.local-replay/0.1`, explicitly enabled with `createRelay({ admission, replay: { windowMs, maxEntries } })`. Require admission mode. Hash the exact `(session, authenticated sender, message ID)` tuple and a deterministic representation of the complete parsed envelope using Node SHA-256. Sorted object keys make JSON property ordering irrelevant; array order and all envelope values remain significant. This representation is an internal equality check, not a wire signing or canonicalization standard.

Remember an authorized, validated acceptance before any synchronous stream writes. Identical retries within a fixed monotonic window return HTTP 202 with `duplicate: true` and zero new writes. Changed content in that scope returns 409. New IDs cannot evict unexpired records: a full ledger returns 503 with Retry-After. Defaults are five minutes/4096 entries; owner configuration is bounded to one hour/4096 entries. Existing modes remain unchanged unless replay is explicitly configured.

Authenticate, validate expiry/resource bounds and authorize every retry before looking up replay state. Credential rotation and session changes do not reset accepted IDs; native server relisten keeps its ledger. New factory instances lose it. The TypeScript SDK exposes the optional duplicate flag, and the Rust example accepts its presence on new-message acceptance responses.

## Alternatives

- Deduplicate all modes by a sender string: rejected because shared-token peers can impersonate that sender and poison its scope.
- Evict live records under pressure: rejected because a flood could reopen the advertised suppression window.
- Start with durable queues, cursors and recipient receipts: deferred until persistence, retention, ordering and recovery are designed together.
- Keep every ID forever: rejected because this local prototype must have finite state.

## Consequences

Acceptance with zero writes is still remembered; reconnecting does not replay it. Suppression expires, restart loses it, and a new ID always represents a new message. An admitted sender can consume ledger capacity. No automatic SDK retry, offline queue, ordering guarantee, recipient acknowledgment, command grant or exactly-once side effect is added. See [../local-replay.md](../local-replay.md) for the contract and [../plans/local-replay.md](../plans/local-replay.md) for checkpoints.
