# ADR 0003: Opt-in bounded per-session sequencing and reconnect resume

Status: accepted for the experimental local implementation under the ongoing implementation task. Date: 2026-10-09. This is a further slice of [issue 4](https://github.com/powerpuff-kitty/XEIP/issues/4), not approval of durable delivery, recipient receipts or exactly-once execution.

## Context

[ADR 0002](0002-local-replay-window.md) suppresses identical authenticated retries but remembers only digests and never replays them. A reconnecting subscriber has no way to learn what it missed, and the transports expose no shared ordering marker. A useful, testable next step is an in-memory, bounded log that assigns an order and can resume within a fixed window, without promising durability.

## Decision

Add `xeip.local-delivery/0.1`, explicitly enabled with `createRelay({ token | admission, delivery: { windowMs, maxPerSession, maxSessions } })`. It does not require admission mode because it only records already-authenticated, validated envelopes. Defaults are five minutes / 512 entries per session / 256 sessions, bounded to one hour / 4096 / 1024.

Assign a strictly increasing integer sequence per session at acceptance, in the same synchronous step as routing, so sequence order equals acceptance order. Expose it only in transport framing: HTTP acceptance `seq`, SSE `id:` lines, and WebSocket `accept`/`message` controls. Do not add it to the stored envelope or the base schema.

Allow reconnect resume by cursor: SSE `Last-Event-ID`/`after`, WebSocket `subscribe.after`. Replay retained entries with a greater sequence, filtered by the same membership and recipient rules as live routing. When the cursor predates the oldest retained entry, emit an explicit `xeip.gap`/`{type:"gap"}` indicator instead of silently skipping. Bound retention per session, by a fixed monotonic window, and by least-recently-used session eviction.

## Alternatives

- Add a sequence field to the XEIP envelope/schema: rejected because ordering is a transport concern and the base wire shape must stay stable for v0.1.
- Reuse the replay digest ledger as the resume log: rejected because it stores no envelopes and cannot reconstruct a backlog.
- Make resume durable across restarts: deferred until persistence, retention and recovery are designed together.
- Silently skip evicted messages on resume: rejected because it hides loss; a gap signal is required.
- Promise exactly-once or recipient acknowledgment: rejected; the relay cannot verify consumption.

## Consequences

Resume only works within the in-memory retention bounds and the same relay process. Restart loses sequence and backlog; resuming outside the window yields a gap. Sequence is acceptance order, not sender creation or application completion order. Receipts, durable queues, cross-relay ordering, integrity and independent review remain future work. See [../local-delivery.md](../local-delivery.md) for the contract and [../plans/local-delivery.md](../plans/local-delivery.md) for checkpoints.
