# ADR 0005: Authenticated recipient receipts over a bounded in-memory correlation ledger

Status: Accepted for the local prototype (implemented in `services/relay/receipts.mjs`). Date: 2026-10-09. This decision records the design for [issue 4](https://github.com/powerpuff-kitty/XEIP/issues/4) and advances the receipt portion of its delivery/correlation scope. It remains an opt-in, in-memory local prototype and does not approve durable delivery or exactly-once execution.

## Context

[Issue 4](https://github.com/powerpuff-kitty/XEIP/issues/4) requires distinguishing relay acceptance, transport write, recipient receipt and application completion, and defining correlation, expiry, deduplication, ordering and reconnect behavior. [ADR 0002](0002-local-replay-window.md) bounded suppression of identical authenticated retries but stores only digests and never replays them. [ADR 0003](0003-local-delivery-resume.md) added per-session sequencing and bounded reconnect resume but no acknowledgment; it states that recipient receipts remain future work. [core.md](../core.md) classifies `kind: "receipt"` as unverified application-level evidence and reserves persistent replay and idempotency for v0.2. [security.md](../security.md) requires binding a connection to the sender entity and enforcing membership, and [threat-model.md](../threat-model.md) T3 lists fabricated receipts and unverified consumption as open residual risks.

The blocker is not the wire shape but trust: only the [local admission profile](../local-admission.md) supplies an authenticated principal and recipient rules, and only the [local delivery profile](../local-delivery.md) retains the acceptance a receipt could be correlated against. A receipted acknowledgment that a shared token could forge would create false confidence, so the design must not run without both.

## Decision

Adopt the design in [../local-receipts.md](../local-receipts.md). In summary:

1. Add `xeip.local-receipts/0.1`, explicitly enabled with `createRelay({ admission, delivery: { ... }, receipts: { windowMs, maxPerSession, maxPerPrincipal } })`. Receipts without admission, without delivery, or with a shared token are errors.
2. Keep the four states separate. The profile implements only recipient receipt (state 3); relay acceptance (1) and transport write (2) remain the existing acceptance/`delivered` behavior, and application completion (4) is explicitly out of protocol scope.
3. Acknowledge through transport controls, not a redefined envelope: HTTP `POST /receipts` and WebSocket `{ "type": "receipt" }`, correlated by delivery `seq` and/or message `id` against the retained delivery log, with `{ "type": "acknowledged" }`/HTTP 202 replies.
4. Store receipts in a fixed-size, per-principal, bounded in-memory ledger (principal/session/ID digests, `seq`, monotonic expiry). Do not broadcast receipts and never return one principal's receipts to another.
5. Re-evaluate admission authorization and recipient eligibility at receipt time; a receipt means an authorized principal asserted it held a retained acceptance, not that a write occurred and not that processing happened.

## Alternatives

- **Reuse `kind: "receipt"` or `replyTo` as the acknowledgment.** Rejected: [core.md](../core.md) defines them as unverified application data; making them protocol-meaningful would reinterpret existing 0.1 envelopes and blur states 3 and 4.
- **Allow receipts in shared-token mode.** Rejected: a shared token cannot bind the acknowledging principal to an intended recipient, so any receipt would be forgeable and misleading.
- **Correlate against a new accepted-ID index instead of the delivery log.** Rejected: it duplicates retention and creates a second unbounded surface; the delivery log already holds the accepted sequence and envelope.
- **Broadcast or attribute receipts to the sender.** Rejected for 0.1: it discloses one principal's activity to another; sender-visible reporting is deferred to an explicit design (open question).
- **Make receipts durable or cross-relay now.** Deferred: persistence, retention, recovery and canonical correlation must be designed together, consistent with [ADR 0002](0002-local-replay-window.md) and [ADR 0003](0003-local-delivery-resume.md).
- **Refuse new receipts when a bound is full, as the replay ledger does.** Not adopted for 0.1: receipts are advisory and non-durable, so oldest-record eviction avoids a new failure mode; the inconsistency is recorded as an open question.
- **Let receipts cancel re-delivery or advance retention.** Rejected: it would turn an unverified assertion into a delivery-guarantee change the relay cannot justify.

## Consequences

Positive: issue 4 gains a documented four-state model, a receipt correlation contract, a state diagram and an explicit non-claim set without changing the 0.1 schemas or existing modes. It composes with replay and delivery, reuses their admission, expiry, digest and framing conventions, and scopes disclosure to the acknowledging principal.

Negative and limiting: nothing is implemented, so the acceptance criteria for conformance tests and any durable/offline profile remain unmet. Receipts are memory-only, bounded, restart-loses and correlation-limited to the delivery retention window; a late or post-eviction receipt fails. A receipt still cannot prove processing or a prior write, and senders learn nothing through this profile. The admission and delivery prerequisites confine it to the local trusted deployment, and no production identity, E2EE or independent review is added. See [../local-receipts.md](../local-receipts.md) for the contract; implementation checkpoints would follow the pattern of [ADR 0003](0003-local-delivery-resume.md).
