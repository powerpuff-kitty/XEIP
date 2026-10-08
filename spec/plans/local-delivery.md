# Local delivery implementation checkpoints

Scope: implement ADR 0003 as an opt-in, in-memory sequencing and resume extension of the existing relay transports. Preserve all existing modes, wire schemas and fixtures. No publication, deployment or issue closure is part of this slice.

1. Specify the profile: sequence assignment point, transport framing, cursor semantics, gap signaling, retention bounds, ordering scope and explicit non-goals. Verify compatibility with the replay profile and both transports.
2. Write a private bounded `DeliveryLog` with per-session entries, fixed monotonic expiry, per-session and least-recently-used session bounds, and copied limits. Cover monotonic clock, gap detection, cross-session independence and invalid configuration with failing-then-passing unit tests.
3. Wire sequencing into the shared `routeMessage` path before any write, thread it through HTTP acceptance, SSE `id:` framing and WebSocket controls, and add resume for `Last-Event-ID`/`after` and `subscribe.after`. Reuse membership, recipient and quota checks for the backlog.
4. Add real HTTP and WebSocket tests for sequence assignment, no-duplicate resume, gap signaling, recipient filtering, malformed/unsupported cursors and cross-transport live delivery after resume. Add a runnable simulated disconnect/resume demo and CI invocation.
5. Review for ordering, retention, lifecycle and authorization defects; update roadmap/security/transport truth and verify Node 22 plus both supported Rust toolchains.

Done: accepted messages receive a per-session sequence exposed only in framing; a resuming subscriber receives retained newer messages exactly once; a cursor outside retention yields an explicit gap; invalid cursors and missing-profile cursors are rejected; and no durable or exactly-once claim is made.

Rollback: omit the delivery option and both transports retain their prior behavior with no `id:` line, no `seq` and no resume. Replay-independent. No persistent data or migration is introduced. Issue 4 remains incomplete until reversible durable queues, receipts, ordering across relays and persistence criteria are met.

Execution result, 2026-10-09: all five checkpoints implemented locally. The `DeliveryLog`, HTTP and WebSocket resume paths, and demo are covered by unit and transport tests. Node 22 passes the combined relay/schema/SDK suites including delivery and resume cases; Rust 1.81.0 and 1.94.1 retain their passing core/example and HTTP/SSE interoperability tests; schema validation, typecheck/build, formatting and Clippy pass. Work remains experimental and uncommitted at time of writing; no release, deployment or issue closure is implied.
