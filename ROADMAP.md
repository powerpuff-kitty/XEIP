# XEIP roadmap

This roadmap tracks a **protocol-first** project, not a commitment to ship a hosted chat product. Protocol versions are independent from SDK versions. Features are only "complete" once tested; examples are not production implementations.

## Principles and non-goals

- Unify interaction among humans, agents, machines, and services; keep actor type orthogonal to capabilities.
- Avoid reinventing MCP tools, A2A tasks, Matrix federation, WebRTC media or WoT device semantics.
- Never equate identity with a self-declared display name; capability advertisements are not grants.
- Specification-first, test vectors second, reference implementations third.
- No mandatory cloud or single vendor. Each transport advertises its security and delivery properties.
- Do not promise end-to-end encryption, exactly-once delivery, offline replay or secure agent delegation before they are designed and tested.

## v0.1 — Experimental local messaging foundation (P0, in progress)

Deliverables:
- [x] Repository charter, protocol scope, security disclosure and extension process.
- [x] First draft of entity, endpoint, session, capability and message data models.
- [x] Draft JSON Schemas and wire fixtures.
- [x] Rust core models and TypeScript models/validation.
- [x] Authenticated **loopback-only** HTTP + SSE example relay (shared demo credential, no identity binding).
- [x] Human → agent → machine demonstration and basic node tests.
- [x] CI for Node tests/schema fixtures, TypeScript typecheck and Rust tests.
- [x] JSON Schema engine with enforced formats and shared Rust/TypeScript/relay validation vectors.
- [x] Incremental, bounded SSE framing and a bounded relay subscriber queue.
- [x] Dependency lockfiles and CI checks for Rust 1.81 plus a pinned newer toolchain.
- [x] Separate Rust and TypeScript HTTP/SSE implementations exchange the public message fixture and nested Unicode JSON over the loopback relay; CI is configured to run the harness.
- [ ] **External client interoperability**: an independently authored third-party client exchanges public wire fixtures. The in-repository cross-language test does not establish independent authorship.
- [x] Internal threat-model and message/session semantics review, with documented residual risks, exact URI routing and duplicate-message tests, and regression fixes for HTTP authority, MIME matching, JSON nesting and acceptance responses. See [spec/threat-model.md](spec/threat-model.md); external security review remains future work.

Exit criteria: two independently authored clients exchange the same 0.1 envelopes using public fixtures; automated tests pass; known gaps listed. Local relay is demonstrator **only**.

## v0.2 — Trust and reliable sessions (P0/P1)

- [x] First local admission slice: separately provisioned entity credentials, credential-bound senders/subscriptions, closed session memberships, recipient authorization, owner-controlled rotation/revocation, active stream removal and bounded subscriptions. Includes separate-credential TypeScript/Rust exchange and negative HTTP checks. See [spec/local-admission.md](spec/local-admission.md) and [ADR 0001](spec/decisions/0001-local-admission.md). This local prototype only partially addresses issues #1/#3.
- [x] First delivery slice: opt-in bounded suppression of identical authenticated retries, conflicting-ID rejection, fixed monotonic expiry, refusal to evict live records under pressure, and an explicit duplicate acceptance flag. Includes a delivery-state diagram, lost-response/concurrent/reconnect checks and TypeScript/Rust exchange. See [spec/local-replay.md](spec/local-replay.md) and [ADR 0002](spec/decisions/0002-local-replay-window.md). Issue #4 remains incomplete: recipient receipts, durable ordering and persistence are pending.
- [x] Second delivery slice: opt-in per-session sequencing, transport framing of the sequence (`seq`/SSE `id`) and bounded reconnect resume by cursor with an explicit gap signal, across HTTP/SSE and WebSocket. See [spec/local-delivery.md](spec/local-delivery.md) and [ADR 0003](spec/decisions/0003-local-delivery-resume.md). A bounded per-principal **recipient receipt** prototype (`xeip.local-receipts/0.1`) is implemented over HTTP and WebSocket; see [spec/local-receipts.md](spec/local-receipts.md) and [ADR 0005](spec/decisions/0005-local-receipts.md). Issue #4 remains incomplete: retention is in-memory, receipts are advisory and unverified for processing, and cross-relay/durable ordering is pending.
- Cryptographically verifiable entity/device identities and key rotation; authenticated session admission. Implemented reference slices: self-certifying key-ID codec (JS/Rust/TS), detached Ed25519 signed envelopes with an opt-in relay enforcement and an SDK↔relay e2e test, signed key documents with chain/rollback/fork and fail-closed trust anchors, signed revocation/status documents, and bounded device-rotation statements (JS + Rust, shared conformance vectors); the relay resolves and revokes envelope `kid`s via trusted key documents. Design in [spec/identity.md](spec/identity.md) / [spec/identity-keys.md](spec/identity-keys.md); library decision in [ADR 0007](spec/decisions/0007-crypto-dependencies.md). Still open: root-rotation rules/recovery, status distribution and live-stream termination, directory discovery, and independent review.
- Per-entity credentials, signed or authenticated envelopes as required, scoped grants, revocation and agent delegation.
- Clear direct/group sessions, membership, per-member filtering, presence and access control.
- Delivery receipts, ordering scopes, idempotency/replay protection, reconnect/resume and bounded durable queue design. A first restart-surviving durable-store slice is implemented behind [spec/local-durable.md](spec/local-durable.md) and [ADR 0006](spec/decisions/0006-durable-delivery.md); compaction, multi-process locking, durable receipts and at-rest encryption remain pending.
- WebSocket transport: first local slice with a dependency-free `/ws` profile, bounded outbound queues, size quotas, ping/pong, close codes and in-memory cursor resume sharing the HTTP/SSE routing/admission path. Includes a reference Rust client example. See [spec/transports/websocket.md](spec/transports/websocket.md). Issue #7 remains incomplete: durable reconnect, compression and production hardening are pending.
- Opt-in request-rate and connection/subscription limits (`xeip.local-limits/0.1`) with `Retry-After`, addressing the residual fair-scheduling gap. See [spec/local-limits.md](spec/local-limits.md) and [ADR 0008](spec/decisions/0008-local-limits.md). It is advisory local limiting, not production rate limiting.
- Cross-language conformance harness and fuzz/security tests.

Exit criteria: no sender spoofing or cross-session leakage in a multi-tenant harness; documented security review; reconnect scenarios pass. Do not publish a production relay beforehand.

## v0.3 — Capability discovery and autonomous interaction (P1)

- Verified discovery manifests, privacy-preserving capability visibility and transport negotiation.
- A2A task adapter, MCP tools/resources adapter and independently versioned semantic profiles.
- Events and telemetry, OpenTelemetry mapping, presence/attention/battery hints.
- XEIP Surface declarative view profile for Monitor.
- Human handoff, approvals, budget limits and auditable tasks in Agent Room reference integration.

Exit criteria: independent Monitor and Agent Room examples consume one shared manifest without bespoke coupling.

## v0.4 — Media, devices and distributed delivery (P2)

- WebRTC signaling profile for audio, video and screen sharing (media itself remains on WebRTC).
- WoT and MQTT device adapter for SEEN-0; IoT power/availability hints and delegated gateway identities.
- Offline/edge routing, peer discovery and optional broker/relay adapter.
- Optional secure group transport (investigate Matrix and MLS/SLIM interop).

## v1.0 — External interoperability and governance (P3)

- Stable normative definitions, compatibility guarantees, version negotiation and migration guides.
- Conformance suite run against independent Rust, JS/TS and third-party implementations.
- Threat modeling and independent review for authentication, authorization, federation and data retention.
- Published SDK releases, security advisories, extension registry and governance decisions.
- Optional federation with no XEIP-specific hosted central dependency.


## GitHub issue map

The live issue tracker is authoritative; completion requires passing acceptance tests, not merely merging code. A checked item below means the described local prototype slice is implemented and tested; its linked GitHub issue stays **open** until every acceptance criterion (often including independent review, durability or production hardening) is met.

| Stage | Open follow-up work |
| --- | --- |
| v0.1 foundation hardening | [#2 version/spec semantics](https://github.com/powerpuff-kitty/XEIP/issues/2), [#6 threat model and fuzzing](https://github.com/powerpuff-kitty/XEIP/issues/6) |
| v0.2 trust and sessions | [#1 identities](https://github.com/powerpuff-kitty/XEIP/issues/1), [#3 session admission](https://github.com/powerpuff-kitty/XEIP/issues/3), [#4 delivery](https://github.com/powerpuff-kitty/XEIP/issues/4), [#7 WebSockets](https://github.com/powerpuff-kitty/XEIP/issues/7) |
| v0.3 integrations | [#11 discovery](https://github.com/powerpuff-kitty/XEIP/issues/11), [#12 A2A](https://github.com/powerpuff-kitty/XEIP/issues/12), [#13 MCP](https://github.com/powerpuff-kitty/XEIP/issues/13), [#14 presence](https://github.com/powerpuff-kitty/XEIP/issues/14), [#15 Surface](https://github.com/powerpuff-kitty/XEIP/issues/15), [#16 Agent Room](https://github.com/powerpuff-kitty/XEIP/issues/16), [#17 telemetry](https://github.com/powerpuff-kitty/XEIP/issues/17), [#18 Swift](https://github.com/powerpuff-kitty/XEIP/issues/18) |
| v0.4 and later | [#19 media](https://github.com/powerpuff-kitty/XEIP/issues/19), [#20 devices](https://github.com/powerpuff-kitty/XEIP/issues/20), [#21 durability](https://github.com/powerpuff-kitty/XEIP/issues/21), [#23 federation](https://github.com/powerpuff-kitty/XEIP/issues/23), [#24 stable releases](https://github.com/powerpuff-kitty/XEIP/issues/24) |

Closed foundation issues (acceptance criteria met; see each issue's closing comment for evidence): [#5 JSON Schema conformance](https://github.com/powerpuff-kitty/XEIP/issues/5), [#8 Rust strict validation](https://github.com/powerpuff-kitty/XEIP/issues/8), [#9 TypeScript SSE hardening](https://github.com/powerpuff-kitty/XEIP/issues/9), [#10 reproducible CI](https://github.com/powerpuff-kitty/XEIP/issues/10).

## Issue conventions

Priorities: **P0 critical foundation**, **P1 next iteration**, **P2 later**, **P3 future research**. Each issue should include acceptance criteria, tests and dependency links where applicable. For protocol change proposals, document backward-compatibility and security implications.

## Suggested integrations

- Monitor: service discovery, health, telemetry, declarative operational surfaces.
- Agent Room: presence, task delegation and human approval.
- NEKON: human/agent/device conversation client and media.
- SEEN-0: machine identity, sensors and events (not camera-control semantics).
- SEIREI: service/resource discovery and data subscriptions.
