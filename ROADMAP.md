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
- [ ] **Independent implementation conformance**, including schema validation against a JSON Schema engine.
- [ ] Threat-model review and message/session canonical semantics review.

Exit criteria: two independently authored clients exchange the same 0.1 envelopes using public fixtures; automated tests pass; known gaps listed. Local relay is demonstrator **only**.

## v0.2 — Trust and reliable sessions (P0/P1)

- Cryptographically verifiable entity/device identities and key rotation; authenticated session admission.
- Per-entity credentials, signed or authenticated envelopes as required, scoped grants, revocation and agent delegation.
- Clear direct/group sessions, membership, per-member filtering, presence and access control.
- Delivery receipts, ordering scopes, idempotency/replay protection, reconnect/resume and bounded durable queue design.
- WebSocket transport profile, backpressure, size quotas and error codes.
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

The live issue tracker is authoritative; completion requires passing acceptance tests, not merely merging code.

| Stage | Open follow-up work |
| --- | --- |
| v0.1 foundation hardening | [#2 core semantics](https://github.com/powerpuff-kitty/XEIP/issues/2), [#5 schema conformance](https://github.com/powerpuff-kitty/XEIP/issues/5), [#6 threat model](https://github.com/powerpuff-kitty/XEIP/issues/6), [#8 Rust validation](https://github.com/powerpuff-kitty/XEIP/issues/8), [#9 SSE hardening](https://github.com/powerpuff-kitty/XEIP/issues/9), [#10 reproducible CI](https://github.com/powerpuff-kitty/XEIP/issues/10) |
| v0.2 trust and sessions | [#1 identities](https://github.com/powerpuff-kitty/XEIP/issues/1), [#3 session admission](https://github.com/powerpuff-kitty/XEIP/issues/3), [#4 delivery](https://github.com/powerpuff-kitty/XEIP/issues/4), [#7 WebSockets](https://github.com/powerpuff-kitty/XEIP/issues/7) |
| v0.3 integrations | [#11 discovery](https://github.com/powerpuff-kitty/XEIP/issues/11), [#12 A2A](https://github.com/powerpuff-kitty/XEIP/issues/12), [#13 MCP](https://github.com/powerpuff-kitty/XEIP/issues/13), [#14 presence](https://github.com/powerpuff-kitty/XEIP/issues/14), [#15 Surface](https://github.com/powerpuff-kitty/XEIP/issues/15), [#16 Agent Room](https://github.com/powerpuff-kitty/XEIP/issues/16), [#17 telemetry](https://github.com/powerpuff-kitty/XEIP/issues/17), [#18 Swift](https://github.com/powerpuff-kitty/XEIP/issues/18) |
| v0.4 and later | [#19 media](https://github.com/powerpuff-kitty/XEIP/issues/19), [#20 devices](https://github.com/powerpuff-kitty/XEIP/issues/20), [#21 durability](https://github.com/powerpuff-kitty/XEIP/issues/21), [#23 federation](https://github.com/powerpuff-kitty/XEIP/issues/23), [#24 stable releases](https://github.com/powerpuff-kitty/XEIP/issues/24) |

## Issue conventions

Priorities: **P0 critical foundation**, **P1 next iteration**, **P2 later**, **P3 future research**. Each issue should include acceptance criteria, tests and dependency links where applicable. For protocol change proposals, document backward-compatibility and security implications.

## Suggested integrations

- Monitor: service discovery, health, telemetry, declarative operational surfaces.
- Agent Room: presence, task delegation and human approval.
- NEKON: human/agent/device conversation client and media.
- SEEN-0: machine identity, sensors and events (not camera-control semantics).
- SEIREI: service/resource discovery and data subscriptions.
