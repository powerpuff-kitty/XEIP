# XEIP — eXtensible Entity Interaction Protocol

[![CI](https://github.com/powerpuff-kitty/XEIP/actions/workflows/ci.yml/badge.svg)](https://github.com/powerpuff-kitty/XEIP/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/Code-Apache--2.0-blue.svg)](LICENSE)
[![Protocol: Experimental](https://img.shields.io/badge/Protocol-0.1%20experimental-orange.svg)](spec/core.md)

**XEIP** is an experimental, open application-layer interoperability protocol for communication among **humans, AI agents, machines, devices, and services**.

> **Status:** Early reference implementation, **not production-ready**. Version 0.1 is an evolving draft; no interoperability or security guarantees are implied.

XEIP describes *who* an entity is, *what* it can do, *how* to reach it, *which session* an interaction belongs to, and *what* authorization is needed. It does **not** replace IP, TLS, WebRTC, MCP, A2A, or an existing federated messenger.

## Try the local proof of concept

Requirements: Node.js >=22. The demo has **no npm dependencies** and binds to loopback only.

```bash
export XEIP_DEV_TOKEN="change-me-to-a-long-random-value"
node services/relay/server.mjs
# In another terminal:
XEIP_DEV_TOKEN="change-me-to-a-long-random-value" node examples/local-relay/demo.mjs
```

Open **http://127.0.0.1:8787/console** to use the browser console. Open two or three tabs, enter the same development token, select a different participant in each tab, and click **Connect** before sending messages. Credentials stay in memory and are not persisted; do not reuse a real secret.

The demo connects three simulated participants (human, AI agent, machine) to an authenticated local HTTP + Server-Sent Events relay, exchanges typed messages, and verifies delivery. It does **not** invoke an LLM, access a real camera, provide multi-user identity authentication, or implement federation.

For separate, locally provisioned entity credentials and closed session membership, run the self-contained admission demo:

```bash
npm run demo:admission
```

It starts an ephemeral loopback relay, generates separate credentials without printing them, exchanges three simulated messages, rejects sender spoofing, and revokes an active participant. [The local admission profile](spec/local-admission.md) documents provisioning, membership, rotation and limits. This is an opt-in local prototype; the shared-token CLI above retains its original behavior.

Run `npm run demo:replay` to additionally suppress identical retries within a bounded window, reject changed-content retries, and check that reconnecting only receives fresh messages. [The local replay profile](spec/local-replay.md) distinguishes acceptance, stream writes and unverified consumption. It keeps no offline queue and provides no exactly-once execution guarantee.

Run `npm run demo:delivery` to assign a per-session sequence, resume a disconnected subscriber from a cursor, receive an explicit gap when older messages aged out, and reject an invalid cursor. [The local delivery profile](spec/local-delivery.md) is in-memory and bounded; a new process or an out-of-window cursor cannot recover the backlog.

Run `npm run demo:receipts` to record an authenticated recipient acknowledgment against a retained delivery, see idempotent duplicate handling, and observe ineligible-recipient and unknown-target denials. [The local receipts profile](spec/local-receipts.md) requires admission and delivery, is bounded and in-memory, and is advisory — never proof of processing or exactly-once execution.

```bash
node --test services/relay/*.test.mjs
npm ci --ignore-scripts      # development tools only; the relay/demo need no install
npm run validate:fixtures    # JSON Schema validation with format checks
npm run typecheck
npm run build:ts
npm run test:ts
cargo test --workspace --all-targets --locked
npm run test:interop         # Rust 1.81+ required; starts its own loopback relay
```

The interoperability test connects the TypeScript SDK and a separate Rust HTTP/SSE example to ephemeral relays in shared-token, local-admission and local-replay modes. It checks the public message fixture and a nested Unicode JSON payload in both directions, including reply correlation, extension preservation and explicit duplicate attempts. See [conformance/README.md](conformance/README.md) for its scope and limitations.

## Architecture

```text
human / AI agent / machine / service
       |       |      |
       +--- XEIP 0.1 manifests, messages, sessions ---+
                          |
        +-----------------+------------------+
        |                 |                  |
   TypeScript SDK     Rust core        Other clients
        |                 |                  |
   HTTP+SSE / WS demo Transport-neutral  Planned: Swift
        |
   Loopback relay (development only)
```

- **Normative draft:** [spec/core.md](spec/core.md), [spec/security.md](spec/security.md), [schemas](schemas/).
- **Identity design (proposed, not implemented):** [spec/identity.md](spec/identity.md).
- **Receipts profile:** [spec/local-receipts.md](spec/local-receipts.md) (opt-in local prototype).
- **Durable delivery design (proposed, not implemented):** [spec/local-durable.md](spec/local-durable.md).
- **Local threat model and review:** [spec/threat-model.md](spec/threat-model.md).
- **Transports:** [HTTP + SSE](spec/transports/http-sse.md) and [WebSocket](spec/transports/websocket.md) local profiles.
- **Roadmap:** [ROADMAP.md](ROADMAP.md) and [GitHub issues](https://github.com/powerpuff-kitty/XEIP/issues).
- **Rust reference models:** [crates/xeip-core](crates/xeip-core).
- **TypeScript SDK:** [sdks/typescript](sdks/typescript).
- **Local relay:** [services/relay](services/relay) (demo only; never expose publicly).
- **Wire fixtures:** [conformance/fixtures](conformance/fixtures).

## Principles

1. **Entity-neutral:** people, AI, services, and devices use one interaction model.
2. **Protocol-first:** versioned schema/specification, independent implementations, shared conformance.
3. **Standards-compatible:** link to MCP tools, A2A agents, WoT things, Matrix rooms, and WebRTC media rather than redefining them.
4. **Secure by design:** identity ≠ display name, advertised capability ≠ permission, and agent delegation must be scoped.
5. **Transport-agnostic:** direct LAN or hosted routing; optional relay, no mandatory proprietary service.
6. **Modular:** basic clients need not implement media, agents, devices, or dashboards.
7. **Observable:** clear delivery, errors, correlation and tracing semantics without exposing sensitive payloads.

## What's actually implemented

| Feature | Status |
| --- | --- |
| 0.1 message/entity/session schemas and draft spec | Initial draft |
| Rust core models and validation | Implemented starter |
| TypeScript models, validation and HTTP/SSE client | Implemented starter |
| Authenticated, loopback HTTP/SSE broadcast demo | Implemented; development only |
| Loopback WebSocket transport (shared routing, bounded queues, close codes, in-memory cursor resume) | Partial v0.2 slice; no durable resume or production hardening; reference Rust client example |
| Per-entity local credentials, closed memberships and live revocation | Opt-in local admission prototype; no portable cryptographic identities |
| Bounded suppression of authenticated retries | Opt-in local replay prototype; fixed window, no durable delivery |
| Bounded per-session sequencing and reconnect resume | Opt-in local delivery prototype; in-memory window, explicit gap signal |
| Bounded per-principal recipient receipts | Opt-in local receipts prototype; in-memory, advisory, not proof of processing |
| Shared Rust/TypeScript/schema validation vectors | Implemented |
| Rust ↔ TypeScript HTTP/SSE fixture exchange | Automated harness; external client review remains planned |
| Local threat model and message/session semantics review | Internal review with regression tests; production controls remain planned |
| Cryptographic identities | Planned |
| Production messaging, offline persistence, groups, federation | Planned |
| MCP/A2A/Matrix bridges, service surfaces and media | Planned |

**Important:** The shared-token demo does not bind senders to distinct identities. The optional admission profile binds bearer credentials to locally provisioned entities and membership, but still requires a trusted workstation and provisioner. Neither mode supports public deployment. See [SECURITY.md](SECURITY.md).

## Scope and compatibility

XEIP is an *interoperability envelope and capability profile*, not a replacement for existing protocols. Agent task adapters should preserve A2A task semantics; tool adapters should preserve MCP authorization; voice/video belongs on established real-time media transports. The implemented core keeps a small number of object types: entity, endpoint, capability, message and session. Grants and their enforcement are planned for v0.2.

We welcome discussion through [issues](https://github.com/powerpuff-kitty/XEIP/issues). Proposed protocol changes should follow [CONTRIBUTING.md](CONTRIBUTING.md) and, for versioned releases, [RELEASING.md](RELEASING.md). Code is Apache-2.0; the specification and examples are licensed under [CC BY 4.0](LICENSE-SPEC).

