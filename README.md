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

```bash
node --test services/relay/*.test.mjs
node tools/validate-fixtures.mjs
npm run typecheck            # requires TypeScript CLI (see package.json)
cargo test --workspace       # requires Rust
```

## Architecture

```text
human / AI agent / machine / service
       |       |      |
       +--- XEIP 0.1 manifests, messages, sessions, grants ---+
                          |
        +-----------------+------------------+
        |                 |                  |
   TypeScript SDK     Rust core        Other clients
        |                 |                  |
   HTTP + SSE demo   Transport-neutral  Planned: Swift
        |
   Loopback relay (development only)
```

- **Normative draft:** [spec/core.md](spec/core.md), [spec/security.md](spec/security.md), [schemas](schemas/).
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
| Cross-language conformance, cryptographic identities | Planned |
| Production messaging, offline persistence, groups, federation | Planned |
| MCP/A2A/Matrix bridges, service surfaces and media | Planned |

**Important:** The demo authenticates clients using one shared development token; it does not bind a message sender to a distinct verified identity. Its in-memory routing is not safe for untrusted participants. See [SECURITY.md](SECURITY.md) before experimenting outside localhost.

## Scope and compatibility

XEIP is an *interoperability envelope and capability profile*, not a replacement for existing protocols. Agent task adapters should preserve A2A task semantics; tool adapters should preserve MCP authorization; voice/video belongs on established real-time media transports. The core deliberately keeps a small number of object types: entity, endpoint, capability, message, session and grant.

We welcome discussion through [issues](https://github.com/powerpuff-kitty/XEIP/issues). Proposed protocol changes should follow [CONTRIBUTING.md](CONTRIBUTING.md). Code is Apache-2.0; the specification and examples are licensed under [CC BY 4.0](LICENSE-SPEC).

