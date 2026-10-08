# XEIP Core — draft 0.1

**Status: experimental, subject to incompatible changes.** This draft defines a basic interoperable envelope, not a completed secure communication standard.

Normative language: MUST, SHOULD, MAY are interpreted as in RFC 2119 / RFC 8174 when in capitals.

## 1. Scope

XEIP is an application-layer interaction model for humans, AI agents, machines, devices and services. It does not prescribe a model vendor, broker, centralized directory, transport, media codec, AI reasoning model or user interface toolkit.

All IDs below are absolute URI strings. Clients MUST treat unknown entities and received manifests as untrusted until verified by their chosen security profile.

## 2. Entities

An entity has:
- `xeip`: protocol version, fixed to `"0.1"` in this draft;
- `id`: stable absolute URI identifier (distinct from display name or session/connection identity);
- `name`: optional presentation label;
- `kinds`: nonempty array containing one or more of `human`, `agent`, `machine`, `service`;
- `endpoints`: zero or more transports and URLs;
- `capabilities`: zero or more capability descriptors.

Kinds express descriptive roles and MUST NOT grant implicit privileges. Machines MAY also offer agent capabilities. Endpoint advertisements MUST NOT be interpreted as authorization to connect or invoke actions.

See `schemas/entity.schema.json`.

## 3. Capabilities and discovery

Each advertised capability has an `id` and optional description or external specification URI. Clients MAY choose supported capabilities and negotiate transport. Discovery is optional and independent of sending messages. The well-known path `/.well-known/xeip.json` is a **proposed XEIP convention**, not a registered Internet standard. See `spec/discovery.md`.

## 4. Sessions

A session is an interaction context (direct or group) with an ID, creation time and zero or more admitted entity identifiers. Sessions are distinct from network sockets: reconnection MUST NOT automatically create a new entity identity. Session membership and admission MUST be enforced by a secure deployment; the local demo relay intentionally does **not** implement this.

## 5. Message envelope

A JSON UTF-8 envelope has:
- `xeip` (required): `"0.1"`
- `id` (required): unique message identifier (absolute URI recommended, e.g. `urn:uuid:...`)
- `kind` (required): `message`, `event`, `command` or `receipt`
- `sender` (required): purported entity URI (MUST be bound to authenticated identity in production)
- `recipient` (optional): target entity URI; omission means session-directed delivery **subject to membership and authorization**
- `session` (required): session URI
- `timestamp` (required): RFC 3339 UTC timestamp
- `body` (required): `{ "contentType": string, "data": any JSON value }`
- `replyTo` (optional): another message ID
- `expiresAt` (optional): RFC 3339 UTC expiry time
- `extensions` (optional): object with reverse-domain keys for negotiated extensions

Clients MUST reject unsupported major/malformed versions rather than silently reinterpreting data. Unknown envelope fields are rejected in 0.1; extensions MUST be negotiated before interpretation. Body data is untrusted input. See `schemas/message.schema.json`.

## 6. Delivery

**This draft only guarantees format interoperability.** A transport MAY acknowledge acceptance without guaranteeing recipient delivery. Receipt messages are application-level evidence, not a guarantee of exactly-once execution. Senders SHOULD avoid processing an expired message. Specific ordering scopes, persistent replay, and idempotency are reserved for v0.2. Commands MUST NOT be executed solely because `kind=command`; authorization and command schema validation remain mandatory.

The development relay delivers to current subscribers of a session only. It does not persist history, authenticate individual senders, validate room membership, encrypt end to end or support delivery guarantees.

## 7. Errors and extensibility

Transport adapters SHOULD expose typed errors (validation, unauthorized, forbidden, unknown-session, unsupported-version, rate-limit, unavailable). Future profiles MUST declare version, required capabilities, security assumptions, optional/required fields, and reference conformance tests. Namespaced extension keys prevent accidental collisions.

## 8. Security

The baseline threat model is in [security.md](security.md). The current examples are **not compliant with production identity requirements** and MUST NOT be used for exposed/untrusted networks.
