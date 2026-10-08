# XEIP Core — draft 0.1

**Status: experimental, subject to incompatible changes.** This draft defines a basic interoperable envelope, not a completed secure communication standard.

Normative language: MUST, SHOULD, MAY are interpreted as in RFC 2119 / RFC 8174 when in capitals.

## 1. Scope

XEIP is an application-layer interaction model for humans, AI agents, machines, devices and services. It does not prescribe a model vendor, broker, centralized directory, transport, media codec, AI reasoning model or user interface toolkit.

Entity, session, message and correlation identifiers are absolute URI strings. Capability IDs use the lowercase ASCII token syntax in their schema, such as `xeip.message`. Clients MUST treat unknown entities and received manifests as untrusted until verified by their chosen security profile.

Identifier fields (`id`, `sender`, `recipient`, `session`, `replyTo`, session members) are opaque, case-sensitive URI strings. Reference implementations compare the exact strings; they MUST NOT silently lowercase, percent-decode, resolve or otherwise normalize identifiers before routing or checking membership. For example, `urn:xeip:entity:agent` and `urn:xeip:entity:%61gent` select different identifiers. URI syntax validation proves neither ownership nor that an endpoint is safe to contact. A future identity profile may specify canonical identifier construction, but must also specify how that representation is bound to authenticated identity.

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

A session descriptor declares an interaction context with `id`, `mode`, `members`, and `createdAt`. `members` is a list of distinct entity URI strings and may be empty. `direct` and `group` are descriptive mode labels in the 0.1 schema; neither imposes a member-count constraint or an admission policy. A descriptor is a claim about participants, not evidence that anyone was admitted. Secure direct/group cardinality and membership changes belong to the v0.2 admission profile.

Sessions are distinct from network sockets: reconnection MUST NOT automatically create a new entity identity. Session membership and admission MUST be enforced by a secure deployment. The shared-token local relay has no session-descriptor endpoint, does not consume `mode` or `members`, and does not create an admitted session when a client subscribes. Its session map only groups currently open streams by their supplied session URI. The separately versioned [local admission profile](local-admission.md) consumes owner-provisioned descriptors and enforces membership and direct-session cardinality without changing this base schema.

## 5. Message envelope

A JSON UTF-8 envelope has:
- `xeip` (required): `"0.1"`
- `id` (required): unique message identifier, an absolute URI (e.g. `urn:uuid:...`); senders MUST assign a new ID to each new logical message
- `kind` (required): `message`, `event`, `command` or `receipt`
- `sender` (required): purported entity URI (MUST be bound to authenticated identity in production)
- `recipient` (optional): target entity URI; omission means session-directed delivery **subject to membership and authorization**
- `session` (required): session URI
- `timestamp` (required): RFC 3339 UTC timestamp with a `T` or `t` date/time separator and uppercase `Z`; whitespace separators and numeric offsets are rejected
- `body` (required): `{ "contentType": string, "data": any JSON value }`
- `replyTo` (optional): another message ID used for correlation; it does not prove that the original exists, was received, or authorized this response
- `expiresAt` (optional): UTC expiry time using the same wire format as `timestamp`
- `extensions` (optional): object with reverse-domain keys for negotiated extensions

This draft accepts exactly the string `"0.1"`; clients MUST reject any other or malformed version rather than silently reinterpreting data. Unknown envelope fields are rejected in 0.1; extensions MUST be negotiated before interpretation. Extension keys should use reverse-domain names to avoid collisions, but the base schema accepts arbitrary object keys and does not validate negotiation. Optional strings may be omitted; explicit JSON null is invalid for those fields. `body.data` must be present and may be any JSON value, including null. `body.contentType` is a nonempty label of at most 255 Unicode code points; the base schema does not validate its media-type grammar or interpret the data. It is separate from the HTTP request's `Content-Type`. Body data is untrusted input. See `schemas/message.schema.json`.

`timestamp` is a sender-supplied time claim, not an ordering, freshness or identity proof. Fractional seconds have arbitrary decimal precision; a structurally valid `23:59:60` leap-second form is accepted without checking a historical leap-second table. Structural validation checks calendar/time syntax, not relations between `timestamp`, `expiresAt`, `createdAt` or message IDs. Transport/application profiles must define their own clock and expiry policy.

The wire format is JSON UTF-8, not a canonical signing serialization. Property order, insignificant whitespace and number formatting may change during parsing/reserialization; no current implementation provides canonical bytes, hashing or signing. Applications requiring interoperable exact integers should keep JSON numeric values within `[-9007199254740991, 9007199254740991]` and use a negotiated string representation for larger values. The base schema accepts other JSON numbers, so it does not guarantee lossless numeric round trips through JavaScript. [RFC 8259 §6](https://www.rfc-editor.org/rfc/rfc8259#section-6) describes this interoperability range. Duplicate JSON object names and unpaired surrogate escapes are unsuitable for cross-language exchange: JavaScript parsing keeps the last duplicate value and can represent lone surrogates, while Rust rejects duplicate known model fields and invalid surrogate pairs. The reference relay does not detect either of those cases; applications must avoid them, and a future signing/security profile must define unambiguous parsing.

## 6. Delivery

**This draft only guarantees format interoperability within implementation resource limits.** A transport MAY acknowledge acceptance without guaranteeing recipient delivery. `message`, `event`, `command` and `receipt` classify an envelope; they do not define an executable command schema, automatic acknowledgments or a receipt body. Receipt messages are application-level evidence, not a guarantee of exactly-once execution. Receivers SHOULD avoid processing an expired message. Specific ordering scopes, persistent replay, and idempotency are reserved for v0.2. Commands MUST NOT be executed solely because `kind=command`; authorization and command schema validation remain mandatory.

The shared-token development relay delivers to current subscribers of a session only. It does not persist history, authenticate individual senders, validate room membership, encrypt end to end or support delivery guarantees. The opt-in local admission profile adds credential-bound routing and membership authorization; persistence and delivery guarantees remain absent.

In that baseline transport, a specified recipient selects every open connection with that entity URI in the selected session. Without a recipient, every open connection in the selected session is eligible, including connections claiming the sender's URI. Multiple connections for one entity count separately. Reposting an ID is forwarded again unless the separately selected [local replay profile](local-replay.md) suppresses an identical authenticated acceptance within its bounded window. No profile performs an original-message lookup for `replyTo`. A structurally valid authorized message for a session with no subscribers can be accepted with zero stream writes. Connection cleanup removes an empty routing bucket; it is not a durable session deletion. The separately selected [local delivery profile](local-delivery.md) adds in-memory per-session sequencing and bounded reconnect resume without durable persistence. See [transports/http-sse.md](transports/http-sse.md) and [transports/websocket.md](transports/websocket.md) for acceptance, expiry and resource limits.

## 7. Errors and extensibility

Transport adapters SHOULD expose typed errors (validation, unauthorized, forbidden, unknown-session, unsupported-version, rate-limit, unavailable). Future profiles MUST declare version, required capabilities, security assumptions, optional/required fields, and reference conformance tests. Namespaced extension keys prevent accidental collisions.

## 8. Security

Production requirements are in [security.md](security.md); the current data flows, threats, verified controls and residual risks are in [threat-model.md](threat-model.md). The current examples are **not compliant with production identity requirements** and MUST NOT be used for exposed/untrusted networks.
