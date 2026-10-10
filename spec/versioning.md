# XEIP versioning — draft 0.1

**Status: experimental, subject to incompatible changes.** This note fixes the version-negotiation semantics of the base `"0.1"` wire format. Normative language: MUST, SHOULD, MAY are interpreted as in RFC 2119 / RFC 8174 when in capitals.

## 1. Version identifier

Every envelope, entity and session carries a required `xeip` member naming the wire-format version. In this draft it MUST be the string `"0.1"`.

A version is **syntactically well-formed** when it is a `MAJOR.MINOR` pair: one or more ASCII digits, a single `.`, and one or more ASCII digits (for example `0.1`, `0.2`, `9.9`). Anything else — a missing member, JSON `null`, a non-string, the empty string, `"0"`, `"0.1.0"`, `"v0.1"` — is **malformed**.

`MAJOR.MINOR` is a label, not an ordering, capability set or compatibility promise. Two implementations that both accept `"0.1"` MUST agree on the shape and meaning defined by this draft; sharing an identifier is not evidence of agreement beyond it.

## 2. Supported-version advertisement

Adapters that expose a version boundary advertise the versions they currently accept:

- The reference relay reports `protocolVersions` in the `GET /health` response, e.g. `{"protocolVersions":["0.1"]}`. The field is additive; existing health fields are unchanged.
- The reference TypeScript SDK exports the same list as `XEIP_SUPPORTED_VERSIONS`, and `XEIP_VERSION` names the version it emits.

An advertisement is informative. A client MUST NOT treat it as an authorization, a delivery guarantee or a promise that every advertised version is accepted on every route. Advertising is the only discovery this draft defines; a deployment MAY replace it with an out-of-band agreement.

## 3. Additive versus breaking changes

A change to a wire version is **additive** when an existing reader of that version can still parse and interpret every message it previously could, without changing the meaning of existing fields. A change is **breaking** when it removes or renames a required field, changes a field's meaning or wire type, adds a new top-level member, tightens validation on valid data, or otherwise requires an existing reader to change behavior to stay correct.

- Because the base `"0.1"` schema is **closed** (unknown top-level members are rejected), an additive change within `"0.1"` is confined to the `extensions` object. Any new top-level member, or any other extension of the base schema, is breaking for `"0.1"` and must instead be introduced by a new version that defines it.
- A breaking change MUST NOT be applied silently to an existing version. It requires a new `xeip` value that defines a new, self-contained schema; readers of the old version reject the envelope as unsupported rather than reinterpreting it.
- The `MAJOR` and `MINOR` components are labels, not an ordering (section 1). A new version is selected by its exact `xeip` string; compatibility is never inferred from numeric precedence, so an additive change to a future version is expressed there, not by advancing a digit.
- This draft defines no version other than `"0.1"`; any later version must ship its own schema, fixtures and compatibility statement.

## 4. Unknown fields and extensions

- Unknown top-level envelope members are invalid in `"0.1"` and MUST be rejected with an ordinary invalid-envelope error. Implementations MUST NOT ignore them, because silently dropping a field can change meaning.
- The `extensions` member is the one open object: it MAY carry arbitrary reverse-domain keys. Its values must be JSON values, but the base schema does not validate or interpret them. An extension MUST NOT be interpreted unless it was negotiated in advance by the participants; an unknown extension key is opaque and MUST NOT alter core behavior.
- Extension negotiation itself (which namespaces are understood, how they are agreed, and how they interact with versions) is **not defined by this draft** and remains open. This document only fixes that unnegotiated extension data is inert.

## 5. Unsupported-version error

When a document is otherwise structurally valid but its `xeip` is well-formed and not supported, adapters report a distinguishable error:

- HTTP: status `422` with body `{"error":"unsupported version"}`.
- WebSocket: status `422` with control `{"type":"error","status":422,"error":"unsupported version"}`.

A malformed or absent `xeip` is **not** this error. It is reported like any other structural failure: HTTP `422` with the ordinary invalid-envelope error body, and the WebSocket equivalent. This separation lets a client tell "I speak a different version" apart from "this is not a version I can even parse", without either case being mistaken for authorization (`401`/`403`) or a payload-size failure (`413`).

The distinct error is a layered adapter behavior, not a JSON Schema keyword. `schemas/message.schema.json` pins `xeip` with `const: "0.1"`, so a schema-only consumer reports every other version as schema-invalid with no further distinction; only the validation/adapter layer distinguishes well-formed-unsupported from malformed.

Within that layer, the reference relay and TypeScript SDK classify `xeip` **first**, before the other structural field checks (after the closed-field check). A document that is itself structurally incomplete — say it omits a required `id` or `kind` — but carries a well-formed unsupported `xeip` therefore reports the distinct `"unsupported version"` error, which can precede the missing-field verdict that the same document would otherwise also attract. The Rust core instead deserializes into a fixed struct before it calls `ensure_version`, so for that same incomplete document serde fails on the missing field first and the distinct error is never reached. The two implementations therefore agree when the document is otherwise structurally complete and when the version is the only failure; they differ only in which of two simultaneous structural failures they surface for an incomplete document. Section 5 does not constrain that ordering, so both remain conformant.

## 6. Probing and negotiation

This draft defines exactly two moves: **advertise** (section 2) and **reject** (section 5). A client MAY:

1. Read the relay `GET /health` `protocolVersions` (or use a configured out-of-band agreement) and
2. Select a version it shares, then send envelopes using it.

If it selects a version the peer does not support, the peer returns the distinct unsupported-version error and the client MAY stop, retry with a mutually supported version, or surface the mismatch. There is no in-protocol negotiation, downgrade, version range, content negotiation, capability exchange or partial-compatibility fallback, and this draft does not claim one. A future profile may define such a protocol, but it is out of scope here.

## 7. Relationship to conformance vectors

`conformance/vectors.json` is a structural acceptance oracle shared by JSON Schema, the TypeScript SDK, the relay and the Rust core. Because the `"0.1"` schema pins `xeip` to `"0.1"`, every unsupported version is already schema-invalid, so the shared vectors cannot express "schema-valid envelope with an unsupported version". For a version case the shared vectors therefore assert only the **schema-invalid verdict**: a malformed `xeip` (for example `"0"`, `"0.1.0"`) and a well-formed but unsupported `xeip` (for example `"0.2"`, `"9.9"`) are both simply rejected. The finer distinction — a distinct `"unsupported version"` reason versus a malformed-version reason — is not part of the shared vector oracle. The distinct-version-error cases therefore live in transport/SDK tests (`services/relay/server.test.mjs`, `sdks/typescript/index.test.mjs`), which assert the reason as well as the verdict, rather than in the shared vectors.

## 8. Migration and compatibility

This section describes how a deployment moves from one wire version to the next. It adds no mechanism beyond **advertise** (section 2) and **reject** (section 5); it defines no negotiation.

### 8.1 How a `0.1 → 0.2` change is made

- The base `"0.1"` schema is **closed** (section 3), so an additive change to `"0.1"` cannot add a top-level member. It is carried either:
  - inside the `extensions` object of `"0.1"` as a reverse-domain key (section 4), whose meaning participants agree on out of band; or
  - by a new version, e.g. `"0.2"`, whose schema defines the new member natively.
- A new version is a **self-contained** schema: it restates the `"0.1"` shape and then adds or changes what it needs. Versions are not deltas, and no reader is expected to merge a new version onto an old one.
- A change that is **breaking** for `"0.1"` (removes or renames a required field, changes a field's meaning or wire type, adds a top-level member, or tightens validation) MUST be made only in a new version. It is never applied silently to `"0.1"`.
- A new version is selected by its exact `xeip` string. `MAJOR`/`MINOR` are labels, not an ordering (section 1), so `"0.2"` is introduced by publishing that string — not by arithmetic on `"0.1"` — and this draft does not claim that `"0.2"` is "greater" than `"0.1"` or that every `"0.1"` reader can read it.

### 8.2 Client behavior on an unsupported version

- Discovery is advertise-only: read `GET /health` `protocolVersions` (or a configured out-of-band agreement) and select a version the peer advertises before sending.
- When a peer rejects a well-formed `xeip` as unsupported — `422` with `"unsupported version"` (section 5) — the client SHOULD stop, retry with a mutually supported version, or surface the mismatch. It MUST NOT downgrade in place, guess a version, or resend the same envelope unmodified.
- When `xeip` is instead malformed or absent, the peer reports the ordinary invalid-envelope error (section 5). The client SHOULD treat that as a local bug rather than a version mismatch.

### 8.3 Deprecated-field policy

- A field is **deprecated** in a version once a later version no longer defines it or redefines its meaning.
- Deprecation is announced in the spec and release notes before the removing version ships; removal is breaking and therefore lands only in a new version (section 3).
- While a version still defines a deprecated field, that field MUST keep its original wire type and meaning for the life of the version. A deprecated field is never reinterpreted in place.
- Readers SHOULD continue to accept a deprecated-but-still-defined field. Senders SHOULD stop emitting it once they target the version that removes it. There is no automatic fallback: a closed version that no longer defines the field rejects it as an unknown top-level member.

### 8.4 What this section does not claim

There is no dynamic negotiation or downgrade. The client selects a version before it sends; the peer only accepts or rejects. This draft defines no version range, content negotiation, capability exchange, partial-compatibility fallback, or on-the-wire migration path (section 6). A deployment that needs a staggered rollout does it out of band — for example by running both versions behind one endpoint, or by advertising only the versions it is ready to accept.
