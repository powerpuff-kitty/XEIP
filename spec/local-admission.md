# Local admission profile — xeip.local-admission/0.1

Experimental local reference profile for the v0.2 trust work. It transports XEIP `"0.1"` envelopes and session descriptors through the existing loopback HTTP/SSE routes. The profile version is separate from the envelope version. [ADR 0001](decisions/0001-local-admission.md) records the choice of authoritative local bearer binding.

## Provisioning and trust

The trusted relay owner creates `LocalAdmission({ credentials, sessions })` and passes it to `createRelay({ admission })`. Passing both admission and a shared token is an error. The default CLI still runs the explicitly shared-token development profile; it does not automatically load credential files or select a more privileged fallback.

Run `npm run demo:admission` for a self-contained simulated exchange, sender-spoof rejection and active revocation check. For embedding:

```js
import { randomBytes } from "node:crypto";
import { LocalAdmission } from "./services/relay/admission.mjs";
import { createRelay } from "./services/relay/server.mjs";

const credentials = ["urn:xeip:entity:human", "urn:xeip:entity:agent"]
  .map(entity => ({ entity, token: randomBytes(32).toString("base64url") }));
const admission = new LocalAdmission({ credentials, sessions: [{
  xeip: "0.1", id: "urn:xeip:session:example", mode: "direct",
  members: credentials.map(row => row.entity), createdAt: new Date().toISOString()
}] });
const relay = createRelay({ admission });
relay.listen(8787, "127.0.0.1");
// Give each local client only its own token using a trusted distribution channel.
// Owner operations: admission.revokeCredential(entity), rotateCredential(entity, token), setMembers(session, members).
```

`credentials` is a nonempty array of `{ entity, token }`: distinct absolute entity URI strings and distinct bearer secrets. A token is 43–128 base64url characters (`A-Z`, `a-z`, `0-9`, `-`, `_`). Generate tokens with `randomBytes(32).toString("base64url")`; syntax validation does not prove entropy. There is one current credential per entity. The policy stores token digests and never returns or logs plaintext credentials.

`sessions` is an array of validated 0.1 session descriptors with distinct IDs. Every member must be a registered entity. This profile requires exactly two distinct members for `direct` sessions; `group` sessions may have zero or more members. Empty groups authorize nobody. Neither declared capabilities nor extensions grant rights. The relay owner is the provisioning/admission authority, and peers have no HTTP administration routes.

There are at most 256 registered entities, 256 sessions, and 64 KiB of serialized JSON per session descriptor. The policy copies validated session inputs, so later changes to the caller's arrays/objects cannot change admission.

## Authentication and authorization

Protected HTTP requests use `Authorization: Bearer <entity-token>`. An unrecognized, malformed or revoked token returns 401. Authentication records identify both the entity and the current credential generation; a record remains valid only while that exact credential is current.

- `/events` still requires a session and entity URI query. The entity must equal the authenticated principal, and that principal must be a current member of the session. The stored routing identity is derived from the credential, not the query.
- `/messages` requires `sender` equal to the authenticated principal. That principal must be a current member of the supplied session; an explicit recipient must also be a member. Omitted recipient broadcasts only to authorized member streams in that session. The relay rechecks the credential and membership after reading/validating the body, before any write.
- Unknown sessions, non-membership, spoofed senders/entities and forbidden recipients all return the same 403 `{ error: "forbidden" }`, without exposing session existence or member lists. Public health/static console routes retain the existing local authority/origin gates and do not list credentials or sessions.
- A structurally valid authorized POST may return 202 with zero stream writes if no authorized matching stream is currently connected. Existing byte/depth/frame/queue bounds and expiry checks continue to apply. The profile adds at most 256 open subscriptions per relay and four per authenticated entity; excess authorized subscriptions return 429.

Filtering and stream-write counts use authenticated entity IDs. The JSON body, command kind, receipt kind and advertised capability still carry no execution authority. Member-to-member publication is the full authorization scope of this prototype, not a command grant.

Admission alone forwards repeated IDs. The optional [local replay extension](local-replay.md), selected through the separate `replay` factory option, suppresses identical authorized retries during a bounded in-memory window. It does not change membership policy or provide durable delivery.

## Trusted-owner mutation API

- `revokeCredential(entity)` disables the current credential. New requests/reconnects fail 401, stale in-flight request records fail revalidation, and existing streams authenticated with it are closed.
- `rotateCredential(entity, token)` atomically validates/replaces that entity's credential; the previous token and authentication records become invalid, affected streams close, and the new token may reconnect subject to current membership. Revoked entities remain registered so membership declarations and rotation remain well-defined. Previously issued tokens cannot be reused for another entity or a later rotation during this policy's lifetime.
- `setMembers(session, members)` validates a complete replacement list before changing a known session. Other descriptor fields remain as provisioned. Removed members' streams close, and subsequent POSTs/subscriptions are denied. Re-adding a member never revives a closed stream or a revoked credential.

These methods are in-process owner operations, never authorization granted by message content. Invalid mutation inputs leave the previous policy intact. The policy emits synchronous change notifications so active streams can be checked immediately. All registered `onChange` observers are called even if an earlier observer throws; any observer exceptions are reported to the owner in an `AggregateError` **after the policy update has committed**. Such an error does not roll back the credential or membership update. Close cleanup removes subscription slots; the relay attaches its policy observer while listening, removes it on close, and reattaches if the same native server listens again.

## Limits of this profile

The workstation, provisioner, runtime and secret distribution channel are trusted. Bearer possession provides locally provisioned entity binding; it does not verify a portable entity/device key, display name, manifest, or a message signature. A compromised holder can send as its assigned entity and replay authorized messages. There is no cryptographic identity standard, recovery mechanism, delegated/scoped command grant, durable store, reconnect/replay protection, E2EE or remote TLS deployment profile.

Credential history is bounded to 4096 issued token digests per policy lifetime; rotation that would exceed the bound fails without changing the current credential. Restarting discards revocation/history and sessions; a future durable authority must persist revocation and define recovery. Do not reload a previously revoked token into a new policy instance and interpret that as durable revocation.

Security principles informing the local design: [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) on default denial and checking each request. This profile is still experimental and loopback-only.
