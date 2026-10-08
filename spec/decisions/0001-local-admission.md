# ADR 0001: Opt-in local credential binding and session admission

Status: accepted for the experimental local reference implementation under the repository implementation task. Date: 2026-10-09. This decision does not approve production deployment or mark identity work complete.

## Context

[Issue 1](https://github.com/powerpuff-kitty/XEIP/issues/1) requires credential-bound senders and revocation, while [issue 3](https://github.com/powerpuff-kitty/XEIP/issues/3) requires authenticated session admission and recipient filtering. The shared-token example intentionally provides neither. The existing TypeScript and Rust HTTP/SSE participants already send bearer headers and 0.1 envelopes; a local authorization layer can exercise these requirements without choosing a portable identity/key/discovery standard.

## Decision

Add the explicit `xeip.local-admission/0.1` profile using administrator-provisioned, per-entity bearer credentials and closed session membership. Configure it through the in-process relay factory; peers cannot create sessions, add members or rotate credentials through HTTP. Credential possession binds a connection/request to the entity the trusted operator registered. This is authoritative local binding, not a cryptographic entity/device identity proof.

Exactly one authentication mode is selected at relay construction: shared demo token or admission policy. No fallback between them is allowed. The admission profile reuses the 0.1 wire envelope and `/events` and `/messages` routes; its security semantics are separately versioned and advertised by health. Subscription filtering derives the entity from the credential. Unknown/unauthorized sessions and recipients produce the same generic 403 response.

Revocation and rotation invalidate existing authentication records, close affected streams, and are rechecked after asynchronous request-body reads. Session membership changes close streams that are no longer authorized. Administrator APIs validate and copy their inputs before mutation. Fixed credential/session/subscription bounds constrain this local prototype; rate limiting, command grants and durable delivery remain future work.

## Alternatives

- Replace shared-token behavior globally: rejected because the runnable 0.1 demo and its interoperability tests are an explicit development profile.
- Start with signed envelopes or a new challenge/response protocol: deferred until entity/device identities, trust roots, rotation/recovery and canonical parsing have a reviewed interoperable design. No custom cryptography will be introduced for this slice.
- Document admission without executing it: insufficient to prove sender-spoofing, cross-session and live revocation behavior.

## Consequences

The operator and workstation are trust roots. Stolen credentials impersonate their assigned entity. Envelope IDs and JSON are not signed; there is no replay protection, delegation, hosted TLS profile or third-party verification. A member may exchange opaque data with other members; membership is not permission to execute a command. The profile stays loopback-only and is tested alongside, not substituted for, the original demo.

The current rules and examples are maintained in [../local-admission.md](../local-admission.md). Implementation checkpoints are in [../plans/local-admission.md](../plans/local-admission.md).
