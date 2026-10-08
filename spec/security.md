# XEIP security model — design requirements, draft 0.1

**Security status:** draft production requirements with experimental local controls. No production-compliant identity, E2EE, delegated grants or multi-tenant deployment is implemented.

See [threat-model.md](threat-model.md) for the reviewed v0.1 data flows, implementation evidence, fixes and residual risks. That internal review does not establish production compliance or external security approval.

## Adversaries

Untrusted peers and directories; malicious service metadata; spoofed agents or devices; replayed command messages; compromised agent tools; unauthorized observers; unauthorized room joins; flooding, slow readers, oversize payloads; prompt injection through messages, tool outputs or capability descriptions.

## Required production protections (local prototypes are incomplete)

1. **Identity binding:** authenticate each connection and cryptographically or authoritatively bind it to the sender entity ID. A claimed sender string is never proof of identity.
2. **Session authorization:** enforce membership and authorization per sender, recipient, session, operation, and requested capability before delivering or acting.
3. **Transport:** use TLS for any remote connection (loopback-only development exceptions) and existing audited authentication/security mechanisms; do not invent new crypto.
4. **Least privilege:** grants identify subject, resource, actions, expiration, audience and delegation boundaries; default deny; explicit revocation.
5. **Commands and agent tasks:** independently validate command schemas, enforce rate/expense limits and require human consent for high-risk operations; untrusted text cannot grant permission.
6. **Replay and persistence:** implement monotonic/idempotent semantics or deduplication where needed; define retention, expiry, redaction and recovery for stored data.
7. **Discovery:** verify manifests against a trusted origin; avoid metadata leakage and SSRF by constraining endpoint resolution; clients MUST NOT load arbitrary code from manifest fields.
8. **Confidentiality:** selective disclosure and logs, including message and trace data; an AI agent decrypting or processing content is an explicit participant, not invisible to E2EE.

## Explicit v0.1 development exceptions

The shared-token CLI uses one token for all simulated participants, binds to IPv4 or IPv6 loopback, streams over local HTTP/SSE and WebSocket, and keeps subscriptions only in memory. Socket, literal Host and same-origin browser checks limit the local HTTP boundary; byte, nesting, SSE frame and per-stream queue bounds limit individual inputs/streams. This mode **cannot** establish distinct human/agent/machine identities or enforce trustworthy group membership. Aggregate connection/rate limits, replay protection and durable delivery are absent. Treat everyone holding the shared token as mutually trusted. Never expose it behind a public reverse proxy or copy its auth model to production.

The opt-in [local admission profile](local-admission.md) instead gives the trusted in-process owner authority to bind individual bearer credentials to entities and provision closed memberships. It enforces sender/subscriber binding, authorized recipients, credential generation checks after body reads, live revocation/rotation and subscription quotas. It does not provide portable cryptographic identities, remote transport security, durable revocation/recovery, scoped command grants or replay protection. Subscription quotas do not bound all HTTP connections or request rates. [ADR 0001](decisions/0001-local-admission.md) records this limited trust boundary; both modes remain local prototypes.

Admission may select the [local replay extension](local-replay.md) to suppress identical authorized acceptance scopes during a fixed window. It bounds retained digest records, rejects conflicting retries and refuses live eviction under pressure. This reduces repeated relay writes after a lost response, but does not implement durable replay protection, recipient acknowledgment, scoped command execution or exactly-once effects. Credential changes do not clear records; expiry/new factory instances do. A member can exhaust ledger capacity, so global/per-principal request quotas and fair scheduling remain needed.

Either mode may select the [local delivery extension](local-delivery.md) to assign a per-session sequence and let a reconnecting subscriber resume within a bounded in-memory window, with an explicit gap when a cursor predates retention. It stores full envelopes in memory, is lost on restart, and is not a durable queue, recipient receipt or exactly-once guarantee. A member can occupy retention slots until expiry, so broader quotas and fair scheduling remain needed.

## Disclosure

Report vulnerabilities privately as described in [../SECURITY.md](../SECURITY.md). Future security decisions require a design review and negative conformance tests.
