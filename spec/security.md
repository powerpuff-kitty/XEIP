# XEIP security model — design requirements, draft 0.1

**Security status:** architectural guidance only. No production-compliant identity, E2EE, delegated grants or multi-tenant routing is implemented in v0.1.

## Adversaries

Untrusted peers and directories; malicious service metadata; spoofed agents or devices; replayed command messages; compromised agent tools; unauthorized observers; unauthorized room joins; flooding, slow readers, oversize payloads; prompt injection through messages, tool outputs or capability descriptions.

## Required production protections (not yet implemented)

1. **Identity binding:** authenticate each connection and cryptographically or authoritatively bind it to the sender entity ID. A claimed sender string is never proof of identity.
2. **Session authorization:** enforce membership and authorization per sender, recipient, session, operation, and requested capability before delivering or acting.
3. **Transport:** use TLS for any remote connection (loopback-only development exceptions) and existing audited authentication/security mechanisms; do not invent new crypto.
4. **Least privilege:** grants identify subject, resource, actions, expiration, audience and delegation boundaries; default deny; explicit revocation.
5. **Commands and agent tasks:** independently validate command schemas, enforce rate/expense limits and require human consent for high-risk operations; untrusted text cannot grant permission.
6. **Replay and persistence:** implement monotonic/idempotent semantics or deduplication where needed; define retention, expiry, redaction and recovery for stored data.
7. **Discovery:** verify manifests against a trusted origin; avoid metadata leakage and SSRF by constraining endpoint resolution; clients MUST NOT load arbitrary code from manifest fields.
8. **Confidentiality:** selective disclosure and logs, including message and trace data; an AI agent decrypting or processing content is an explicit participant, not invisible to E2EE.

## Explicit v0.1 development exceptions

The example relay uses one shared token for all simulated participants, binds to `127.0.0.1`, streams over local HTTP/SSE, and keeps subscriptions only in memory. It **cannot** establish distinct human/agent/machine identities and **cannot** enforce trustworthy group membership. Treat everyone holding the demo token as mutually trusted. Never expose it behind a public reverse proxy or copy its auth model to production.

## Disclosure

Report vulnerabilities privately as described in [../SECURITY.md](../SECURITY.md). Future security decisions require a design review and negative conformance tests.
