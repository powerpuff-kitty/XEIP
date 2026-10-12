# ADR 0015: Signed organization actions and non-retrying MCP execution

Status: Accepted for experimental implementation, 2026-10-11.

Expose organization operations through a separate versioned signed HTTPS endpoint. Bind the Keycloak principal to the entity-signature key, exact operation/session/recipient and a short envelope deadline. Keep the demonstrator relay's loopback boundary intact. Construct a lightweight store facade per request so its authorization closure retains the exact authenticated principal and signed deadline.

Execute an operator-pinned MCP target only after a newly committed PostgreSQL claim. Carry the approved proposal and stored approver internally into a final identity/policy/trust check at the tool POST boundary. Persist the result and terminal state atomically. Add migration 002 without modifying the historical migration 001 checksum. Current authorized members may inspect a recorded result even after action expiry; claim capabilities never become public endpoint authority.

Use official MCP SDK 2.3.1 with protocol 2026-07-28. Discover the exact protected resource and authorization server, pin the token endpoint and use target-specific client credentials. Supplying only the acquired token to the transport avoids automatic credential-refresh replay. A separate send guard permits one tool POST, including when a peer requests corrective negotiation or interactive continuation. Older protocol fallback and interactive continuation are outside this first workflow.

An attempted POST with no trustworthy result is indeterminate; a valid explicit tool-error result is failed and retained. Neither means effects are safe to repeat. This conservative classification can require operator reconciliation even when the upstream did no work. It prevents a lost response from becoming an unapproved duplicate effect.

This introduces an HTTPS API, OAuth client credentials, result retention and a separate runtime to operate. It does not settle the human approval interface, automated trust distribution, production configuration, retention, reconciliation, artifacts or security acceptance. See the [service contract](../organization-service.md), [execution evidence](../plans/organization-service.md) and [production gates](../../PRODUCTION_READINESS.md).
