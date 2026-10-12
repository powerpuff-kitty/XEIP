# ADR 0016: isolated organization runtime and operational boundaries

Status: accepted for experimental implementation, 11 October 2026.

The signed action service needs a deployable process without extending the local demonstrator's network permissions. The selected profile is one organization, one active application process, self-hosted Keycloak, PostgreSQL and pinned internal MCP tools.

Use a dedicated direct-TLS executable with a strict protected-file configuration. Keep PostgreSQL 18 migration/owner credentials in a separate maintenance command and require a direct runtime login without role memberships or elevated object grants. Startup inspects schema, durability and effective privileges, verifies signed trust/checkpoints and probes pinned provider discovery/JWKS/introspection before exposing the action listener. Normal startup never performs DDL.

Track actual controller workers beyond HTTP response lifetime. Drain refuses new work and keeps the database available for accepted outcomes. Reserve a bounded cancellation/completion interval; force a nonzero process exit when work cannot settle. An abandoned consumed claim requires reconciliation and never automatic replay. Owner-only SIGHUP reloads signed trust atomically; subject/policy/target/secret/certificate changes require restart.

Expose bounded aggregate metrics through a separate loopback TLS listener with a dedicated bearer. Redacted logs use generated request IDs and fixed labels, not action contents or raw errors. Database audit remains authoritative for ambiguous outcomes. The initial distribution is code plus templates and runbooks; it is not an independently certified deployment or supported artifact release.

Consequences: explicit owner maintenance and TLS certificate operations are required. Role composition, PostgreSQL upgrades, reverse-proxy trust and multi-process deployment each need a new compatibility/security decision. The user's ≤2-second P95, ≤1-hour restore and no-acknowledged-action-loss goals still require measured capacity and the selected storage/failover drill; a local logical dump is insufficient for primary-storage-loss recovery. Human PKCE/approval UX, retention, independent security review and artifact/pilot acceptance remain open.

Contracts: [runtime](../organization-runtime.md), [operations](../../services/organization/OPERATIONS.md), [execution record](../plans/organization-runtime.md).
