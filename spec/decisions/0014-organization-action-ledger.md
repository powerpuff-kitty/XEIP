# ADR 0014: Transactional organization action approvals

Status: Accepted for experimental implementation, 2026-10-11. User authorized continued production-readiness work for one self-hosted organization using Keycloak, with a target of 500 users, 200 agents and 120 action requests/minute.

Use a separate PostgreSQL action ledger for immutable canonical action content, short-lived explicit approval grants, single-use execution claims and atomic audit events. Pin `pg` 8.23.1 and a PostgreSQL 18.6 test image by digest. Row locks and transactional state/audit changes implement the approval contract; database migration/runtime roles must be separated in deployment. The local relay's segmented transport log remains a demonstrator and is not silently promoted to an action database.

PostgreSQL provides the transaction and recovery machinery this action workflow needs. It adds an operated service, migration/backup responsibilities and client deadlines. This choice is based on the consistency contract and local failure drills, not a capacity claim or a complete comparative benchmark. The selected rollout workload still needs combined provider/database/MCP measurements.

An approval binds the exact request digest and the policy revision. A separate subject and entity must approve. Consent expires no later than the human token or action, and current local membership/key trust is required when claiming. Do not retain the human bearer token: disabling provider login does not automatically revoke an already-issued grant. Explicit action/membership/key revocation is required until a centralized grant-revocation mechanism exists.

Only a successfully committed new claim can initiate an effect. Lost commit responses are unavailable, never permission to execute; authorized status inspection remains available after action expiry or policy changes. An executing/indeterminate action is never automatically retried. Operator reconciliation and upstream idempotency are necessary for ambiguous external effects.

See [action contract](../organization-actions.md), [implementation evidence](../plans/organization-actions.md) and [production gates](../../PRODUCTION_READINESS.md). HTTP/signature enforcement, the MCP bridge, runtime least privilege, retention and production recovery acceptance remain separate requirements.
