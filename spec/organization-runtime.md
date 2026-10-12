# Self-hosted organization runtime

Implementation contract for the service built in [organization-service.md](organization-service.md). Target one organization with one active service process, self-hosted Keycloak, PostgreSQL and operator-controlled MCP endpoints. The experimental runtime is implemented; its [execution record](plans/organization-runtime.md) and [operations guide](../services/organization/OPERATIONS.md) describe verification and remaining deployment gates.

## Configuration and startup

Provide a dedicated executable organization service, separate from the demonstrator relay. Read an explicit operator-owned JSON configuration file with an exact, versioned schema. Reject unknown fields, insecure fixture flags, embedded URL credentials, unbounded deadlines and permissive private-file modes. Secrets and TLS private keys come from protected files, never command arguments, query strings or logs. Validate the complete configuration before opening a listener.

Configuration names the canonical HTTPS origin and bind address, TLS certificate/key, pinned Keycloak issuer/audiences/clients and subject mappings, policy sessions and target revisions, pinned target-specific MCP OAuth metadata/endpoints, database connection/TLS settings, persistent trust directory, and signed trust-provisioning file. Require verified TLS for remote provider/MCP/database connections. Do not use development Keycloak or public fixture keys in deployment examples.

Keep schema migration separate from normal startup. An owner applies known migrations through an explicit maintenance command. A runtime database role has schema usage, required action select/insert/update privileges, append-only audit select/insert plus its identity sequence, and read-only migration inspection. It must not own schema/tables, create/alter/drop objects, truncate records, update/delete audit rows or modify migration history. Verify those boundaries with a real restricted PostgreSQL role; a check using an owner role does not satisfy this gate.

Before listening, verify database schema checksums/version and durability settings, required runtime permissions, signed trust provisioning/checkpoint health, TLS material, and provider discovery/JWKS availability. Readiness must reflect draining state and current critical dependency health without exposing configuration or credentials. Liveness remains independent from dependency availability. Startup failures produce stable redacted error codes and exit unsuccessfully.

## Process lifecycle and trust refresh

On termination, stop accepting work, make readiness unavailable, close idle connections and give accepted work a bounded drain period. Keep the database available while workers record completed or indeterminate effects. At the drain deadline, cancel remaining requests and bound process shutdown. A claimed action abandoned by process death remains consumed and requires reconciliation; shutdown must never queue a replay.

Reload verified trust provisioning through an owner-only local signal or equivalent local administration command. Verify and persist a complete replacement atomically before activating it; preserve the current valid policy on a validation failure, and fail closed if trust persistence becomes uncertain. Policy, subject mappings and endpoint/secret changes initially require a controlled drain/restart so their revisions and in-flight ownership remain clear.

## Operations and evidence

Emit structured startup, shutdown, request-outcome and dependency-health events with random correlation IDs, operation names, safe error codes, state and elapsed time. Never log bearer/client secrets, signing material, request arguments/results or raw upstream/database exceptions. Expose aggregate counters, active-work gauges and latency histograms through a separate protected management surface. Bound cardinality: subjects, action IDs, tool arguments and arbitrary request paths are not metric labels.

Provide configuration validation, migration, backup/restore, upgrade/rollback, trust refresh, key/secret rotation and ambiguous-action reconciliation runbooks. Configure alerts for readiness failure, database errors, expired trust, stalled/indeterminate actions and failed SLOs. The restore target is ≤1 hour; no acknowledged-action loss must be demonstrated on the selected storage and backup configuration. Local fixtures prove behavior, not operator infrastructure reliability.

Keep container/artifact hardening and human PKCE/approval UX as subsequent explicit release gates. A supported release needs those gates plus the real target, independent security review, named owners and pilot acceptance recorded in [production readiness](../PRODUCTION_READINESS.md).

## Asynchronous trust reload

The organization launcher awaits `EntityTrustPolicy.updateAsync` for SIGHUP. A single disposable worker prepares public signed provisioning under a 30-second deadline; the owner thread retains exclusive checkpoint persistence and atomic activation. Overlapping reloads reject. Reads during preparation use the current verified policy; live provider checks and monotonic status expiry still apply. Close, cancellation, expiry at commit, invalid candidates and persistence failure cannot activate late or unverified trust. Reload is tracked in graceful drain. The existing synchronous relay API remains unchanged. See [design and measured evidence](plans/identity-async-refresh.md).

Database corruption protection: PostgreSQL readiness and owner runtime-grant validation require `data_checksums=on`, `ignore_checksum_failure=off` and `zero_damaged_pages=off`, in addition to fsync/full-page-write and primary-role checks. Unsupported or missing values fail closed. Operators must explicitly arrange any offline checksum enablement consistently across their replication topology; startup does not mutate storage or bypass damaged pages. The local physical-corruption fixture proves detection and fixed-cut isolated restore only, not whole-organization disaster recovery.
