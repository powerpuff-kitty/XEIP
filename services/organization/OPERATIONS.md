# Organization service operations

This is the experimental single-organization runtime, separate from the loopback demonstration relay. Do not treat these templates as a supported release: human login/approval UX, real-tool acceptance, storage disaster recovery, release artifacts and independent security review remain gates in [production readiness](../../PRODUCTION_READINESS.md).

## Prepare and start

Use Linux and Node 22 with the locked dependencies and compiled TypeScript SDK (`npm ci --ignore-scripts && npm run build:ts`). Only one active service process is supported. The launcher enforces a dedicated PostgreSQL ownership lease and fences action transactions/tool dispatch against control changes. Schema maintenance uses the same exclusive lock and performs its mutations on the locked connection. Owner enrollment/change commands are implemented locally; combined recovery remains incomplete; do not interpret the local launcher as an accepted production rollout. PostgreSQL 18 is the current checked backend; provision a dedicated database, an owner/migration login and a separate unprivileged runtime login. Runtime has no role memberships, including non-inherited ones, and never receives owner credentials. Startup also rejects effective parameter grants, executable SECURITY DEFINER routines and direct/PUBLIC EXECUTE on protected PostgreSQL built-ins (all overloads). The protected-function policy is pinned to upstream 18.6 initialization SQL and must be reviewed on database upgrades; excessive grants require explicit owner repair. PostgreSQL must use verified TLS, `fsync=on`, `full_page_writes=on`, `data_checksums=on`, `ignore_checksum_failure=off` and `zero_damaged_pages=off`; action transactions explicitly enable synchronous commit. Operator storage guarantees remain a separate requirement.

Copy and fill [organization.example.json](../../deploy/organization.example.json) and [database-owner.example.json](../../deploy/database-owner.example.json). Place files at absolute paths. Secret/private-key files must be readable by the service account, owned by that UID or root, with no group/other permissions (normally 0600). Public certificates/configuration may be 0644 but must not be group/world writable. Ancestor directories must be controlled by root or the service UID and not group/world writable; a root-owned sticky temporary root is allowed for tests. Final file symlinks are rejected. No passwords belong in command arguments or the JSON itself. Use your actual certificate, signing identities and signed provisioning; every `REPLACE_WITH_...` value deliberately fails validation.

The signed provisioning file contains exactly `keyDocuments` and `statusDocuments` arrays described in [live trust](../../spec/live-entity-trust.md), including explicit root anchors. `trust.directory` remains a validated compatibility setting for legacy checkpoint import; the Linux launcher no longer opens or creates that checkpoint. PostgreSQL control history is authoritative, and the signed file must match its enrolled current state exactly. Migration alone does not enroll an organization. Use the explicit enrollment/change commands below. A populated legacy action database cannot be freshly enrolled: stop and reconcile its complete history. Combined recovery and production acceptance remain open.

Configure Keycloak API roles (`agent` and `approver`), permitted client IDs, explicit subject/entity/signing-key bindings, and access-token audiences for both `xeip-api` and the confidential introspection client. Token lifetimes default to at most 300 seconds. The human role in the conformance fixture is a service account; it is not the production human login flow. Each MCP target must independently publish matching protected-resource/OAuth metadata and accept its own least-privilege connector client. The inbound XEIP bearer is never forwarded to it.

Run owner maintenance explicitly against that **dedicated** database:

```sh
npm run organization:migrate -- --config /etc/xeip-maintenance/database-owner.json --runtime-role xeip_runtime
# Initial enrollment only: empty control, action and audit ledgers.
npm run organization:control -- enroll --owner-config /etc/xeip-maintenance/database-owner.json --runtime-config /etc/xeip/organization.json --expect-empty
npm run organization:check -- --config /etc/xeip/organization.json
npm run organization:serve -- --config /etc/xeip/organization.json
```

Maintenance applies checksum-verified migrations and grants the already-created runtime role. It removes PUBLIC database CREATE/TEMP privileges and application schema/object grants; do not use it on a shared application database. Owner migration and grant provisioning are separate transactions; a failed grant stage leaves an applied migration and requires correction/re-run before startup. `organization:check` validates files and configuration without opening listeners or verifying live dependencies. `serve` verifies enrolled PostgreSQL control state, exact public input, current signed trust and database schema/durability/privileges, and pinned Keycloak discovery/JWKS/introspection credentials before exposing the action listener. The dependency-startup phase is limited to 30 seconds and emits redacted failure codes; module loading and protected-file validation precede that timer. The supervisor must also enforce an overall startup/readiness deadline on the chosen hardware. It does not prove the actual MCP tool's behavior until an authorized action runs.

Direct application TLS is the supported initial boundary. The canonical origin drives exact Host/Origin checks. Configure trusted private CAs through the Node trust store when needed; never disable TLS verification. The database CA is explicit in its configuration. A reverse-proxy trust model is not implemented. The [systemd template](../../deploy/xeip-organization.service) assumes a separately created `xeip` account and installed `/opt/xeip` artifact; it is not installed or certified by these tests.

## Enroll or change control state

Run owner commands as an operator who can read the protected owner and runtime
configuration files. They must select the same database host, port and name, with
separate owner/runtime users. The CLI uses verified database TLS and never opens
listeners. Stop and drain the runtime before enrollment, inspection or changes;
its database session lock causes competing commands to refuse immediately.

For a genuinely new organization, leave the final `trust.directory` absent and
ensure its protected parent exists. Enrollment temporarily reserves that directory
and its `LOCK`, then removes the empty reservation. An existing directory must
contain a valid protected `trust.json`; all records, including removed entities,
are imported under its exclusive lock without changing the file. Missing, malformed,
unsafe or oversized existing history is refused. Never delete history or an active
lock to force enrollment. After a crash, verify that the old owner process is gone
and reconcile any uncertain database result before an operator handles a stale lock.

Inspect the stored head, then use the exact returned revision and digest with the
new protected runtime configuration (replace `REVISION` and `DIGEST` below):

```sh
npm run organization:control -- inspect --owner-config /etc/xeip-maintenance/database-owner.json
npm run organization:control -- change --owner-config /etc/xeip-maintenance/database-owner.json --runtime-config /etc/xeip/organization.next.json --expected-revision REVISION --expected-digest DIGEST
```

`inspect` needs only the owner configuration. It returns `control_empty` or the
historically validated current revision/digest, without requiring fresh provisioning
or runtime secrets. It does **not** prove live readiness, complete historical-chain
integrity, the absence of later acknowledgements, or protection against whole-database
rollback. It emits the shared durability marker before acknowledging the read.

Enrollment and change verify signed inputs and preserve retained high-water marks;
change appends a complete public-authority event only if the expected head matches.
Success prints only `control_enrolled` or `control_changed` plus revision/digest.
Failures use `control_maintenance_failed` and a nonzero exit, including cancellation
or uncertain commit. A failure is not proof of rollback: inspect and reconcile the
observed head and intended protected inputs before retrying. Do not substitute the
latest head automatically for a stale expected head. Commands have a 30-second
cancellation deadline and the executable allows at most 3 further seconds for cleanup.

After a confirmed change, atomically install the matching protected runtime file
and start the service through the normal checks. Startup independently checks current
signature freshness, exact public inputs, database privileges and provider health.
Owner command success alone is not permission to activate a restored database or
claim production readiness.

## Monitor and drain

`GET /live` reports process liveness independently of dependencies. `GET /ready` fails when draining, trust is stale/failed, or dependency checks fail. Database/provider checks are coalesced and cached for five seconds; idle pool errors invalidate that cache. Request limits remain bounded. Every response carries a generated `X-Request-Id`; structured logs contain that ID, fixed route/operation/state/status labels and machine duration, never arguments, results, bearers or raw exceptions.

Metrics are available only over a separate loopback TLS listener at `GET /metrics` with its own bearer secret. Use a co-located scraper and [Prometheus example](../../deploy/prometheus.example.yml), with a separately protected copy of the token readable by the scraper. Its `credentials_file` and `tls_config` use the [official Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/). There is no public management or administrative HTTP endpoint.

Alert on sustained `xeip_ready=0`, 503/504 rates, active-operation saturation, log failures, and P95 action latency above 2 seconds. `xeip_request_duration_seconds` measures machine HTTP handling; human review is outside a request. Execution outcome counters represent observed execute responses; query the protected ledger for authoritative stalled/indeterminate actions because lost responses/process death may prevent a metric observation. Logs and metrics do not replace the transactionally appended audit.

Send SIGTERM/SIGINT for drain. New operations are refused, idle sockets close, and accepted workers keep database access while recording outcomes. The final third of `shutdownMs` (at most ten seconds) cancels remaining requests and allows completion recording. Unsettled work or pool closure at the deadline causes executable exit 1; consumed claims remain consumed. Fatal API or management-listener errors use the same bounded drain and exit nonzero even when all work settles, allowing `Restart=on-failure` supervision. Configure the supervisor's hard kill deadline longer than this budget. Never treat a forced shutdown as permission to replay.

Atomically replace the protected signed provisioning file and send SIGHUP to reload it. The launcher prepares current signatures in one bounded identity worker. Current control-state verification and transition preparation also run in a bounded worker with an 8-second deadline; they no longer repeat signature validation on the listener thread. Concurrent reloads reject. Requests may use the current verified policy during preparation, but local trust denies authorization once database publication starts. `trust_reloaded` is logged only after certain synchronous commit and fresh activation. Cancellation or failure after entering publication leaves trust unavailable until reopen; an unavailable response does not imply rollback. Close never activates a late result. Invalid preparation before publication preserves the previous valid policy. Adding or re-adding an entity requires the explicit owner `change` command below. Public endpoint/policy/subject changes require an owner control event and drain/restart, while secret-only and TLS changes require drain/restart. Target revisions must change when public execution settings change. The launcher locks the control head before action rows and captures a revision for each request. After a durable revision check and live provider revalidation, the connector invokes the tool fetch synchronously under that revision. Publication prevents old-snapshot dispatch, but cannot recall an already-started POST; completion still records its outcome. These local guards require one runtime and drained owner changes. The runtime acquires its session lease before trust/listeners, retains it through drain and work-pool closure, and invalidates authority on observed connection/heartbeat loss. Competing runtime/schema-maintenance sessions refuse immediately. Owner schema mutations share the lease backend, so backend termination also aborts their transaction. Do not bypass this boundary with direct control-table writes. External infrastructure fencing and combined recovery remain pending; this is not a completed production activation procedure.

## Recover and reconcile

Startup/readiness and runtime grant provisioning reject disabled data checksums or enabled page-recovery bypasses. Check existing clusters before upgrading this experimental runtime: PostgreSQL 18’s initialization default does not prove an upgraded cluster has checksums enabled. If protection is disabled, the database operator must plan a coordinated offline operation with verified backups and all affected replicas; XEIP does not automatically rewrite the cluster. PostgreSQL documents the shutdown and replication precautions for [pg_checksums](https://www.postgresql.org/docs/18/app-pgchecksums.html). Never enable `ignore_checksum_failure` or `zero_damaged_pages` to make the application ready.

The `node conformance/organization-corruption.mjs` drill damages a synthetic action page offline, confirms checksum detection and unavailable reads/claims without a connector call, then restores a fixed acknowledged backup cut into a separate database. No actions are accepted after that cut. This is corruption detection and isolated logical-restore evidence; a periodic dump still cannot satisfy zero acknowledged-action loss after later work. Treat the damaged original as fenced, preserve evidence, and use the accepted coordinated database/WAL/trust recovery procedure for an actual incident.

Monitor available bytes and inodes separately for PostgreSQL data/tablespaces, WAL and backup/archive destinations. Investigate sustained write errors or 503s promptly; the application cannot manufacture storage capacity. Data-file exhaustion can reject transactions; WAL exhaustion can instead stop the server, so the responses and recovery steps differ ([PostgreSQL disk usage guidance](https://www.postgresql.org/docs/18/diskusage.html)). Never delete action/audit rows or WAL files to clear an alert. Restore capacity under the database operator’s runbook, then reconcile uncertain request IDs before further effects.

The `node conformance/organization-disk-full.mjs` check exhausts an isolated audit tablespace in a disposable container, not the host disk. It exercises real `53100` write errors and recovery of capacity; it does not certify WAL exhaustion, disk corruption or the deployed storage system.

The separate `node conformance/organization-wal-full.mjs` drill exercises actual WAL ENOSPC, PostgreSQL termination and native restart after capacity restoration. The fixture keeps its container alive solely to retain its bounded temporary filesystem. It preserves acknowledged logical state and prevents a connector call for the interrupted claim. Operators must preserve the real database/WAL and resolve capacity before supervised restart; never use `pg_resetwal` or delete WAL to force startup. Reconcile uncertain actions against the recovered ledger and upstream evidence. Production recovery still depends on the accepted storage/backup/failure model.


Every ledger transaction, including status inspection and idempotent retries, writes an empty transactional WAL marker before the final authorization check. The runtime needs `EXECUTE` on `pg_catalog.pg_logical_emit_message(boolean,text,text,boolean)`; owner maintenance grants it explicitly and startup verifies it. Status operations therefore require a writable primary and the configured synchronous standby acknowledgement. Revalidate this PostgreSQL 18 behavior before a major upgrade.

PostgreSQL can report a cancelled synchronous commit as a successful COMMIT plus a warning after local commit. XEIP enables warning delivery, rejects any COMMIT notice as uncertain durability and discards that connection. An unavailable response does not mean rollback: preserve the request ID and reconcile only after durability is restored. Never start an external effect on an uncertain claim. Do not disable the required standby to make operations succeed; a promoted primary needs an accepted replacement durability peer before it acknowledges new work. `synchronous_commit=on` alone does not configure such a peer.

The disposable `npm run test:postgres:replication` drill destroys its original primary before promotion and compares all eight acknowledged action states, audit history and four consumed claims. It also cancels blocked proposals, inspections and retries, which must refuse acknowledgement. Two containers on one workstation demonstrate application behavior only; they do not certify independent storage, full organization recovery or the one-hour operator target.

`npm run test:postgres:archive-recovery` exercises a different path: native physical base backup plus archived WAL for later acknowledged actions. Its incomplete archive must fail the required named recovery target. The complete archive restores into a paused, read-only candidate for exact action/audit comparison before the disposable fixture resumes and checks consumed-claim suppression. The original source is destroyed before either candidate starts. See [the recovery evidence](../../spec/plans/postgres-archive-recovery.md). This test deliberately waits for its cut to be archived; it does not show zero acknowledged-action loss during arbitrary archive lag or restore Keycloak, trust checkpoints, configuration and secrets. Do not use fixture configuration or its automatic resume as an operator activation procedure.

Preserve PostgreSQL data/WAL including control history, exact current signed provisioning/public configuration and separately backed-up secrets. Preserve legacy filesystem checkpoints for explicit migration reconciliation; they no longer grant authority to this launcher. Encrypt and restrict backups; define retention before storing real arguments/results. Current ledger rows cannot be deleted or rewritten by runtime credentials; no retention purge is implemented.

The original mixed-state [A12 probe](../../spec/audits/2026-10-12-linux-control-recovery.md) showed that older provisioning plus an older filesystem checkpoint could reactivate a revoked device. The launcher now uses PostgreSQL-backed trust: local actual-database tests refuse older provisioning before provider probes/listeners and preserve revocation with current input. A12 remains open until action/dispatch fencing, maintenance coordination and full control/action recovery are proved. A fully consistent rollback of the database still needs independent acknowledgement evidence and accepted storage/fencing.

The targets are restore ≤1 hour and **no loss of acknowledged actions**. A periodic logical dump alone cannot meet zero acknowledged-action loss after primary storage failure. Select a PostgreSQL synchronous-replication/storage failure model and continuous backup/WAL archive, then prove it with an operator drill. PostgreSQL documents the loss window of asynchronous failover in [replication](https://www.postgresql.org/docs/18/high-availability.html) and backup replay in [continuous archiving](https://www.postgresql.org/docs/18/continuous-archiving.html). The local kill/restart and logical restore fixtures do not certify that deployment.

During a restore: fence the old writer, stop application ingress, restore the approved database/WAL point including control state and exact public input, verify that every externally recorded successful request ID and audit event remains present, verify schema/checksums and current signed trust, then restart one writer and run an approved harmless tool action. Measure from incident declaration through usable service restoration. The maintenance/recovery activation procedure remains incomplete; do not use an empty control ledger or older runtime to suppress an enrollment or rollback refusal.

Inspect an uncertain action using the signed `inspect` operation and the existing request ID. `succeeded`/`failed` has a recorded result when one was trustworthy. `executing` after process death and `indeterminate` after an attempted but unresolved call require comparison with the MCP tool's own audit/idempotency evidence. Even an explicit tool error may have partial effects. Do not reset the state, replace the request ID to retry, or alter ledger rows. Record the investigation outside the immutable action record; use a new, separately approved compensating action only after its necessity and safety are established. Automatic reconciliation/compensation is not implemented.

For upgrades: drain, preserve a recoverable database/trust backup and artifact/configuration versions, apply owner migrations, verify startup, and run a harmless approved operation before reopening use. Historical v1→v3 preservation has a real fixture; it also refuses control enrollment over a populated legacy ledger without reconciliation. There are no down migrations; roll back code only if compatible with the installed schema, otherwise restore the coordinated backup without silently discarding acknowledged work. Stop the rollout if that cannot preserve the recovery contract.
