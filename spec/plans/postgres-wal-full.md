# Verify WAL exhaustion and database restart

The preceding data-full fixture does not exercise WAL-volume failure. PostgreSQL documents that WAL exhaustion can cause server panic/shutdown. Add an isolated real ENOSPC check for the no-false-acknowledgement/no-replay contract, preserving the full production recovery scope.

- [x] Add opt-in bounded WAL storage and a holding supervisor to the disposable pinned PostgreSQL fixture; retain default behavior and exact resource cleanup.
- [x] Exercise real WAL allocation failure at an ActionStore claim commit boundary, require database termination and zero connector calls, restore capacity without deleting/resetting WAL, and compare acknowledged actions/audit and consumed claims after recovery.
- [x] Verify this drill and the normal fixture path, record evidence and add CI/docs.

Only a newly created fixture container uses a 64 MiB WAL tmpfs, inside its existing 512 MiB memory cap. A shell remains alive after PostgreSQL exits, preserving the mount for capacity restoration and native crash recovery; the whole container is removed afterward. Do not interpret the in-memory fixture as production durable storage. PostgreSQL data stays in its existing disposable volume. Credentials remain synthetic and protected. No operator endpoint, production configuration or cloud changes.

The fault is injected through actual PostgreSQL WAL emission/switching in the uncommitted claim transaction. No database error is mocked. After observing WAL ENOSPC and server exit, the test frees its own filler, restarts PostgreSQL, compares exact previously acknowledged state and refuses replay of consumed claims. No automatic tool execution or claim reset is permitted. Default fixture verification is required because the shared harness changes.

Backout removes the optional fixture mode/command only. Independent storage failure, physical corruption, complete trust/configuration/Keycloak recovery, hosted latency, one-hour operator restore and external acceptance remain separate open gates.

References: [PostgreSQL disk-full behavior](https://www.postgresql.org/docs/18/diskusage.html), [initdb WAL-directory option](https://www.postgresql.org/docs/18/app-initdb.html), [pg_ctl lifecycle](https://www.postgresql.org/docs/18/app-pg-ctl.html).

Native first run: `/tmp/xeip-postgres-wal-full-first.log`, exit 0. Actual WAL `PANIC` with `No space left on device` was observed internally; the holding container remained alive and `pg_ctl status` confirmed the database stopped. After removing only the filler and native restart, exact snapshots preserved **3 acknowledged actions / 2 consumed claims / 0 connector calls for the interrupted claim / 1 new recovered proposal**. No application runtime defect or repair was needed. Database runs in pinned PostgreSQL 18.6/Linux; fixture client is Node 26.8.1/macOS. This does not certify power-loss durability of temporary storage.

The default-path regression run is pending. The helper rejects combining WAL mode with default baseline tests, whose deliberate whole-container restart would discard the temporary WAL mount. CI uses the dedicated command. Application source, dependencies and package manifests remain unchanged; no runtime-image rebuild or broad unrelated suite rerun is needed for this fixture-only increment.

Closing verification: `/tmp/xeip-postgres-wal-full-default.log`, exit 0. The normal fixture still passes migration, lost-response, concurrency, database kill/restart, logical restore, restricted-role checks and the signed HTTPS→PostgreSQL→MCP single-effect/revocation/uncertain-completion path. Separate no-resource check rejects incompatible `walFault:true` plus default baseline mode. Syntax and whitespace checks pass. Owned PostgreSQL fixture containers are absent after cleanup. No cloud resources, production configuration, user data or runtime code changed. Remote CI has not run; this closes a local functional evidence task, not G3 or production readiness.
