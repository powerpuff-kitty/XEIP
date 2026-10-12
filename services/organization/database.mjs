/** Dedicated PostgreSQL 18 database boundary. Never performs startup migrations. */
import { migrations } from "./schema.mjs";
import { protectedFunctions } from "./protected-functions.mjs";
/** @typedef {import('./transactions.mjs').TransactionPool} Pool */
/** @typedef {import('pg').PoolClient} Client */
export class DatabaseNotReady extends Error {
  constructor() {
    super("organization database not ready");
    this.name = "DatabaseNotReady";
  }
}

/** @template T @param {Pool} pool @param {boolean} readOnly @param {(client:Client)=>Promise<T>} work */
async function checked(pool, readOnly, work) {
  for (const value of [
    pool?.options?.connectionTimeoutMillis,
    pool?.options?.query_timeout,
  ])
    if (
      !Number.isInteger(value) ||
      value === undefined ||
      value < 100 ||
      value > 10000
    )
      throw new DatabaseNotReady();
  let client;
  let broken = false;
  try {
    client = await pool.connect();
    await client.query(readOnly ? "BEGIN READ ONLY" : "BEGIN");
    await client.query(
      "SET LOCAL search_path = pg_catalog; SET LOCAL statement_timeout = '10s'; SET LOCAL lock_timeout = '3s'; SET LOCAL idle_in_transaction_session_timeout = '30s'",
    );
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch {
    broken = true; // Destroy a possibly timed-out connection; never expose raw DB diagnostics.
    throw new DatabaseNotReady();
  } finally {
    client?.release(broken);
  }
}

/** @param {Client} client */
async function schemaReady(client) {
  const settings = (
    await client.query(
      "SELECT current_setting('server_version_num')::integer AS version, current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes, current_setting('data_checksums') AS data_checksums, current_setting('ignore_checksum_failure') AS ignore_checksum_failure, current_setting('zero_damaged_pages') AS zero_damaged_pages, pg_is_in_recovery() AS recovering",
    )
  ).rows[0];
  if (
    settings.version < 180000 ||
    settings.version >= 190000 ||
    settings.fsync !== "on" ||
    settings.full_page_writes !== "on" ||
    settings.data_checksums !== "on" ||
    settings.ignore_checksum_failure !== "off" ||
    settings.zero_damaged_pages !== "off" ||
    settings.recovering !== false
  )
    throw new DatabaseNotReady();
  const installed = (
    await client.query(
      "SELECT version,checksum FROM xeip_org.migrations ORDER BY version",
    )
  ).rows;
  if (
    installed.length !== migrations.length ||
    installed.some(
      (row, i) =>
        row.version !== i + 1 || row.checksum !== migrations[i].checksum,
    )
  )
    throw new DatabaseNotReady();
  const triggers = (
    await client.query(
      "SELECT t.tgname, t.tgenabled, p.prosecdef FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN ('xeip_org.actions'::regclass,'xeip_org.audit'::regclass,'xeip_org.control_events'::regclass,'xeip_org.control_head'::regclass) AND NOT t.tgisinternal ORDER BY t.tgname",
    )
  ).rows;
  if (
    triggers.length !== 7 ||
    triggers.some(
      (row, i) =>
        row.tgname !==
          [
            "protect_action",
            "protect_audit",
            "protect_control_event",
            "protect_control_event_truncate",
            "protect_control_head",
            "protect_control_head_truncate",
            "publish_control_head",
          ][i] ||
        row.tgenabled !== "O" ||
        row.prosecdef !== false,
    )
  )
    throw new DatabaseNotReady();
}

/** Reject memberships even without INHERIT: SET ROLE can otherwise escalate.
 * @param {Client} client @param {string} role
 */
async function roleReady(client, role) {
  const rows = (
    await client.query(
      `SELECT r.oid FROM pg_roles r WHERE r.rolname=$1 AND r.rolcanlogin
    AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
    AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid)
    AND NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba=r.oid)
    AND NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner=r.oid)
    AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner=r.oid)
    AND NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.proowner=r.oid)`,
      [role],
    )
  ).rows;
  if (rows.length !== 1) throw new DatabaseNotReady();
}

/** @param {Client} client @param {string} role */
async function privilegesReady(client, role) {
  await roleReady(client, role);
  const boundaries = (
    await client.query(
      `SELECT
    has_database_privilege($1,current_database(),'CONNECT') AS connected,
    has_function_privilege($1,'pg_catalog.pg_logical_emit_message(boolean,text,text,boolean)','EXECUTE') AS durability_marker,
    has_database_privilege($1,current_database(),'CREATE,TEMP') AS database_write,
    has_schema_privilege($1,'xeip_org','USAGE') AS schema_read,
    EXISTS (SELECT 1 FROM pg_namespace n WHERE has_schema_privilege($1,n.oid,'CREATE')) AS schema_write,
    EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE p.prosecdef AND has_function_privilege($1,p.oid,'EXECUTE')) AS definer_access,
    EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='pg_catalog' AND p.proname=ANY($2::text[]) AND has_function_privilege($1,p.oid,'EXECUTE')) AS protected_function_access,
    EXISTS (SELECT 1 FROM pg_parameter_acl p WHERE has_parameter_privilege($1,p.parname,'SET,ALTER SYSTEM')) AS parameter_access,
    current_setting('session_replication_role') AS trigger_mode`,
      [role, protectedFunctions],
    )
  ).rows[0];
  if (
    !boundaries.connected ||
    boundaries.durability_marker !== true ||
    boundaries.database_write ||
    !boundaries.schema_read ||
    boundaries.schema_write ||
    boundaries.definer_access ||
    boundaries.protected_function_access ||
    boundaries.parameter_access ||
    boundaries.trigger_mode !== "origin"
  )
    throw new DatabaseNotReady();
  const tables = /** @type {const} */ ([
    ["actions", ["SELECT", "INSERT", "UPDATE"]],
    ["audit", ["SELECT", "INSERT"]],
    ["migrations", ["SELECT"]],
    ["control_events", ["SELECT", "INSERT"]],
    ["control_head", ["SELECT", "INSERT", "UPDATE"]],
  ]);
  for (const [table, required] of tables) {
    for (const privilege of [
      "SELECT",
      "INSERT",
      "UPDATE",
      "DELETE",
      "TRUNCATE",
      "REFERENCES",
      "TRIGGER",
      "MAINTAIN",
    ]) {
      const result = (
        await client.query(
          "SELECT has_table_privilege($1,$2,$3) AS allowed, has_table_privilege($1,$2,$4) AS grantable",
          [
            role,
            "xeip_org." + table,
            privilege,
            privilege + " WITH GRANT OPTION",
          ],
        )
      ).rows[0];
      const wanted = /** @type {readonly string[]} */ (required).includes(
        privilege,
      );
      if (result.allowed !== wanted || result.grantable)
        throw new DatabaseNotReady();
      if (["SELECT", "INSERT", "UPDATE", "REFERENCES"].includes(privilege)) {
        const columns = (
          await client.query(
            "SELECT has_any_column_privilege($1,$2,$3) AS allowed, has_any_column_privilege($1,$2,$4) AS grantable",
            [
              role,
              "xeip_org." + table,
              privilege,
              privilege + " WITH GRANT OPTION",
            ],
          )
        ).rows[0];
        if (columns.allowed !== wanted || columns.grantable)
          throw new DatabaseNotReady();
      }
    }
  }
  for (const privilege of ["USAGE", "SELECT", "UPDATE"]) {
    const result = (
      await client.query(
        "SELECT has_sequence_privilege($1,'xeip_org.audit_sequence_seq',$2) AS allowed, has_sequence_privilege($1,'xeip_org.audit_sequence_seq',$3) AS grantable",
        [role, privilege, privilege + " WITH GRANT OPTION"],
      )
    ).rows[0];
    if (result.allowed !== (privilege === "USAGE") || result.grantable)
      throw new DatabaseNotReady();
  }
}

/** Read-only startup/readiness check. Owner tooling may request schema-only inspection.
 * @param {Pool} pool @param {{runtime?:boolean}} [options]
 */
export async function verifyDatabase(pool, { runtime = true } = {}) {
  return checked(pool, true, async (client) => {
    await schemaReady(client);
    if (runtime) {
      const identity = (
        await client.query(
          "SELECT current_user AS active, session_user AS login",
        )
      ).rows[0];
      if (identity.active !== identity.login) throw new DatabaseNotReady();
      await privilegesReady(client, identity.active);
    }
  });
}

/** Explicit owner maintenance for a DEDICATED database and existing unprivileged login.
 * Removes PUBLIC create/temp and application-object grants. Never creates credentials.
 * @param {Pool} pool @param {string} role
 */
export async function grantRuntime(pool, role) {
  if (
    typeof role !== "string" ||
    !/^[a-z][a-z0-9_]{0,62}$/.test(role) ||
    role.startsWith("pg_") ||
    role === "public"
  )
    throw new DatabaseNotReady();
  return checked(pool, false, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(1480935760, 1)");
    await schemaReady(client);
    await roleReady(client, role);
    const database = (await client.query("SELECT current_database() AS name"))
      .rows[0].name;
    const quotedDatabase = '"' + database.replaceAll('"', '""') + '"';
    const quotedRole = '"' + role + '"';
    await client.query(
      `REVOKE CREATE,TEMP ON DATABASE ${quotedDatabase} FROM PUBLIC, ${quotedRole}`,
    );
    await client.query(
      `GRANT CONNECT ON DATABASE ${quotedDatabase} TO ${quotedRole}`,
    );
    await client.query(
      `REVOKE CREATE ON SCHEMA public FROM PUBLIC, ${quotedRole}`,
    );
    await client.query(
      `REVOKE ALL ON SCHEMA xeip_org FROM PUBLIC, ${quotedRole}`,
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA xeip_org FROM PUBLIC, ${quotedRole}`,
    );
    await client.query(
      `REVOKE ALL ON ALL SEQUENCES IN SCHEMA xeip_org FROM PUBLIC, ${quotedRole}`,
    );
    await client.query(
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA xeip_org FROM PUBLIC, ${quotedRole}`,
    );
    await client.query(
      `GRANT EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean,text,text,boolean) TO ${quotedRole}`,
    );
    await client.query(`GRANT USAGE ON SCHEMA xeip_org TO ${quotedRole}`);
    await client.query(
      `GRANT SELECT,INSERT,UPDATE ON xeip_org.actions TO ${quotedRole}`,
    );
    await client.query(
      `GRANT SELECT,INSERT ON xeip_org.audit TO ${quotedRole}`,
    );
    await client.query(`GRANT SELECT ON xeip_org.migrations TO ${quotedRole}`);
    await client.query(
      `GRANT SELECT,INSERT ON xeip_org.control_events TO ${quotedRole}`,
    );
    await client.query(
      `GRANT SELECT,INSERT,UPDATE ON xeip_org.control_head TO ${quotedRole}`,
    );
    await client.query(
      `GRANT USAGE ON SEQUENCE xeip_org.audit_sequence_seq TO ${quotedRole}`,
    );
    await privilegesReady(client, role);
  });
}
