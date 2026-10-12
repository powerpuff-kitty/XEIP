import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import pg from "pg";
import { migrate, ActionStore } from "../services/organization/store.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import {
  verifyDatabase,
  grantRuntime,
  DatabaseNotReady,
} from "../services/organization/database.mjs";

export async function verifyRuntimeDatabase(owner) {
  const name = "xeip_runtime_" + randomBytes(6).toString("hex");
  const password = randomBytes(32).toString("hex");
  let database;
  let runtime;
  let unexpectedIdleError = false;
  let cleaning = false;
  const idleError = () => {
    if (!cleaning) unexpectedIdleError = true;
  };
  await owner.query(`CREATE DATABASE ${name}`);
  try {
    database = new pg.Pool({
      ...owner.options,
      password: owner.options.password,
      database: name,
    });
    database.on("error", idleError);
    // Fixture-only random hexadecimal identifiers/password, never operator input.
    await database.query(`CREATE ROLE ${name} LOGIN PASSWORD '${password}'`);
    await migrate(database);
    await verifyDatabase(database, { runtime: false });
    await assert.rejects(verifyDatabase(database), DatabaseNotReady);
    await grantRuntime(database, name);
    runtime = new pg.Pool({
      ...owner.options,
      database: name,
      user: name,
      password,
    });
    runtime.on("error", idleError);
    await verifyDatabase(runtime);
    const marker =
      "pg_catalog.pg_logical_emit_message(boolean,text,text,boolean)";
    await database.query(
      `REVOKE EXECUTE ON FUNCTION ${marker} FROM PUBLIC, ${name}`,
    );
    await assert.rejects(verifyDatabase(runtime), DatabaseNotReady);
    await grantRuntime(database, name);
    await verifyDatabase(runtime);
    await database.query(`GRANT EXECUTE ON FUNCTION ${marker} TO PUBLIC`);

    const entity =
      "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
    const other =
      "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
    const policy = new ActionPolicy({
      targets: [
        { id: "internal", revision: "1", recipient: other, tools: ["lookup"] },
      ],
      sessions: [
        {
          id: "runtime",
          agents: ["agent"],
          approvers: ["human"],
          targets: ["internal"],
        },
      ],
    });
    const principal = (subject, identity, role) =>
      Object.freeze({
        subject,
        entity: identity,
        kid: identity.slice("urn:xeip:entity:".length),
        clientId: "fixture",
        roles: Object.freeze([role]),
        expiresAt: Math.floor(Date.now() / 1000) + 300,
      });
    const agent = principal("agent", entity, "agent");
    const human = principal("human", other, "approver");
    const store = new ActionStore(runtime, policy, async () => true);
    const proposed = await store.propose(agent, {
      id: "restricted",
      session: "runtime",
      target: "internal",
      tool: "lookup",
      arguments: { query: "safe" },
      expiresAt: Math.floor(Date.now() / 1000) + 240,
    });
    await store.decide(
      human,
      "runtime",
      "restricted",
      proposed.proposal.digest,
      "approve",
    );
    const claim = await store.claim(
      agent,
      "runtime",
      "restricted",
      proposed.proposal.digest,
    );
    await store.finish("runtime", "restricted", claim.claimId, "succeeded", {
      ok: true,
    });
    assert.deepEqual(
      (await store.inspect(agent, "runtime", "restricted")).result,
      { ok: true },
    );
    assert.equal(
      (await runtime.query("SELECT count(*) FROM xeip_org.audit")).rows[0]
        .count,
      "4",
    );
    for (const sql of [
      "CREATE SCHEMA unauthorized",
      "CREATE TEMP TABLE unauthorized(i int)",
      "CREATE TABLE public.unauthorized(i int)",
      "ALTER TABLE xeip_org.actions DISABLE TRIGGER ALL",
      "DROP TABLE xeip_org.audit",
      "TRUNCATE xeip_org.actions CASCADE",
      "DELETE FROM xeip_org.actions",
      "UPDATE xeip_org.audit SET event=event",
      "DELETE FROM xeip_org.audit",
      "UPDATE xeip_org.migrations SET checksum=checksum",
      "INSERT INTO xeip_org.migrations VALUES (9,'invalid',now())",
      "ALTER FUNCTION xeip_org.protect_action() OWNER TO " + name,
      "GRANT UPDATE ON xeip_org.audit TO PUBLIC",
    ]) {
      // GRANT may warn and return success with no grant on PostgreSQL; test it separately below.
      if (!sql.startsWith("GRANT"))
        await assert.rejects(runtime.query(sql), { code: "42501" }, sql);
    }
    await runtime.query("GRANT UPDATE ON xeip_org.audit TO PUBLIC");
    await verifyDatabase(runtime); // No grant was added.
    await assert.rejects(migrate(runtime));
    for (const [grant, revoke] of [
      [
        `GRANT DELETE ON xeip_org.actions TO ${name}`,
        `REVOKE DELETE ON xeip_org.actions FROM ${name}`,
      ],
      [
        `GRANT UPDATE(actor) ON xeip_org.audit TO ${name}`,
        `REVOKE UPDATE(actor) ON xeip_org.audit FROM ${name}`,
      ],
      [
        `GRANT SELECT ON xeip_org.actions TO ${name} WITH GRANT OPTION`,
        `REVOKE GRANT OPTION FOR SELECT ON xeip_org.actions FROM ${name}`,
      ],
      [
        `GRANT CREATE ON SCHEMA public TO ${name}`,
        `REVOKE CREATE ON SCHEMA public FROM ${name}`,
      ],
      [
        `GRANT pg_read_all_data TO ${name} WITH INHERIT FALSE, SET TRUE`,
        `REVOKE pg_read_all_data FROM ${name}`,
      ],
      [
        `GRANT SET ON PARAMETER session_replication_role TO ${name}`,
        `REVOKE SET ON PARAMETER session_replication_role FROM ${name}`,
      ],
    ]) {
      await database.query(grant);
      try {
        await assert.rejects(verifyDatabase(runtime), DatabaseNotReady, grant);
      } finally {
        await database.query(revoke);
      }
      await verifyDatabase(runtime);
    }
    for (const signature of [
      "lo_export(oid,text)",
      "lo_import(text)",
      "lo_import(text,oid)",
      "pg_read_file(text)",
      "pg_read_file(text,bigint,bigint,boolean)",
      "pg_get_backend_memory_contexts()",
    ]) {
      for (const grantee of [name, "PUBLIC"]) {
        await database.query(
          `GRANT EXECUTE ON FUNCTION pg_catalog.${signature} TO ${grantee}`,
        );
        try {
          await assert.rejects(
            verifyDatabase(runtime),
            DatabaseNotReady,
            `${signature} to ${grantee}`,
          );
          await assert.rejects(grantRuntime(database, name), DatabaseNotReady);
        } finally {
          await database.query(
            `REVOKE EXECUTE ON FUNCTION pg_catalog.${signature} FROM ${grantee}`,
          );
        }
        await verifyDatabase(runtime);
      }
    }
    await database.query(`REVOKE INSERT ON xeip_org.audit FROM ${name}`);
    await assert.rejects(verifyDatabase(runtime), DatabaseNotReady);
    await grantRuntime(database, name);
    await verifyDatabase(runtime);
    await database.query(
      "UPDATE xeip_org.migrations SET checksum='tampered' WHERE version=2",
    );
    await assert.rejects(verifyDatabase(runtime), DatabaseNotReady);
    assert.equal(unexpectedIdleError, false);
    console.log(
      "PASS PostgreSQL restricted runtime: full action lifecycle, schema checks, denied DDL/audit/history mutation, privilege drift and non-inherited role escalation",
    );
  } finally {
    cleaning = true; // Rejected checks destroy clients; DROP DATABASE may close their pending sockets.
    if (runtime) await runtime.end();
    if (database) await database.end();
    await owner.query(`DROP DATABASE ${name} WITH (FORCE)`);
    await owner.query(`DROP ROLE IF EXISTS ${name}`);
  }
}

// Run through `npm run test:postgres`; keeping this module import-only avoids
// a top-level-await cycle when the PostgreSQL runner imports its test cases.
