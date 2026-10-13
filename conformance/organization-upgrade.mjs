// Upgrade an actual historical v1 database without rewriting its migration checksum.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import pg from "pg";
import { migrate } from "../services/organization/store.mjs";
import { ControlStore } from "../services/organization/control-store.mjs";
import { StoreUnavailable } from "../services/organization/errors.mjs";
import { publicAuthority } from "../services/organization/control-state.mjs";
import {
  configuration,
  provisioning,
  acceptedAt,
} from "../services/organization/test-fixtures/control.mjs";
export async function verifyUpgrade(pool) {
  await pool.query("CREATE DATABASE xeip_upgrade");
  // pg intentionally makes password non-enumerable; object spread alone loses it.
  const historical = new pg.Pool({
    ...pool.options,
    password: pool.options.password,
    database: "xeip_upgrade",
  });
  let failure;
  try {
    const sql = readFileSync(
        new URL(
          "../services/organization/migrations/001-actions.sql",
          import.meta.url,
        ),
        "utf8",
      ),
      checksum = createHash("sha256").update(sql).digest("hex");
    await historical.query("CREATE SCHEMA xeip_org");
    await historical.query(sql);
    await historical.query(
      "CREATE TABLE xeip_org.migrations(version integer PRIMARY KEY,checksum text NOT NULL,installed_at timestamptz NOT NULL DEFAULT clock_timestamp())",
    );
    await historical.query(
      "INSERT INTO xeip_org.migrations(version,checksum) VALUES(1,$1)",
      [checksum],
    );
    await historical.query(
      "INSERT INTO xeip_org.actions(session_id,request_id,digest,canonical,expires_at,state) VALUES ('historical','one',$1,'{}',1,'pending')",
      ["a".repeat(64)],
    );
    await historical.query(
      "INSERT INTO xeip_org.audit(session_id,request_id,digest,event,actor) VALUES ('historical','one',$1,'proposed','{}')",
      ["a".repeat(64)],
    );
    await migrate(historical);
    await migrate(historical);
    assert.deepEqual(
      (
        await historical.query(
          "SELECT version FROM xeip_org.migrations ORDER BY version",
        )
      ).rows,
      [{ version: 1 }, { version: 2 }, { version: 3 }, { version: 4 }],
    );
    await assert.rejects(
      new ControlStore(historical).enroll({
        authority: publicAuthority(configuration()),
        provisioning: provisioning(),
        acceptedAt,
        retainedRecords: {},
      }),
      StoreUnavailable,
    );
    assert.equal(
      (await historical.query("SELECT count(*) FROM xeip_org.control_events"))
        .rows[0].count,
      "0",
    );
    assert.equal(
      (await historical.query("SELECT count(*) FROM xeip_org.control_head"))
        .rows[0].count,
      "0",
    );
    assert.deepEqual(
      (
        await historical.query(
          "SELECT canonical,state,result_canonical FROM xeip_org.actions",
        )
      ).rows,
      [{ canonical: "{}", state: "pending", result_canonical: null }],
    );
    assert.equal(
      (
        await historical.query(
          "SELECT checksum FROM xeip_org.migrations WHERE version=1",
        )
      ).rows[0].checksum,
      checksum,
    );
    assert.equal(
      (await historical.query("SELECT count(*) FROM xeip_org.audit")).rows[0]
        .count,
      "1",
    );
    console.log(
      "PASS PostgreSQL: v1-to-v4 migration preserves historical actions, audit and checksum; refuses implicit control enrollment",
    );
  } catch (error) {
    failure = error;
  } finally {
    await historical.end();
    try {
      await pool.query("DROP DATABASE xeip_upgrade");
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) throw failure;
}
