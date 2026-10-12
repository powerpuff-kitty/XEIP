// Owned PostgreSQL owner workflow. Provider/tool/production activation are excluded.
import assert from "node:assert/strict";
import pg from "pg";
import { execFileSync, execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
import { randomBytes, createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { withPostgres } from "./postgres.mjs";
import { grantRuntime } from "../services/organization/database.mjs";
import { maintainControl } from "../services/organization/control-maintenance.mjs";
import { maintainDatabase } from "../services/organization/maintenance.mjs";
import { openControlLease } from "../services/organization/control-lease.mjs";
import { ControlStore } from "../services/organization/control-store.mjs";
import {
  publicAuthority,
  verifyControlState,
} from "../services/organization/control-state.mjs";
import { prepareEntityTrust } from "../packages/identity/trust-state.mjs";
import { signStatusDocument } from "../packages/identity/identity-status.mjs";
import { signKeyDocument } from "../packages/identity/key-document.mjs";
import {
  configuration,
  provisioning,
  fixture,
} from "../services/organization/test-fixtures/control.mjs";
const now = () => Math.floor(Date.now() / 1000);
const date = () => new Date(now() * 1000).toISOString().replace(".000Z", "Z");
function fresh(serial) {
  const p = provisioning(serial);
  p.statusDocuments[0].document = signStatusDocument(
    { ...p.statusDocuments[0].document, issuedAt: date(), signatures: [] },
    {
      privateKey: Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
      kid: p.keyDocuments[0].document.genesis,
    },
  );
  return p;
}
await withPostgres(
  async ({ pool, container }) => {
    const role = "xeip_owner_test_" + randomBytes(5).toString("hex"),
      password = randomBytes(32).toString("hex");
    await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await grantRuntime(pool, role);
    const runtime = new pg.Pool({
      ...pool.options,
      user: role,
      password,
      max: 1,
    });
    runtime.on("error", () => {});
    const directory = mkdtempSync(join(tmpdir(), "xeip-owner-workflow-"));
    let lease, blocker, legacyPool;
    try {
      const config = configuration();
      config.database = { ...pool.options, user: role, password };
      config.trust.directory = join(directory, "trust");
      config.provisioning = fresh(2);
      const file = (name, value) => {
        const path = join(directory, name);
        writeFileSync(path, value, { mode: 0o600 });
        return path;
      };
      const certificate = readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/cert.pem",
          import.meta.url,
        ),
      );
      const privateKey = readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/key.pem",
          import.meta.url,
        ),
      );
      const certificateFile = file("certificate.pem", certificate),
        privateKeyFile = file("key.pem", privateKey);
      // Enable TLS only inside the fixture-owned disposable database.
      for (const [name, value] of [
        ["certificate", certificate],
        ["key", privateKey],
      ]) {
        execFileSync(
          "docker",
          [
            "exec",
            "-i",
            "--user",
            "postgres",
            container,
            "sh",
            "-c",
            `umask 077; cat > /tmp/xeip-owner-${name}.pem`,
          ],
          { input: value, timeout: 30000, stdio: ["pipe", "pipe", "pipe"] },
        );
      }
      await pool.query(
        "ALTER SYSTEM SET ssl_cert_file='/tmp/xeip-owner-certificate.pem'",
      );
      await pool.query(
        "ALTER SYSTEM SET ssl_key_file='/tmp/xeip-owner-key.pem'",
      );
      await pool.query("ALTER SYSTEM SET ssl='on'");
      await pool.query("SELECT pg_reload_conf()");
      const db = (user, passwordFile) => ({
        host: pool.options.host,
        port: pool.options.port,
        name: pool.options.database,
        user,
        passwordFile,
        caFile: certificateFile,
        max: 1,
      });
      const ownerPath = file(
        "owner.json",
        JSON.stringify({
          version: 1,
          database: db(
            pool.options.user,
            file("owner-password", pool.options.password),
          ),
        }),
      );
      const runtimePassword = file("runtime-password", password),
        appSecret = file("app-secret", "synthetic-secret"),
        managementToken = file("management-token", "a".repeat(48));
      const runtimePath = join(directory, "runtime.json");
      const saveRuntime = (value) => {
        const { introspectionClientSecret, ...authentication } =
          value.authentication;
        const serialized = {
          ...value,
          version: 1,
          tls: { certificateFile, privateKeyFile },
          database: db(role, runtimePassword),
          authentication: {
            ...authentication,
            introspectionClientSecretFile: appSecret,
          },
          targets: value.targets.map(({ clientSecret, ...target }) => ({
            ...target,
            clientSecretFile: appSecret,
          })),
          trust: {
            ...value.trust,
            provisioningFile: file(
              "provisioning.json",
              JSON.stringify(value.provisioning),
            ),
          },
          management: {
            host: "127.0.0.1",
            port: 9443,
            tokenFile: managementToken,
          },
        };
        delete serialized.provisioning;
        writeFileSync(runtimePath, JSON.stringify(serialized), { mode: 0o600 });
      };
      const cli = async (args) => {
        const result = await exec(
          process.execPath,
          ["services/organization/control-maintenance.mjs", ...args],
          { timeout: 35000, maxBuffer: 4096 },
        );
        assert.equal(result.stderr, "");
        const value = JSON.parse(result.stdout);
        assert.ok(result.stdout.length < 256);
        return value;
      };
      assert.deepEqual(await cli(["inspect", "--owner-config", ownerPath]), {
        event: "control_empty",
      });
      lease = await openControlLease(runtime.options);
      await assert.rejects(
        maintainControl(pool.options, {
          operation: "enroll",
          configuration: config,
        }),
      );
      assert.equal(existsSync(config.trust.directory), false);
      await lease.close();
      lease = undefined;
      const removed = "urn:xeip:entity:" + fixture.kid;
      const signing = {
        privateKey: Buffer.from(fixture.seed, "hex"),
        kid: fixture.kid,
      };
      const old = {
        keyDocuments: [
          ...config.provisioning.keyDocuments,
          {
            document: signKeyDocument(
              {
                xeip: "xeip.keydoc/0.1",
                entity: removed,
                genesis: fixture.kid,
                generation: 1,
                issuedAt: date(),
                roots: [fixture.kid],
                devices: [],
                signatures: [],
              },
              signing,
            ),
            anchor: { genesisKid: fixture.kid },
          },
        ],
        statusDocuments: [
          ...config.provisioning.statusDocuments,
          {
            document: signStatusDocument(
              {
                xeip: "xeip.status/0.1",
                entity: removed,
                serial: 1,
                issuedAt: date(),
                revoked: [],
                signatures: [],
              },
              signing,
            ),
          },
        ],
      };
      const records = prepareEntityTrust(
        { maxAgeSeconds: 300 },
        old.keyDocuments,
        old.statusDocuments,
        now(),
      ).checkpoints;
      mkdirSync(config.trust.directory, { mode: 0o700 });
      const legacy = join(config.trust.directory, "trust.json"),
        bytes = JSON.stringify({ version: 1, entities: records });
      writeFileSync(legacy, bytes, { mode: 0o600 });
      const firstInput = {
        authority: publicAuthority(config),
        provisioning: config.provisioning,
        acceptedAt: now(),
        retainedRecords: records,
      };
      await assert.rejects(new ControlStore(runtime).enroll(firstInput));
      saveRuntime(config);
      const enrolled = await cli([
        "enroll",
        "--owner-config",
        ownerPath,
        "--runtime-config",
        runtimePath,
        "--expect-empty",
      ]);
      assert.equal(enrolled.event, "control_enrolled");
      assert.equal(enrolled.revision, 1);
      assert.deepEqual(Object.keys(enrolled).sort(), [
        "digest",
        "event",
        "revision",
      ]);
      assert.equal(readFileSync(legacy, "utf8"), bytes);
      assert.equal(existsSync(join(config.trust.directory, "LOCK")), false);
      const stored = async () =>
        verifyControlState(
          (
            await pool.query(
              "SELECT state_canonical FROM xeip_org.control_events ORDER BY revision DESC LIMIT 1",
            )
          ).rows[0].state_canonical,
        ).state;
      assert.deepEqual(
        { ...(await stored()).records[removed] },
        records[removed],
      );
      await assert.rejects(
        maintainControl(pool.options, {
          operation: "enroll",
          configuration: config,
        }),
      );
      const changed = structuredClone(config);
      changed.authentication.audience = "xeip-next";
      changed.provisioning = fresh(3);
      const expected = { revision: enrolled.revision, digest: enrolled.digest };
      await assert.rejects(
        new ControlStore(runtime).changeAuthority(expected, {
          authority: publicAuthority(changed),
          provisioning: changed.provisioning,
          acceptedAt: now(),
        }),
      );
      await assert.rejects(
        maintainControl(pool.options, {
          operation: "change",
          configuration: changed,
          expected: { ...expected, digest: "0".repeat(64) },
        }),
      );
      assert.equal(
        (await maintainControl(pool.options, { operation: "inspect" }))
          .revision,
        1,
      );
      lease = await openControlLease(runtime.options);
      await assert.rejects(
        maintainControl(pool.options, {
          operation: "change",
          configuration: changed,
          expected,
        }),
      );
      await lease.close();
      lease = undefined;
      saveRuntime(changed);
      const updated = await cli([
        "change",
        "--owner-config",
        ownerPath,
        "--runtime-config",
        runtimePath,
        "--expected-revision",
        String(expected.revision),
        "--expected-digest",
        expected.digest,
      ]);
      assert.equal(updated.event, "control_changed");
      assert.equal(updated.revision, 2);
      assert.deepEqual(
        { ...(await stored()).records[removed] },
        records[removed],
      );
      // Inspection requires no fresh provisioning or runtime secret files.
      rmSync(join(directory, "provisioning.json"));
      assert.deepEqual(await cli(["inspect", "--owner-config", ownerPath]), {
        ...updated,
        event: "control_head",
      });
      blocker = await pool.connect();
      await blocker.query("BEGIN");
      await blocker.query(
        "LOCK TABLE xeip_org.control_events IN ACCESS EXCLUSIVE MODE",
      );
      const abort = new AbortController();
      const interrupted = maintainControl(
        pool.options,
        {
          operation: "change",
          configuration: changed,
          expected: { revision: updated.revision, digest: updated.digest },
        },
        { signal: abort.signal },
      );
      const refused = assert.rejects(
        interrupted,
        (e) => e.message === "control_maintenance_failed",
      );
      try {
        let observed = false;
        for (let i = 0; i < 60; i++) {
          const rows = (
            await pool.query(
              "SELECT 1 FROM pg_stat_activity WHERE application_name='xeip-control-lease' AND wait_event_type='Lock' AND query LIKE '%control_events%' ",
            )
          ).rows;
          if (rows.length) {
            observed = true;
            break;
          }
          await delay(50);
        }
        assert.equal(
          observed,
          true,
          "observe command waiting on actual SQL before abort",
        );
      } finally {
        abort.abort();
        await refused;
        await blocker.query("ROLLBACK");
        blocker.release();
        blocker = undefined;
      }
      assert.deepEqual(
        await maintainControl(pool.options, { operation: "inspect" }),
        { ...updated, event: "control_head" },
      );
      await pool.query("CREATE DATABASE xeip_owner_fresh");
      const freshOwner = {
        ...pool.options,
        password: pool.options.password,
        database: "xeip_owner_fresh",
      };
      await maintainDatabase(freshOwner, role);
      const freshConfig = structuredClone(config);
      freshConfig.database.database = freshOwner.database;
      freshConfig.trust.directory = join(directory, "fresh-trust");
      freshConfig.provisioning = fresh(4);
      const first = await maintainControl(freshOwner, {
        operation: "enroll",
        configuration: freshConfig,
      });
      assert.equal(first.event, "control_enrolled");
      assert.equal(first.revision, 1);
      assert.equal(existsSync(freshConfig.trust.directory), false);
      await pool.query("CREATE DATABASE xeip_owner_legacy");
      const legacyOwner = { ...freshOwner, database: "xeip_owner_legacy" };
      legacyPool = new pg.Pool(legacyOwner);
      legacyPool.on("error", () => {});
      const v1 = readFileSync(
        new URL(
          "../services/organization/migrations/001-actions.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await legacyPool.query("CREATE SCHEMA xeip_org");
      await legacyPool.query(v1);
      await legacyPool.query(
        "CREATE TABLE xeip_org.migrations(version integer PRIMARY KEY,checksum text NOT NULL,installed_at timestamptz NOT NULL DEFAULT clock_timestamp())",
      );
      await legacyPool.query(
        "INSERT INTO xeip_org.migrations(version,checksum) VALUES(1,$1)",
        [createHash("sha256").update(v1).digest("hex")],
      );
      await legacyPool.query(
        "INSERT INTO xeip_org.actions(session_id,request_id,digest,canonical,expires_at,state) VALUES ('legacy','one',$1,'{}',1,'pending')",
        ["a".repeat(64)],
      );
      await legacyPool.query(
        "INSERT INTO xeip_org.audit(session_id,request_id,digest,event,actor) VALUES ('legacy','one',$1,'proposed','{}')",
        ["a".repeat(64)],
      );
      await maintainDatabase(legacyOwner, role);
      freshConfig.database.database = legacyOwner.database;
      freshConfig.trust.directory = join(directory, "missing-legacy-history");
      await assert.rejects(
        maintainControl(legacyOwner, {
          operation: "enroll",
          configuration: freshConfig,
        }),
      );
      assert.equal(
        (
          await legacyPool.query(
            "SELECT count(*)::integer AS n FROM xeip_org.control_events",
          )
        ).rows[0].n,
        0,
      );
      assert.equal(
        (
          await legacyPool.query(
            "SELECT count(*)::integer AS n FROM xeip_org.actions",
          )
        ).rows[0].n,
        1,
      );
      assert.equal(
        (
          await legacyPool.query(
            "SELECT count(*)::integer AS n FROM xeip_org.audit",
          )
        ).rows[0].n,
        1,
      );
      assert.equal(existsSync(freshConfig.trust.directory), false);
      console.log(
        JSON.stringify({
          result: "pass",
          controlEvents: 2,
          freshDatabaseEnrolled: true,
          populatedLegacyDatabaseRefused: true,
          removedEntityRecordsPreserved: true,
          legacyCheckpointUnchanged: true,
          runtimeOwnerOperationsDenied: true,
          activeRuntimeExcludesOwner: true,
          staleHeadRefused: true,
          interruptedCommandNoPublication: true,
          headInspectionWithoutProvisioning: true,
          protectedCliVerifiedTls: true,
          scope:
            "actual owned PostgreSQL, protected CLI over verified TLS and programmatic interruption/role tests; physical recovery and operator acceptance remain open",
        }),
      );
    } finally {
      if (blocker) {
        try {
          await blocker.query("ROLLBACK");
        } finally {
          blocker.release(true);
        }
      }
      await lease?.close();
      await legacyPool?.end();
      await runtime.end();
      rmSync(directory, { recursive: true, force: true });
    }
  },
  { baselineChecks: false },
);
