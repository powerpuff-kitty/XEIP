// Physical archive recovery against owned disposable fixtures only.
// Never accepts operator endpoints, credentials, archive paths or containers.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, cpSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { withPostgres } from "./postgres.mjs";
import { registerFixtureCleanup } from "./fixture-cleanup.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import {
  ActionStore,
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/store.mjs";
import {
  verifyDatabase,
  DatabaseNotReady,
} from "../services/organization/database.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";

const docker = (args) =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: 60000,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
function containerLog(name) {
  // PostgreSQL logs use stderr; docker logs preserves that stream distinction.
  const result = spawnSync("docker", ["logs", name], {
    encoding: "utf8",
    timeout: 10000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.status, 0, "fixture log collection failed");
  return result.stdout + result.stderr;
}
async function until(check, label) {
  for (let i = 0; i < 120; i++) {
    if (await check().catch(() => false)) return;
    await delay(250);
  }
  throw new Error("archive fixture readiness failed: " + label);
}
const snapshot = async (database) => ({
  actions: (
    await database.query(
      "SELECT * FROM xeip_org.actions ORDER BY session_id,request_id",
    )
  ).rows,
  audit: (
    await database.query("SELECT * FROM xeip_org.audit ORDER BY sequence")
  ).rows,
});
const hostPort = (name) =>
  Number(
    JSON.parse(
      docker(["inspect", "--format", "{{json .NetworkSettings.Ports}}", name]),
    )["5432/tcp"][0].HostPort,
  );
let phase = "primary-fixture";
async function drill({ pool, container, image, destroyPrimary }) {
  const suffix = process.pid + "-" + randomBytes(4).toString("hex");
  const prefix = "xeip-archive-recovery-" + suffix;
  const directory = mkdtempSync(join(tmpdir(), "xeip-archive-recovery-"));
  const created = new Set(),
    connections = new Set();
  const cleanup = async () => {
    let failed = false;
    for (const connection of connections) {
      try {
        await connection.end();
        connections.delete(connection);
      } catch {
        failed = true;
      }
    }
    for (const name of [...created].reverse()) {
      try {
        const ownership = spawnSync(
          "docker",
          [
            "inspect",
            "--format",
            '{{ index .Config.Labels "xeip.archive-recovery" }}',
            name,
          ],
          {
            encoding: "utf8",
            timeout: 10000,
          },
        );
        if (
          ownership.status === 1 &&
          ownership.stderr.trim() === "Error: No such object: " + name
        ) {
          created.delete(name);
          continue;
        }
        assert.equal(
          ownership.status,
          0,
          "fixture ownership inspection failed",
        );
        assert.equal(
          ownership.stdout.trim(),
          prefix,
          "refuse cleanup of foreign container",
        );
        docker(["rm", "-f", "-v", name]);
        created.delete(name);
      } catch {
        failed = true;
      }
    }
    rmSync(directory, { recursive: true, force: true });
    if (failed) {
      if (created.size)
        console.error(
          "Inspect owned archive-recovery candidates: " +
            [...created].join(", "),
        );
      throw new Error("owned archive-recovery fixture cleanup failed");
    }
  };
  const unregister = registerFixtureCleanup(cleanup);
  try {
    phase = "configure-archive";
    docker([
      "exec",
      container,
      "install",
      "-d",
      "-m",
      "0700",
      "-o",
      "postgres",
      "-g",
      "postgres",
      "/tmp/xeip-archive",
    ]);
    await pool.query("ALTER SYSTEM SET archive_mode = 'on'");
    // One fixture archiver, fixed local paths. Publish only a synchronized copy;
    // an existing final file must match rather than be silently overwritten.
    await pool.query(
      `ALTER SYSTEM SET archive_command = 'if test -f /tmp/xeip-archive/%f; then cmp %p /tmp/xeip-archive/%f && sync /tmp/xeip-archive/%f; else cp %p /tmp/xeip-archive/%f.tmp && sync /tmp/xeip-archive/%f.tmp && mv /tmp/xeip-archive/%f.tmp /tmp/xeip-archive/%f && sync /tmp/xeip-archive; fi'`,
    );
    docker(["restart", container]);
    pool.options.port = hostPort(container);
    await until(
      async () =>
        (await pool.query("SHOW archive_mode")).rows[0].archive_mode === "on",
      "archive configuration",
    );
    await verifyDatabase(pool, { runtime: false });
    const entity =
      "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
    const humanEntity =
      "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
    const principal = (subject, identity, role) =>
      Object.freeze({
        subject,
        entity: identity,
        kid: identity.slice("urn:xeip:entity:".length),
        clientId: "archive-fixture",
        roles: Object.freeze([role]),
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });
    const agent = principal("archive-agent", entity, "agent");
    const human = principal("archive-human", humanEntity, "approver");
    const session = "urn:xeip:session:archive-recovery";
    const policy = new ActionPolicy({
      targets: [
        { id: "internal", revision: "1", recipient: entity, tools: ["lookup"] },
      ],
      sessions: [
        {
          id: session,
          agents: [agent.subject],
          approvers: [human.subject],
          targets: ["internal"],
        },
      ],
    });
    const store = new ActionStore(pool, policy, async () => true);
    const request = (id) => ({
      id,
      session,
      target: "internal",
      tool: "lookup",
      arguments: { fixture: true },
      expiresAt: Math.floor(Date.now() / 1000) + 290,
    });
    await store.propose(agent, request("urn:xeip:archive:before-base"));
    const baseCut = await snapshot(pool);
    phase = "physical-base-backup";
    docker([
      "exec",
      "--user",
      "postgres",
      container,
      "pg_basebackup",
      "-U",
      "postgres",
      "-h",
      "/var/run/postgresql",
      "-D",
      "/tmp/xeip-base",
      "-X",
      "stream",
      "-c",
      "fast",
    ]);
    docker([
      "exec",
      "--user",
      "postgres",
      container,
      "pg_verifybackup",
      "/tmp/xeip-base",
    ]);
    docker(["cp", container + ":/tmp/xeip-base", join(directory, "base")]);
    console.log(
      "PASS native physical base backup verifies before post-backup actions",
    );
    phase = "post-base-actions";
    const claims = [];
    for (const state of [
      "pending",
      "approved",
      "executing",
      "succeeded",
      "failed",
      "indeterminate",
      "rejected",
      "revoked",
    ]) {
      const id = "urn:xeip:archive:" + state;
      const proposed = await store.propose(agent, request(id));
      const digest = proposed.proposal.digest;
      if (state === "rejected")
        await store.decide(human, session, id, digest, "reject");
      else if (state === "revoked")
        await store.revoke(agent, session, id, digest);
      else if (state !== "pending") {
        await store.decide(human, session, id, digest, "approve");
        if (state !== "approved") {
          const claim = await store.claim(agent, session, id, digest);
          claims.push({ id, digest, claimId: claim.claimId });
          if (state !== "executing")
            await store.finish(session, id, claim.claimId, state);
        }
      }
    }
    const acknowledged = await snapshot(pool);
    assert.equal(acknowledged.actions.length, baseCut.actions.length + 8);
    assert.ok(acknowledged.audit.length > baseCut.audit.length);
    phase = "seal-archived-cut";
    const target = "xeip_acknowledged_cut";
    const lsn = (
      await pool.query("SELECT pg_create_restore_point($1) AS lsn", [target])
    ).rows[0].lsn;
    const segment = (
      await pool.query("SELECT pg_walfile_name($1::pg_lsn) AS name", [lsn])
    ).rows[0].name;
    assert.match(segment, /^[0-9A-F]{24}$/);
    await pool.query("SELECT pg_switch_wal()");
    await until(async () => {
      const row = (
        await pool.query("SELECT last_archived_wal FROM pg_stat_archiver")
      ).rows[0];
      return row.last_archived_wal && row.last_archived_wal >= segment;
    }, "acknowledged cut archived");
    docker([
      "cp",
      container + ":/tmp/xeip-archive",
      join(directory, "archive"),
    ]);
    assert.ok(readdirSync(join(directory, "archive")).includes(segment));
    // Omit the segment that contains post-base commits and the required target.
    mkdirSync(join(directory, "incomplete"), { mode: 0o700 });
    for (const file of readdirSync(join(directory, "archive"))) {
      if (file !== segment)
        cpSync(
          join(directory, "archive", file),
          join(directory, "incomplete", file),
        );
    }
    phase = "destroy-source";
    destroyPrimary();
    let sourceExists = true;
    try {
      docker(["inspect", container]);
    } catch {
      sourceExists = false;
    }
    assert.equal(
      sourceExists,
      false,
      "source must be destroyed before restoration",
    );
    const recoveryStarted = performance.now();
    const candidate = (label, archive) => {
      const name = prefix + "-" + label;
      // Register before the request: a lost create response can still leave a
      // daemon-side container/volume. Cleanup verifies the unique ownership label.
      created.add(name);
      docker([
        "create",
        "--name",
        name,
        "--label",
        "xeip.archive-recovery=" + prefix,
        "--memory",
        "512m",
        "--cpus",
        "1",
        "-p",
        "127.0.0.1::5432",
        "--mount",
        "type=bind,src=" + directory + ",dst=/source,readonly",
        "--entrypoint",
        "sh",
        image,
        "-c",
        'set -e; install -d -m 0700 -o postgres -g postgres "$PGDATA" /recovery-archive; cp -a /source/base/. "$PGDATA"/; cp -a /source/' +
          archive +
          '/. /recovery-archive/; chown -R postgres:postgres "$PGDATA" /recovery-archive; gosu postgres pg_verifybackup "$PGDATA"; touch "$PGDATA/recovery.signal"; chown postgres:postgres "$PGDATA/recovery.signal"; exec docker-entrypoint.sh postgres -c archive_mode=off -c "restore_command=cp /recovery-archive/%f %p" -c recovery_target_name=' +
          target +
          " -c recovery_target_action=pause",
      ]);
      docker(["start", name]);
      return name;
    };
    phase = "missing-segment-refusal";
    const incomplete = candidate("incomplete", "incomplete");
    await until(
      async () =>
        JSON.parse(docker(["inspect", incomplete]))[0].State.Running === false,
      "incomplete archive failure",
    );
    const failure = JSON.parse(docker(["inspect", incomplete]))[0].State;
    assert.notEqual(failure.ExitCode, 0);
    const failureLog = containerLog(incomplete);
    assert.match(
      failureLog,
      /recovery ended before configured recovery target was reached/,
    );
    assert.doesNotMatch(
      failureLog,
      /database system is ready to accept connections\n/,
    );
    console.log(
      "PASS missing archived segment prevents required target recovery",
    );
    phase = "complete-archive-restore";
    const restored = candidate("complete", "archive");
    const recovered = new pg.Pool({
      host: "127.0.0.1",
      port: hostPort(restored),
      user: "postgres",
      password: pool.options.password,
      database: "xeip_fixture",
      max: 2,
      connectionTimeoutMillis: 1000,
      query_timeout: 5000,
    });
    recovered.on("error", () => {});
    connections.add(recovered);
    await until(async () => {
      const r = (
        await recovered.query(
          "SELECT pg_is_in_recovery() AS recovery, pg_get_wal_replay_pause_state() AS state",
        )
      ).rows[0];
      return r.recovery && r.state === "paused";
    }, "paused recovery target");
    assert.equal(
      (await recovered.query("SHOW transaction_read_only")).rows[0]
        .transaction_read_only,
      "on",
    );
    assert.deepEqual(await snapshot(recovered), acknowledged);
    assert.equal(
      (
        await recovered.query(
          "SELECT pg_last_wal_replay_lsn() >= $1::pg_lsn AS reached",
          [lsn],
        )
      ).rows[0].reached,
      true,
    );
    await assert.rejects(
      verifyDatabase(recovered, { runtime: false }),
      DatabaseNotReady,
    );
    const restoredStore = new ActionStore(recovered, policy, async () => true);
    let effects = 0;
    const execute = createActionExecutor(policy, {
      call: async () => {
        effects++;
        return null;
      },
    });
    const command = claims[0];
    await assert.rejects(
      execute(
        agent,
        { session, id: command.id, digest: command.digest },
        { store: restoredStore, authorize: async () => true },
      ),
      StoreUnavailable,
    );
    assert.equal(effects, 0);
    console.log(
      "PASS paused target has exact acknowledged actions/audit and refuses runtime writes",
    );
    phase = "fixture-promotion-and-replay-check";
    await recovered.query("SELECT pg_wal_replay_resume()");
    await until(
      async () =>
        !(await recovered.query("SELECT pg_is_in_recovery() AS recovery"))
          .rows[0].recovery,
      "fixture promotion",
    );
    await verifyDatabase(recovered, { runtime: false });
    for (const claim of claims) {
      await assert.rejects(
        execute(
          agent,
          { session, id: claim.id, digest: claim.digest },
          { store: restoredStore, authorize: async () => true },
        ),
        StoreConflict,
      );
      assert.equal(
        (
          await recovered.query(
            "SELECT claim_id FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2",
            [session, claim.id],
          )
        ).rows[0].claim_id,
        claim.claimId,
      );
    }
    assert.equal(effects, 0);
    assert.deepEqual(await snapshot(recovered), acknowledged);
    console.log(
      JSON.stringify({
        result: "pass",
        baseActions: baseCut.actions.length,
        acknowledgedActions: acknowledged.actions.length,
        auditEvents: acknowledged.audit.length,
        postBaseActions: 8,
        consumedClaims: claims.length,
        repeatedEffects: effects,
        recoveryMs: performance.now() - recoveryStarted,
        note: "Explicitly archived cut after physical backup; not arbitrary-failure zero-RPO, independent storage or whole-organization recovery.",
      }),
    );
  } finally {
    try {
      await cleanup();
    } finally {
      unregister();
    }
  }
}
try {
  await withPostgres(drill, { baselineChecks: false });
} catch (error) {
  const code =
    typeof error.code === "string" && /^[A-Z0-9_]{1,40}$/.test(error.code)
      ? error.code
      : "unclassified";
  console.error(
    "PostgreSQL archive recovery fixture failed at " +
      phase +
      " (" +
      code +
      ")",
  );
  process.exitCode = 1;
}
