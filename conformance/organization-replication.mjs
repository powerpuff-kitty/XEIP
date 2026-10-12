// Disposable functional recovery drill; never accepts operator endpoints or credentials.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { withPostgres } from "./postgres.mjs";
import { registerFixtureCleanup } from "./fixture-cleanup.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import { ControlStore } from "../services/organization/control-store.mjs";
import { publicAuthority } from "../services/organization/control-state.mjs";
import {
  configuration,
  provisioning,
  acceptedAt,
  fixture,
} from "../services/organization/test-fixtures/control.mjs";
import {
  ActionStore,
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/store.mjs";
const docker = (args) =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: 60000,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
async function until(check, label) {
  for (let i = 0; i < 120; i++) {
    if (await check().catch(() => false)) return;
    await delay(250);
  }
  throw new Error("replication fixture readiness failed: " + label);
}
let phase = "primary-fixture";
async function drill({ pool, container, image, destroyPrimary }) {
  const suffix = process.pid + "-" + randomBytes(4).toString("hex");
  const network = "xeip-replication-" + suffix,
    volume = network + "-data",
    standby = network + "-standby",
    backup = network + "-backup";
  const directory = mkdtempSync(join(tmpdir(), "xeip-replication-"));
  const passfile = join(directory, "replication-password");
  const secret = randomBytes(32).toString("hex");
  writeFileSync(passfile, "xeip-primary:5432:*:xeip_replica:" + secret + "\n", {
    mode: 0o444,
  });
  let networkCreated = false,
    volumeCreated = false,
    replica,
    clientPool;
  const created = new Set();
  const cleanup = async () => {
    let failed = false;
    for (const connection of [clientPool, replica]) {
      try {
        await connection?.end();
      } catch {
        failed = true;
      }
    }
    clientPool = replica = undefined;
    for (const name of [...created].reverse()) {
      try {
        docker(["rm", "-f", name]);
        created.delete(name);
      } catch {
        failed = true;
      }
    }
    if (networkCreated) {
      try {
        docker(["network", "disconnect", "-f", network, container]);
      } catch {}
      try {
        docker(["network", "rm", network]);
        networkCreated = false;
      } catch {
        failed = true;
      }
    }
    if (volumeCreated) {
      try {
        docker(["volume", "rm", volume]);
        volumeCreated = false;
      } catch {
        failed = true;
      }
    }
    rmSync(directory, { recursive: true, force: true });
    if (failed) throw new Error("owned replication fixture cleanup failed");
  };
  const unregister = registerFixtureCleanup(cleanup);
  try {
    phase = "standby-setup";
    docker(["network", "create", "--internal", network]);
    networkCreated = true;
    docker([
      "network",
      "connect",
      "--alias",
      "xeip-primary",
      network,
      container,
    ]);
    // Hex-only generated fixture password, never caller-supplied SQL or diagnostics.
    await pool.query(
      "CREATE ROLE xeip_replica WITH LOGIN REPLICATION PASSWORD '" +
        secret +
        "'",
    );
    docker([
      "exec",
      container,
      "sh",
      "-c",
      'printf "%s\\n" "host replication xeip_replica all scram-sha-256" >> "$PGDATA/pg_hba.conf"',
    ]);
    await pool.query("SELECT pg_reload_conf()");
    docker(["volume", "create", volume]);
    volumeCreated = true;
    const common = [
      "--network",
      network,
      "--memory",
      "512m",
      "--cpus",
      "1",
      "--mount",
      "type=volume,src=" + volume + ",dst=/var/lib/postgresql",
    ];
    docker([
      "create",
      "--name",
      backup,
      ...common,
      "--mount",
      "type=bind,src=" +
        passfile +
        ",dst=/run/fixture-replica-password,readonly",
      "--entrypoint",
      "sh",
      image,
      "-c",
      'install -d -m 0700 -o postgres -g postgres "$PGDATA"; cp /run/fixture-replica-password /var/lib/postgresql/replication.pgpass; chown postgres:postgres /var/lib/postgresql/replication.pgpass; chmod 0600 /var/lib/postgresql/replication.pgpass; exec gosu postgres pg_basebackup -D "$PGDATA" -R -X stream -c fast -d "host=xeip-primary user=xeip_replica application_name=xeip_sync_standby passfile=/var/lib/postgresql/replication.pgpass"',
    ]);
    created.add(backup);
    docker(["start", "-a", backup]);
    assert.equal(
      JSON.parse(docker(["inspect", backup]))[0].State.ExitCode,
      0,
      "base backup failed",
    );
    docker(["rm", backup]);
    created.delete(backup);
    docker([
      "create",
      "--name",
      standby,
      ...common.slice(2),
      "-p",
      "127.0.0.1::5432",
      image,
      "postgres",
      "-c",
      "synchronous_standby_names=FIRST 1 (xeip_required_replacement)",
    ]);
    created.add(standby);
    docker(["network", "connect", network, standby]);
    docker(["start", standby]);
    const port = Number(
      JSON.parse(
        docker([
          "inspect",
          "--format",
          "{{json .NetworkSettings.Ports}}",
          standby,
        ]),
      )["5432/tcp"][0].HostPort,
    );
    const options = {
      host: "127.0.0.1",
      port,
      user: "postgres",
      password: pool.options.password,
      database: "xeip_fixture",
      max: 2,
      connectionTimeoutMillis: 3000,
      query_timeout: 10000,
    };
    replica = new pg.Pool(options);
    replica.on("error", () => {});
    await until(
      async () =>
        (await replica.query("SELECT pg_is_in_recovery() AS recovery")).rows[0]
          .recovery,
      "standby",
    );
    await pool.query(
      "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (xeip_sync_standby)'",
    );
    await pool.query("SELECT pg_reload_conf()");
    await until(
      async () =>
        (
          await pool.query(
            "SELECT 1 FROM pg_stat_replication WHERE application_name='xeip_sync_standby' AND state='streaming' AND sync_state='sync'",
          )
        ).rowCount === 1,
      "synchronous streaming",
    );
    console.log(
      "PASS dedicated synchronous standby is streaming on separate fixture storage",
    );
    clientPool = new pg.Pool({
      ...pool.options,
      password: pool.options.password,
      max: 1,
      query_timeout: 10000,
      application_name: "xeip-replication-drill",
      options: "-c client_min_messages=error",
    });
    clientPool.on("error", () => {});
    phase = "control-transitions";
    const control = new ControlStore(clientPool);
    const controlInput = (serial) => ({
      authority: publicAuthority(configuration()),
      provisioning: provisioning(
        serial,
        serial > 1 ? [{ kid: fixture.kid, generation: 1 }] : [],
      ),
      acceptedAt: acceptedAt + serial,
    });
    const initialControl = await control.enroll({
      ...controlInput(1),
      retainedRecords: {},
    });
    const acknowledgedControl = await control.publishTrust(
      initialControl,
      controlInput(2),
    );
    const acknowledgedControlEvents = (
      await pool.query(
        "SELECT * FROM xeip_org.control_events ORDER BY revision",
      )
    ).rows;
    const entity =
        "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
      kid = entity.slice("urn:xeip:entity:".length),
      now = Math.floor(Date.now() / 1000);
    const agent = Object.freeze({
      subject: "replication-agent",
      entity,
      kid,
      clientId: "agent",
      roles: Object.freeze(["agent"]),
      expiresAt: now + 300,
    });
    const humanEntity =
      "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
    const human = Object.freeze({
      ...agent,
      entity: humanEntity,
      kid: humanEntity.slice("urn:xeip:entity:".length),
      subject: "replication-human",
      roles: Object.freeze(["approver"]),
      clientId: "console",
    });
    const session = "urn:xeip:session:replication";
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
    const store = new ActionStore(clientPool, policy, async () => true);
    const request = (id) => ({
      id,
      session,
      target: "internal",
      tool: "lookup",
      arguments: { fixture: true },
      expiresAt: now + 240,
    });
    phase = "action-transitions";
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
      const id = "urn:xeip:replication:" + state;
      phase = "action-" + state;
      const proposed = await store.propose(agent, request(id));
      if (state === "rejected")
        await store.decide(
          human,
          session,
          id,
          proposed.proposal.digest,
          "reject",
        );
      else if (state === "revoked")
        await store.revoke(agent, session, id, proposed.proposal.digest);
      else if (state !== "pending") {
        await store.decide(
          human,
          session,
          id,
          proposed.proposal.digest,
          "approve",
        );
        if (state !== "approved") {
          const claim = await store.claim(
            agent,
            session,
            id,
            proposed.proposal.digest,
          );
          claims.push({
            id,
            digest: proposed.proposal.digest,
            claimId: claim.claimId,
          });
          if (state !== "executing")
            await store.finish(session, id, claim.claimId, state);
        }
      }
    }
    const acknowledged = (
      await pool.query(
        "SELECT * FROM xeip_org.actions WHERE session_id=$1 ORDER BY request_id",
        [session],
      )
    ).rows;
    const acknowledgedAudit = (
      await pool.query(
        "SELECT * FROM xeip_org.audit WHERE session_id=$1 ORDER BY sequence",
        [session],
      )
    ).rows;
    phase = "cancelled-commit";
    // Cancellation of a synchronous COMMIT must never be reported as a durable success.
    await pool.query(
      "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (xeip_missing_standby)'",
    );
    await pool.query("SELECT pg_reload_conf()");
    await until(
      async () =>
        (
          await pool.query("SHOW synchronous_standby_names")
        ).rows[0].synchronous_standby_names.includes("xeip_missing_standby"),
      "missing standby configuration",
    );
    docker(["pause", standby]);
    const uncertainRequest = request("urn:xeip:replication:uncertain");
    async function refused(operation, database) {
      let settled = false,
        blockedPid;
      const pending = operation().then(
        (value) => {
          settled = true;
          return { value };
        },
        (error) => {
          settled = true;
          return { error };
        },
      );
      await until(async () => {
        const rows = (
          await database.query(
            "SELECT pid FROM pg_stat_activity WHERE wait_event='SyncRep' AND usename=current_user",
          )
        ).rows;
        blockedPid = rows[0]?.pid;
        return settled || !!blockedPid;
      }, "unacknowledged commit");
      assert.ok(
        blockedPid,
        "every successful result must wait for configured synchronous durability",
      );
      await database.query("SELECT pg_cancel_backend($1)", [blockedPid]);
      const outcome = await pending;
      assert.ok(
        outcome.error instanceof StoreUnavailable,
        "cancelled synchronous commit must not acknowledge an action",
      );
    }
    await refused(() => store.propose(agent, uncertainRequest), pool);
    assert.equal(
      (
        await pool.query(
          "SELECT count(*) FROM xeip_org.actions WHERE request_id=$1",
          [uncertainRequest.id],
        )
      ).rows[0].count,
      "1",
    );
    await refused(
      () => store.inspect(agent, session, uncertainRequest.id),
      pool,
    );
    await refused(() => store.propose(agent, uncertainRequest), pool);
    console.log("PASS cancelled synchronous commit refuses acknowledgement");
    await refused(
      () => control.publishTrust(acknowledgedControl, controlInput(3)),
      pool,
    );
    assert.equal(
      (await pool.query("SELECT revision::text FROM xeip_org.control_head"))
        .rows[0].revision,
      "3",
    );
    await refused(() => control.open(controlInput(3)), pool);
    console.log(
      "PASS cancelled control publication and reopen refuse acknowledgement",
    );
    // Destroy the old primary before promotion. No automatic failback or dual writer.
    const started = performance.now();
    phase = "promote-and-reconcile";
    destroyPrimary();
    docker(["unpause", standby]);
    await clientPool.end();
    clientPool = undefined;
    assert.equal(
      (await replica.query("SELECT pg_promote(true,30) AS promoted")).rows[0]
        .promoted,
      true,
    );
    assert.equal(
      (await replica.query("SELECT pg_is_in_recovery() AS recovery")).rows[0]
        .recovery,
      false,
    );
    const ids = acknowledged.map((row) => row.request_id);
    assert.deepEqual(
      (
        await replica.query(
          "SELECT * FROM xeip_org.control_events WHERE revision<=2 ORDER BY revision",
        )
      ).rows,
      acknowledgedControlEvents,
    );
    assert.deepEqual(
      (
        await replica.query(
          "SELECT * FROM xeip_org.actions WHERE session_id=$1 AND request_id=ANY($2) ORDER BY request_id",
          [session, ids],
        )
      ).rows,
      acknowledged,
    );
    assert.deepEqual(
      (
        await replica.query(
          "SELECT * FROM xeip_org.audit WHERE session_id=$1 AND request_id=ANY($2) ORDER BY sequence",
          [session, ids],
        )
      ).rows,
      acknowledgedAudit,
    );
    const recovered = new ActionStore(replica, policy, async () => true);
    for (const claim of claims) {
      assert.equal(
        acknowledged.find((row) => row.request_id === claim.id).claim_id,
        claim.claimId,
      );
      await assert.rejects(
        recovered.claim(agent, session, claim.id, claim.digest),
        StoreConflict,
      );
    }
    assert.match(
      (await replica.query("SHOW synchronous_standby_names")).rows[0]
        .synchronous_standby_names,
      /xeip_required_replacement/,
    );
    await refused(
      () => recovered.inspect(agent, session, claims[0].id),
      replica,
    );
    console.log(
      JSON.stringify({
        result: "pass",
        acknowledgedActions: acknowledged.length,
        consumedClaims: claims.length,
        failoverMs: performance.now() - started,
        note: "Local two-container functional evidence; hosted recovery time and independent failure-domain acceptance remain unproven.",
      }),
    );
  } catch (error) {
    const diagnostic = String(error.stderr ?? error.message)
      .replaceAll(secret, "[redacted]")
      .replaceAll(pool.options.password, "[redacted]");
    console.error("Fixture diagnostic: " + diagnostic.slice(0, 2000));
    throw error;
  } finally {
    // Restore only the still-existing owned primary so cleanup cannot wait on a missing peer.
    try {
      docker(["inspect", container]);
      await pool.query("ALTER SYSTEM SET synchronous_standby_names = ''");
      await pool.query("SELECT pg_reload_conf()");
    } catch {}
    try {
      await cleanup();
    } finally {
      unregister();
    }
  }
}
try {
  await withPostgres(drill, { baselineChecks: false });
} catch {
  console.error(
    "PostgreSQL replication drill failed at " +
      phase +
      "; no recovery acceptance was established.",
  );
  process.exitCode = 1;
}
