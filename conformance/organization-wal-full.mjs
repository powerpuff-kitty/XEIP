// Real WAL ENOSPC/recovery in an isolated disposable fixture, never an operator database.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { withPostgres } from "./postgres.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import {
  ActionStore,
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/store.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
const docker = (args) =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: 30000,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
async function until(check, label) {
  for (let i = 0; i < 120; i++) {
    if (await check().catch(() => false)) return;
    await delay(250);
  }
  throw new Error("fixture readiness failed: " + label);
}
let phase = "primary-fixture";
async function drill({ pool, container }) {
  const session = "urn:xeip:session:wal-full";
  const entities = [
    "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
    "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
  ];
  const principal = (subject, entity, role) =>
    Object.freeze({
      subject,
      entity,
      kid: entity.slice("urn:xeip:entity:".length),
      clientId: "fixture",
      roles: Object.freeze([role]),
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    });
  const agent = principal("fixture-agent", entities[0], "agent"),
    human = principal("fixture-human", entities[1], "approver");
  const policy = new ActionPolicy({
    targets: [
      {
        id: "internal",
        revision: "1",
        recipient: entities[1],
        tools: ["lookup"],
      },
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
  let inject = false,
    boundaryReached = false;
  const observedPool = {
    options: pool.options,
    connect: async () => {
      const client = await pool.connect();
      return {
        release: (broken) => client.release(broken),
        on: (...args) => client.on(...args),
        removeListener: (...args) => client.removeListener(...args),
        query: async (...args) => {
          if (inject && args[0] === "COMMIT") {
            inject = false;
            boundaryReached = true;
            // Real writes inside the pending claim transaction, not a simulated driver error.
            // A reserved physical slot prevents recycling earlier segments around the bound.
            for (let i = 0; i < 8; i++) {
              await client.query(
                "SELECT pg_catalog.pg_logical_emit_message(true, 'xeip.fixture', ''::text, false)",
              );
              await client.query("SELECT pg_switch_wal()");
            }
            assert.fail(
              "WAL growth unexpectedly succeeded on the full bounded mount",
            );
          }
          return client.query(...args);
        },
      };
    },
  };
  const store = new ActionStore(observedPool, policy, async () => true);
  const request = (id) => ({
    id,
    session,
    target: "internal",
    tool: "lookup",
    arguments: { fixture: true },
    expiresAt: Math.floor(Date.now() / 1000) + 240,
  });
  const snapshot = async () => ({
    actions: (
      await pool.query(
        "SELECT * FROM xeip_org.actions ORDER BY session_id,request_id",
      )
    ).rows,
    audit: (await pool.query("SELECT * FROM xeip_org.audit ORDER BY sequence"))
      .rows,
  });
  phase = "acknowledged-actions";
  const claims = [];
  for (const state of ["executing", "succeeded"]) {
    const id = "urn:xeip:wal-full:" + state;
    const proposal = await store.propose(agent, request(id));
    const digest = proposal.proposal.digest;
    await store.decide(human, session, id, digest, "approve");
    const claim = await store.claim(agent, session, id, digest);
    claims.push({ id, digest, claimId: claim.claimId });
    if (state === "succeeded")
      await store.finish(session, id, claim.claimId, state);
  }
  const waitingId = "urn:xeip:wal-full:waiting";
  const waiting = await store.propose(agent, request(waitingId));
  await store.decide(
    human,
    session,
    waitingId,
    waiting.proposal.digest,
    "approve",
  );
  const acknowledged = await snapshot();
  phase = "bounded-wal-mount";
  assert.equal(
    docker(["exec", container, "sh", "-c", 'readlink "$PGDATA/pg_wal"']),
    "/xeip-wal",
  );
  const mount = JSON.parse(
    docker(["inspect", "--format", "{{json .HostConfig.Mounts}}", container]),
  ).find((value) => value.Target === "/xeip-wal");
  assert.equal(mount.Type, "tmpfs");
  assert.equal(mount.TmpfsOptions.SizeBytes, 64 * 1024 * 1024);
  await pool.query(
    "SELECT pg_create_physical_replication_slot('xeip_fault', true)",
  );
  const fill = spawnSync(
    "docker",
    [
      "exec",
      "--user",
      "postgres",
      container,
      "dd",
      "if=/dev/zero",
      "of=/xeip-wal/xeip-fill",
      "bs=1048576",
      "count=64",
    ],
    { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] },
  );
  assert.equal(fill.error, undefined);
  assert.equal(fill.status, 1);
  assert.match(fill.stderr, /No space left on device/);
  phase = "claim-wal-exhaustion";
  let effects = 0;
  const execute = createActionExecutor(policy, {
    call: async () => {
      effects++;
      return null;
    },
  });
  inject = true;
  await assert.rejects(
    execute(
      agent,
      { session, id: waitingId, digest: waiting.proposal.digest },
      { store, authorize: async () => true },
    ),
    StoreUnavailable,
  );
  assert.equal(boundaryReached, true, "must reach real claim commit boundary");
  assert.equal(
    effects,
    0,
    "an unacknowledged claim must not reach the connector",
  );
  phase = "server-shutdown";
  await until(
    async () =>
      docker(["exec", container, "test", "-f", "/tmp/xeip-postgres-exited"]) ===
      "",
    "database exit",
  );
  const stopped = spawnSync(
    "docker",
    ["exec", "--user", "postgres", container, "pg_ctl", "status"],
    { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] },
  );
  assert.equal(
    stopped.status,
    3,
    "PostgreSQL must have stopped while its container remains alive",
  );
  // Read server diagnostics internally; never print raw SQL, paths or credentials.
  const logs = spawnSync("docker", ["logs", container], {
    encoding: "utf8",
    timeout: 30000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(logs.status, 0);
  const diagnostics = logs.stdout + logs.stderr;
  assert.match(diagnostics, /PANIC:.*pg_wal.*No space left on device/);
  console.log(
    "PASS actual WAL ENOSPC terminates PostgreSQL and the pending claim reaches no connector",
  );
  phase = "restore-capacity";
  docker([
    "exec",
    "--user",
    "postgres",
    container,
    "rm",
    "/xeip-wal/xeip-fill",
  ]);
  // Preserve all WAL and data. Do not reset WAL or reinitialize the cluster.
  docker([
    "exec",
    "--user",
    "postgres",
    container,
    "pg_ctl",
    "start",
    "-w",
    "-t",
    "25",
    "-l",
    "/tmp/xeip-recovered.log",
    "-o",
    "-c restart_after_crash=off",
  ]);
  await until(
    async () => (await pool.query("SELECT 1")).rowCount === 1,
    "recovered database",
  );
  phase = "acknowledgement-reconciliation";
  assert.deepEqual(
    await snapshot(),
    acknowledged,
    "native crash recovery must preserve every acknowledged action/audit and roll back the interrupted claim",
  );
  for (const claim of claims) {
    await assert.rejects(
      store.claim(agent, session, claim.id, claim.digest),
      StoreConflict,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT claim_id FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2",
          [session, claim.id],
        )
      ).rows[0].claim_id,
      claim.claimId,
    );
  }
  assert.equal(
    (await store.inspect(agent, session, waitingId)).state,
    "approved",
  );
  const recoveredRequest = request("urn:xeip:wal-full:after-recovery");
  const proposed = await store.propose(agent, recoveredRequest);
  assert.equal(proposed.state, "pending");
  assert.deepEqual(await store.propose(agent, recoveredRequest), proposed);
  assert.equal(effects, 0);
  console.log(
    JSON.stringify({
      result: "pass",
      acknowledgedActions: acknowledged.actions.length,
      consumedClaims: claims.length,
      effectsDuringFailedClaim: effects,
      recoveredProposal: 1,
      note: "Bounded container-local WAL filesystem failure and native restart; not independent storage, physical corruption or hosted recovery certification.",
    }),
  );
}
try {
  await withPostgres(drill, { baselineChecks: false, walFault: true });
} catch {
  console.error("PostgreSQL WAL-full fixture failed at " + phase);
  process.exitCode = 1;
}
