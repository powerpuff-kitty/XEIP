// Real ENOSPC in a disposable container only; never accepts operator targets.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { withPostgres } from "./postgres.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import {
  ActionStore,
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/store.mjs";
const docker = (args) =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: 30000,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
let phase = "primary-fixture";
async function drill({ pool, container }) {
  const session = "urn:xeip:session:disk-full";
  const entity =
    "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
  const other =
    "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
  const principal = (subject, entity, role) =>
    Object.freeze({
      subject,
      clientId: "fixture",
      entity,
      kid: entity.slice("urn:xeip:entity:".length),
      roles: Object.freeze([role]),
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    });
  const agent = principal("fixture-agent", entity, "agent");
  const human = principal("fixture-human", other, "approver");
  const policy = new ActionPolicy({
    targets: [
      { id: "internal", revision: "1", recipient: other, tools: ["lookup"] },
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
  let databaseFailure;
  const observedPool = {
    options: pool.options,
    connect: async () => {
      const client = await pool.connect();
      return {
        release: (broken) => client.release(broken),
        on: (...args) => client.on(...args),
        removeListener: (...args) => client.removeListener(...args),
        query: async (...args) => {
          try {
            return await client.query(...args);
          } catch (error) {
            databaseFailure = { code: error.code, query: args[0] };
            throw error;
          }
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
    const id = "urn:xeip:disk-full:" + state;
    const proposed = await store.propose(agent, request(id));
    const digest = proposed.proposal.digest;
    await store.decide(human, session, id, digest, "approve");
    const claim = await store.claim(agent, session, id, digest);
    claims.push({ id, digest, claimId: claim.claimId });
    if (state === "succeeded")
      await store.finish(session, id, claim.claimId, state);
  }
  const waitingId = "urn:xeip:disk-full:" + "x".repeat(100);
  const waiting = await store.propose(agent, request(waitingId));
  await store.decide(
    human,
    session,
    waitingId,
    waiting.proposal.digest,
    "approve",
  );
  phase = "tablespace";
  // /dev/shm is the fixture container's bounded tmpfs, never the host filesystem.
  assert.equal(
    Number(
      docker(["inspect", "--format", "{{.HostConfig.ShmSize}}", container]),
    ),
    64 * 1024 * 1024,
  );
  docker([
    "exec",
    "--user",
    "postgres",
    container,
    "mkdir",
    "-m",
    "700",
    "/dev/shm/xeip-full",
  ]);
  await pool.query("CREATE TABLESPACE xeip_full LOCATION '/dev/shm/xeip-full'");
  await pool.query("ALTER TABLE xeip_org.audit SET TABLESPACE xeip_full");
  await pool.query(
    "CREATE TABLE public.xeip_space_probe (value text) TABLESPACE xeip_full",
  );
  const baseline = await snapshot();
  let witnessed = baseline;
  phase = "fill-bounded-filesystem";
  const fill = spawnSync(
    "docker",
    [
      "exec",
      "--user",
      "postgres",
      container,
      "dd",
      "if=/dev/zero",
      "of=/dev/shm/xeip-fill",
      "bs=1048576",
      "count=64",
    ],
    {
      encoding: "utf8",
      timeout: 30000,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  assert.equal(fill.error, undefined, "bounded fill must terminate normally");
  assert.equal(fill.status, 1, "bounded tmpfs must reject the excess write");
  assert.match(fill.stderr, /No space left on device/);
  try {
    phase = "postgres-enospc-probe";
    await assert.rejects(
      pool.query("INSERT INTO public.xeip_space_probe VALUES ('fixture')"),
      (error) => error.code === "53100",
    );
    phase = "audit-append-exhaustion";
    let failed;
    // Existing allocated pages may still accept rows; those successes must also survive.
    for (let i = 0; i < 128; i++) {
      const id = "urn:xeip:disk-full:proposal:" + i;
      databaseFailure = undefined;
      const input = request(id);
      try {
        const accepted = await store.propose(agent, input);
        assert.equal(accepted.state, "pending");
        const next = await snapshot();
        assert.equal(next.actions.length, witnessed.actions.length + 1);
        assert.equal(next.audit.length, witnessed.audit.length + 1);
        assert.equal(
          next.actions.find((row) => row.request_id === id)?.digest,
          accepted.proposal.digest,
        );
        assert.equal(next.audit.at(-1).request_id, id);
        assert.equal(next.audit.at(-1).event, "proposed");
        witnessed = next;
      } catch (error) {
        assert.ok(error instanceof StoreUnavailable);
        assert.equal(error.message, "action store unavailable");
        assert.equal(
          databaseFailure?.code,
          "53100",
          "must reach PostgreSQL disk-full, not another refusal",
        );
        assert.match(databaseFailure.query, /INSERT INTO xeip_org\.audit/);
        failed = input;
        break;
      }
    }
    assert.ok(failed, "bounded attempts must exhaust the audit page");
    assert.deepEqual(
      await snapshot(),
      witnessed,
      "failed audit insert must roll back its action too",
    );
    assert.equal(
      (
        await pool.query(
          "SELECT 1 FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2",
          [session, failed.id],
        )
      ).rowCount,
      0,
    );
    for (const claim of claims) {
      assert.equal(
        (await store.inspect(agent, session, claim.id)).state,
        claim.id.endsWith("succeeded") ? "succeeded" : "executing",
      );
      await assert.rejects(
        store.claim(agent, session, claim.id, claim.digest),
        StoreConflict,
      );
    }
    phase = "claim-audit-exhaustion";
    let effects = 0;
    const execute = createActionExecutor(policy, {
      call: async () => {
        effects++;
        return null;
      },
    });
    databaseFailure = undefined;
    await assert.rejects(
      execute(
        agent,
        { session, id: waitingId, digest: waiting.proposal.digest },
        { store, authorize: async () => true },
      ),
      StoreUnavailable,
    );
    assert.equal(databaseFailure?.code, "53100");
    assert.match(databaseFailure.query, /INSERT INTO xeip_org\.audit/);
    assert.equal(
      effects,
      0,
      "a failed durable claim must not reach the connector",
    );
    assert.deepEqual(
      await snapshot(),
      witnessed,
      "failed claim audit must roll back the claim and preserve all rows",
    );
    console.log(
      "PASS real PostgreSQL SQLSTATE 53100 refuses action acknowledgement and preserves acknowledged rows, audit and consumed claims",
    );
    phase = "space-restoration";
    docker([
      "exec",
      "--user",
      "postgres",
      container,
      "rm",
      "/dev/shm/xeip-fill",
    ]);
    const retry = failed;
    const result = await store.propose(agent, retry);
    assert.equal(result.state, "pending");
    const repeated = await store.propose(agent, retry);
    assert.deepEqual(repeated, result);
    assert.equal(
      (
        await pool.query(
          "SELECT 1 FROM xeip_org.audit WHERE session_id=$1 AND request_id=$2",
          [session, failed.id],
        )
      ).rowCount,
      1,
    );
    const recovered = await snapshot();
    assert.deepEqual(
      recovered.actions.filter((row) => row.request_id !== failed.id),
      witnessed.actions,
    );

    assert.deepEqual(
      recovered.actions.filter((row) =>
        claims.some((claim) => claim.id === row.request_id),
      ),
      baseline.actions.filter((row) =>
        claims.some((claim) => claim.id === row.request_id),
      ),
    );
    assert.deepEqual(
      recovered.audit.slice(0, baseline.audit.length),
      baseline.audit,
    );
    assert.equal(recovered.actions.length, witnessed.actions.length + 1);
    assert.deepEqual(recovered.audit.slice(0, -1), witnessed.audit);
    for (const claim of claims)
      assert.equal(
        recovered.actions.find((row) => row.request_id === claim.id).claim_id,
        claim.claimId,
      );
    console.log(
      JSON.stringify({
        result: "pass",
        acknowledgedBeforeRecovery: witnessed.actions.length,
        consumedClaims: claims.length,
        recoveredProposal: 1,
        effectsDuringFailedClaim: effects,
        note: "Container-local audit data ENOSPC only; WAL exhaustion, corruption and deployment recovery remain unproven.",
      }),
    );
  } finally {
    // Exact fixture-only filler; primary fixture removes its container/volumes on exit or signal.
    docker([
      "exec",
      "--user",
      "postgres",
      container,
      "rm",
      "-f",
      "/dev/shm/xeip-fill",
    ]);
  }
}
try {
  await withPostgres(drill, { baselineChecks: false });
} catch {
  console.error("PostgreSQL disk-full fixture failed at " + phase);
  process.exitCode = 1;
}
