// Offline corruption of synthetic fixture data only. No operator targets accepted.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import pg from "pg";
import { setTimeout as delay } from "node:timers/promises";
import { withPostgres } from "./postgres.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import {
  ActionStore,
  StoreUnavailable,
  StoreConflict,
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
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
let phase = "primary-fixture";
async function drill({ pool, container }) {
  const stop = () =>
    docker([
      "exec",
      "--user",
      "postgres",
      container,
      "pg_ctl",
      "stop",
      "-m",
      "fast",
      "-w",
      "-t",
      "25",
    ]);
  const start = async () => {
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
      "/tmp/xeip-corruption-server.log",
      "-o",
      "-c restart_after_crash=off",
    ]);
    // Synchronous pg_ctl can finish before Node receives closed idle socket events.
    // Reconnect only this fixture's readiness probe, never an application operation.
    for (let attempt = 0; attempt < 10; attempt++) {
      try {
        await pool.query("SELECT 1");
        return;
      } catch {
        await delay(100);
      }
    }
    throw new Error("fixture database did not reconnect");
  };
  phase = "checksum-readiness";
  await verifyDatabase(pool, { runtime: false });
  phase = "stop-before-disable";
  stop();
  phase = "disable-checksums";
  docker([
    "exec",
    "--user",
    "postgres",
    container,
    "pg_checksums",
    "--disable",
  ]);
  phase = "start-without-checksums";
  await start();
  phase = "read-disabled-checksums";
  assert.equal(
    (await pool.query("SHOW data_checksums")).rows[0].data_checksums,
    "off",
  );
  const gaps = [];
  const rejectsUnsafe = async (database, label) => {
    try {
      await verifyDatabase(database, { runtime: false });
      gaps.push(label);
    } catch (error) {
      assert.ok(error instanceof DatabaseNotReady);
    }
  };
  await rejectsUnsafe(pool, "data_checksums=off");
  stop();
  docker(["exec", "--user", "postgres", container, "pg_checksums", "--enable"]);
  await start();
  await verifyDatabase(pool, { runtime: false });
  for (const setting of ["ignore_checksum_failure", "zero_damaged_pages"]) {
    const unsafe = new pg.Pool({
      ...pool.options,
      password: pool.options.password,
      options: "-c " + setting + "=on",
      max: 1,
    });
    unsafe.on("error", () => {});
    try {
      assert.equal(
        (await unsafe.query("SHOW " + setting)).rows[0][setting],
        "on",
      );
      await rejectsUnsafe(unsafe, setting + "=on");
    } finally {
      await unsafe.end();
    }
  }
  if (gaps.length)
    console.error("Unsafe readiness accepted: " + gaps.join(", "));
  assert.deepEqual(
    gaps,
    [],
    "readiness must require database corruption protections",
  );
  console.log(
    "PASS readiness refuses disabled checksums and unsafe page-recovery bypasses",
  );
  phase = "acknowledged-actions";
  const session = "urn:xeip:session:corruption";
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
  const store = new ActionStore(pool, policy, async () => true);
  const request = (id) => ({
    id,
    session,
    target: "internal",
    tool: "lookup",
    arguments: { fixture: true },
    expiresAt: Math.floor(Date.now() / 1000) + 240,
  });
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
  const claims = [];
  for (const state of ["executing", "succeeded"]) {
    const id = "urn:xeip:corruption:" + state;
    const proposed = await store.propose(agent, request(id));
    const digest = proposed.proposal.digest;
    await store.decide(human, session, id, digest, "approve");
    const claim = await store.claim(agent, session, id, digest);
    claims.push({ id, digest, claimId: claim.claimId });
    if (state === "succeeded")
      await store.finish(session, id, claim.claimId, state);
  }
  const waitingId = "urn:xeip:corruption:waiting";
  const waiting = await store.propose(agent, request(waitingId));
  await store.decide(
    human,
    session,
    waitingId,
    waiting.proposal.digest,
    "approve",
  );
  const acknowledged = await snapshot(pool);
  const dump = execFileSync(
    "docker",
    [
      "exec",
      container,
      "pg_dump",
      "-U",
      "postgres",
      "-d",
      "xeip_fixture",
      "-Fc",
    ],
    {
      timeout: 60000,
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const { path, location, block_size } = (
    await pool.query(
      "SELECT pg_relation_filepath('xeip_org.actions') AS path, ctid::text AS location, current_setting('block_size')::integer AS block_size FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2",
      [session, waitingId],
    )
  ).rows[0];
  assert.match(path, /^base\/[0-9]+\/[0-9]+$/);
  assert.equal(block_size, 8192);
  const match = /^\(([0-9]+),[0-9]+\)$/.exec(location);
  assert.ok(match);
  const offset = Number(match[1]) * block_size + 8; // PostgreSQL pd_checksum, not tuple data or WAL.
  assert.ok(
    Number.isSafeInteger(offset) && offset >= 8 && offset < 1024 * 1024,
  );
  const dataDir = docker([
    "exec",
    container,
    "sh",
    "-c",
    'printf %s "$PGDATA"',
  ]);
  assert.equal(dataDir, "/var/lib/postgresql/18/docker");
  const file = dataDir + "/" + path;
  phase = "offline-corruption";
  stop();
  docker(["exec", "--user", "postgres", container, "pg_checksums", "--check"]);
  const original = Number(
    docker([
      "exec",
      "--user",
      "postgres",
      container,
      "od",
      "-An",
      "-t",
      "u1",
      "-j",
      String(offset),
      "-N",
      "1",
      file,
    ]),
  );
  assert.ok(Number.isInteger(original) && original >= 0 && original <= 255);
  execFileSync(
    "docker",
    [
      "exec",
      "-i",
      "--user",
      "postgres",
      container,
      "dd",
      "of=" + file,
      "bs=1",
      "seek=" + offset,
      "count=1",
      "conv=notrunc",
    ],
    {
      input: Buffer.from([original ^ 255]),
      timeout: 30000,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const check = spawnSync(
    "docker",
    [
      "exec",
      "--user",
      "postgres",
      container,
      "pg_checksums",
      "--check",
      "--filenode",
      path.split("/").at(-1),
    ],
    { encoding: "utf8", timeout: 60000 },
  );
  assert.equal(
    check.status,
    1,
    "offline checksum scan must detect the modified page",
  );
  assert.match(
    check.stdout + check.stderr,
    /checksum verification failed|checksum mismatch/,
  );
  await start();
  phase = "damaged-page-refusal";
  await assert.rejects(
    pool.query(
      "SELECT canonical FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2",
      [session, waitingId],
    ),
    (error) => error.code === "XX001",
  );
  await assert.rejects(
    store.inspect(agent, session, waitingId),
    StoreUnavailable,
  );
  let effects = 0;
  const execute = createActionExecutor(policy, {
    call: async () => {
      effects++;
      return null;
    },
  });
  await assert.rejects(
    execute(
      agent,
      { session, id: waitingId, digest: waiting.proposal.digest },
      { store, authorize: async () => true },
    ),
    StoreUnavailable,
  );
  assert.equal(effects, 0);
  console.log(
    "PASS offline checksum scan and live reads reject a damaged action page; failed claim reaches no connector",
  );
  phase = "isolated-restore";
  await pool.query("CREATE DATABASE xeip_corruption_restored");
  execFileSync(
    "docker",
    [
      "exec",
      "-i",
      container,
      "pg_restore",
      "-U",
      "postgres",
      "-d",
      "xeip_corruption_restored",
      "--exit-on-error",
    ],
    { input: dump, timeout: 60000, stdio: ["pipe", "pipe", "pipe"] },
  );
  const recovered = new pg.Pool({
    ...pool.options,
    password: pool.options.password,
    database: "xeip_corruption_restored",
  });
  recovered.on("error", () => {});
  try {
    await verifyDatabase(recovered, { runtime: false });
    assert.deepEqual(await snapshot(recovered), acknowledged);
    const restoredStore = new ActionStore(recovered, policy, async () => true);
    for (const claim of claims) {
      await assert.rejects(
        restoredStore.claim(agent, session, claim.id, claim.digest),
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
    assert.equal(
      (await restoredStore.inspect(agent, session, waitingId)).state,
      "approved",
    );
    assert.equal(effects, 0);
    console.log(
      JSON.stringify({
        result: "pass",
        acknowledgedActions: acknowledged.actions.length,
        consumedClaims: claims.length,
        effectsDuringCorruption: effects,
        note: "Fixed-cut logical restore after one damaged fixture page; not a periodic-backup zero-loss guarantee or full organization recovery.",
      }),
    );
  } finally {
    await recovered.end();
  }
}
try {
  await withPostgres(drill, { baselineChecks: false, walFault: true });
} catch (error) {
  const code =
    typeof error.code === "string" && /^[A-Z0-9_]{1,40}$/.test(error.code)
      ? error.code
      : "unclassified";
  console.error(
    "PostgreSQL corruption fixture failed at " + phase + " (" + code + ")",
  );
  process.exitCode = 1;
}
