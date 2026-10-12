import assert from "node:assert/strict";
import {
  ActionPolicy,
  PolicyDenied,
} from "../services/organization/actions.mjs";
import {
  ActionStore,
  StoreConflict,
  StoreUnavailable,
  migrate,
} from "../services/organization/store.mjs";
const entity =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const other =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const kid = other.slice("urn:xeip:entity:".length);
export async function verifyStore({ pool, restart, backupRestore }) {
  const policy = new ActionPolicy({
    targets: [
      { id: "internal", revision: "1", recipient: other, tools: ["lookup"] },
    ],
    sessions: [
      {
        id: "session-1",
        agents: ["agent-1"],
        approvers: ["human-1"],
        targets: ["internal"],
      },
    ],
  });
  const now = Math.floor(Date.now() / 1000);
  const agent = Object.freeze({
    subject: "agent-1",
    entity,
    kid,
    clientId: "agent",
    roles: Object.freeze(["agent"]),
    expiresAt: now + 300,
  });
  const human = Object.freeze({
    subject: "human-1",
    entity: other,
    kid,
    clientId: "console",
    roles: Object.freeze(["approver"]),
    expiresAt: now + 300,
  });
  let active = true;
  let gate = async () => {};
  const store = new ActionStore(pool, policy, async (_principal, context) => {
    await gate(context);
    return active;
  });
  const request = (id) => ({
    id,
    session: "session-1",
    target: "internal",
    tool: "lookup",
    arguments: { query: "status" },
    expiresAt: now + 240,
  });
  await migrate(pool);
  await migrate(pool); // Repeat migration must verify checksum and preserve data.
  // A final request guard denial must roll back both the mutation and its audit.
  for (const phase of ["propose", "decide", "revoke", "claim"]) {
    const id = "late-" + phase;
    let proposal;
    if (phase !== "propose") proposal = await store.propose(agent, request(id));
    if (phase === "claim")
      await store.decide(
        human,
        "session-1",
        id,
        proposal.proposal.digest,
        "approve",
      );
    const before = (
      await pool.query(
        "SELECT count(*) FROM xeip_org.audit WHERE request_id=$1",
        [id],
      )
    ).rows[0].count;
    let checks = 0;
    gate = async (context) => {
      if (context.phase === phase && ++checks === 2) active = false;
    };
    await assert.rejects(
      phase === "propose"
        ? store.propose(agent, request(id))
        : phase === "decide"
          ? store.decide(
              human,
              "session-1",
              id,
              proposal.proposal.digest,
              "approve",
            )
          : store[phase](agent, "session-1", id, proposal.proposal.digest),
      PolicyDenied,
    );
    active = true;
    gate = async () => {};
    assert.equal(
      (
        await pool.query(
          "SELECT count(*) FROM xeip_org.audit WHERE request_id=$1",
          [id],
        )
      ).rows[0].count,
      before,
    );
    const rows = (
      await pool.query(
        "SELECT state FROM xeip_org.actions WHERE request_id=$1",
        [id],
      )
    ).rows;
    assert.deepEqual(
      rows,
      phase === "propose"
        ? []
        : [{ state: phase === "claim" ? "approved" : "pending" }],
    );
  }
  console.log(
    "PASS PostgreSQL: late authorization denial rolls back proposals, decisions, revocations and claims with their audit events",
  );
  assert.equal(
    (await pool.query("SELECT count(*) FROM xeip_org.migrations")).rows[0]
      .count,
    "3",
  );
  const first = await store.propose(agent, request("one"));
  assert.equal(first.state, "pending");
  assert.deepEqual(await store.propose(agent, request("one")), first);
  await assert.rejects(
    store.propose(agent, {
      ...request("one"),
      arguments: { query: "changed" },
    }),
    StoreConflict,
  );
  await assert.rejects(
    store.decide(agent, "session-1", "one", first.proposal.digest, "approve"),
    PolicyDenied,
  );
  await assert.rejects(
    store.decide(human, "session-1", "one", "0".repeat(64), "approve"),
    StoreConflict,
  );
  assert.equal(
    (
      await store.decide(
        human,
        "session-1",
        "one",
        first.proposal.digest,
        "approve",
      )
    ).state,
    "approved",
  );
  const claims = await Promise.allSettled(
    Array.from({ length: 8 }, () =>
      store.claim(agent, "session-1", "one", first.proposal.digest),
    ),
  );
  const winners = claims.filter((result) => result.status === "fulfilled");
  assert.equal(winners.length, 1, "exactly one concurrent execution claim");
  assert.equal(
    claims.filter(
      (result) =>
        result.status === "rejected" && result.reason instanceof StoreConflict,
    ).length,
    7,
  );
  const claim = winners[0].value;
  assert.equal(claim.state, "executing");
  assert.equal(claim.approver.subject, human.subject);
  assert.match(claim.claimId, /^[0-9a-f-]{36}$/);
  await assert.rejects(
    store.finish(
      "session-1",
      "one",
      "00000000-0000-0000-0000-000000000000",
      "succeeded",
    ),
    StoreConflict,
  );
  assert.equal(
    (
      await store.finish("session-1", "one", claim.claimId, "succeeded", {
        content: [{ type: "text", text: "recorded outcome" }],
      })
    ).state,
    "succeeded",
  );
  assert.equal(
    (
      await store.finish("session-1", "one", claim.claimId, "succeeded", {
        content: [{ type: "text", text: "recorded outcome" }],
      })
    ).state,
    "succeeded",
  );
  await assert.rejects(
    store.finish("session-1", "one", claim.claimId, "failed"),
    StoreConflict,
  );
  await assert.rejects(
    store.finish("session-1", "one", claim.claimId, "succeeded", {
      content: [],
    }),
    StoreConflict,
  );
  assert.deepEqual((await store.inspect(agent, "session-1", "one")).result, {
    content: [{ type: "text", text: "recorded outcome" }],
  });
  console.log(
    "PASS PostgreSQL: migration, immutable retries, exact approval and concurrent single-use claims",
  );

  const denied = await store.propose(agent, request("denied"));
  active = false;
  await assert.rejects(
    store.decide(
      human,
      "session-1",
      "denied",
      denied.proposal.digest,
      "approve",
    ),
    PolicyDenied,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM xeip_org.actions WHERE request_id='denied'",
      )
    ).rows[0].state,
    "pending",
  );
  active = true;
  await store.decide(
    human,
    "session-1",
    "denied",
    denied.proposal.digest,
    "reject",
  );
  await assert.rejects(
    store.claim(agent, "session-1", "denied", denied.proposal.digest),
    StoreConflict,
  );
  const revoked = await store.propose(agent, request("revoked"));
  await store.decide(
    human,
    "session-1",
    "revoked",
    revoked.proposal.digest,
    "approve",
  );
  await store.revoke(agent, "session-1", "revoked", revoked.proposal.digest);
  await assert.rejects(
    store.claim(agent, "session-1", "revoked", revoked.proposal.digest),
    StoreConflict,
  );
  await assert.rejects(
    pool.query(
      "UPDATE xeip_org.actions SET canonical='{}' WHERE request_id='one'",
    ),
  );
  await assert.rejects(
    pool.query("DELETE FROM xeip_org.audit WHERE request_id='one'"),
  );
  const events = (
    await pool.query(
      "SELECT event FROM xeip_org.audit WHERE request_id='one' ORDER BY sequence",
    )
  ).rows.map((row) => row.event);
  assert.deepEqual(events, ["proposed", "approved", "claimed", "succeeded"]);
  console.log(
    "PASS PostgreSQL: failed authorization rollback, rejection/revocation and immutable audit history",
  );

  await pool.query(
    "CREATE FUNCTION xeip_org.fixture_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.request_id='audit-failure' THEN RAISE EXCEPTION 'fixture write failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON xeip_org.audit FOR EACH ROW EXECUTE FUNCTION xeip_org.fixture_audit_failure()",
  );
  await assert.rejects(
    store.propose(agent, request("audit-failure")),
    StoreUnavailable,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT count(*) FROM xeip_org.actions WHERE request_id='audit-failure'",
      )
    ).rows[0].count,
    "0",
    "audit failure rolls back action acceptance",
  );
  await pool.query(
    "DROP TRIGGER fixture_audit_failure ON xeip_org.audit; DROP FUNCTION xeip_org.fixture_audit_failure()",
  );
  const race = await store.propose(agent, request("race"));
  await store.decide(
    human,
    "session-1",
    "race",
    race.proposal.digest,
    "approve",
  );
  let release, entered;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const inside = new Promise((resolve) => {
    entered = resolve;
  });
  gate = async (context) => {
    if (context.phase === "revoke") {
      entered();
      await held;
    }
  };
  const revoking = store.revoke(
    agent,
    "session-1",
    "race",
    race.proposal.digest,
  );
  await inside;
  const losingClaim = assert.rejects(
    store.claim(agent, "session-1", "race", race.proposal.digest),
    StoreConflict,
  );
  release();
  await revoking;
  await losingClaim;
  gate = async () => {};
  const oldChecksum = (
    await pool.query("SELECT checksum FROM xeip_org.migrations WHERE version=1")
  ).rows[0].checksum;
  await pool.query(
    "UPDATE xeip_org.migrations SET checksum='changed' WHERE version=1",
  );
  await assert.rejects(migrate(pool), StoreUnavailable);
  await pool.query(
    "UPDATE xeip_org.migrations SET checksum=$1 WHERE version=1",
    [oldChecksum],
  );
  console.log(
    "PASS PostgreSQL: atomic audit failure rollback, revocation/claim race and migration checksum enforcement",
  );

  const ambiguous = await store.propose(agent, request("ambiguous"));
  await store.decide(
    human,
    "session-1",
    "ambiguous",
    ambiguous.proposal.digest,
    "approve",
  );
  const lostCommitPool = {
    options: pool.options,
    connect: async () => {
      const client = await pool.connect();
      return {
        release: (broken) => client.release(broken),
        on: (...args) => client.on(...args),
        removeListener: (...args) => client.removeListener(...args),
        query: async (...args) => {
          const result = await client.query(...args);
          if (args[0] === "COMMIT")
            throw new Error("fixture lost commit response");
          return result;
        },
      };
    },
  };
  const uncertainStore = new ActionStore(
    lostCommitPool,
    policy,
    async () => true,
  );
  await assert.rejects(
    uncertainStore.claim(
      agent,
      "session-1",
      "ambiguous",
      ambiguous.proposal.digest,
    ),
    StoreUnavailable,
  );
  const status = await store.inspect(agent, "session-1", "ambiguous");
  assert.equal(status.state, "executing");
  assert.equal(Object.hasOwn(status, "claimId"), false);
  await assert.rejects(
    store.claim(agent, "session-1", "ambiguous", ambiguous.proposal.digest),
    StoreConflict,
  );
  const realNow = Date.now;
  try {
    Date.now = () => (now + 241) * 1000;
    assert.equal(
      (await store.inspect(agent, "session-1", "ambiguous")).state,
      "executing",
    );
  } finally {
    Date.now = realNow;
  }
  const revisedPolicy = new ActionPolicy({
    targets: [
      { id: "internal", revision: "2", recipient: other, tools: ["lookup"] },
    ],
    sessions: [
      {
        id: "session-1",
        agents: ["agent-1"],
        approvers: ["human-1"],
        targets: ["internal"],
      },
    ],
  });
  assert.equal(
    (
      await new ActionStore(pool, revisedPolicy, async () => true).inspect(
        human,
        "session-1",
        "ambiguous",
      )
    ).state,
    "executing",
  );
  const outsider = Object.freeze({ ...agent, subject: "outsider" });
  await assert.rejects(
    store.inspect(outsider, "session-1", "ambiguous"),
    PolicyDenied,
  );
  console.log(
    "PASS PostgreSQL: lost commit response resolved without replay, including expiry and policy revision",
  );

  const crashing = await store.propose(agent, request("crash"));
  await store.decide(
    human,
    "session-1",
    "crash",
    crashing.proposal.digest,
    "approve",
  );
  await store.claim(agent, "session-1", "crash", crashing.proposal.digest);
  await restart();
  await assert.rejects(
    store.claim(agent, "session-1", "crash", crashing.proposal.digest),
    StoreConflict,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM xeip_org.actions WHERE request_id='crash'",
      )
    ).rows[0].state,
    "executing",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM xeip_org.actions WHERE request_id='one'",
      )
    ).rows[0].state,
    "succeeded",
  );
  console.log(
    "PASS PostgreSQL: acknowledged transitions survive abrupt database kill; consumed claim cannot replay",
  );
  const restored = await backupRestore();
  try {
    await migrate(restored);
    const restoredStore = new ActionStore(restored, policy, async () => true);
    await assert.rejects(
      restoredStore.claim(
        agent,
        "session-1",
        "crash",
        crashing.proposal.digest,
      ),
      StoreConflict,
    );
    assert.deepEqual(
      (
        await restored.query(
          "SELECT event FROM xeip_org.audit WHERE request_id='one' ORDER BY sequence",
        )
      ).rows.map((row) => row.event),
      events,
    );
    console.log(
      "PASS PostgreSQL: logical backup restores action state and audit history without replaying consumed claims",
    );
  } finally {
    await restored.end();
  }
}
