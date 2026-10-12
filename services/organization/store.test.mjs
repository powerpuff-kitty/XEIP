import test from "node:test";
import { EventEmitter } from "node:events";
import assert from "node:assert/strict";
import { ActionPolicy, PolicyDenied } from "./actions.mjs";
import { ActionStore, StoreUnavailable, StoreConflict } from "./store.mjs";
const entity =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const kid = "z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const policy = new ActionPolicy({
  targets: [
    { id: "internal", revision: "1", recipient: entity, tools: ["lookup"] },
  ],
  sessions: [
    {
      id: "session-1",
      agents: ["agent"],
      approvers: ["human"],
      targets: ["internal"],
    },
  ],
});
const principal = (subject) =>
  Object.freeze({
    subject,
    entity,
    kid,
    clientId: "client",
    roles: Object.freeze(["agent", "approver"]),
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  });
const proposal = policy.propose(principal("agent"), {
  id: "request-1",
  session: "session-1",
  target: "internal",
  tool: "lookup",
  arguments: {},
  expiresAt: Math.floor(Date.now() / 1000) + 240,
});
const row = {
  session_id: "session-1",
  request_id: "request-1",
  digest: proposal.digest,
  canonical: JSON.stringify(proposal.action),
  state: "pending",
};

for (const operation of ["decide", "claim", "revoke"])
  test(
    operation + " rejects local nonmembers before locks or provider requests",
    async () => {
      const queries = [];
      let providerCalls = 0;
      const client = Object.assign(new EventEmitter(), {
        query: async (sql) => {
          queries.push(sql);
          return { rows: [row] };
        },
        release: () => {},
      });
      const pool = {
        options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
        connect: async () => client,
      };
      const store = new ActionStore(pool, policy, async () => {
        providerCalls++;
        return true;
      });
      await assert.rejects(
        store[operation](
          principal("outsider"),
          "session-1",
          "request-1",
          proposal.digest,
          "approve",
        ),
        PolicyDenied,
      );
      assert.equal(
        queries.some((sql) => sql.includes("FOR UPDATE")),
        false,
      );
      assert.equal(providerCalls, 0);
    },
  );

test("rejects pools without bounded acquisition and client query deadlines", () => {
  for (const options of [
    {},
    { connectionTimeoutMillis: 3000 },
    { connectionTimeoutMillis: 3000, query_timeout: 0 },
    { connectionTimeoutMillis: Infinity, query_timeout: 3000 },
  ]) {
    assert.throws(
      () => new ActionStore({ options }, policy, async () => true),
      TypeError,
    );
  }
});

test("mutation calls require an explicit expected digest before any lookup", async () => {
  let queries = 0;
  const pool = {
    options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
    connect: async () =>
      Object.assign(new EventEmitter(), {
        query: async () => {
          queries++;
          return { rows: [row] };
        },
        release: () => {},
      }),
  };
  const store = new ActionStore(pool, policy, async () => true);
  await assert.rejects(
    store.claim(principal("agent"), "session-1", "request-1", undefined),
    StoreConflict,
  );
  assert.equal(queries, 3); // BEGIN, transaction settings and ROLLBACK only.
});

test("a stalled authorization cannot retain the transaction indefinitely", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let entered, destroyed;
  const inside = new Promise((resolve) => {
    entered = resolve;
  });
  const pool = {
    options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
    connect: async () =>
      Object.assign(new EventEmitter(), {
        query: async () => ({ rows: [] }),
        release: (broken) => {
          destroyed = broken;
        },
      }),
  };
  const store = new ActionStore(pool, policy, async () => {
    entered();
    return await new Promise(() => {});
  });
  const result = store.propose(principal("agent"), {
    id: "timed",
    session: "session-1",
    target: "internal",
    tool: "lookup",
    arguments: {},
    expiresAt: Math.floor(Date.now() / 1000) + 120,
  });
  const failure = assert.rejects(result, StoreUnavailable);
  await inside;
  t.mock.timers.tick(10001);
  await failure;
  assert.equal(destroyed, true);
});

for (const operation of ["propose", "decide", "revoke", "claim"])
  test(
    operation +
      " rechecks authorization after mutation/audit waits before COMMIT",
    async () => {
      const agent = principal("agent"),
        human = Object.freeze({
          ...principal("human"),
          entity: "urn:xeip:entity:" + kid,
        });
      const record = {
        ...row,
        state: operation === "claim" ? "approved" : "pending",
        approver: human,
        claim_id: "00000000-0000-0000-0000-000000000001",
        result_canonical: null,
      };
      const queries = [];
      let allowed = true;
      const pool = {
        options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
        connect: async () =>
          Object.assign(new EventEmitter(), {
            query: async (sql) => {
              queries.push(sql);
              if (sql.startsWith("INSERT INTO xeip_org.audit")) allowed = false;
              return { rows: [record] };
            },
            release: () => {},
          }),
      };
      const store = new ActionStore(pool, policy, async () => allowed);
      const pending =
        operation === "propose"
          ? store.propose(agent, {
              id: "request-1",
              session: "session-1",
              target: "internal",
              tool: "lookup",
              arguments: {},
              expiresAt: Math.floor(Date.now() / 1000) + 120,
            })
          : operation === "decide"
            ? store.decide(
                human,
                "session-1",
                "request-1",
                proposal.digest,
                "approve",
              )
            : store[operation](
                agent,
                "session-1",
                "request-1",
                proposal.digest,
              );
      await assert.rejects(pending, PolicyDenied);
      assert.equal(queries.includes("COMMIT"), false);
      assert.equal(queries.at(-1), "ROLLBACK");
    },
  );
test("internal completion remains durable after client authorization is gone", async () => {
  const claimId = "00000000-0000-0000-0000-000000000001",
    record = {
      ...row,
      state: "executing",
      claim_id: claimId,
      result_canonical: null,
    };
  const queries = [];
  let authorizationCalls = 0;
  const pool = {
    options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
    connect: async () =>
      Object.assign(new EventEmitter(), {
        query: async (sql, args) => {
          queries.push(sql);
          if (sql.startsWith("UPDATE")) record.state = args[2];
          return { rows: [record] };
        },
        release: () => {},
      }),
  };
  const store = new ActionStore(pool, policy, async () => {
    authorizationCalls++;
    return false;
  });
  assert.equal(
    (await store.finish("session-1", "request-1", claimId, "succeeded")).state,
    "succeeded",
  );
  assert.equal(authorizationCalls, 0);
  assert.equal(queries.at(-1), "COMMIT");
});

test("COMMIT notices are ambiguous durability, redact diagnostics and release the listener", async () => {
  const client = new EventEmitter();
  let broken;
  client.query = async (sql) => {
    if (sql === "COMMIT")
      client.emit("notice", {
        severity: "WARNING",
        message: "private database diagnostic",
      });
    return { rows: [row] };
  };
  client.release = (value) => {
    broken = value;
  };
  const store = new ActionStore(
    {
      options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
      connect: async () => client,
    },
    policy,
    async () => true,
  );
  await assert.rejects(
    store.propose(principal("agent"), {
      id: "request-1",
      session: "session-1",
      target: "internal",
      tool: "lookup",
      arguments: {},
      expiresAt: Math.floor(Date.now() / 1000) + 240,
    }),
    (error) =>
      error instanceof StoreUnavailable && !error.stack.includes("private"),
  );
  assert.equal(broken, true);
  assert.equal(client.listenerCount("notice"), 0);
});

for (const phase of ["inspect", "propose", "decide", "revoke", "claim"]) {
  test(`${phase} takes the control fence before any action access`, async () => {
    const queries = [];
    const client = Object.assign(new EventEmitter(), {
      query: async (sql) => {
        queries.push(sql);
        return { rows: [row] };
      },
      release: () => {},
    });
    const pool = {
      options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
      connect: async () => client,
    };
    const fence = {
      current: () => true,
      lock: async (actual) => {
        assert.equal(actual, client);
        throw new StoreConflict();
      },
    };
    const store = new ActionStore(pool, policy, async () => true, fence);
    const p = principal(phase === "decide" ? "human" : "agent");
    const operation =
      phase === "propose"
        ? store.propose(p, {
            id: "request-1",
            session: "session-1",
            target: "internal",
            tool: "lookup",
            arguments: {},
            expiresAt: Math.floor(Date.now() / 1000) + 120,
          })
        : store[phase](p, "session-1", "request-1", proposal.digest, "approve");
    await assert.rejects(operation, StoreConflict);
    assert.equal(
      queries.some((sql) => sql.includes("xeip_org.actions")),
      false,
    );
    assert.equal(queries.includes("COMMIT"), false);
  });
}

test("publication during the final provider check rolls back the action", async () => {
  const queries = [];
  let current = true,
    calls = 0;
  const pool = {
    options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
    connect: async () =>
      Object.assign(new EventEmitter(), {
        query: async (sql) => {
          queries.push(sql);
          return { rows: [row] };
        },
        release: () => {},
      }),
  };
  const store = new ActionStore(
    pool,
    policy,
    async () => {
      if (++calls === 2) current = false;
      return true;
    },
    { current: () => current, lock: async () => {} },
  );
  await assert.rejects(
    store.propose(principal("agent"), {
      id: "request-1",
      session: "session-1",
      target: "internal",
      tool: "lookup",
      arguments: {},
      expiresAt: Math.floor(Date.now() / 1000) + 120,
    }),
    StoreUnavailable,
  );
  assert.equal(queries.includes("COMMIT"), false);
});
