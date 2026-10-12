import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
let runtime;
const options = {
  organization: "fixture-organization",
  stream: "d2e1c945-697b-4f94-a3f1-5309893d299c",
};
before(async () => {
  runtime = await harness({
    entryPoint: new URL(
      "./organization-cloudflare-action-recovery-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "RecoveredLedgerFixture",
    durableObjects: {
      JOURNAL: { className: "RecoveryFixture", useSQLite: true },
      SERVICE: { className: "LifecycleFixture", useSQLite: true },
      MIGRATION: { className: "RecoveryMigrationFixture", useSQLite: true },
    },
  });
});
after(async () => {
  await runtime?.close();
});
const journal = (f, value) => f.send({ operation: "journal", value });
const open = (f, extra = {}) =>
  f.send({ operation: "openRecovery", options, ...extra });
const initialize = async (f) => {
  assert.equal(
    (await journal(f, { operation: "initialize", options })).status,
    200,
  );
  assert.equal((await open(f, { initialize: true })).status, 200);
};
const propose = (f, id = "one") =>
  f.send({
    operation: "propose",
    principal: "agent",
    request: {
      id,
      session: "operations",
      target: "internal",
      tool: "lookup",
      arguments: { query: "fixture" },
      expiresAt: Math.floor(Date.now() / 1000) + 240,
    },
  });
test("enrolled action acknowledgements are present in independent recovery storage", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const response = await propose(f);
  assert.equal(response.status, 200);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 1);
  const part = (await journal(f, { operation: "part", sequence: 1, part: 0 }))
    .body;
  const payload = JSON.parse(Buffer.from(part.data, "base64").toString());
  assert.equal(payload.schema, "xeip.action-recovery/1");
  assert.equal(payload.sequence, 1);
  assert.equal(payload.record.row.state, "pending");
  assert.equal(
    payload.record.row.canonical,
    JSON.stringify(response.body.proposal.action),
  );
});
test("persisted enrollment cannot be bypassed by removing the runtime adapter", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await propose(f);
  assert.equal(
    (await f.send({ operation: "openWithoutRecovery" })).status,
    503,
  );
  assert.equal((await open(f)).status, 200);
});
const controls = (f, control) =>
  f.send({ operation: "recoveryControls", control });
const journalControls = (f, control) =>
  journal(f, { operation: "controls", control });
const health = async (f) =>
  (await f.send({ operation: "recoveryHealth" })).body.healthy;
const decide = (f, p, decision = "approve") =>
  f.send({
    operation: "decide",
    principal: "human",
    session: p.action.session,
    id: p.action.id,
    digest: p.digest,
    decision,
  });
const execute = (f, p) =>
  f.send({
    operation: "execute",
    principal: "agent",
    session: p.action.session,
    id: p.action.id,
    digest: p.digest,
  });
const waitSync = async (f, n) => {
  for (let i = 0; i < 200; i++) {
    if ((await journalControls(f, {})).body.syncs >= n) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.fail("journal did not reach held synchronization");
};
const rows = async (f) => ({
  xeip_actions: (
    await f.sql("SELECT * FROM xeip_actions ORDER BY session_id,request_id")
  ).body.rows,
  xeip_audit: (await f.sql("SELECT * FROM xeip_audit ORDER BY sequence")).body
    .rows,
});
test("recovery records every decision, consumed claim and completion, and duplicate proposal adds nothing", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const first = await propose(f),
    p = first.body.proposal;
  const retry = await f.send({
    operation: "propose",
    principal: "agent",
    request: {
      id: p.action.id,
      session: p.action.session,
      target: p.action.target.id,
      tool: p.action.tool,
      arguments: p.action.arguments,
      expiresAt: p.action.expiresAt,
    },
  });
  assert.equal(retry.status, 200);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 1);
  assert.equal((await decide(f, p)).status, 200);
  assert.equal((await execute(f, p)).status, 200);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 4);
  for (const [sequence, state] of [
    [1, "pending"],
    [2, "approved"],
    [3, "executing"],
    [4, "succeeded"],
  ]) {
    const data = (await journal(f, { operation: "part", sequence, part: 0 }))
      .body.data;
    const record = JSON.parse(Buffer.from(data, "base64")).record;
    assert.equal(record.row.state, state);
    assert.equal(record.history.at(-1).sequence, sequence);
  }
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
  assert.equal((await open(f)).status, 200);
  assert.equal((await execute(f, p)).body.error, "StoreConflict");
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
});
test("action acknowledgement and concurrent reads wait behind independent journal synchronization", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await journalControls(f, { holdSync: 2 });
  let finished = false;
  const pending = propose(f).then((r) => {
    finished = true;
    return r;
  });
  try {
    await waitSync(f, 2);
    assert.equal(finished, false);
    assert.equal(await health(f), false);
    assert.equal((await propose(f, "other")).body.error, "StoreConflict");
    assert.equal(
      (
        await f.send({
          operation: "inspect",
          principal: "agent",
          session: "operations",
          id: "one",
        })
      ).body.error,
      "StoreConflict",
    );
    assert.equal(
      (await f.send({ operation: "actionSnapshot" })).body.error,
      "StoreConflict",
    );
  } finally {
    await journalControls(f, { holdSync: 0 });
  }
  assert.equal((await pending).status, 200);
  assert.equal(await health(f), true);
});
test("lost remote response quarantines then recognizes committed recovery tail on reopen", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await controls(f, { lostReceipt: true });
  assert.equal((await propose(f)).body.error, "StoreUnavailable");
  assert.equal(await health(f), false);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 1);
  await controls(f, { lostReceipt: false });
  assert.equal((await open(f)).status, 200);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 1);
  assert.equal((await propose(f, "next")).status, 200);
});
test("failed local sync publishes only the unacknowledged tail on a fresh open", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await f.send({ operation: "controls", fault: "sync" });
  assert.equal((await propose(f)).body.error, "StoreUnavailable");
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 0);
  assert.equal((await open(f)).status, 200);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 1);
  assert.equal((await f.send({ operation: "controls" })).body.effects, 0);
});
test("source rollback behind independent acknowledged history remains fenced", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const p = (await propose(f)).body.proposal;
  await decide(f, p);
  const saved = await rows(f);
  await execute(f, p);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 4);
  assert.equal(
    (await f.send({ operation: "restoreSource", rows: saved })).status,
    200,
  );
  assert.equal((await open(f)).status, 503);
  assert.equal((await execute(f, p)).body.error, "StoreUnavailable");
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
});
test("uncertain claim receipt never sends a tool call and reopening never revives the claim", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const p = (await propose(f)).body.proposal;
  await decide(f, p);
  await controls(f, { lostReceipt: true });
  assert.equal((await execute(f, p)).body.error, "StoreUnavailable");
  assert.equal((await f.send({ operation: "controls" })).body.effects, 0);
  await controls(f, { lostReceipt: false });
  assert.equal((await open(f)).status, 200);
  assert.equal((await execute(f, p)).body.error, "StoreConflict");
  assert.equal((await f.send({ operation: "controls" })).body.effects, 0);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 3);
});
test("revocation or close during claim journal synchronization prevents late execution", async () => {
  for (const mode of ["revocation", "close", "timeout"]) {
    const f = await runtime.fixture();
    await initialize(f);
    if (mode === "timeout")
      assert.equal(
        (await open(f, { options: { ...options, timeoutMs: 100 } })).status,
        200,
      );
    const p = (await propose(f)).body.proposal;
    await decide(f, p);
    await journalControls(f, { holdSync: 4 });
    const pending = execute(f, p);
    try {
      await waitSync(f, 4);
      if (mode === "revocation")
        await f.send({ operation: "controls", bump: true });
      else if (mode === "close") await f.send({ operation: "closeRecovery" });
      else await new Promise((r) => setTimeout(r, 160));
    } finally {
      await journalControls(f, { holdSync: 0 });
    }
    assert.notEqual((await pending).status, 200);
    assert.equal((await f.send({ operation: "controls" })).body.effects, 0);
    assert.equal((await open(f)).status, 200);
    assert.equal((await execute(f, p)).body.error, "StoreConflict");
  }
});
test("wrong scope, sequence, predecessor or payload receipt cannot acknowledge a mutation", async () => {
  for (const receiptCorruption of [
    { organization: "wrong" },
    { stream: "d2e1c945-697b-4f94-a3f1-5309893d299d" },
    { sequence: 2 },
    { previous: "0".repeat(64) },
    { payloadDigest: "0".repeat(64) },
    { extra: true },
  ]) {
    const f = await runtime.fixture();
    await initialize(f);
    await controls(f, { receiptCorruption });
    assert.equal((await propose(f)).body.error, "StoreUnavailable");
    assert.equal(await health(f), false);
  }
});
test("journal head or entry fork, changed caps and SQL binding replacement are rejected", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await propose(f);
  for (const query of [
    "DELETE FROM xeip_action_recovery",
    "UPDATE xeip_action_recovery SET canonical=canonical",
    "INSERT OR REPLACE INTO xeip_action_recovery SELECT * FROM xeip_action_recovery",
  ])
    assert.notEqual((await f.sql(query)).status, 200);
  assert.equal(
    (await open(f, { options: { ...options, maxBytes: 100000 } })).status,
    503,
  );
  await controls(f, { entryCorruption: { checksum: "0".repeat(64) } });
  assert.equal((await open(f)).status, 503);
  await controls(f, { entryCorruption: null });
  assert.equal((await open(f)).status, 200);
  await controls(f, { headCorruption: { checksum: "0".repeat(64) } });
  assert.equal((await propose(f, "next")).body.error, "StoreUnavailable");
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS n FROM xeip_actions")).body.rows[0].n,
    1,
  );
});
test("enrollment cannot adopt a populated unconfigured source", async () => {
  const f = await runtime.fixture();
  assert.equal(
    (await f.send({ operation: "openWithoutRecovery" })).status,
    200,
  );
  assert.equal((await propose(f)).status, 200);
  await journal(f, { operation: "initialize", options });
  assert.equal((await open(f, { initialize: true })).status, 503);
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_action_recovery")).body.rows,
    [],
  );
});
test("whole-runtime restart reconciles durable histories without recreating consumed capabilities", async () => {
  let f = await runtime.fixture();
  await initialize(f);
  const p = (await propose(f)).body.proposal;
  await decide(f, p);
  await execute(f, p);
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal((await journal(f, { operation: "open", options })).status, 200);
  assert.equal((await open(f)).status, 200);
  assert.equal((await execute(f, p)).body.error, "StoreConflict");
  assert.equal((await f.send({ operation: "controls" })).body.effects, 0);
});
test("schema6 upgrade preserves source evidence, rolls back applied DDL on failure and refuses downgrade", async () => {
  const source = await runtime.fixture();
  await source.send({ operation: "openWithoutRecovery" });
  await propose(source);
  const saved = await rows(source);
  const f = await runtime.fixture(undefined, "MIGRATION");
  assert.equal((await f.send({ operation: "v6" })).status, 200);
  for (const table of ["xeip_actions", "xeip_audit"])
    for (const row of saved[table])
      assert.equal(
        (
          await f.sql(
            "INSERT INTO " +
              table +
              "(" +
              Object.keys(row).join(",") +
              ") VALUES(" +
              Object.keys(row)
                .map(() => "?")
                .join(",") +
              ")",
            ...Object.values(row),
          )
        ).status,
        200,
      );
  const catalog = (
      await f.sql("SELECT * FROM sqlite_master ORDER BY type,name")
    ).body.rows,
    schema = (await f.sql("SELECT * FROM xeip_schema")).body.rows;
  assert.equal((await f.send({ operation: "v7", fail: true })).status, 503);
  assert.equal((await f.send({ operation: "applied" })).body.applied, 4);
  assert.deepEqual(
    (await f.sql("SELECT * FROM sqlite_master ORDER BY type,name")).body.rows,
    catalog,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_schema")).body.rows,
    schema,
  );
  assert.deepEqual(await rows(f), saved);
  assert.equal((await f.send({ operation: "v7" })).status, 200);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  assert.deepEqual(await rows(f), saved);
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_action_recovery")).body.rows,
    [],
  );
  assert.equal((await f.send({ operation: "v6" })).status, 503);
});
test("service pins recovery identity in lifecycle intent and awaits journal before activation", async (t) => {
  const { fixture: providerFixture } = await import(
    "../services/organization/test-fixtures/provider.mjs"
  );
  const { mcpFixture } = await import(
    "../services/organization/test-fixtures/mcp.mjs"
  );
  const { identity, configuration } = await import(
    "./fixtures/cloudflare/authority-harness.mjs"
  );
  const provider = await providerFixture(t),
    mcp = await mcpFixture(t),
    actors = [identity("agent"), identity("human")],
    config = configuration(provider, actors),
    f = await runtime.fixture(undefined, "SERVICE");
  mcp.config.revision = "1";
  mcp.config.recipient = actors[0].entity;
  const settings = {
      organization: "lifecycle-fixture",
      origin: "https://xeip.example",
      gateway: actors[0].entity,
      trust: { maxAgeSeconds: 300 },
      targets: [mcp.config],
      introspectionClientSecret: provider.config.introspectionClientSecret,
    },
    recovery = { ...options, organization: "lifecycle-fixture" };
  assert.equal(
    (
      await f.send({
        operation: "recoveryJournal",
        value: { operation: "initialize", options: recovery },
      })
    ).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "open", configuration: settings, recovery }))
      .body.state,
    "uninitialized",
  );
  assert.equal(
    (await f.send({ operation: "initialize", configuration: config })).body
      .state,
    "initialized",
  );
  const intent = JSON.parse(
    (await f.sql("SELECT runtime_configuration FROM xeip_service_state")).body
      .rows[0].runtime_configuration,
  );
  assert.equal(intent.recovery.stream, recovery.stream);
  assert.equal(
    (await f.send({ operation: "open", configuration: settings })).body.state,
    "failed",
  );
  assert.equal(
    (
      await f.send({
        operation: "open",
        configuration: settings,
        recovery: {
          ...recovery,
          stream: "d2e1c945-697b-4f94-a3f1-5309893d299d",
        },
      })
    ).body.state,
    "failed",
  );
  assert.equal(
    (await f.send({ operation: "open", configuration: settings, recovery }))
      .body.state,
    "initialized",
  );
});
test("recovery captures escaped near-limit arguments and outcomes in bounded parts", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const request = {
    id: "large",
    session: "operations",
    target: "internal",
    tool: "lookup",
    arguments: { value: '"'.repeat(30000) },
    expiresAt: Math.floor(Date.now() / 1000) + 240,
  };
  const proposed = await f.send({
    operation: "propose",
    principal: "agent",
    request,
  });
  assert.equal(proposed.status, 200);
  const p = proposed.body.proposal;
  await decide(f, p);
  const claim = await f.send({
    operation: "claim",
    principal: "agent",
    session: "operations",
    id: "large",
    digest: p.digest,
  });
  assert.equal(claim.status, 200);
  const result = '"'.repeat(60000);
  assert.equal(
    (
      await f.send({
        operation: "finish",
        session: "operations",
        id: "large",
        claimId: claim.body.claimId,
        outcome: "succeeded",
        result,
      })
    ).status,
    200,
  );
  const entry = (await journal(f, { operation: "entry", sequence: 4 })).body;
  assert.equal(entry.parts, 2);
  const parts = [];
  for (let part = 0; part < entry.parts; part++)
    parts.push(
      Buffer.from(
        (await journal(f, { operation: "part", sequence: 4, part })).body.data,
        "base64",
      ),
    );
  assert.equal(
    JSON.parse(
      JSON.parse(Buffer.concat(parts).toString()).record.row.result_canonical,
    ),
    result,
  );
  assert.equal((await open(f)).status, 200);
});
test("signed service facade gates real MCP execution on independent claim durability", async (t) => {
  const { fixture: providerFixture } = await import(
    "../services/organization/test-fixtures/provider.mjs"
  );
  const { mcpFixture } = await import(
    "../services/organization/test-fixtures/mcp.mjs"
  );
  const { identity, configuration, provisioning, command } = await import(
    "./fixtures/cloudflare/authority-harness.mjs"
  );
  const provider = await providerFixture(t),
    mcp = await mcpFixture(t),
    actors = [identity("agent"), identity("human")],
    config = configuration(provider, actors),
    f = await runtime.fixture(undefined, "SERVICE");
  mcp.config.revision = "1";
  mcp.config.recipient = actors[0].entity;
  const settings = {
      organization: "lifecycle-fixture",
      origin: "https://xeip.example",
      gateway: actors[0].entity,
      trust: { maxAgeSeconds: 300 },
      targets: [mcp.config],
      introspectionClientSecret: provider.config.introspectionClientSecret,
    },
    recovery = { ...options, organization: "lifecycle-fixture" };
  const remote = (value) => f.send({ operation: "recoveryJournal", value });
  await remote({ operation: "initialize", options: recovery });
  await f.send({ operation: "open", configuration: settings, recovery });
  assert.equal(
    (await f.send({ operation: "initialize", configuration: config })).body
      .state,
    "initialized",
  );
  await f.send({
    operation: "refresh",
    provisioning: provisioning(actors, 1),
    expectedRevision: 0,
  });
  const agent = await provider.token({
      sub: "agent",
      azp: "xeip-agent",
      resource_access: { "xeip-api": { roles: ["agent"] } },
    }),
    human = await provider.token({ sub: "human" });
  const send = async (operation, digest) =>
    (
      await f.send({
        operation: "http",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer " + (operation === "approve" ? human : agent),
        },
        body: command(
          actors[operation === "approve" ? 1 : 0],
          actors[0].entity,
          operation,
          "flow",
          digest,
          { query: "approved" },
        ),
      })
    ).body;
  const proposed = await send("propose");
  assert.equal(proposed.body.state, "pending");
  const digest = proposed.body.proposal.digest;
  assert.equal((await send("approve", digest)).body.state, "approved");
  await remote({ operation: "controls", control: { holdSync: 4 } });
  const pending = send("execute", digest);
  try {
    for (let i = 0; i < 200; i++) {
      if (
        (await remote({ operation: "controls", control: {} })).body.syncs === 4
      )
        break;
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.equal(
      (await remote({ operation: "controls", control: {} })).body.syncs,
      4,
    );
    assert.equal(mcp.state.calls.length, 0);
  } finally {
    await remote({ operation: "controls", control: { holdSync: 0 } });
  }
  assert.equal((await pending).body.state, "succeeded");
  assert.deepEqual(mcp.state.calls, [{ query: "approved" }]);
  assert.equal((await remote({ operation: "head" })).body.sequence, 4);
});
test("two unpublished source transitions cannot be adopted as one interrupted operation", async () => {
  const donor = await runtime.fixture();
  await donor.send({ operation: "openWithoutRecovery" });
  await propose(donor, "a");
  await propose(donor, "b");
  const f = await runtime.fixture();
  await initialize(f);
  assert.equal(
    (await f.send({ operation: "restoreSource", rows: await rows(donor) }))
      .status,
    200,
  );
  assert.equal((await open(f)).status, 503);
  assert.equal((await journal(f, { operation: "head" })).body.sequence, 0);
});
test("missing binding cannot be re-enrolled over history and forked source records cannot reopen", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await propose(f);
  const trigger = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_action_recovery_delete'",
    )
  ).body.rows[0].sql;
  assert.equal(
    (await f.sql("DROP TRIGGER xeip_action_recovery_delete")).status,
    200,
  );
  assert.equal((await f.sql("DELETE FROM xeip_action_recovery")).status, 200);
  assert.equal((await f.sql(trigger)).status, 200);
  assert.equal((await open(f)).status, 503);
  assert.equal((await open(f, { initialize: true })).status, 503);
  const donor = await runtime.fixture();
  await donor.send({ operation: "openWithoutRecovery" });
  await propose(donor, "different");
  const target = await runtime.fixture();
  await initialize(target);
  await propose(target, "original");
  assert.equal(
    (await target.send({ operation: "restoreSource", rows: await rows(donor) }))
      .status,
    200,
  );
  assert.equal((await open(target)).status, 503);
});
async function concurrencyService(t) {
  const { fixture: providerFixture } = await import(
      "../services/organization/test-fixtures/provider.mjs"
    ),
    { mcpFixture } = await import(
      "../services/organization/test-fixtures/mcp.mjs"
    ),
    { identity, configuration, provisioning, command } = await import(
      "./fixtures/cloudflare/authority-harness.mjs"
    );
  const provider = await providerFixture(t),
    mcp = await mcpFixture(t),
    actors = [identity("agent"), identity("human")],
    config = configuration(provider, actors),
    f = await runtime.fixture(undefined, "SERVICE");
  mcp.config.revision = "1";
  mcp.config.recipient = actors[0].entity;
  const settings = {
      organization: "lifecycle-fixture",
      origin: "https://xeip.example",
      gateway: actors[0].entity,
      trust: { maxAgeSeconds: 300 },
      targets: [mcp.config],
      introspectionClientSecret: provider.config.introspectionClientSecret,
    },
    recovery = { ...options, organization: "lifecycle-fixture" };
  const remote = (value) => f.send({ operation: "recoveryJournal", value });
  await remote({ operation: "initialize", options: recovery });
  await f.send({ operation: "open", configuration: settings, recovery });
  await f.send({ operation: "initialize", configuration: config });
  await f.send({
    operation: "refresh",
    provisioning: provisioning(actors, 1),
    expectedRevision: 0,
  });
  const agent = await provider.token({
      sub: "agent",
      azp: "xeip-agent",
      resource_access: { "xeip-api": { roles: ["agent"] } },
    }),
    human = await provider.token({ sub: "human" });
  const send = async (operation, digest) =>
    (
      await f.send({
        operation: "http",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer " + (operation === "approve" ? human : agent),
        },
        body: command(
          actors[operation === "approve" ? 1 : 0],
          actors[0].entity,
          operation,
          "flow",
          digest,
          { query: "approved" },
        ),
      })
    ).body;
  const proposed = await send("propose"),
    digest = proposed.body.proposal.digest;
  assert.equal((await send("approve", digest)).body.state, "approved");
  return { f, mcp, send, digest, remote };
}
async function until(predicate) {
  const stop = Date.now() + 10000;
  while (!(await predicate())) {
    if (Date.now() > stop) assert.fail("fixture boundary not reached");
    await new Promise((r) => setTimeout(r, 5));
  }
}
for (const phase of ["response", "grant"])
  test(
    "review: concurrent inspection preserves " +
      phase +
      "-stage MCP execution and completion",
    async (t) => {
      const s = await concurrencyService(t);
      let release,
        entered = false;
      const held = new Promise((r) => {
        release = r;
      });
      t.after(() => release());
      s.mcp.state[phase === "response" ? "beforeTool" : "beforeGrant"] =
        async () => {
          entered = true;
          await held;
        };
      const executing = s.send("execute", s.digest);
      await until(() => entered);
      const sync = (await s.f.send({ operation: "controls" })).body.syncs + 1;
      await s.f.send({ operation: "controls", control: { holdSync: sync } });
      const inspecting = s.send("inspect");
      try {
        await until(
          async () =>
            (await s.f.send({ operation: "controls" })).body.syncs === sync,
        );
        release();
        await new Promise((r) => setTimeout(r, 50));
      } finally {
        release();
        await s.f.send({ operation: "controls", control: { holdSync: 0 } });
        await Promise.allSettled([executing, inspecting]);
      }
      assert.equal((await inspecting).status, 200);
      const result = await executing;
      assert.equal(result.body.state, "succeeded");
      assert.equal(s.mcp.state.calls.length, 1);
      assert.equal((await s.remote({ operation: "head" })).body.sequence, 4);
      assert.equal(
        (await s.f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
        "succeeded",
      );
    },
  );
for (const mode of ["timeout", "close"])
  test(
    "queued completion " + mode + " cannot execute a late source mutation",
    async () => {
      const f = await runtime.fixture();
      await initialize(f);
      if (mode === "timeout")
        assert.equal(
          (await open(f, { options: { ...options, timeoutMs: 100 } })).status,
          200,
        );
      const p = (await propose(f)).body.proposal;
      await decide(f, p);
      const claim = (
        await f.send({
          operation: "claim",
          principal: "agent",
          session: "operations",
          id: "one",
          digest: p.digest,
        })
      ).body;
      const entered = (await f.send({ operation: "controls" })).body.entered;
      await f.send({ operation: "controls", hold: "inspect" });
      const inspection = f.send({
        operation: "inspect",
        principal: "agent",
        session: "operations",
        id: "one",
      });
      await until(
        async () =>
          (await f.send({ operation: "controls" })).body.entered > entered,
      );
      const completion = f.send({
        operation: "finish",
        session: "operations",
        id: "one",
        claimId: claim.claimId,
        outcome: "succeeded",
        result: { content: [] },
      });
      try {
        if (mode === "close") {
          await new Promise((r) => setTimeout(r, 10));
          await f.send({ operation: "closeRecovery" });
        }
        assert.equal((await completion).body.error, "StoreUnavailable");
      } finally {
        await f.send({ operation: "controls", hold: null });
        await Promise.allSettled([inspection, completion]);
      }
      assert.equal(
        (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
        "executing",
      );
      assert.equal((await journal(f, { operation: "head" })).body.sequence, 3);
      assert.equal((await open(f)).status, 200);
    },
  );
