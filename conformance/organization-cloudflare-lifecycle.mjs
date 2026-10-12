import { randomUUID } from "node:crypto";
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { fixture as providerFixture } from "../services/organization/test-fixtures/provider.mjs";
import { mcpFixture } from "../services/organization/test-fixtures/mcp.mjs";
import {
  identity,
  configuration,
  provisioning,
  command,
} from "./fixtures/cloudflare/authority-harness.mjs";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
import { recoveryJournal } from "./fixtures/cloudflare/recovery-http-harness.mjs";
let runtime;
before(async () => {
  runtime = await harness();
});
after(async () => {
  await runtime?.close();
});
test("lifecycle schema prevents replacement, deletion and completed-phase rollback", async () => {
  const f = await runtime.fixture();
  await f.send({ operation: "schema" });
  const inserted = await f.sql(
    "INSERT INTO xeip_service_state(singleton,runtime_configuration,initial_authority,checksum,phase) VALUES (1,?,?,?,?)",
    "{}",
    "{}",
    "0".repeat(64),
    "initializing",
  );
  assert.equal(inserted.status, 200, JSON.stringify(inserted));
  assert.equal(
    (await f.sql("UPDATE xeip_service_state SET phase='initialized'")).status,
    200,
  );
  for (const query of [
    "DELETE FROM xeip_service_state",
    "UPDATE xeip_service_state SET phase='initializing'",
    "UPDATE xeip_service_state SET runtime_configuration='[]'",
    "UPDATE xeip_service_state SET checksum='" + "1".repeat(64) + "'",
    "INSERT OR REPLACE INTO xeip_service_state SELECT * FROM xeip_service_state",
  ])
    assert.equal((await f.sql(query)).status, 500, query);
  assert.equal(
    (await f.sql("SELECT phase FROM xeip_service_state")).body.rows[0].phase,
    "initialized",
  );
});
test("v3 migration preserves existing authority tables and does not invent service initialization", async () => {
  const f = await runtime.fixture();
  await f.send({ operation: "v3" });
  const old = (
    await f.sql(
      "SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY type,name",
    )
  ).body.rows;
  assert.equal((await f.send({ operation: "schema" })).body.ok, true);
  const next = (
    await f.sql(
      "SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY type,name",
    )
  ).body.rows;
  for (const row of old)
    assert.deepEqual(
      next.find((n) => n.name === row.name),
      row,
    );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_service_state")).body.rows,
    [],
  );
});

async function setup(t) {
  const provider = await providerFixture(t),
    mcp = await mcpFixture(t),
    actors = [identity("agent"), identity("human")],
    config = configuration(provider, actors),
    f = await runtime.fixture();
  mcp.config.revision = "1";
  mcp.config.recipient = actors[0].entity;
  const settings = {
    organization: "lifecycle-fixture",
    origin: "https://xeip.example",
    gateway: actors[0].entity,
    trust: { maxAgeSeconds: 300 },
    targets: [mcp.config],
    introspectionClientSecret: provider.config.introspectionClientSecret,
  };
  return { provider, mcp, actors, config, f, settings };
}
async function until(fn) {
  const end = Date.now() + 5000;
  while (!(await fn())) {
    if (Date.now() > end) throw Error("condition not reached");
    await new Promise((r) => setTimeout(r, 10));
  }
}
const open = (s) => s.f.send({ operation: "open", configuration: s.settings });
const initialize = (s) =>
  s.f.send({ operation: "initialize", configuration: s.config });
const refresh = (s, expectedRevision = 0, serial = 1) =>
  s.f.send({
    operation: "refresh",
    provisioning: provisioning(s.actors, serial),
    expectedRevision,
  });
test("configured lifecycle persists normalized recovery identity without its credential or timeout", async (t) => {
  const s = await setup(t),
    remote = await recoveryJournal(t, s.settings.organization);
  const source = await harness({
    outboundService: (request) => remote.outbound(request),
  });
  t.after(() => source.close());
  s.f = await source.fixture();
  s.settings.recovery = remote.recovery;
  s.settings.recoveryToken = remote.token;
  assert.equal((await open(s)).body.state, "uninitialized");
  assert.equal((await initialize(s)).body.state, "initialized");
  const row = (
    await s.f.sql(
      "SELECT runtime_configuration,initial_authority FROM xeip_service_state",
    )
  ).body.rows[0];
  assert.ok(!JSON.stringify(row).includes(remote.token));
  const captured = await s.f.send({ operation: "lifecycleCheckpoint" });
  assert.equal(captured.status, 200);
  const recovered = validateLifecycleCheckpoint(
    captured.body,
    s.settings.organization,
  );
  assert.equal(canonicalize(recovered.runtime), row.runtime_configuration);
  assert.equal(JSON.stringify(recovered).includes(remote.token), false);
  const persisted = JSON.parse(row.runtime_configuration).recovery;
  assert.deepEqual(
    Object.keys(persisted).sort(),
    [
      "organization",
      "stream",
      "maxEntries",
      "maxBytes",
      "genesis",
      "url",
    ].sort(),
  );
  assert.equal(persisted.url, remote.recovery.url);
  assert.equal(persisted.stream, remote.recovery.stream);
  assert.equal(persisted.organization, s.settings.organization);
  assert.equal(persisted.maxEntries, 1000000);
  assert.equal(persisted.maxBytes, 1073741824);
  const binding = (await s.f.sql("SELECT canonical FROM xeip_action_recovery"))
    .body.rows[0].canonical;
  assert.ok(!binding.includes(remote.token));
  assert.ok(!binding.includes('"url"'));
  s.settings.recovery = {
    ...remote.recovery,
    maxEntries: 1000000,
    maxBytes: 1073741824,
    timeoutMs: 8000,
  };
  assert.equal((await open(s)).body.state, "initialized");
  assert.equal(
    (await s.f.sql("SELECT runtime_configuration FROM xeip_service_state")).body
      .rows[0].runtime_configuration,
    row.runtime_configuration,
  );
});
test("service configuration cannot override HTTPS recovery with an injected adapter", async (t) => {
  const s = await setup(t),
    remote = await recoveryJournal(t, s.settings.organization);
  s.settings.recovery = remote.recovery;
  s.settings.recoveryToken = remote.token;
  const result = await s.f.send({
    operation: "open",
    configuration: s.settings,
    recovery: remote.options,
  });
  assert.equal(result.body.error, "TypeError");
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
  assert.equal(remote.requests.length, 0);
});
test("service validates recovery credential pairing even without the Worker profile parser", async (t) => {
  const s = await setup(t);
  for (const extra of [
    { recoveryToken: "a1".repeat(32) },
    {
      recovery: {
        url: "https://journal.example/v1/recovery",
        stream: randomUUID(),
      },
    },
    {
      recovery: {
        url: "https://journal.example/v1/recovery",
        stream: randomUUID(),
      },
      recoveryToken: "invalid",
    },
    { recovery: null, recoveryToken: "a1".repeat(32) },
  ])
    assert.equal(
      (
        await s.f.send({
          operation: "open",
          configuration: { ...s.settings, ...extra },
        })
      ).body.error,
      "TypeError",
    );
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
});
test("public open and requests leave empty storage uninitialized without writing schema", async (t) => {
  const s = await setup(t);
  assert.equal((await open(s)).body.state, "uninitialized");
  assert.equal((await s.f.send({ operation: "http" })).body.status, 503);
  assert.equal(
    (
      await s.f.send({
        operation: "http",
        url: "https://xeip.example/live",
        method: "GET",
      })
    ).body.status,
    200,
  );
  assert.equal(
    (
      await s.f.send({
        operation: "http",
        url: "https://xeip.example/ready",
        method: "GET",
      })
    ).body.status,
    503,
  );
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
});
test("explicit initialization requires separate signed refresh before provider readiness", async (t) => {
  const s = await setup(t);
  await open(s);
  assert.equal((await initialize(s)).body.state, "initialized");
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
  assert.equal((await refresh(s)).body.trust.state, "ready");
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, true);
  const persisted = JSON.stringify(
    (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows,
  );
  assert.equal(persisted.includes(s.settings.introspectionClientSecret), false);
  assert.equal(persisted.includes(s.mcp.config.clientSecret), false);
});
for (const step of [1, 2, 3, 4])
  test(
    "bootstrap sync fault " +
      step +
      " quarantines and exact owner retry resumes after restart",
    async (t) => {
      const s = await setup(t);
      await open(s);
      await s.f.send({ operation: "controls", control: { failSync: step } });
      assert.equal((await initialize(s)).status, 500);
      assert.equal(
        (await s.f.send({ operation: "status" })).body.state,
        "failed",
      );
      await runtime.restart();
      s.f = await runtime.fixture(s.f.name);
      const opened = await open(s);
      assert.ok(
        ["initializing", "initialized"].includes(opened.body.state),
        JSON.stringify(opened),
      );
      assert.equal((await initialize(s)).body.state, "initialized");
      assert.equal((await refresh(s)).body.trust.state, "ready");
    },
  );
test("changed retry intent cannot overwrite a partial bootstrap", async (t) => {
  const s = await setup(t);
  await open(s);
  await s.f.send({ operation: "controls", control: { failSync: 1 } });
  await initialize(s);
  await runtime.restart();
  s.f = await runtime.fixture(s.f.name);
  await open(s);
  const changed = structuredClone(s.config);
  changed.policy.sessions[0].approvers = [];
  assert.equal(
    (await s.f.send({ operation: "initialize", configuration: changed })).body
      .error,
    "StoreConflict",
  );
  assert.equal((await initialize(s)).body.state, "initialized");
});
for (const component of [
  "xeip_trust_state",
  "xeip_authority_state",
  "xeip_service_state",
])
  test("completed service never recreates missing " + component, async (t) => {
    const s = await setup(t);
    await open(s);
    await initialize(s);
    await refresh(s);
    const triggers = (
      await s.f.sql(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
        component,
      )
    ).body.rows;
    for (const row of triggers) await s.f.sql("DROP TRIGGER " + row.name);
    await s.f.sql("DELETE FROM " + component);
    for (const row of triggers) await s.f.sql(row.sql);
    await runtime.restart();
    s.f = await runtime.fixture(s.f.name);
    assert.equal((await open(s)).body.state, "failed");
    assert.equal((await initialize(s)).status, 500);
    assert.equal(
      (await s.f.sql("SELECT COUNT(*) AS count FROM " + component)).body.rows[0]
        .count,
      0,
    );
  });
test("runtime route drift fails closed while secret rotation preserves persisted public configuration", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  const original = structuredClone(s.settings);
  s.settings.targets[0].endpoint += "/changed";
  assert.equal((await open(s)).body.state, "failed");
  s.settings = original;
  s.settings.introspectionClientSecret = "new-runtime-secret";
  assert.equal((await open(s)).body.state, "initialized");
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
});
test("invalid initialization leaves empty storage untouched", async (t) => {
  const s = await setup(t);
  await open(s);
  s.config.authentication.introspectionClientSecret = "secret-forbidden";
  assert.equal((await initialize(s)).status, 500);
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
});
test("closing during initialization cannot reactivate the service", async (t) => {
  const s = await setup(t);
  await open(s);
  await s.f.send({ operation: "controls", control: { holdSync: 1 } });
  const pending = initialize(s);
  await until(
    async () => (await s.f.send({ operation: "controls" })).body.syncs === 1,
  );
  assert.equal((await s.f.send({ operation: "close" })).body.state, "closed");
  await s.f.send({ operation: "controls", control: { holdSync: 0 } });
  assert.equal((await pending).status, 500);
  assert.equal((await s.f.send({ operation: "status" })).body.state, "closed");
});
test("failure writing the first intent rolls back schema and permits explicit retry after restart", async (t) => {
  const s = await setup(t);
  await open(s);
  await s.f.send({
    operation: "controls",
    control: { failQuery: "INSERT INTO xeip_service_state" },
  });
  assert.equal((await initialize(s)).status, 500);
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
  await runtime.restart();
  s.f = await runtime.fixture(s.f.name);
  assert.equal((await open(s)).body.state, "uninitialized");
  assert.equal((await initialize(s)).body.state, "initialized");
});
async function approved(t, supplied) {
  const s = supplied ?? (await setup(t));
  assert.equal((await open(s)).body.state, "uninitialized");
  assert.equal((await initialize(s)).body.state, "initialized");
  assert.equal((await refresh(s)).status, 200);
  s.agent = await s.provider.token({
    sub: "agent",
    azp: "xeip-agent",
    resource_access: { "xeip-api": { roles: ["agent"] } },
  });
  s.human = await s.provider.token({ sub: "human" });
  s.send = async (operation, digest) => {
    const human = operation === "approve";
    return (
      await s.f.send({
        operation: "http",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer " + (human ? s.human : s.agent),
        },
        body: command(
          s.actors[human ? 1 : 0],
          s.actors[0].entity,
          operation,
          "flow",
          digest,
          { query: "approved" },
        ),
      })
    ).body;
  };
  const proposed = await s.send("propose");
  assert.equal(proposed.body.state, "pending", JSON.stringify(proposed));
  s.digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", s.digest)).body.state, "approved");
  return s;
}
test("service owns the signed lifecycle, persists the MCP outcome and never replays after restart", async (t) => {
  const s = await approved(t);
  assert.equal((await s.send("execute", s.digest)).body.state, "succeeded");
  assert.deepEqual(s.mcp.state.calls, [{ query: "approved" }]);
  await runtime.restart();
  s.f = await runtime.fixture(s.f.name);
  assert.equal((await open(s)).body.state, "initialized");
  assert.equal((await s.send("inspect")).body.state, "succeeded");
  assert.equal((await s.send("execute", s.digest)).status, 409);
  assert.equal((await initialize(s)).body.state, "initialized");
  assert.equal((await s.send("inspect")).body.state, "succeeded");
  assert.equal(s.mcp.state.calls.length, 1);
});
test("stale owner revisions and invalid targets preserve usable authority and trust", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  await refresh(s);
  assert.equal((await refresh(s, 0, 2)).body.error, "StoreConflict");
  const changed = structuredClone(s.config);
  changed.policy.sessions[0].approvers = [];
  assert.equal(
    (
      await s.f.send({
        operation: "update",
        configuration: changed,
        expectedRevision: 0,
      })
    ).body.authority.revision,
    1,
  );
  assert.equal(
    (
      await s.f.send({
        operation: "update",
        configuration: s.config,
        expectedRevision: 0,
      })
    ).body.error,
    "StoreConflict",
  );
  const unconfigured = structuredClone(s.config);
  unconfigured.policy.targets[0].revision = "2";
  assert.equal(
    (
      await s.f.send({
        operation: "update",
        configuration: unconfigured,
        expectedRevision: 1,
      })
    ).status,
    500,
  );
  assert.equal((await initialize(s)).body.authority.revision, 1);
  assert.deepEqual(
    JSON.parse(
      (await s.f.sql("SELECT configuration FROM xeip_authority_state")).body
        .rows[0].configuration,
    ).policy.sessions[0].approvers,
    [],
  );
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, true);
});
test("readiness follows provider outage without invoking a tool", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  await refresh(s);
  s.provider.state.introspectionStatus = 503;
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
  s.provider.state.introspectionStatus = 200;
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, true);
  assert.equal(s.mcp.state.requests.length, 0);
});
test("a trust update during readiness invalidates the late provider result", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  await refresh(s);
  let entered = false,
    release;
  const held = new Promise((r) => {
    release = r;
  });
  s.provider.state.beforeIntrospection = async () => {
    entered = true;
    await held;
  };
  const pending = s.f.send({ operation: "ready" });
  try {
    await until(async () => entered);
    assert.equal((await refresh(s, 1, 2)).status, 200);
  } finally {
    release();
  }
  assert.equal((await pending).body.ready, false);
  s.provider.state.beforeIntrospection = null;
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, true);
});
test("policy removal during MCP OAuth prevents sending the actual effect", async (t) => {
  const s = await approved(t);
  let entered = false,
    release;
  const held = new Promise((r) => {
    release = r;
  });
  s.mcp.state.beforeGrant = async () => {
    entered = true;
    await held;
  };
  const pending = s.send("execute", s.digest);
  try {
    await until(async () => entered);
    const next = structuredClone(s.config);
    next.policy.sessions[0].approvers = [];
    assert.equal(
      (
        await s.f.send({
          operation: "update",
          configuration: next,
          expectedRevision: 0,
        })
      ).status,
      200,
    );
  } finally {
    release();
  }
  assert.equal((await pending).body.state, "failed");
  assert.equal(
    s.mcp.state.requests.filter((r) => r.body?.method === "tools/call").length,
    0,
  );
});
test("owner mutation is exclusive while persistence awaits and public readiness stays unavailable", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  const next = (await s.f.send({ operation: "controls" })).body.syncs + 1;
  await s.f.send({ operation: "controls", control: { holdSync: next } });
  const pending = refresh(s);
  await until(
    async () => (await s.f.send({ operation: "controls" })).body.syncs === next,
  );
  try {
    assert.equal((await initialize(s)).body.error, "StoreConflict");
    assert.equal(
      (
        await s.f.send({
          operation: "update",
          configuration: s.config,
          expectedRevision: 0,
        })
      ).body.error,
      "StoreConflict",
    );
    assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
  } finally {
    await s.f.send({ operation: "controls", control: { holdSync: 0 } });
  }
  assert.equal((await pending).body.trust.state, "ready");
});
test("trust persistence failure quarantines the service rather than reporting ready", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  await refresh(s);
  const next = (await s.f.send({ operation: "controls" })).body.syncs + 1;
  await s.f.send({ operation: "controls", control: { failSync: next } });
  assert.equal((await refresh(s, 1, 2)).status, 500);
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
  assert.equal((await s.f.send({ operation: "http" })).body.status, 503);
});
test("ledger integrity quarantine makes readiness false even with healthy provider and trust", async (t) => {
  const s = await approved(t);
  const trigger = (
    await s.f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_action_update'",
    )
  ).body.rows[0].sql;
  await s.f.sql("DROP TRIGGER xeip_action_update");
  await s.f.sql("UPDATE xeip_actions SET digest=?", "0".repeat(64));
  await s.f.sql(trigger);
  assert.equal((await s.send("inspect")).status, 503);
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
  assert.equal((await s.send("execute", s.digest)).status, 503);
  assert.equal(s.mcp.state.calls.length, 0);
});
test("stale signed trust makes readiness false until an owner refresh", async (t) => {
  const s = await setup(t);
  s.settings.trust.maxAgeSeconds = 2;
  await open(s);
  await initialize(s);
  await refresh(s);
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, true);
  await new Promise((r) => setTimeout(r, 3100));
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, false);
  assert.equal((await refresh(s, 1, 2)).body.trust.state, "ready");
  assert.equal((await s.f.send({ operation: "ready" })).body.ready, true);
});
test("unknown target credential fields cannot enter the public persisted runtime configuration", async (t) => {
  const s = await setup(t);
  s.settings.targets[0].extraCredential = "must-not-persist";
  assert.equal((await open(s)).status, 500);
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
});
test("v3 upgrade preserves actual signed trust, authority history, consumed claim and audit byte-for-byte", async (t) => {
  const s = await approved(t);
  assert.equal((await s.send("execute", s.digest)).body.state, "succeeded");
  const tables = [
    "xeip_trust_state",
    "xeip_trust_checkpoints",
    "xeip_authority_state",
    "xeip_authority_events",
    "xeip_actions",
    "xeip_audit",
  ];
  const rows = {};
  for (const table of tables)
    rows[table] = (await s.f.sql("SELECT * FROM " + table)).body.rows;
  const legacy = await runtime.fixture();
  assert.equal(
    (await legacy.send({ operation: "seed-v3", rows })).body.ok,
    true,
  );
  assert.equal((await legacy.send({ operation: "schema" })).body.ok, true);
  for (const table of tables)
    assert.deepEqual(
      (await legacy.sql("SELECT * FROM " + table)).body.rows,
      rows[table],
      table,
    );
  assert.equal(
    (await legacy.send({ operation: "open", configuration: s.settings })).body
      .state,
    "failed",
  );
  assert.equal(
    (await legacy.send({ operation: "initialize", configuration: s.config }))
      .status,
    500,
  );
  assert.deepEqual(
    (await legacy.sql("SELECT * FROM xeip_actions")).body.rows,
    rows.xeip_actions,
  );
});
for (const [step, table] of [
  [2, "xeip_trust_state"],
  [3, "xeip_authority_state"],
])
  test(
    "partial bootstrap refuses drift in " + table + " instead of resetting it",
    async (t) => {
      const s = await setup(t);
      await open(s);
      await s.f.send({ operation: "controls", control: { failSync: step } });
      await initialize(s);
      assert.equal(
        (await s.f.sql("UPDATE " + table + " SET revision=1")).status,
        200,
      );
      await runtime.restart();
      s.f = await runtime.fixture(s.f.name);
      assert.equal((await open(s)).body.state, "initializing");
      assert.equal((await initialize(s)).status, 500);
      assert.equal(
        (await s.f.sql("SELECT revision FROM " + table)).body.rows[0].revision,
        1,
      );
    },
  );
test("lost result synchronization quarantines service and reopening preserves the consumed effect", async (t) => {
  const s = await approved(t);
  s.mcp.state.beforeTool = async () => {
    const next = (await s.f.send({ operation: "controls" })).body.syncs + 1;
    await s.f.send({ operation: "controls", control: { failSync: next } });
  };
  assert.equal((await s.send("execute", s.digest)).status, 503);
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
  assert.equal(s.mcp.state.calls.length, 1);
  await runtime.restart();
  s.f = await runtime.fixture(s.f.name);
  await open(s);
  assert.equal((await s.send("inspect")).body.state, "succeeded");
  assert.equal((await s.send("execute", s.digest)).status, 409);
  assert.equal(s.mcp.state.calls.length, 1);
});

test("resume rejects unexpected action rows", async (t) => {
  const s = await approved(t);
  const row = (await s.f.sql("SELECT * FROM xeip_actions")).body.rows[0];
  s.f = await runtime.fixture();
  await open(s);
  await s.f.send({ operation: "controls", control: { failSync: 1 } });
  assert.equal((await initialize(s)).status, 500);
  const pending = {
    ...row,
    state: "pending",
    version: 0,
    approver: null,
    approval_expires_at: null,
    claim_id: null,
    result_canonical: null,
  };
  assert.equal(
    (
      await s.f.sql(
        "INSERT INTO xeip_actions (" +
          Object.keys(pending).join(",") +
          ") VALUES (" +
          Object.keys(pending)
            .map(() => "?")
            .join(",") +
          ")",
        ...Object.values(pending),
      )
    ).status,
    200,
  );
  await runtime.restart();
  s.f = await runtime.fixture(s.f.name);
  assert.equal((await open(s)).body.state, "initializing");
  const resumed = await initialize(s);
  assert.equal(resumed.status, 500);
});
for (const phase of ["OAuth", "final authorization"])
  test(
    "ledger quarantine prevents pending effect during " + phase,
    async (t) => {
      const s = await approved(t);
      let entered = false,
        release;
      const held = new Promise((r) => {
        release = r;
      });
      const hold = async () => {
        entered = true;
        await held;
      };
      s.mcp.state.beforeGrant =
        phase === "OAuth"
          ? hold
          : async () => {
              s.provider.state.beforeIntrospection = async () => {
                s.provider.state.beforeIntrospection = null;
                await hold();
              };
            };
      const pending = s.send("execute", s.digest);
      try {
        await until(async () => entered);
        const trigger = (
          await s.f.sql(
            "SELECT sql FROM sqlite_master WHERE name='xeip_action_update'",
          )
        ).body.rows[0].sql;
        await s.f.sql("DROP TRIGGER xeip_action_update");
        await s.f.sql("UPDATE xeip_actions SET digest=?", "0".repeat(64));
        await s.f.sql(trigger);
        assert.equal((await s.send("inspect")).status, 503);
        assert.equal(
          (await s.f.send({ operation: "ready" })).body.ready,
          false,
        );
      } finally {
        release();
      }
      const result = await pending;
      assert.equal(result.status, 503);
      assert.equal(s.mcp.state.calls.length, 0);
    },
  );

const manage = (s, operation, extra = {}) =>
  s.f.send({
    operation: "manage",
    operator: "operations:alice",
    raw: JSON.stringify({ operation, requestId: randomUUID(), ...extra }),
  });
async function managedSetup(t) {
  const s = await setup(t);
  s.config.authentication.issuer = "https://id.example/realms/xeip";
  delete s.config.authentication.allowInsecureLoopback;
  await open(s);
  return s;
}
test("owner initialization persists its audit before state changes and acknowledgment", async (t) => {
  const s = await managedSetup(t);
  await s.f.send({ operation: "controls", control: { holdSync: 1 } });
  const pending = manage(s, "initialize", { configuration: s.config });
  await until(
    async () =>
      (await s.f.send({ operation: "controls", control: {} })).body.syncs >= 1,
  );
  assert.equal(
    (await s.f.sql("SELECT COUNT(*) AS count FROM xeip_owner_events")).body
      .rows[0].count,
    1,
  );
  assert.equal(
    (await s.f.sql("SELECT COUNT(*) AS count FROM xeip_authority_state")).body
      .rows[0].count,
    0,
  );
  await s.f.send({ operation: "controls", control: { holdSync: 0 } });
  assert.equal((await pending).body.state, "initialized");
  const page = (await manage(s, "auditExport")).body;
  assert.deepEqual(
    page.records.map((r) => r.event.outcome),
    ["started", "completed"],
  );
  assert.equal(page.records[0].event.before.state, "uninitialized");
  assert.equal(page.records[1].event.after.state, "initialized");
  assert.ok(
    !JSON.stringify(page).includes(s.settings.introspectionClientSecret),
  );
});
test("first journal write and initialization intent roll back together", async (t) => {
  const s = await managedSetup(t);
  await s.f.send({
    operation: "controls",
    control: { failQuery: "INSERT INTO xeip_owner_events" },
  });
  assert.equal(
    (await manage(s, "initialize", { configuration: s.config })).body.error,
    "StoreUnavailable",
  );
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
});
for (const where of ["start", "completion"])
  test(`owner ${where} durability failure never acknowledges trust refresh`, async (t) => {
    const s = await managedSetup(t);
    assert.equal(
      (await manage(s, "initialize", { configuration: s.config })).status,
      200,
    );
    const count = (await s.f.send({ operation: "controls", control: {} })).body
      .syncs;
    await s.f.send({
      operation: "controls",
      control: { failSync: count + (where === "start" ? 1 : 3) },
    });
    assert.equal(
      (
        await manage(s, "refreshTrust", {
          provisioning: provisioning(s.actors),
          expectedRevision: 0,
        })
      ).body.error,
      "StoreUnavailable",
    );
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      "failed",
    );
    await s.f.send({ operation: "controls", control: { failSync: 0 } });
    await open(s);
    assert.equal(
      (await s.f.send({ operation: "status" })).body.trust.revision,
      where === "start" ? 0 : 1,
    );
    const page = (await manage(s, "auditExport")).body;
    assert.equal(page.records[2].event.outcome, "started");
    assert.equal(page.records.length, where === "start" ? 3 : 4);
  });
test("stale owner revisions produce durable conflict records without changing policy", async (t) => {
  const s = await managedSetup(t);
  await manage(s, "initialize", { configuration: s.config });
  assert.equal(
    (
      await manage(s, "updateAuthority", {
        configuration: s.config,
        expectedRevision: 99,
      })
    ).body.error,
    "StoreConflict",
  );
  const page = (await manage(s, "auditExport")).body;
  assert.equal(page.records.at(-1).event.outcome, "conflict");
  assert.equal(page.records.at(-1).event.after.authorityRevision, 0);
});
test("owner export is read-only before initialization and journal corruption quarantines public service", async (t) => {
  const s = await managedSetup(t);
  assert.equal((await manage(s, "auditExport")).body.headSequence, 0);
  assert.deepEqual(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
  await manage(s, "initialize", { configuration: s.config });
  await s.f.sql("DROP TRIGGER xeip_owner_delete");
  assert.equal((await manage(s, "auditExport")).body.error, "StoreUnavailable");
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
});

for (const when of ["before", "after"])
  test(`owner bootstrap transaction ${when}-commit failure quarantines uncertain setup`, async (t) => {
    const s = await managedSetup(t);
    await s.f.send({
      operation: "controls",
      control: { failTransaction: when },
    });
    assert.equal(
      (await manage(s, "initialize", { configuration: s.config })).body.error,
      "StoreUnavailable",
    );
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      "failed",
    );
    await s.f.send({
      operation: "controls",
      control: { failTransaction: null },
    });
    assert.equal(
      (await open(s)).body.state,
      when === "before" ? "uninitialized" : "initializing",
    );
    assert.equal(
      (await manage(s, "auditExport")).body.headSequence,
      when === "before" ? 0 : 1,
    );
    assert.equal(
      (await manage(s, "initialize", { configuration: s.config })).body.state,
      "initialized",
    );
    assert.equal(
      (await manage(s, "auditExport")).body.headSequence,
      when === "before" ? 2 : 3,
    );
  });

for (const operation of ["actionSnapshot", "actionPage"])
  test(
    operation + " rejection preserves uninitialized and initializing service",
    async (t) => {
      const s = await setup(t);
      await open(s);
      const extra = operation === "actionPage" ? { cut: 0, after: 0 } : {};
      assert.equal(
        (await manage(s, operation, extra)).body.error,
        "StoreUnavailable",
      );
      assert.equal(
        (await s.f.send({ operation: "status" })).body.state,
        "uninitialized",
      );
      await s.f.send({ operation: "controls", control: { holdSync: 1 } });
      const pending = initialize(s);
      try {
        await until(
          async () =>
            (await s.f.send({ operation: "controls" })).body.syncs === 1,
        );
        assert.equal(
          (await s.f.send({ operation: "status" })).body.state,
          "initializing",
        );
        assert.equal(
          (await manage(s, operation, extra)).body.error,
          "StoreUnavailable",
        );
        assert.equal(
          (await s.f.send({ operation: "status" })).body.state,
          "initializing",
        );
      } finally {
        await s.f.send({ operation: "controls", control: { holdSync: 0 } });
        await pending;
      }
      assert.equal((await pending).body.state, "initialized");
      assert.equal((await manage(s, operation, extra)).status, 200);
    },
  );

test("service bootstrap refuses orphan trust representation chunks", async (t) => {
  const s = await setup(t);
  await open(s);
  await s.f.send({ operation: "schema" });
  const definition = (
    await s.f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_trust_chunk_new'",
    )
  ).body.rows[0].sql;
  await s.f.sql("DROP TRIGGER xeip_trust_chunk_new");
  assert.equal(
    (await s.f.sql("INSERT INTO xeip_trust_chunks VALUES(0,0,'AAAA')")).status,
    200,
  );
  await s.f.sql(definition);
  assert.equal((await initialize(s)).status, 500);
  assert.deepEqual(
    (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows,
    [],
  );
  assert.equal(
    (await s.f.sql("SELECT COUNT(*) AS count FROM xeip_trust_chunks")).body
      .rows[0].count,
    1,
  );
});

import { createHash } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { recoveryDescriptor } from "../services/organization/cloudflare/action-recovery.mjs";
import { validateLifecycleCheckpoint } from "../services/organization/cloudflare/lifecycle-checkpoint.mjs";
const lifecycleCapture = (s) => s.f.send({ operation: "lifecycleCheckpoint" });
function sealLifecycle(c) {
  c.checksum = createHash("sha256")
    .update(
      "XEIP organization lifecycle v1\n" +
        canonicalize([
          canonicalize(c.runtime),
          canonicalize(c.initialAuthority),
        ]),
    )
    .digest("hex");
  const { digest, ...body } = c;
  c.digest = createHash("sha256")
    .update("XEIP lifecycle checkpoint v1\n" + canonicalize(body))
    .digest("hex");
  return c;
}
function lifecycleRecord(s) {
  return sealLifecycle({
    schema: "xeip.lifecycle-checkpoint/1",
    organization: s.settings.organization,
    runtime: {
      organization: s.settings.organization,
      origin: s.settings.origin,
      gateway: s.settings.gateway,
      trust: structuredClone(s.settings.trust),
      targets: s.settings.targets.map(({ clientSecret, ...target }) =>
        structuredClone(target),
      ),
    },
    initialAuthority: structuredClone(s.config),
    phase: "initialized",
  });
}
test("lifecycle recovery checkpoint validates isolated intent and rejects rehashed secret, scope and target drift", async (t) => {
  const s = await setup(t),
    c = lifecycleRecord(s);
  const verified = validateLifecycleCheckpoint(c, s.settings.organization);
  c.runtime.targets[0].tools.push("extra");
  assert.deepEqual(
    verified.runtime.targets[0].tools,
    s.settings.targets[0].tools,
  );
  for (const mutate of [
    (c) => (c.runtime.introspectionClientSecret = "must-not-export"),
    (c) => (c.runtime.targets[0].clientSecret = "must-not-export"),
    (c) =>
      (c.initialAuthority.authentication.introspectionClientSecret =
        "must-not-export"),
    (c) => (c.runtime.trustFeedToken = "must-not-export"),
    (c) => (c.runtime.recoveryToken = "must-not-export"),
    (c) => (c.runtime.organization = "other"),
    (c) => (c.runtime.origin = "http://xeip.example"),
    (c) => (c.runtime.targets[0].tools = ["different"]),
    (c) => (c.runtime.targets[0].revision = "different"),
    (c) => (c.phase = "ready"),
    (c) => (c.phase = ["initialized"]),
    (c) => (c.extra = true),
  ]) {
    const bad = lifecycleRecord(s);
    mutate(bad);
    sealLifecycle(bad);
    assert.throws(
      () => validateLifecycleCheckpoint(bad, s.settings.organization),
      TypeError,
    );
  }
  const enrolled = lifecycleRecord(s);
  enrolled.runtime.recovery = recoveryDescriptor({
    organization: s.settings.organization,
    stream: randomUUID(),
  });
  sealLifecycle(enrolled);
  assert.equal(
    canonicalize(
      validateLifecycleCheckpoint(enrolled, s.settings.organization).runtime
        .recovery,
    ),
    canonicalize(enrolled.runtime.recovery),
  );
  enrolled.runtime.recovery = recoveryDescriptor({
    organization: "other",
    stream: randomUUID(),
  });
  sealLifecycle(enrolled);
  assert.throws(
    () => validateLifecycleCheckpoint(enrolled, s.settings.organization),
    TypeError,
  );
  const oversized = lifecycleRecord(s);
  oversized.runtime.trust.knownExtensions = ["x".repeat(2097152)];
  sealLifecycle(oversized);
  assert.throws(
    () => validateLifecycleCheckpoint(oversized, s.settings.organization),
    TypeError,
  );
  const damaged = lifecycleRecord(s);
  damaged.phase = "initializing";
  assert.throws(
    () => validateLifecycleCheckpoint(damaged, s.settings.organization),
    TypeError,
  );
});
test("lifecycle recovery checkpoint captures exact initial intent after current authority changes without secrets or writes", async (t) => {
  const s = await setup(t);
  s.settings.trustFeed = { url: "https://feed.example/trust" };
  s.settings.trustFeedToken = "synthetic-feed-token";
  await open(s);
  await initialize(s);
  const before = (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows;
  const config = structuredClone(s.config);
  config.authentication.clientIds.push("later-client");
  assert.equal(
    (
      await s.f.send({
        operation: "update",
        configuration: config,
        expectedRevision: 0,
      })
    ).status,
    200,
  );
  const result = await lifecycleCapture(s);
  assert.equal(result.status, 200);
  const c = validateLifecycleCheckpoint(result.body, s.settings.organization);
  assert.equal(c.phase, "initialized");
  assert.equal(canonicalize(c.runtime), before[0].runtime_configuration);
  assert.equal(canonicalize(c.initialAuthority), before[0].initial_authority);
  assert.equal(c.checksum, before[0].checksum);
  assert.equal(c.runtime.trustFeed.url, s.settings.trustFeed.url);
  assert.equal(JSON.stringify(c).includes(s.settings.trustFeedToken), false);
  assert.equal(
    JSON.stringify(c).includes(s.settings.introspectionClientSecret),
    false,
  );
  assert.equal(
    JSON.stringify(c).includes(s.settings.targets[0].clientSecret),
    false,
  );
  assert.deepEqual(
    (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows,
    before,
  );
  assert.equal(s.provider.state.introspectionCalls, 0);
});
test("lifecycle recovery checkpoint preserves interrupted initialization without completing it", async (t) => {
  const s = await setup(t);
  await open(s);
  await s.f.send({ operation: "controls", control: { failSync: 1 } });
  assert.equal((await initialize(s)).status, 500);
  await s.f.send({ operation: "controls", control: { failSync: 0 } });
  assert.equal((await open(s)).body.state, "initializing");
  const before = (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows;
  const result = await lifecycleCapture(s);
  assert.equal(result.status, 200);
  assert.equal(
    validateLifecycleCheckpoint(result.body, s.settings.organization).phase,
    "initializing",
  );
  assert.equal(
    (await s.f.send({ operation: "status" })).body.state,
    "initializing",
  );
  assert.deepEqual(
    (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows,
    before,
  );
});
test("lifecycle recovery checkpoint gates other control mutations until local synchronization finishes", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  const before = (await s.f.send({ operation: "controls" })).body.syncs;
  await s.f.send({ operation: "controls", control: { holdSync: before + 1 } });
  let settled = false;
  const pending = lifecycleCapture(s).finally(() => {
    settled = true;
  });
  try {
    await until(
      async () =>
        (await s.f.send({ operation: "controls" })).body.syncs === before + 1 ||
        settled,
    );
    assert.equal(settled, false);
    assert.equal((await lifecycleCapture(s)).body.error, "StoreConflict");
    assert.equal(
      (
        await s.f.send({
          operation: "update",
          configuration: s.config,
          expectedRevision: 0,
        })
      ).body.error,
      "StoreConflict",
    );
  } finally {
    await s.f.send({ operation: "controls", control: { holdSync: 0 } });
  }
  assert.equal((await pending).status, 200);
});
for (const closed of [false, true])
  test(`lifecycle recovery checkpoint refuses ${closed ? "closure during" : "failure of"} synchronization`, async (t) => {
    const s = await setup(t);
    await open(s);
    await initialize(s);
    const n = (await s.f.send({ operation: "controls" })).body.syncs + 1;
    await s.f.send({
      operation: "controls",
      control: closed ? { holdSync: n } : { failSync: n },
    });
    const pending = lifecycleCapture(s);
    if (closed) {
      try {
        await until(
          async () =>
            (await s.f.send({ operation: "controls" })).body.syncs === n,
        );
        await s.f.send({ operation: "close" });
      } finally {
        await s.f.send({ operation: "controls", control: { holdSync: 0 } });
      }
    }
    assert.equal((await pending).body.error, "StoreUnavailable");
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      closed ? "closed" : "failed",
    );
  });
test("lifecycle recovery checkpoint refuses empty state and corrupt intent without initializing or repairing", async (t) => {
  const s = await setup(t);
  await open(s);
  assert.equal((await lifecycleCapture(s)).body.error, "StoreUnavailable");
  assert.equal(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows.length,
    0,
  );
  await initialize(s);
  const trigger = (
    await s.f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_service_update'",
    )
  ).body.rows[0].sql;
  await s.f.sql("DROP TRIGGER xeip_service_update");
  await s.f.sql("UPDATE xeip_service_state SET checksum=?", "a".repeat(64));
  await s.f.sql(trigger);
  assert.equal((await lifecycleCapture(s)).body.error, "StoreUnavailable");
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
});
test("lifecycle recovery checkpoint preflight refuses foreign injected recovery before any schema write", async (t) => {
  const s = await setup(t);
  const opened = await s.f.send({
    operation: "open",
    configuration: s.settings,
    recovery: { organization: "other", stream: randomUUID() },
  });
  assert.equal(opened.body.error, "TypeError");
  assert.equal(
    (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows.length,
    0,
  );
});
test("lifecycle recovery checkpoint refuses valid intent replacement during synchronization", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  const row = (await s.f.sql("SELECT * FROM xeip_service_state")).body.rows[0];
  const trigger = (
    await s.f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_service_update'",
    )
  ).body.rows[0].sql;
  const config = structuredClone(s.config);
  config.authentication.clientIds.push("replacement-client");
  const replacement = canonicalize(config);
  const checksum = createHash("sha256")
    .update(
      "XEIP organization lifecycle v1\n" +
        canonicalize([row.runtime_configuration, replacement]),
    )
    .digest("hex");
  const n = (await s.f.send({ operation: "controls" })).body.syncs + 1;
  await s.f.send({ operation: "controls", control: { holdSync: n } });
  const pending = lifecycleCapture(s);
  try {
    await until(
      async () => (await s.f.send({ operation: "controls" })).body.syncs === n,
    );
    assert.equal(
      (await s.f.sql("DROP TRIGGER xeip_service_update")).status,
      200,
    );
    assert.equal(
      (
        await s.f.sql(
          "UPDATE xeip_service_state SET initial_authority=?,checksum=?",
          replacement,
          checksum,
        )
      ).status,
      200,
    );
    assert.equal((await s.f.sql(trigger)).status, 200);
  } finally {
    await s.f.send({ operation: "controls", control: { holdSync: 0 } });
  }
  assert.equal((await pending).body.error, "StoreUnavailable");
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
  assert.equal(
    (await s.f.sql("SELECT initial_authority FROM xeip_service_state")).body
      .rows[0].initial_authority,
    replacement,
  );
});
for (const managed of [false, true])
  test(`lifecycle recovery checkpoint conflicts during pending ${managed ? "owner administration" : "initialization"}`, async (t) => {
    const s = await setup(t);
    if (managed) {
      s.config.authentication.issuer = "https://id.example/realms/xeip";
      delete s.config.authentication.allowInsecureLoopback;
    }
    await open(s);
    await s.f.send({ operation: "controls", control: { holdSync: 1 } });
    const pending = managed
      ? s.f.send({
          operation: "manage",
          operator: "operations:fixture",
          raw: JSON.stringify({
            operation: "initialize",
            requestId: randomUUID(),
            configuration: s.config,
          }),
        })
      : initialize(s);
    try {
      await until(
        async () =>
          (await s.f.send({ operation: "controls" })).body.syncs === 1,
      );
      assert.equal((await lifecycleCapture(s)).body.error, "StoreConflict");
    } finally {
      await s.f.send({ operation: "controls", control: { holdSync: 0 } });
    }
    assert.equal((await pending).status, 200);
    assert.equal((await lifecycleCapture(s)).status, 200);
  });
test("lifecycle recovery checkpoint accepts a configured target at its existing byte limit", async (t) => {
  const s = await setup(t),
    target = s.settings.targets[0];
  target.clientSecret = "x";
  target.clientId = "c".repeat(4096);
  target.scope = "s".repeat(4096);
  const remaining = 16384 - Buffer.byteLength(canonicalize(target));
  assert.ok(remaining > 0);
  target.endpoint += "p".repeat(remaining);
  assert.equal(Buffer.byteLength(canonicalize(target)), 16384);
  assert.equal((await open(s)).status, 200);
  assert.equal((await initialize(s)).status, 200);
  const result = await lifecycleCapture(s);
  assert.equal(result.status, 200);
  const captured = validateLifecycleCheckpoint(
    result.body,
    s.settings.organization,
  );
  const { clientSecret, ...expected } = target;
  assert.equal(
    canonicalize(captured.runtime.targets[0]),
    canonicalize(expected),
  );
});
test("lifecycle recovery checkpoint conflicts while trust polling awaits its feed", async (t) => {
  const s = await setup(t);
  let entered = false,
    release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const source = await harness({
    outboundService: async (request) => {
      assert.equal(request.url, "https://feed.example/trust");
      entered = true;
      await held;
      return Response.json(provisioning(s.actors, 2));
    },
  });
  t.after(() => source.close());
  s.f = await source.fixture();
  s.settings.trustFeed = {
    url: "https://feed.example/trust",
    timeoutMs: 10000,
  };
  s.settings.trustFeedToken = "synthetic-feed-token";
  await open(s);
  await initialize(s);
  assert.equal((await refresh(s)).status, 200);
  const pending = s.f.send({ operation: "pollTrustFeed" });
  try {
    await until(async () => entered);
    assert.equal((await lifecycleCapture(s)).body.error, "StoreConflict");
  } finally {
    release();
  }
  assert.equal((await pending).body.outcome, "updated");
  assert.equal((await lifecycleCapture(s)).status, 200);
});

const organizationCapture = (s) =>
  s.f.send({ operation: "recoveryCheckpoint" });
const organizationPage = (s, manifest, section, cursor) =>
  s.f.send({
    operation: "recoveryPage",
    manifest,
    options: { section, cursor },
  });
const organizationCodec = () =>
  import("../services/organization/cloudflare/organization-checkpoint.mjs");

test("private organization export keeps captured controls after native owner updates", async (t) => {
  const s = await managedSetup(t);
  await initialize(s);
  const begin = await s.f.send({
    operation: "exportBegin",
    operator: "fixture:owner",
  });
  assert.equal(begin.status, 200, JSON.stringify(begin.body));
  const { exportId, manifest } = begin.body;
  const changed = structuredClone(s.config);
  changed.authentication.clientIds.push("after-export");
  assert.equal(
    (
      await manage(s, "updateAuthority", {
        configuration: changed,
        expectedRevision: 0,
      })
    ).status,
    200,
  );
  const checkpoint = { manifest };
  for (const [component, descriptor] of Object.entries(begin.body.components)) {
    const chunks = [];
    for (let index = 0; index < descriptor.parts; index++) {
      const part = await s.f.send({
        operation: "exportPart",
        operator: "fixture:owner",
        exportId,
        component,
        index,
      });
      assert.equal(part.status, 200, JSON.stringify(part.body));
      chunks.push(Buffer.from(part.body.data, "base64"));
    }
    const raw = Buffer.concat(chunks);
    assert.equal(raw.length, descriptor.bytes);
    assert.equal(
      createHash("sha256").update(raw).digest("hex"),
      descriptor.sha256,
    );
    checkpoint[component] = JSON.parse(raw);
  }
  const { validateOrganizationCheckpoint } = await organizationCodec();
  const captured = validateOrganizationCheckpoint(
    checkpoint,
    s.settings.organization,
  );
  assert.equal(captured.authority.revision, 0);
  assert.equal(
    captured.authority.configuration.authentication.clientIds.includes(
      "after-export",
    ),
    false,
  );
  assert.equal(captured.administration.headSequence, 0);
  for (const section of ["authority", "administration"]) {
    const result = await s.f.send({
      operation: "exportPage",
      operator: "fixture:owner",
      exportId,
      options: { section, cursor: {} },
    });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.checkpointDigest, manifest.digest);
    assert.equal(result.body.page.complete, true);
    assert.equal(
      result.body.page.records.length,
      section === "authority" ? 1 : 0,
    );
  }
  assert.equal(
    (
      await s.f.send({
        operation: "exportClose",
        operator: "fixture:owner",
        exportId,
      })
    ).status,
    200,
  );
  assert.equal(
    (await s.f.send({ operation: "status" })).body.authority.revision,
    1,
  );
});

test("private organization export invalidates on native source closure and cannot revive on reopen", async (t) => {
  const s = await approved(t);
  const begin = await s.f.send({
    operation: "exportBegin",
    operator: "fixture:owner",
  });
  assert.equal(begin.status, 200, JSON.stringify(begin.body));
  const read = (operator = "fixture:owner") =>
    s.f.send({
      operation: "exportPart",
      operator,
      exportId: begin.body.exportId,
      component: "trust",
      index: 0,
    });
  assert.equal((await read("fixture:foreign")).body.error, "StoreUnavailable");
  assert.equal((await read()).status, 200);
  await s.f.send({ operation: "close" });
  assert.equal((await read()).body.error, "StoreUnavailable");
  await open(s);
  assert.equal((await read()).body.error, "StoreUnavailable");
  assert.equal(
    (await s.f.send({ operation: "exportBegin", operator: "fixture:owner" }))
      .status,
    200,
  );
  assert.equal((await s.send("execute", s.digest)).body.state, "succeeded");
  assert.equal(s.mcp.state.calls.length, 1);
});
test("organization recovery checkpoint binds all controls and fixed action evidence without credentials", async (t) => {
  const s = await approved(t);
  const captured = await organizationCapture(s);
  assert.equal(captured.status, 200);
  const { validateOrganizationCheckpoint } = await organizationCodec();
  const c = validateOrganizationCheckpoint(
    captured.body,
    s.settings.organization,
  );
  assert.equal(c.manifest.schema, "xeip.organization-checkpoint/1");
  assert.equal(c.manifest.actions.cut, 2);
  assert.equal(c.manifest.actions.actions, 1);
  assert.equal(c.lifecycle.phase, "initialized");
  assert.equal(c.trust.revision, 1);
  assert.equal(c.authority.revision, 0);
  assert.equal(c.administration.headSequence, 0);
  for (const secret of [
    s.settings.introspectionClientSecret,
    s.settings.targets[0].clientSecret,
    s.agent,
    s.human,
  ])
    assert.equal(JSON.stringify(c).includes(secret), false);
  const page = await organizationPage(s, c.manifest, "actions", 0);
  assert.equal(page.status, 200);
  assert.equal(page.body.checkpointDigest, c.manifest.digest);
  assert.equal(page.body.page.record.row.state, "approved");
  assert.equal(
    (await organizationPage(s, c.manifest, "authority", {})).body.page.complete,
    true,
  );
  assert.equal(
    (await organizationPage(s, c.manifest, "administration", {})).body.page
      .complete,
    true,
  );
});
test("organization recovery checkpoint retains an earlier action cut while actions finish during synchronization", async (t) => {
  const s = await approved(t);
  const n = (await s.f.send({ operation: "controls" })).body.syncs + 1;
  await s.f.send({ operation: "controls", control: { holdSync: n } });
  let settled = false;
  const pending = organizationCapture(s).finally(() => {
    settled = true;
  });
  try {
    await until(
      async () =>
        (await s.f.send({ operation: "controls" })).body.syncs === n || settled,
    );
    assert.equal(settled, false);
    assert.equal((await s.send("execute", s.digest)).body.state, "succeeded");
    assert.equal(s.mcp.state.calls.length, 1);
    assert.equal((await organizationCapture(s)).body.error, "StoreConflict");
    assert.equal((await refresh(s, 1, 2)).body.error, "StoreConflict");
    assert.equal(
      (
        await s.f.send({
          operation: "update",
          configuration: s.config,
          expectedRevision: 0,
        })
      ).body.error,
      "StoreConflict",
    );
  } finally {
    await s.f.send({ operation: "controls", control: { holdSync: 0 } });
  }
  const result = await pending;
  assert.equal(result.status, 200);
  assert.equal(result.body.manifest.actions.cut, 2);
  assert.equal(
    (await organizationPage(s, result.body.manifest, "actions", 0)).body.page
      .record.row.state,
    "approved",
  );
  const later = await organizationCapture(s);
  assert.equal(later.body.manifest.actions.cut, 4);
  assert.equal(
    (await organizationPage(s, later.body.manifest, "actions", 0)).body.page
      .record.row.state,
    "succeeded",
  );
  assert.equal(s.mcp.state.calls.length, 1);
});
for (const transport of ["checkpoint", "export"])
  test(`organization ${transport} refuses empty or incomplete setup without completing it`, async (t) => {
    const s = await setup(t);
    await open(s);
    const capture = () =>
      transport === "checkpoint"
        ? organizationCapture(s)
        : s.f.send({ operation: "exportBegin", operator: "fixture:owner" });
    assert.equal((await capture()).body.error, "StoreUnavailable");
    assert.equal(
      (await s.f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
        .body.rows.length,
      0,
    );
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      "uninitialized",
    );
    await s.f.send({ operation: "controls", control: { failSync: 1 } });
    await initialize(s);
    await s.f.send({ operation: "controls", control: { failSync: 0 } });
    assert.equal((await open(s)).body.state, "initializing");
    assert.equal((await capture()).body.error, "StoreUnavailable");
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      "initializing",
    );
  });

for (const transport of ["checkpoint", "export"])
  for (const closed of [false, true])
    test(`organization ${transport} refuses ${closed ? "closure during" : "failure of"} synchronization`, async (t) => {
      const s = await setup(t);
      await open(s);
      await initialize(s);
      const n = (await s.f.send({ operation: "controls" })).body.syncs + 1;
      await s.f.send({
        operation: "controls",
        control: closed ? { holdSync: n } : { failSync: n },
      });
      let settled = false;
      const pending = (
        transport === "checkpoint"
          ? organizationCapture(s)
          : s.f.send({ operation: "exportBegin", operator: "fixture:owner" })
      ).finally(() => {
        settled = true;
      });
      if (closed) {
        try {
          await until(
            async () =>
              (await s.f.send({ operation: "controls" })).body.syncs === n ||
              settled,
          );
          assert.equal(settled, false);
          await s.f.send({ operation: "close" });
        } finally {
          await s.f.send({ operation: "controls", control: { holdSync: 0 } });
        }
      }
      assert.equal((await pending).body.error, "StoreUnavailable");
      assert.equal(
        (await s.f.send({ operation: "status" })).body.state,
        closed ? "closed" : "failed",
      );
    });
test("organization recovery checkpoint rejects rehashed mixed component settings and scope", async (t) => {
  const s = await approved(t),
    original = await organizationCapture(s);
  assert.equal(original.status, 200);
  const { validateOrganizationCheckpoint } = await organizationCodec();
  const { authorityEventChecksum, authorityCheckpointDigest } = await import(
    "../services/organization/cloudflare/authority-checkpoint.mjs"
  );
  const { trustStateChecksum } = await import(
    "../services/organization/cloudflare/trust-checkpoint.mjs"
  );
  const hash = (value) => createHash("sha256").update(value).digest("hex");
  const reseal = (c) => {
    sealLifecycle(c.lifecycle);
    c.authority.checksum = authorityEventChecksum(
      c.authority.revision,
      hash(canonicalize(c.authority.configuration)),
      c.authority.previousChecksum,
    );
    const { digest, ...authority } = c.authority;
    c.authority.digest = authorityCheckpointDigest(authority);
    c.trust.checksum = trustStateChecksum({
      configuration: canonicalize(c.trust.configuration),
      provisioning: canonicalize(c.trust.provisioning),
      revision: c.trust.revision,
      accepted_at: c.trust.acceptedAt,
      checkpoints_digest: hash(canonicalize(c.trust.records)),
    });
    c.manifest.lifecycleDigest = c.lifecycle.digest;
    c.manifest.trustDigest = hash(
      "XEIP organization trust checkpoint v1\n" + canonicalize(c.trust),
    );
    c.manifest.authorityDigest = c.authority.digest;
    const { digest: old, ...manifest } = c.manifest;
    c.manifest.digest = hash(
      "XEIP organization checkpoint v1\n" + canonicalize(manifest),
    );
    return c;
  };
  for (const alter of [
    (c) => (c.lifecycle.phase = "initializing"),
    (c) => (c.trust.organization = "other"),
    (c) => c.trust.configuration.maxAgeSeconds++,
    (c) =>
      (c.authority.configuration.authentication.issuer =
        "https://other.example/realms/xeip"),
    (c) => {
      c.authority.revision = 1;
      c.authority.configuration.policy.targets[0].revision = "different";
    },
    (c) =>
      c.authority.configuration.authentication.clientIds.push(
        "not-in-initial-intent",
      ),
    (c) => (c.manifest.actions.organization = "other"),
    (c) => (c.lifecycle.runtime.targets[0].clientSecret = "never-export"),
  ]) {
    const bad = structuredClone(original.body);
    alter(bad);
    assert.throws(
      () =>
        validateOrganizationCheckpoint(reseal(bad), s.settings.organization),
      TypeError,
    );
  }
  const copy = structuredClone(original.body),
    valid = validateOrganizationCheckpoint(copy, s.settings.organization);
  copy.trust.provisioning.keyDocuments.length = 0;
  assert.equal(valid.trust.provisioning.keyDocuments.length, 2);
  assert.throws(
    () =>
      validateOrganizationCheckpoint(
        { ...original.body, secret: "extra" },
        s.settings.organization,
      ),
    TypeError,
  );
});
test("organization recovery pages reject changed control heads and invalid input without poisoning current state", async (t) => {
  const s = await managedSetup(t);
  await initialize(s);
  const c = await organizationCapture(s);
  assert.equal(c.status, 200);
  for (const [section, cursor] of [
    ["other", {}],
    ["actions", -1],
    ["authority", null],
    ["administration", { after: 1 }],
  ])
    assert.equal(
      (await organizationPage(s, c.body.manifest, section, cursor)).body.error,
      "TypeError",
    );
  const changed = structuredClone(s.config);
  changed.authentication.clientIds.push("later");
  assert.equal(
    (
      await manage(s, "updateAuthority", {
        configuration: changed,
        expectedRevision: 0,
      })
    ).status,
    200,
  );
  for (const section of ["authority", "administration"])
    assert.equal(
      (await organizationPage(s, c.body.manifest, section, {})).body.error,
      "StoreConflict",
    );
  assert.equal((await organizationCapture(s)).status, 200);
});

test("organization recovery checkpoint preserves an in-flight consumed claim without interrupting the effect", async (t) => {
  const s = await approved(t);
  let entered = false,
    release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  s.mcp.state.beforeTool = async () => {
    entered = true;
    await held;
  };
  const executing = s.send("execute", s.digest);
  let captured;
  try {
    await until(async () => entered);
    captured = await organizationCapture(s);
    assert.equal(captured.status, 200);
    assert.equal(captured.body.manifest.actions.cut, 3);
    const page = await organizationPage(
      s,
      captured.body.manifest,
      "actions",
      0,
    );
    assert.equal(page.body.page.record.row.state, "executing");
    assert.ok(page.body.page.record.row.claim_id);
  } finally {
    release();
  }
  assert.equal((await executing).body.state, "succeeded");
  assert.equal(
    (await organizationPage(s, captured.body.manifest, "actions", 0)).body.page
      .record.row.state,
    "executing",
  );
  assert.equal(s.mcp.state.calls.length, 1);
});
for (const transport of ["checkpoint", "export"])
  test(`organization ${transport} refuses a valid administrative append during synchronization`, async (t) => {
    const s = await approved(t);
    const { auditChecksum } = await import(
      "../services/organization/cloudflare/admin-record.mjs"
    );
    const n = (await s.f.send({ operation: "controls" })).body.syncs + 1;
    await s.f.send({ operation: "controls", control: { holdSync: n } });
    const pending =
      transport === "checkpoint"
        ? organizationCapture(s)
        : s.f.send({ operation: "exportBegin", operator: "fixture:owner" });
    try {
      await until(
        async () =>
          (await s.f.send({ operation: "controls" })).body.syncs === n,
      );
      const event = {
        operator: "operations:other-writer",
        requestId: randomUUID(),
        attemptId: randomUUID(),
        operation: "updateAuthority",
        commandDigest: "a".repeat(64),
        outcome: "started",
        occurredAt: 1000,
        before: {
          state: "initialized",
          trustRevision: 1,
          authorityRevision: 0,
        },
      };
      const encoded = canonicalize(event),
        previous = "0".repeat(64);
      assert.equal(
        (
          await s.f.sql(
            "INSERT INTO xeip_owner_events(sequence,attempt_id,outcome,canonical,previous,checksum) VALUES(1,?,'started',?,?,?)",
            event.attemptId,
            encoded,
            previous,
            auditChecksum(1, previous, encoded),
          )
        ).status,
        200,
      );
    } finally {
      await s.f.send({ operation: "controls", control: { holdSync: 0 } });
    }
    assert.equal((await pending).body.error, "StoreUnavailable");
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      "failed",
    );
    assert.equal(
      (await s.f.sql("SELECT COUNT(*) AS n FROM xeip_owner_events")).body
        .rows[0].n,
      1,
    );
  });
test("organization recovery checkpoint conflicts with a pending action journal receipt and leaves the source usable", async (t) => {
  const s = await setup(t),
    remote = await recoveryJournal(t, s.settings.organization);
  let hold = false,
    entered = false,
    release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const source = await harness({
    outboundService: async (request) => {
      if (request.url !== remote.recovery.url) {
        assert.ok(
          [
            new URL(s.provider.config.issuer).origin,
            new URL(s.mcp.config.endpoint).origin,
          ].includes(new URL(request.url).origin),
        );
        return fetch(request.url, {
          method: request.method,
          headers: [...request.headers],
          ...(!["GET", "HEAD"].includes(request.method)
            ? { body: await request.arrayBuffer() }
            : {}),
        });
      }
      if (hold) {
        entered = true;
        await held;
      }
      return remote.outbound(request);
    },
  });
  t.after(() => source.close());
  s.f = await source.fixture();
  s.settings.recovery = remote.recovery;
  s.settings.recoveryToken = remote.token;
  await approved(t, s);
  hold = true;
  const executing = s.send("execute", s.digest);
  try {
    await until(async () => entered);
    assert.equal((await organizationCapture(s)).body.error, "StoreConflict");
    assert.equal(
      (await s.f.send({ operation: "status" })).body.state,
      "initialized",
    );
  } finally {
    hold = false;
    release();
  }
  assert.equal((await executing).body.state, "succeeded");
  const captured = await organizationCapture(s);
  assert.equal(captured.status, 200);
  assert.equal(captured.body.manifest.actions.cut, 4);
  assert.equal(s.mcp.state.calls.length, 1);
});

test("organization recovery pages quarantine missing captured action history but preserve healthy invalid-cut conflicts", async (t) => {
  const s = await approved(t),
    captured = await organizationCapture(s),
    { organizationCheckpointDigest } = await organizationCodec();
  assert.equal(captured.status, 200);
  assert.equal(captured.body.manifest.actions.cut, 2);
  const { digest, ...body } = structuredClone(captured.body.manifest);
  body.actions.cut = 3;
  const invalidCut = { ...body, digest: organizationCheckpointDigest(body) };
  assert.equal(
    (await organizationPage(s, invalidCut, "actions", 0)).body.error,
    "StoreConflict",
  );
  assert.equal(
    (await s.f.send({ operation: "status" })).body.state,
    "initialized",
  );
  assert.equal(
    (await organizationPage(s, captured.body.manifest, "actions", 0)).status,
    200,
  );

  const trigger = (
    await s.f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_audit_delete'",
    )
  ).body.rows[0].sql;
  assert.equal((await s.f.sql("DROP TRIGGER xeip_audit_delete")).status, 200);
  assert.equal(
    (await s.f.sql("DELETE FROM xeip_audit WHERE sequence=?", 2)).status,
    200,
  );
  assert.equal((await s.f.sql(trigger)).status, 200);
  assert.equal(
    (await organizationPage(s, captured.body.manifest, "actions", 0)).body
      .error,
    "StoreUnavailable",
  );
  assert.equal((await s.f.send({ operation: "status" })).body.state, "failed");
  assert.equal((await s.send("execute", s.digest)).status, 503);
  assert.equal(s.mcp.state.calls.length, 0);
});

for (const transport of ["internal capture", "private export"])
  test(`organization bundle captures and restores a consumed claim through ${transport} while the native action completes`, async (t) => {
    const { mkdtemp, rm, readFile } = await import("node:fs/promises"),
      { join } = await import("node:path"),
      { tmpdir } = await import("node:os"),
      { collectOrganizationBundle, verifyOrganizationBundle } = await import(
        "../services/organization/cloudflare/organization-bundle.mjs"
      ),
      root = await mkdtemp(join(tmpdir(), "xeip-native-organization-bundle-")),
      s = await approved(t);
    t.after(() => rm(root, { recursive: true, force: true }));
    let entered = false,
      release;
    const held = new Promise((r) => {
      release = r;
    });
    s.mcp.state.beforeTool = async () => {
      entered = true;
      await held;
    };
    const executing = s.send("execute", s.digest);
    try {
      await until(async () => entered);
      const directory = join(root, "bundle");
      let exportId;
      const manifest = await collectOrganizationBundle({
        directory,
        organization: s.settings.organization,
        capture: async () => {
          if (transport === "private export") {
            const result = await s.f.send({
              operation: "exportBegin",
              operator: "fixture:owner",
            });
            assert.equal(result.status, 200, JSON.stringify(result.body));
            exportId = result.body.exportId;
            assert.equal(result.body.manifest.actions.cut, 3);
            release();
            assert.equal((await executing).body.state, "succeeded");
            const changed = structuredClone(s.config);
            changed.authentication.clientIds.push("after-capture");
            assert.equal(
              (
                await s.f.send({
                  operation: "update",
                  configuration: changed,
                  expectedRevision: 0,
                })
              ).status,
              200,
            );
            assert.equal(
              (
                await manage(s, "refreshTrust", {
                  provisioning: provisioning(s.actors, 2),
                  expectedRevision: 1,
                })
              ).status,
              200,
            );
            const checkpoint = { manifest: result.body.manifest };
            for (const [component, descriptor] of Object.entries(
              result.body.components,
            )) {
              const chunks = [];
              for (let index = 0; index < descriptor.parts; index++) {
                const part = await s.f.send({
                  operation: "exportPart",
                  operator: "fixture:owner",
                  exportId,
                  component,
                  index,
                });
                assert.equal(part.status, 200, JSON.stringify(part.body));
                chunks.push(Buffer.from(part.body.data, "base64"));
              }
              const raw = Buffer.concat(chunks);
              assert.equal(raw.length, descriptor.bytes);
              assert.equal(
                createHash("sha256").update(raw).digest("hex"),
                descriptor.sha256,
              );
              checkpoint[component] = JSON.parse(raw);
            }
            assert.equal(checkpoint.authority.revision, 0);
            assert.equal(checkpoint.trust.revision, 1);
            assert.equal(checkpoint.administration.headSequence, 0);
            return checkpoint;
          }
          const result = await organizationCapture(s);
          assert.equal(result.status, 200);
          assert.equal(result.body.manifest.actions.cut, 3);
          release();
          assert.equal((await executing).body.state, "succeeded");
          return result.body;
        },
        readPage: async (manifest, { section, cursor }) => {
          if (transport === "private export") {
            const result = await s.f.send({
              operation: "exportPage",
              operator: "fixture:owner",
              exportId,
              options: { section, cursor },
            });
            assert.equal(result.status, 200, JSON.stringify(result.body));
            assert.equal(result.body.exportId, exportId);
            const { exportId: _, ...page } = result.body;
            return page;
          }
          const result = await organizationPage(s, manifest, section, cursor);
          assert.equal(result.status, 200);
          return result.body;
        },
      });
      if (transport === "private export")
        assert.equal(
          (
            await s.f.send({
              operation: "exportClose",
              operator: "fixture:owner",
              exportId,
            })
          ).status,
          200,
        );
      assert.equal(
        (
          await verifyOrganizationBundle(directory, {
            organization: s.settings.organization,
            expectedDigest: manifest.checkpoint.digest,
          })
        ).checksum,
        manifest.checksum,
      );
      const record = JSON.parse(
        await readFile(join(directory, "actions-000001.json"), "utf8"),
      );
      assert.equal(record.row.state, "executing");
      assert.ok(record.row.claim_id);
      assert.equal(record.history.length, 3);
      const restoreRuntime = await harness({
        entryPoint: new URL(
          "./organization-cloudflare-organization-restore-worker.mjs",
          import.meta.url,
        ).pathname,
        className: "OrganizationRestoreFixture",
      });
      t.after(() => restoreRuntime.close());
      const candidate = await restoreRuntime.fixture();
      const checkpoint = { manifest: manifest.checkpoint };
      for (const section of [
        "lifecycle",
        "trust",
        "authority",
        "administration",
      ])
        checkpoint[section] = JSON.parse(
          await readFile(join(directory, section + ".json"), "utf8"),
        );
      assert.equal(
        (
          await candidate.send({
            operation: "organizationRestoreInitialize",
            organization: s.settings.organization,
            checkpoint,
            manifest,
          })
        ).status,
        200,
      );
      let sequence = 0;
      for (const name of [
        "actions-000001.json",
        "authority-000001.json",
        "administration-000001.json",
      ]) {
        const value = JSON.parse(await readFile(join(directory, name), "utf8"));
        assert.equal(
          (
            await candidate.send({
              operation: "organizationRestoreApply",
              sequence: ++sequence,
              value,
            })
          ).status,
          200,
        );
      }
      const verified = await candidate.send({
        operation: "organizationRestoreVerify",
      });
      assert.equal(verified.body.phase, "verified");
      assert.equal(verified.body.blocked, true);
      const restored = (await candidate.sql("SELECT * FROM xeip_actions")).body
        .rows[0];
      assert.equal(restored.state, "executing");
      assert.equal(restored.claim_id, record.row.claim_id);
      assert.equal(
        (await candidate.send({ operation: "open", configuration: s.settings }))
          .body.state,
        "failed",
      );
      assert.equal(
        (await candidate.send({ operation: "ready" })).body.ready,
        false,
      );
      const denied = await candidate.send({
        operation: "http",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer " + s.agent,
        },
        body: command(
          s.actors[0],
          s.actors[0].entity,
          "execute",
          "flow",
          s.digest,
          { query: "approved" },
        ),
      });
      assert.equal(denied.body.status, 503);

      assert.equal((await s.send("inspect")).body.state, "succeeded");
      assert.equal((await s.send("execute", s.digest)).status, 409);
      assert.equal(s.mcp.state.calls.length, 1);
    } finally {
      release();
      await executing;
    }
  });

test("private organization export creates readers within its two synchronized history scans", async (t) => {
  const s = await setup(t);
  await open(s);
  await initialize(s);
  // Substantial histories on both stores make a third scan observable.
  for (let revision = 0; revision < 32; revision++) {
    const updated = await s.f.send({
      operation: "update",
      configuration: s.config,
      expectedRevision: revision,
    });
    assert.equal(updated.status, 200, JSON.stringify(updated.body));
  }
  await s.f.send({ operation: "close" });
  const { organizationBundleFixture } = await import(
    "./fixtures/cloudflare/organization-bundle-harness.mjs"
  );
  const { adminRows } = organizationBundleFixture({
    actions: 0,
    attempts: 1000,
  });
  assert.equal(
    (
      await s.f.send({
        operation: "seedAdministration",
        records: adminRows.map((row) => ({
          ...row,
          canonical: canonicalize(row.event),
        })),
      })
    ).status,
    200,
  );
  assert.equal((await open(s)).body.state, "initialized");
  await s.f.send({
    operation: "controls",
    control: { administrativeRows: 0, authorityRows: 0 },
  });
  const captured = await s.f.send({
    operation: "exportBegin",
    operator: "fixture:owner",
  });
  assert.equal(captured.status, 200, JSON.stringify(captured.body));
  const cost = (await s.f.send({ operation: "controls" })).body;
  assert.ok(
    cost.administrativeRows >= 2000 && cost.administrativeRows <= 2020,
    `read ${cost.administrativeRows} administrative rows for synchronized export`,
  );
  assert.ok(
    cost.authorityRows >= 66 && cost.authorityRows <= 72,
    `read ${cost.authorityRows} authority rows for synchronized export`,
  );
  const page = await s.f.send({
    operation: "exportPage",
    operator: "fixture:owner",
    exportId: captured.body.exportId,
    options: {
      section: "administration",
      cursor: {
        after: 984,
        previousChecksum: adminRows[983].checksum,
        limit: 16,
      },
    },
  });
  assert.equal(page.status, 200, JSON.stringify(page.body));
  assert.equal(page.body.page.next, 1000);
  assert.equal(page.body.page.complete, true);
  await s.f.send({
    operation: "exportClose",
    operator: "fixture:owner",
    exportId: captured.body.exportId,
  });
});
