import { before, after, test } from "node:test";
import assert from "node:assert/strict";
import { harness } from "./fixtures/cloudflare/transport-harness.mjs";
import { fixture as providerFixture } from "../services/organization/test-fixtures/provider.mjs";
import {
  identity,
  configuration,
  provisioning,
  command,
} from "./fixtures/cloudflare/authority-harness.mjs";
import { mcpFixture } from "../services/organization/test-fixtures/mcp.mjs";
let runtime;
before(async () => {
  runtime = await harness();
});
after(async () => {
  await runtime?.close();
});
const action = (f) => ({
  target: {
    id: f.config.id,
    revision: f.config.revision,
    recipient: f.config.recipient,
  },
  tool: "lookup",
  arguments: { query: "approved" },
});
const tools = (f) =>
  f.state.requests.filter((r) => r.body?.method === "tools/call");

test("native MCP sends exactly the approved tool with target-scoped credentials", async (t) => {
  const f = await mcpFixture(t),
    worker = await runtime.fixture();
  const { body } = await worker.send({
    operation: "mcp",
    target: f.config,
    action: action(f),
  });
  assert.equal(body.result?.isError, false, JSON.stringify(body));
  assert.equal(body.checks, 1);
  assert.deepEqual(f.state.calls, [{ query: "approved" }]);
  assert.equal(tools(f).length, 1);
  assert.equal(tools(f)[0].authorization, "Bearer " + f.token);
  assert.equal(
    tools(f)[0].body.params._meta["io.modelcontextprotocol/protocolVersion"],
    "2026-07-28",
  );
  assert.equal(f.state.grants[0].resource, f.config.endpoint);
  assert.equal(
    f.state.requests.find((r) => r.path === "/resource").authorization,
    undefined,
  );
});
for (const mode of [
  "redirect",
  "unauthorized",
  "disconnect",
  "malformed",
  "oversize",
  "continuation",
  "invalid-utf8",
])
  test("native MCP never retries uncertain " + mode + " effects", async (t) => {
    const f = await mcpFixture(t),
      worker = await runtime.fixture();
    f.state.mode = mode;
    const { body } = await worker.send({
      operation: "mcp",
      target: f.config,
      action: action(f),
    });
    assert.equal(body.sent, true, JSON.stringify(body));
    assert.equal(tools(f).length, 1);
    assert.equal(
      f.state.requests.some((r) => r.path === "/stolen"),
      false,
    );
  });
for (const option of [
  { allow: false },
  { abort: true },
  { stall: 1500, timeoutMs: 1000 },
])
  test(
    "native MCP stops before sending " + JSON.stringify(option),
    async (t) => {
      const f = await mcpFixture(t),
        worker = await runtime.fixture();
      const { body } = await worker.send({
        operation: "mcp",
        target: f.config,
        action: action(f),
        ...option,
      });
      assert.equal(body.sent, false);
      assert.equal(body.checks, 1);
      assert.equal(tools(f).length, 0);
    },
  );
test("native MCP rejects substituted target before any network request", async (t) => {
  const f = await mcpFixture(t),
    worker = await runtime.fixture(),
    a = action(f);
  a.target.revision = "other";
  const { body } = await worker.send({
    operation: "mcp",
    target: f.config,
    action: a,
  });
  assert.equal(body.sent, false);
  assert.equal(f.state.requests.length, 0);
});

for (const path of [
  "/resource",
  "/.well-known/oauth-authorization-server",
  "/token",
])
  test("native MCP refuses redirects from " + path, async (t) => {
    const f = await mcpFixture(t),
      worker = await runtime.fixture();
    f.state.redirects[path] = f.origin + "/stolen";
    const { body } = await worker.send({
      operation: "mcp",
      target: f.config,
      action: action(f),
    });
    assert.equal(body.sent, false);
    assert.equal(tools(f).length, 0);
    assert.equal(
      f.state.requests.some((r) => r.path === "/stolen"),
      false,
    );
  });

async function httpFixture(options = {}, controls = {}) {
  const f = await runtime.fixture();
  await f.send({ operation: "http-init", options, controls });
  return {
    send: async (input) => (await f.send({ operation: "http", ...input })).body,
    controls: async (controls) =>
      (await f.send({ operation: "controls", controls })).body,
  };
}
async function until(fn) {
  const end = Date.now() + 5000;
  while (!(await fn())) {
    if (Date.now() > end) throw Error("condition not reached");
    await new Promise((r) => setTimeout(r, 10));
  }
}
test("Fetch ingress forwards only bounded signed payloads and emits safe response headers", async () => {
  const f = await httpFixture(),
    r = await f.send({ body: '{"signed":"payload"}' });
  assert.equal(r.status, 200);
  assert.equal(r.body.body, '{"signed":"payload"}');
  assert.equal(r.body.header, "Bearer fixture");
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.headers["x-content-type-options"], "nosniff");
  assert.match(r.headers["x-request-id"], /^[0-9a-f-]{36}$/);
  assert.equal(r.headers["access-control-allow-origin"], undefined);
});
for (const [name, input, status] of [
  ["wrong origin", { url: "https://evil.example/v1/actions" }, 403],
  ["plaintext", { url: "http://xeip.example/v1/actions" }, 403],
  [
    "wrong host",
    { headers: { host: "evil.example", "content-type": "application/json" } },
    403,
  ],
  [
    "browser origin",
    {
      headers: {
        origin: "https://evil.example",
        "content-type": "application/json",
      },
    },
    403,
  ],
  ["query", { url: "https://xeip.example/v1/actions?x=1" }, 400],
  ["fragment", { url: "https://xeip.example/v1/actions#x" }, 400],
  ["unknown route", { url: "https://xeip.example/admin" }, 404],
  ["wrong method", { method: "GET" }, 405],
  ["media", { headers: { "content-type": "text/plain" } }, 415],
  [
    "compressed",
    {
      headers: {
        "content-type": "application/json",
        "content-encoding": "gzip",
      },
    },
    415,
  ],
  [
    "combined authorization",
    {
      headers: {
        "content-type": "application/json",
        authorization: "Bearer one, Bearer two",
      },
    },
    400,
  ],
  [
    "combined media",
    { headers: { "content-type": "application/json, application/json" } },
    415,
  ],
  [
    "combined length",
    {
      headers: { "content-type": "application/json", "content-length": "2, 2" },
    },
    400,
  ],
  [
    "large declared",
    {
      headers: {
        "content-type": "application/json",
        "content-length": "98305",
      },
    },
    413,
  ],
  [
    "large streamed",
    { chunks: [Array(50000).fill(32), Array(50000).fill(32)] },
    413,
  ],
  ["invalid utf8", { chunks: [[0xc3, 0x28]] }, 400],
  [
    "length mismatch",
    {
      headers: { "content-type": "application/json", "content-length": "3" },
      body: "{}",
    },
    400,
  ],
  ["cancelled", { aborted: true }, 400],
])
  test("Fetch ingress rejects " + name + " before controller use", async () => {
    const f = await httpFixture(),
      r = await f.send(input);
    assert.equal(r.status, status, JSON.stringify(r));
    assert.equal((await f.controls()).calls, 0);
  });
test("Fetch ingress permits same-origin browsers and missing bearer reaches authentication", async () => {
  const f = await httpFixture();
  assert.equal(
    (
      await f.send({
        headers: {
          origin: "https://xeip.example",
          "content-type": "application/json",
        },
      })
    ).status,
    200,
  );
});
test("Fetch ingress expires stalled body reads without controller effects", async () => {
  const f = await httpFixture({ bodyTimeoutMs: 100 });
  assert.equal((await f.send({ stallBody: true })).status, 408);
  assert.equal((await f.controls()).calls, 0);
  assert.equal((await f.send({})).status, 200);
});
test("Fetch ingress times out operations but retains slots until the task actually settles", async () => {
  const f = await httpFixture(
    { maxConcurrent: 1, operationTimeoutMs: 100 },
    { hold: true },
  );
  const r = await f.send({});
  assert.equal(r.status, 504);
  assert.equal((await f.controls()).pending, 1);
  const busy = await f.send({});
  assert.equal(busy.status, 429);
  assert.equal(busy.headers["retry-after"], "1");
  assert.equal(
    (await f.send({ url: "https://xeip.example/live", method: "GET" })).status,
    200,
  );
  await f.controls({ hold: false });
  await until(async () => (await f.controls()).settled === 1);
  assert.equal((await f.controls()).aborted, 1);
  assert.equal((await f.send({})).status, 200);
});
test("Fetch ingress cancellation retains the unfinished operation slot", async () => {
  const f = await httpFixture({ maxConcurrent: 1 }, { hold: true });
  assert.equal((await f.send({ abortMs: 25 })).status, 400);
  assert.equal((await f.send({})).status, 429);
  await f.controls({ hold: false });
  await until(async () => (await f.controls()).settled === 1);
  assert.equal((await f.controls()).aborted, 1);
  assert.equal((await f.send({})).status, 200);
});
test("Fetch readiness deadlines retain admission while liveness remains available", async () => {
  const f = await httpFixture(
    { maxConcurrent: 1, readinessTimeoutMs: 100 },
    { holdReady: true },
  );
  assert.equal(
    (await f.send({ url: "https://xeip.example/ready", method: "GET" })).status,
    503,
  );
  assert.equal((await f.send({})).status, 429);
  assert.equal(
    (await f.send({ url: "https://xeip.example/live", method: "GET" })).body
      .status,
    "live",
  );
  await f.controls({ holdReady: false });
  await until(async () => (await f.controls()).pending === 0);
  assert.equal(
    (await f.send({ url: "https://xeip.example/ready", method: "GET" })).body
      .status,
    "ready",
  );
});
for (const [controls, status, error] of [
  [{ error: "unsafe" }, 503, "unavailable"],
  [{ error: "safe" }, 403, "forbidden"],
  [{ large: true }, 503, "unavailable"],
])
  test(
    "Fetch ingress bounds and redacts results " + JSON.stringify(controls),
    async () => {
      const f = await httpFixture({}, controls),
        r = await f.send({});
      assert.equal(r.status, status);
      assert.deepEqual(r.body, { error });
      assert.equal(JSON.stringify(r).includes("secret-credential"), false);
    },
  );

async function composed(t, options = {}, name) {
  const provider = await providerFixture(t),
    mcp = await mcpFixture(t),
    actors = [identity("agent"), identity("human")],
    config = configuration(provider, actors),
    f = await runtime.fixture(name);
  mcp.config.revision = "1";
  mcp.config.recipient = actors[0].entity;
  const open = {
    operation: "open",
    initialize: true,
    provisioning: provisioning(actors),
    configuration: config,
    secret: provider.config.introspectionClientSecret,
    gateway: actors[0].entity,
    target: mcp.config,
    httpOptions: options,
  };
  assert.equal((await f.send(open)).body.ok, true);
  const agent = await provider.token({
      sub: "agent",
      azp: "xeip-agent",
      resource_access: { "xeip-api": { roles: ["agent"] } },
    }),
    human = await provider.token({ sub: "human" });
  const s = { provider, mcp, actors, config, f, open, agent, human };
  s.send = async (operation, digest) => {
    const isHuman = operation === "approve";
    return (
      await s.f.send({
        operation: "http",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer " + (isHuman ? human : agent),
        },
        body: command(
          actors[isHuman ? 1 : 0],
          actors[0].entity,
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
test("signed Fetch lifecycle reaches actual OAuth MCP once and survives runtime restart", async (t) => {
  const s = await composed(t);
  const result = await s.send("execute", s.digest);
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal(result.body.state, "succeeded");
  assert.equal(result.body.result.content[0].text, "fixture result");
  assert.equal(JSON.stringify(result).includes("claimId"), false);
  assert.deepEqual(s.mcp.state.calls, [{ query: "approved" }]);
  assert.equal(
    s.mcp.state.requests.some((r) => r.authorization === "Bearer " + s.agent),
    false,
  );
  assert.equal((await s.send("execute", s.digest)).status, 409);
  await runtime.restart();
  s.f = await runtime.fixture(s.f.name);
  assert.equal(
    (
      await s.f.send({
        ...s.open,
        initialize: false,
        provisioning: undefined,
        configuration: undefined,
      })
    ).body.ok,
    true,
  );
  assert.equal((await s.send("inspect")).body.state, "succeeded");
  assert.equal((await s.send("execute", s.digest)).status, 409);
  assert.equal(tools(s.mcp).length, 1);
  assert.deepEqual(
    (
      await s.f.sql("SELECT event FROM xeip_audit ORDER BY sequence")
    ).body.rows.map((r) => r.event),
    ["proposed", "approved", "claimed", "succeeded"],
  );
});
for (const change of ["provider", "approver trust"])
  test(
    "revocation during MCP OAuth prevents actual effect: " + change,
    async (t) => {
      const s = await composed(t);
      let enter, release;
      const entered = new Promise((r) => {
          enter = r;
        }),
        held = new Promise((r) => {
          release = r;
        });
      s.mcp.state.beforeGrant = async () => {
        enter();
        await held;
      };
      const pending = s.send("execute", s.digest);
      try {
        await Promise.race([
          entered,
          new Promise((_, reject) => {
            const timer = setTimeout(
              () => reject(Error("OAuth not entered")),
              5000,
            );
            timer.unref();
          }),
        ]);
        if (change === "provider") s.provider.state.active = false;
        else
          await s.f.send({
            operation: "trust-update",
            provisioning: provisioning(s.actors, 2, "human"),
          });
      } finally {
        release();
      }
      assert.equal((await pending).body.state, "failed");
      assert.equal(tools(s.mcp).length, 0);
      assert.equal(
        (await s.f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
        "failed",
      );
    },
  );
for (const mode of ["disconnect", "redirect", "malformed"])
  test(
    "signed uncertain " + mode + " persists indeterminate and cannot replay",
    async (t) => {
      const s = await composed(t);
      s.mcp.state.mode = mode;
      assert.equal(
        (await s.send("execute", s.digest)).body.state,
        "indeterminate",
      );
      assert.equal((await s.send("execute", s.digest)).status, 409);
      assert.equal((await s.send("inspect")).body.state, "indeterminate");
      assert.equal(tools(s.mcp).length, 1);
    },
  );
test("lost HTTP response after tool send records a consumed claim without replay", async (t) => {
  const s = await composed(t, { operationTimeoutMs: 1000 });
  let entered = false,
    release;
  const held = new Promise((r) => {
    release = r;
  });
  s.mcp.state.beforeTool = async () => {
    entered = true;
    await held;
  };
  const pending = s.send("execute", s.digest);
  try {
    await until(async () => entered);
    assert.equal((await pending).status, 504);
    await until(
      async () =>
        (await s.f.sql("SELECT state FROM xeip_actions")).body.rows[0].state ===
        "indeterminate",
    );
  } finally {
    release();
  }
  assert.equal((await s.send("execute", s.digest)).status, 409);
  assert.equal(tools(s.mcp).length, 1);
});
test("public Worker routing serves signed requests and exposes no fixture administration", async (t) => {
  const s = await composed(t, {}, "public");
  const inspected = await runtime.dispatch("https://xeip.example/v1/actions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer " + s.agent,
    },
    body: command(s.actors[0], s.actors[0].entity, "inspect", "flow"),
  });
  assert.equal(inspected.body.state, "approved", JSON.stringify(inspected));
  for (const url of [
    "https://fixture.invalid/",
    "https://xeip.example/sql",
    "https://xeip.example/admin",
  ]) {
    const r = await runtime.dispatch(url, {
      method: "POST",
      body: JSON.stringify({ operation: "sql", query: "SELECT 1" }),
    });
    assert.ok([403, 503, 404].includes(r.status), JSON.stringify(r));
    assert.equal(JSON.stringify(r).includes("rows"), false);
  }
});

test("unsigned payload and proxy identity cannot enter the signed workflow", async (t) => {
  const s = await composed(t);
  const r = (
    await s.f.send({
      operation: "http",
      body: '{"operation":"execute"}',
      headers: {
        "content-type": "application/json",
        "x-forwarded-user": "agent",
        "cf-access-authenticated-user-email": "admin@example.org",
      },
    })
  ).body;
  assert.ok([400, 401].includes(r.status));
  assert.equal(tools(s.mcp).length, 0);
  const envelope = JSON.parse(
    command(s.actors[0], s.actors[0].entity, "execute", "flow", s.digest),
  );
  envelope.body.data.digest = "0".repeat(64);
  const tampered = (
    await s.f.send({
      operation: "http",
      body: JSON.stringify(envelope),
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + s.agent,
      },
    })
  ).body;
  assert.equal(tampered.status, 403);
  assert.equal(tools(s.mcp).length, 0);
});
test("Fetch ingress cancels a stalled body without starting work", async () => {
  const f = await httpFixture({ maxConcurrent: 1 });
  assert.equal((await f.send({ stallBody: true, abortMs: 25 })).status, 400);
  assert.equal((await f.controls()).calls, 0);
  assert.equal((await f.send({})).status, 200);
});
