import test from "node:test";
import assert from "node:assert/strict";
import { McpConnector, ConnectorFailure } from "./mcp.mjs";
import { mcpFixture } from "./test-fixtures/mcp.mjs";
const action = (f) => ({
  target: {
    id: f.config.id,
    revision: f.config.revision,
    recipient: f.config.recipient,
  },
  tool: "lookup",
  arguments: { query: "approved" },
});
test("official MCP server receives the approved tool, protocol metadata and only target-scoped credentials", async (t) => {
  const f = await mcpFixture(t),
    connector = new McpConnector([f.config]);
  let checks = 0;
  const result = await connector.call(action(f), {
    beforeSend: async () => {
      checks++;
      return true;
    },
  });
  assert.equal(result.isError, false);
  assert.equal(checks, 1);
  assert.deepEqual(f.state.calls, [{ query: "approved" }]);
  const tool = f.state.requests.find((r) => r.body?.method === "tools/call");
  assert.equal(tool.authorization, "Bearer " + f.token);
  assert.equal(
    tool.body.params._meta["io.modelcontextprotocol/protocolVersion"],
    "2026-07-28",
  );
  assert.equal(f.state.grants[0].resource, f.config.endpoint);
});
for (const mode of [
  "unauthorized",
  "redirect",
  "disconnect",
  "malformed",
  "oversize",
  "continuation",
  "invalid-utf8",
])
  test("does not retry an uncertain " + mode + " tool call", async (t) => {
    const f = await mcpFixture(t);
    f.state.mode = mode;
    await assert.rejects(
      new McpConnector([f.config]).call(action(f), {
        beforeSend: async () => true,
      }),
      (e) =>
        e instanceof ConnectorFailure &&
        e.sent === true &&
        e.message === "MCP target unavailable",
    );
    assert.equal(
      f.state.requests.filter((r) => r.body?.method === "tools/call").length,
      1,
    );
    assert.equal(
      f.state.requests.some((r) => r.path === "/stolen"),
      false,
    );
  });
test("preserves explicit tool errors as results", async (t) => {
  const f = await mcpFixture(t);
  f.state.mode = "tool-error";
  assert.equal(
    (
      await new McpConnector([f.config]).call(action(f), {
        beforeSend: async () => true,
      })
    ).isError,
    true,
  );
});
test("denial immediately before sending prevents all tool effects", async (t) => {
  const f = await mcpFixture(t);
  await assert.rejects(
    new McpConnector([f.config]).call(action(f), {
      beforeSend: async () => false,
    }),
    (e) => e instanceof ConnectorFailure && !e.sent,
  );
  assert.equal(f.state.calls.length, 0);
  assert.equal(
    f.state.requests.filter((r) => r.body?.method === "tools/call").length,
    0,
  );
});
test("target revision, recipient and tool substitutions fail before network traffic", async (t) => {
  const f = await mcpFixture(t),
    connector = new McpConnector([f.config]);
  for (const edit of [
    (a) => (a.target.revision = "other"),
    (a) => (a.target.recipient = "other"),
    (a) => (a.tool = "delete"),
    (a) => (a.target.id = "other"),
  ]) {
    const a = action(f);
    edit(a);
    await assert.rejects(
      connector.call(a, { beforeSend: async () => true }),
      (e) => e instanceof ConnectorFailure && !e.sent,
    );
  }
  assert.equal(f.state.requests.length, 0);
});
test("resource, issuer and token endpoint metadata cannot redirect credentials", async (t) => {
  const f = await mcpFixture(t),
    connector = new McpConnector([f.config]);
  for (const changes of [
    { metadata: { resource: f.origin + "/other" } },
    { metadata: { authorization_servers: ["https://attacker.invalid"] } },
    { issuerMetadata: { issuer: f.origin + "/other" } },
    { issuerMetadata: { token_endpoint: f.origin + "/stolen" } },
  ]) {
    f.state.metadata = {};
    f.state.issuerMetadata = {};
    Object.assign(f.state, changes);
    await assert.rejects(
      connector.call(action(f), { beforeSend: async () => true }),
      (e) => e instanceof ConnectorFailure && !e.sent,
    );
  }
  assert.equal(f.state.grants.length, 0);
  assert.equal(f.state.calls.length, 0);
});
test("cancellation while revalidating never sends the tool request", async (t) => {
  const f = await mcpFixture(t),
    abort = new AbortController();
  await assert.rejects(
    new McpConnector([f.config]).call(action(f), {
      signal: abort.signal,
      beforeSend: async () => {
        abort.abort();
        return true;
      },
    }),
    (e) => e instanceof ConnectorFailure && !e.sent,
  );
  assert.equal(f.state.calls.length, 0);
});
test("operator configuration requires HTTPS except explicit literal-loopback fixtures", async (t) => {
  const f = await mcpFixture(t);
  assert.throws(
    () => new McpConnector([{ ...f.config, allowInsecureLoopback: false }]),
    TypeError,
  );
  assert.throws(
    () => new McpConnector([{ ...f.config, endpoint: "http://localhost/mcp" }]),
    TypeError,
  );
  assert.throws(() => new McpConnector([f.config, f.config]), TypeError);
});
test("a stalled pre-send gate is bounded by the connector deadline", async (t) => {
  const f = await mcpFixture(t);
  await assert.rejects(
    new McpConnector([f.config], { timeoutMs: 100 }).call(action(f), {
      beforeSend: () => new Promise(() => {}),
    }),
    (e) => e instanceof ConnectorFailure && !e.sent,
  );
  assert.equal(f.state.calls.length, 0);
});

test("dispatch refusal after successful asynchronous guard sends no tool request", async (t) => {
  const f = await mcpFixture(t);
  let validated = false;
  await assert.rejects(
    new McpConnector([f.config]).call(action(f), {
      beforeSend: async () => {
        validated = true;
        return true;
      },
      dispatch: () => {
        assert.equal(validated, true);
        throw new Error("control changed");
      },
    }),
    (e) => e instanceof ConnectorFailure && !e.sent,
  );
  assert.equal(f.state.calls.length, 0);
  assert.equal(
    f.state.requests.some((r) => r.body?.method === "tools/call"),
    false,
  );
});

test("dispatch callback invokes the tool request once and preserves its result", async (t) => {
  const f = await mcpFixture(t);
  let invoked = 0;
  const result = await new McpConnector([f.config]).call(action(f), {
    beforeSend: async () => true,
    dispatch: (send) => {
      invoked++;
      return send();
    },
  });
  assert.equal(invoked, 1);
  assert.equal(result.isError, false);
  assert.deepEqual(f.state.calls, [{ query: "approved" }]);
});
