import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { harness } from "./fixtures/cloudflare/worker-harness.mjs";
import { recoveryJournal } from "./fixtures/cloudflare/recovery-http-harness.mjs";
import {
  identity,
  configuration,
} from "./fixtures/cloudflare/authority-harness.mjs";
const actor = identity("owner");
const profile = {
  organization: "worker-fixture",
  origin: "https://xeip.example",
  gateway: actor.entity,
  trust: { maxAgeSeconds: 300 },
  targets: [
    {
      id: "internal",
      revision: "1",
      recipient: actor.entity,
      tools: ["lookup"],
      endpoint: "https://mcp.example/mcp",
      resourceMetadataUrl: "https://mcp.example/resource",
      issuer: "https://mcp.example",
      tokenEndpoint: "https://mcp.example/token",
      clientId: "xeip",
      scope: "tools:lookup",
    },
  ],
};
const bindings = () => ({
  XEIP_PROFILE: JSON.stringify(profile),
  XEIP_CREDENTIALS: JSON.stringify({
    introspectionClientSecret: "fixture-secret-never-log",
    targets: { internal: "target-secret-never-log" },
  }),
});
const raw = (operation, extra = {}) =>
  JSON.stringify({ operation, requestId: randomUUID(), ...extra });
async function setup(t, b = bindings()) {
  const h = await harness(b);
  t.after(() => h.close());
  return h;
}
test("production entrypoint exposes liveness but public/default RPC cannot administer", async (t) => {
  const h = await setup(t);
  assert.equal((await h.send({ kind: "public" })).status, 200);
  for (const path of ["/initialize", "/manage", "/owner", "/refreshTrust"])
    assert.equal(
      (
        await h.send({
          kind: "public",
          url: "https://xeip.example" + path,
          method: "POST",
          body: raw("initialize"),
        })
      ).status,
      404,
    );
  assert.equal(
    (await h.send({ kind: "owner-http", raw: raw("status") })).status,
    404,
  );
  assert.equal(
    (await h.send({ kind: "default-rpc", raw: raw("status") })).status,
    502,
  );
  assert.equal(
    (await h.send({ kind: "missing-operator", raw: raw("status") })).body.error,
    "forbidden",
  );
  const result = (await h.send({ raw: raw("status") })).body;
  assert.equal(result.ok, true);
  assert.equal(result.status.state, "uninitialized");
  assert.equal(result.operator, "fixture:operator");
});
test("private owner rejects malformed/oversized commands without leaking credentials", async (t) => {
  const h = await setup(t);
  for (const value of [
    "{",
    " ".repeat(2097153),
    raw("reset"),
    raw("status", { operator: "spoof" }),
    { operation: "status" },
  ]) {
    const result = await h.send({ raw: value });
    assert.equal(result.body.ok, false);
    assert.equal(result.body.error, "invalid_request");
    assert.ok(!JSON.stringify(result).includes("never-log"));
  }
  assert.equal(
    (await h.send({ raw: raw("status") })).body.status.state,
    "uninitialized",
  );
});
test("invalid production secrets do not bootstrap and corrected reopen is still uninitialized", async (t) => {
  const b = bindings();
  b.XEIP_CREDENTIALS = '{"introspectionClientSecret":"sensitive","targets":{}}';
  const h = await setup(t, b);
  const unavailable = await h.send({ raw: raw("status") });
  assert.equal(unavailable.body.error, "unavailable");
  assert.ok(!JSON.stringify(unavailable).includes("sensitive"));
  await h.restart(bindings());
  assert.equal(
    (await h.send({ raw: raw("status") })).body.status.state,
    "uninitialized",
  );
});
test("owner setup persists and organization drift cannot select a new empty object", async (t) => {
  const h = await setup(t);
  const config = configuration(
    {
      config: {
        issuer: "https://id.example/realms/xeip",
        audience: "xeip-api",
        clientIds: ["xeip-agent", "xeip-console"],
        introspectionClientId: "xeip-introspection",
      },
    },
    [actor, identity("human")],
  );
  delete config.authentication.allowInsecureLoopback;
  const init = await h.send({
    raw: raw("initialize", { configuration: config }),
  });
  assert.equal(init.body.ok, true, JSON.stringify(init));
  assert.equal(init.body.status.state, "initialized");
  await h.restart();
  assert.equal(
    (await h.send({ raw: raw("status") })).body.status.state,
    "initialized",
  );
  const changed = bindings();
  changed.XEIP_PROFILE = JSON.stringify({
    ...profile,
    organization: "other-organization",
  });
  await h.restart(changed);
  assert.equal(
    (await h.send({ raw: raw("status") })).body.status.state,
    "failed",
  );
});

// Only the fixture maps pinned HTTPS endpoints to local independent HTTP servers.
// This exercises production URL/configuration checks, not hosted TLS/private routing.
async function flow(t, options = {}) {
  const { fixture } = await import(
    "../services/organization/test-fixtures/provider.mjs"
  );
  const { mcpFixture } = await import(
    "../services/organization/test-fixtures/mcp.mjs"
  );
  const provider = await fixture(t),
    mcp = await mcpFixture(t),
    actors = [identity("agent"), identity("human")];
  const issuer = "https://id.example/realms/xeip";
  const config = configuration(provider, actors);
  config.authentication.issuer = issuer;
  delete config.authentication.allowInsecureLoopback;
  const target = {
    ...profile.targets[0],
    recipient: actors[0].entity,
    clientId: mcp.config.clientId,
  };
  const recovery = options.recovery
    ? await recoveryJournal(t, profile.organization)
    : undefined;
  const env = {
    XEIP_PROFILE: JSON.stringify({
      ...profile,
      gateway: actors[0].entity,
      targets: [target],
      ...(recovery ? { recovery: recovery.recovery } : {}),
    }),
    XEIP_CREDENTIALS: JSON.stringify({
      introspectionClientSecret: provider.config.introspectionClientSecret,
      targets: { internal: mcp.config.clientSecret },
      ...(recovery
        ? { recoveryToken: options.recoveryToken ?? recovery.token }
        : {}),
    }),
  };
  const outboundService = async (request) => {
    if (recovery && request.url === recovery.recovery.url)
      return recovery.outbound(request);
    const url = new URL(request.url),
      isProvider = url.origin === "https://id.example",
      expected = isProvider ? issuer : "https://mcp.example",
      actual = isProvider ? provider.config.issuer : mcp.origin;
    assert.ok(request.url.startsWith(expected + "/"), request.url);
    let body = request.body ? await request.text() : undefined;
    if (body && url.pathname === "/token") {
      const form = new URLSearchParams(body);
      form.set("resource", mcp.origin + "/mcp");
      body = form.toString();
    }
    const requestHeaders = new Headers(request.headers);
    requestHeaders.delete("content-length");
    const response = await fetch(request.url.replace(expected, actual), {
      method: request.method,
      headers: requestHeaders,
      body,
      redirect: "manual",
    });
    const text = (await response.text()).split(actual).join(expected);
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    headers.delete("content-encoding");
    return new Response(text, { status: response.status, headers });
  };
  let artifactPath;
  if (options.packaged) {
    const { mkdtemp, readFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { createHash } = await import("node:crypto");
    const { buildPackage } = await import(
      "../services/organization/cloudflare/build.mjs"
    );
    const directory = await mkdtemp(
      join(tmpdir(), "xeip-recovery-worker-flow-"),
    );
    t.after(() => rm(directory, { recursive: true, force: true }));
    const outdir = join(directory, "artifact");
    const manifest = await buildPackage({
      profile: env.XEIP_PROFILE,
      name: "xeip-recovery-fixture",
      outdir,
    });
    artifactPath = join(outdir, "worker.mjs");
    const data = await readFile(artifactPath);
    assert.equal(
      createHash("sha256").update(data).digest("hex"),
      manifest.files.find((f) => f.path === "worker.mjs").sha256,
    );
    const generated = JSON.parse(
      await readFile(join(outdir, "wrangler.json"), "utf8"),
    );
    assert.deepEqual(
      JSON.parse(generated.vars.XEIP_PROFILE).recovery,
      recovery.recovery,
    );
    assert.ok(!JSON.stringify(generated).includes(recovery.token));
  }
  const h = await harness(env, { outboundService, artifactPath });
  t.after(() => h.close());
  const manage = (operation, extra) => h.send({ raw: raw(operation, extra) });
  if (options.initialize !== false)
    assert.equal(
      (await manage("initialize", { configuration: config })).body.ok,
      true,
    );
  const { provisioning, command } = await import(
    "./fixtures/cloudflare/authority-harness.mjs"
  );
  const initialProvisioning = provisioning(actors);
  if (options.signatureCopies) {
    const signature =
      initialProvisioning.keyDocuments[0].document.signatures[0];
    initialProvisioning.keyDocuments[0].document.signatures = Array.from(
      { length: options.signatureCopies },
      () => ({ ...signature }),
    );
  }
  if (options.initialize !== false)
    assert.equal(
      (
        await manage("refreshTrust", {
          expectedRevision: 0,
          provisioning: initialProvisioning,
        })
      ).body.ok,
      true,
    );
  const agent = await provider.token({
      iss: issuer,
      sub: "agent",
      azp: "xeip-agent",
      resource_access: { "xeip-api": { roles: ["agent"] } },
    }),
    human = await provider.token({ iss: issuer, sub: "human" });
  const send = async (
    operation,
    digest,
    argumentsValue = { query: "approved" },
  ) =>
    h.send({
      kind: "public",
      url: profile.origin + "/v1/actions",
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + (operation === "approve" ? human : agent),
      },
      body: command(
        actors[operation === "approve" ? 1 : 0],
        actors[0].entity,
        operation,
        "worker-flow",
        digest,
        argumentsValue,
      ),
    });
  return {
    h,
    provider,
    mcp,
    actors,
    config,
    manage,
    send,
    provisioning,
    env,
    recovery,
  };
}
test("configured production Worker journals signed actions and preserves consumed claims on reopen", async (t) => {
  const s = await flow(t, { recovery: true });
  const proposed = await s.send("propose"),
    digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", digest)).body.state, "approved");
  assert.equal((await s.send("execute", digest)).body.state, "succeeded");
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    4,
  );
  assert.equal(s.recovery.requests.filter((v) => v === "append").length, 4);
  assert.deepEqual(s.mcp.state.calls, [{ query: "approved" }]);
  await s.h.restart();
  assert.equal((await s.send("inspect")).body.state, "succeeded");
  assert.equal((await s.send("execute", digest)).status, 409);
  assert.equal(s.mcp.state.calls.length, 1);
});
test("exact recovery-enabled Worker artifact initializes privately and executes one durable signed action", async (t) => {
  const s = await flow(t, { recovery: true, packaged: true });
  const proposed = await s.send("propose"),
    digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", digest)).body.state, "approved");
  assert.equal((await s.send("execute", digest)).body.state, "succeeded");
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    4,
  );
  assert.equal(s.mcp.state.calls.length, 1);
  await s.h.restart();
  assert.equal((await s.send("execute", digest)).status, 409);
  assert.equal(s.mcp.state.calls.length, 1);
  assert.equal(
    (await s.h.send({ kind: "default-rpc", raw: raw("status") })).status,
    502,
  );
  assert.equal(
    (await s.h.send({ kind: "owner-http", raw: raw("initialize") })).status,
    404,
  );
});
test("configured Worker holds tool execution until the journal synchronizes its claim", async (t) => {
  const s = await flow(t, { recovery: true }),
    j = s.recovery.journal;
  const digest = (await s.send("propose")).body.proposal.digest;
  await s.send("approve", digest);
  await j.send({ operation: "controls", control: { holdSync: 4 } });
  let completed = false;
  const pending = s.send("execute", digest).then((r) => {
    completed = true;
    return r;
  });
  try {
    const until = Date.now() + 5000;
    while (
      (await j.send({ operation: "controls", control: {} })).body.syncs !== 4
    ) {
      if (Date.now() > until) throw Error("claim journal sync not reached");
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.equal(completed, false);
    assert.equal(s.mcp.state.calls.length, 0);
  } finally {
    await j.send({ operation: "controls", control: { holdSync: 0 } });
  }
  assert.equal((await pending).body.state, "succeeded");
  assert.equal(s.mcp.state.calls.length, 1);
});
test("configured Worker cannot execute after a lost claim receipt and cannot replay on restart", async (t) => {
  const s = await flow(t, { recovery: true });
  const digest = (await s.send("propose")).body.proposal.digest;
  await s.send("approve", digest);
  s.recovery.faults.loseAppend = true;
  assert.equal((await s.send("execute", digest)).status, 503);
  assert.equal(s.mcp.state.calls.length, 0);
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    3,
  );
  s.recovery.faults.loseAppend = false;
  await s.h.restart();
  assert.equal((await s.send("inspect")).body.state, "executing");
  assert.equal((await s.send("execute", digest)).status, 409);
  assert.equal(s.mcp.state.calls.length, 0);
});
test("configured Worker recovery omission and identity drift fail before contacting a replacement", async (t) => {
  const s = await flow(t, { recovery: true });
  const proposed = await s.send("propose");
  assert.equal(
    proposed.status,
    200,
    JSON.stringify({ status: proposed.status, error: proposed.body.error }),
  );
  assert.equal(proposed.body.state, "pending");
  const original = JSON.parse(s.env.XEIP_PROFILE),
    secret = JSON.parse(s.env.XEIP_CREDENTIALS);
  for (const changes of [
    null,
    { url: "https://replacement.example/v1/recovery" },
    { stream: randomUUID() },
    { maxEntries: 999999 },
    { maxBytes: 999999999 },
  ]) {
    const p = structuredClone(original),
      c = structuredClone(secret);
    if (changes === null) {
      delete p.recovery;
      delete c.recoveryToken;
    } else Object.assign(p.recovery, changes);
    const before = s.recovery.requests.length;
    await s.h.restart({
      XEIP_PROFILE: JSON.stringify(p),
      XEIP_CREDENTIALS: JSON.stringify(c),
    });
    assert.equal((await s.manage("status")).body.status.state, "failed");
    assert.equal(s.recovery.requests.length, before);
  }
  await s.h.restart(s.env);
  const restored = await s.manage("status");
  assert.equal(
    restored.body.status.state,
    "initialized",
    JSON.stringify(restored.body),
  );
  const inspected = await s.send("inspect");
  assert.equal(
    inspected.status,
    200,
    JSON.stringify({ status: inspected.status, error: inspected.body.error }),
  );
  assert.equal(inspected.body.state, "pending");
});
test("configured Worker rotates only the recovery credential and runtime deadline on fresh open", async (t) => {
  const s = await flow(t, { recovery: true });
  await s.send("propose");
  const token = "b2".repeat(32),
    p = JSON.parse(s.env.XEIP_PROFILE),
    c = JSON.parse(s.env.XEIP_CREDENTIALS);
  c.recoveryToken = token;
  p.recovery.timeoutMs = 9000;
  await s.recovery.rotate(token);
  await s.h.restart({
    XEIP_PROFILE: JSON.stringify(p),
    XEIP_CREDENTIALS: JSON.stringify(c),
  });
  assert.equal((await s.send("inspect")).body.state, "pending");
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    1,
  );
});
test("public empty Worker does not contact recovery or initialize until an owner command", async (t) => {
  const s = await flow(t, { recovery: true, initialize: false });
  assert.equal((await s.manage("status")).body.status.state, "uninitialized");
  assert.equal(
    (await s.h.send({ kind: "public", url: profile.origin + "/ready" })).status,
    503,
  );
  assert.equal(s.recovery.requests.length, 0);
  assert.equal(
    (await s.manage("initialize", { configuration: s.config })).body.ok,
    true,
  );
  assert.ok(s.recovery.requests.includes("head"));
});
test("wrong recovery credential leaves initialization incomplete and exact correction resumes", async (t) => {
  const s = await flow(t, {
    recovery: true,
    initialize: false,
    recoveryToken: "c3".repeat(32),
  });
  const failed = await s.manage("initialize", { configuration: s.config });
  assert.equal(failed.body.ok, false);
  assert.equal(failed.body.error, "unavailable");
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    0,
  );
  const c = JSON.parse(s.env.XEIP_CREDENTIALS);
  c.recoveryToken = s.recovery.token;
  await s.h.restart({ ...s.env, XEIP_CREDENTIALS: JSON.stringify(c) });
  const initialized = await s.manage("initialize", { configuration: s.config });
  assert.equal(initialized.body.ok, true);
  assert.equal(initialized.body.status.state, "initialized");
});
test("configured Worker refuses unavailable recovery before claiming and resumes only after reopen", async (t) => {
  const s = await flow(t, { recovery: true });
  const digest = (await s.send("propose")).body.proposal.digest;
  await s.send("approve", digest);
  s.recovery.faults.unavailable = true;
  assert.equal((await s.send("execute", digest)).status, 503);
  assert.equal(s.mcp.state.calls.length, 0);
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    2,
  );
  s.recovery.faults.unavailable = false;
  await s.h.restart();
  assert.equal((await s.send("execute", digest)).body.state, "succeeded");
  assert.equal(s.mcp.state.calls.length, 1);
});
test("Worker recovery configuration cannot adopt an initialized populated source", async (t) => {
  const s = await flow(t, { recovery: true, initialize: false });
  const p = JSON.parse(s.env.XEIP_PROFILE),
    c = JSON.parse(s.env.XEIP_CREDENTIALS);
  delete p.recovery;
  delete c.recoveryToken;
  const unconfigured = {
    XEIP_PROFILE: JSON.stringify(p),
    XEIP_CREDENTIALS: JSON.stringify(c),
  };
  await s.h.restart(unconfigured);
  assert.equal(
    (await s.manage("initialize", { configuration: s.config })).body.ok,
    true,
  );
  assert.equal(
    (
      await s.manage("refreshTrust", {
        expectedRevision: 0,
        provisioning: s.provisioning(s.actors),
      })
    ).body.ok,
    true,
  );
  assert.equal((await s.send("propose")).body.state, "pending");
  await s.h.restart(s.env);
  assert.equal((await s.manage("status")).body.status.state, "failed");
  assert.equal(s.recovery.requests.length, 0);
  await s.h.restart(unconfigured);
  assert.equal((await s.send("inspect")).body.state, "pending");
});
test("Worker first enrollment refuses a journal that already contains an unrelated history", async (t) => {
  const s = await flow(t, { recovery: true, initialize: false });
  assert.equal(
    (await s.recovery.journal.send({ operation: "append" })).status,
    200,
  );
  assert.equal(
    (await s.manage("initialize", { configuration: s.config })).body.error,
    "unavailable",
  );
  assert.equal(
    (await s.recovery.journal.send({ operation: "head" })).body.sequence,
    1,
  );
  assert.equal(s.mcp.state.calls.length, 0);
});
test("missing Worker recovery credential leaves an empty source uninitialized after correction", async (t) => {
  const s = await flow(t, { recovery: true, initialize: false });
  const c = JSON.parse(s.env.XEIP_CREDENTIALS);
  delete c.recoveryToken;
  await s.h.restart({ ...s.env, XEIP_CREDENTIALS: JSON.stringify(c) });
  assert.equal((await s.manage("status")).body.error, "unavailable");
  assert.equal(s.recovery.requests.length, 0);
  await s.h.restart(s.env);
  assert.equal((await s.manage("status")).body.status.state, "uninitialized");
});
test("production Worker private setup enables signed MCP execution and preserves consumed claim on restart", async (t) => {
  const s = await flow(t);
  assert.equal(
    (await s.h.send({ kind: "public", url: profile.origin + "/ready" })).status,
    200,
  );
  const proposed = await s.send("propose");
  assert.equal(proposed.body.state, "pending", JSON.stringify(proposed));
  const digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", digest)).body.state, "approved");
  const result = await s.send("execute", digest);
  assert.equal(result.body.state, "succeeded", JSON.stringify(result));
  assert.deepEqual(s.mcp.state.calls, [{ query: "approved" }]);
  await s.h.restart();
  assert.equal((await s.send("inspect")).body.state, "succeeded");
  assert.equal((await s.send("execute", digest)).status, 409);
  assert.equal(s.mcp.state.calls.length, 1);
  assert.equal(
    (
      await s.manage("refreshTrust", {
        expectedRevision: 0,
        provisioning: s.provisioning(s.actors, 2),
      })
    ).body.error,
    "conflict",
  );
  const changed = structuredClone(s.config);
  changed.policy.sessions[0].approvers = [];
  assert.equal(
    (
      await s.manage("updateAuthority", {
        expectedRevision: 0,
        configuration: changed,
      })
    ).body.ok,
    true,
  );
  assert.equal(
    (await s.manage("initialize", { configuration: s.config })).body.status
      .authority.revision,
    1,
  );
});
test("private policy revocation during MCP OAuth prevents the actual production Worker effect", async (t) => {
  const s = await flow(t);
  const proposed = await s.send("propose"),
    digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", digest)).body.state, "approved");
  let entered = false,
    release;
  const held = new Promise((r) => (release = r));
  s.mcp.state.beforeGrant = async () => {
    entered = true;
    await held;
  };
  const pending = s.send("execute", digest);
  try {
    const end = Date.now() + 5000;
    while (!entered) {
      if (Date.now() > end) throw Error("OAuth did not start");
      await new Promise((r) => setTimeout(r, 10));
    }
    const changed = structuredClone(s.config);
    changed.policy.sessions[0].approvers = [];
    assert.equal(
      (
        await s.manage("updateAuthority", {
          expectedRevision: 0,
          configuration: changed,
        })
      ).body.ok,
      true,
    );
  } finally {
    release();
  }
  assert.equal((await pending).body.state, "failed");
  assert.equal(s.mcp.state.calls.length, 0);
});

test("private owner can provision the full 500-user and 200-agent organization", async (t) => {
  const actors = Array.from({ length: 700 }, (_, i) =>
    identity((i < 200 ? "agent-" : "human-") + i),
  );
  const config = configuration(
    {
      config: {
        issuer: "https://id.example/realms/xeip",
        audience: "xeip-api",
        clientIds: ["xeip-agent", "xeip-console"],
        introspectionClientId: "xeip-introspection",
      },
    },
    actors,
  );
  config.policy.sessions[0].agents = actors.slice(0, 200).map((a) => a.subject);
  config.policy.sessions[0].approvers = actors.slice(200).map((a) => a.subject);
  const b = bindings();
  b.XEIP_PROFILE = JSON.stringify({
    ...profile,
    gateway: actors[0].entity,
    targets: [{ ...profile.targets[0], recipient: actors[0].entity }],
  });
  const h = await setup(t, b);
  const initialized = await h.send({
    raw: raw("initialize", { configuration: config }),
  });
  assert.equal(initialized.body.ok, true, JSON.stringify(initialized));
  const { provisioning } = await import(
    "./fixtures/cloudflare/authority-harness.mjs"
  );
  const refreshed = await h.send({
    raw: raw("refreshTrust", {
      expectedRevision: 0,
      provisioning: provisioning(actors),
    }),
  });
  assert.equal(refreshed.body.ok, true, JSON.stringify(refreshed));
  assert.equal(refreshed.body.status.trust.entities, 700);
  await h.restart();
  const reopened = (await h.send({ raw: raw("status") })).body;
  assert.equal(reopened.status.trust.entities, 700);
  assert.equal(reopened.status.authority.revision, 0);
});

test("private audit export survives restart and cannot be selected through public HTTP or default RPC", async (t) => {
  const s = await flow(t);
  assert.equal(
    (
      await s.manage("updateAuthority", {
        configuration: s.config,
        expectedRevision: 99,
      })
    ).body.error,
    "conflict",
  );
  const command = {
    operation: "auditExport",
    requestId: randomUUID(),
    after: 0,
    limit: 4,
  };
  const first = (await s.h.send({ raw: JSON.stringify(command) })).body;
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.audit.records.length, 4);
  assert.equal(first.audit.headSequence, 6);
  const { validateOwnerReceipt } = await import(
    "../services/organization/cloudflare/owner.mjs"
  );
  assert.equal(
    validateOwnerReceipt(JSON.stringify(first), {
      ...command,
      operator: "fixture:operator",
    }).ok,
    true,
  );
  for (const mutate of [
    (v) => (v.audit.records[0].event.secret = "sentinel-secret"),
    (v) => (v.audit.records[0].checksum = "f".repeat(64)),
    (v) => (v.audit.headSequence = -1),
    (v) => (v.audit.next = 99),
    (v) => (v.audit.extra = "sentinel-secret"),
    (v) => (v.audit.records[0].sequence = 2),
    (v) => (v.audit.records[1].previous = "f".repeat(64)),
  ]) {
    const bad = structuredClone(first);
    mutate(bad);
    assert.throws(
      () =>
        validateOwnerReceipt(JSON.stringify(bad), {
          ...command,
          operator: "fixture:operator",
        }),
      /invalid owner response/,
    );
  }
  await s.h.restart();
  const second = (
    await s.manage("auditExport", { after: first.audit.next, limit: 4 })
  ).body.audit;
  assert.equal(second.records.length, 2);
  assert.equal(second.records[0].previous, first.audit.records.at(-1).checksum);
  assert.equal(second.records.at(-1).event.outcome, "conflict");
  assert.equal(second.headChecksum, second.records.at(-1).checksum);
  for (const path of ["/auditExport", "/audit", "/owner/audit"]) {
    assert.equal(
      (
        await s.h.send({
          kind: "public",
          url: profile.origin + path,
          method: "POST",
          body: JSON.stringify(command),
        })
      ).status,
      404,
    );
  }
  assert.equal(
    (await s.h.send({ kind: "default-rpc", raw: JSON.stringify(command) }))
      .status,
    502,
  );
});
test("private action snapshot/page preserves a fixed cut and carries large payloads without public access", async (t) => {
  const s = await flow(t),
    args = { query: '"'.repeat(30000) };
  const proposed = await s.send("propose", undefined, args);
  assert.equal(proposed.status, 200);
  const first = (await s.manage("actionSnapshot")).body;
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.snapshot.actions, 1);
  const digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", digest)).body.state, "approved");
  const page = (
    await s.manage("actionPage", { cut: first.snapshot.cut, after: 0 })
  ).body;
  assert.equal(page.ok, true);
  assert.equal(page.page.record.row.state, "pending");
  assert.deepEqual(JSON.parse(page.page.record.row.canonical).arguments, args);
  assert.ok(Buffer.byteLength(JSON.stringify(page)) > 65536);
  const { validateOwnerReceipt } = await import(
    "../services/organization/cloudflare/owner.mjs"
  );
  validateOwnerReceipt(JSON.stringify(page), {
    operation: "actionPage",
    requestId: page.requestId,
    operator: "fixture:operator",
    cut: first.snapshot.cut,
    after: 0,
  });
  for (const kind of ["default-rpc", "owner-http", "missing-operator"]) {
    const denied = await s.h.send({ kind, raw: raw("actionSnapshot") });
    assert.notEqual(denied.body?.ok, true);
  }
  const { mkdtemp, rm } = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const root = await mkdtemp(join(tmpdir(), "xeip-native-action-archive-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { collectActionArchive, verifyActionArchive } = await import(
    "../services/organization/cloudflare/action-archive.mjs"
  );
  const source = {
    name: "xeip-native-archive",
    compatibility_date: "2026-07-30",
    services: [
      {
        binding: "OWNER",
        service: "xeip",
        entrypoint: "OwnerEntrypoint",
        remote: false,
        props: { operator: "fixture:operator" },
      },
    ],
  };
  const capture = async (cut) =>
    (await s.manage("actionSnapshot", cut === undefined ? {} : { cut })).body
      .snapshot;
  const readPage = async (options) =>
    (await s.manage("actionPage", options)).body.page;
  const previous = join(root, "prior");
  await collectActionArchive({
    directory: previous,
    source,
    capture: (cut) => capture(cut ?? first.snapshot.cut),
    readPage,
  });
  const final = join(root, "current"),
    archive = await collectActionArchive({
      directory: final,
      source,
      previous,
      capture,
      readPage,
    });
  assert.equal(archive.snapshot.cut, first.snapshot.cut + 1);
  await s.h.restart();
  assert.equal(
    (await verifyActionArchive(final)).manifestChecksum,
    archive.manifestChecksum,
  );
  assert.deepEqual(
    (await s.manage("actionSnapshot", { cut: first.snapshot.cut })).body
      .snapshot,
    first.snapshot,
  );
  for (const extra of [
    { cut: -1, after: 0 },
    { cut: 1, after: 0, limit: 1 },
    { cut: 1, after: "0" },
  ])
    assert.equal(
      (await s.manage("actionPage", extra)).body.error,
      "invalid_request",
    );
});
test("action export cannot silently initialize an empty organization", async (t) => {
  const h = await setup(t);
  for (const command of [
    raw("actionSnapshot"),
    raw("actionPage", { cut: 0, after: 0 }),
  ])
    assert.equal((await h.send({ raw: command })).body.error, "unavailable");
  assert.equal(
    (await h.send({ raw: raw("status") })).body.status.state,
    "uninitialized",
  );
  assert.equal(
    (await h.send({ raw: raw("auditExport") })).body.audit.headSequence,
    0,
  );
});

test("private organization export RPC transfers bounded captured components and histories after live updates", async (t) => {
  const s = await flow(t, { signatureCopies: 3000 });
  const { validateOwnerReceipt } = await import(
    "../services/organization/cloudflare/owner.mjs"
  );
  const { validateOrganizationCheckpoint } = await import(
    "../services/organization/cloudflare/organization-checkpoint.mjs"
  );
  const { createHash } = await import("node:crypto");
  const proposed = await s.send("propose", undefined, {
    query: '"'.repeat(30000),
  });
  assert.equal(proposed.status, 200);
  const send = async (operation, extra = {}, exportContext) => {
    const command = { operation, requestId: randomUUID(), ...extra };
    const response = await s.h.send({ raw: JSON.stringify(command) });
    assert.equal(response.body.ok, true, JSON.stringify(response.body));
    return validateOwnerReceipt(JSON.stringify(response.body), {
      ...command,
      operator: "fixture:operator",
      exportContext,
    });
  };
  const description = (
    await send(
      "organizationExportBegin",
      {},
      { organization: profile.organization },
    )
  ).export;
  assert.equal(description.manifest.actions.cut, 1);
  assert.ok(description.components.trust.parts > 1);
  assert.equal(
    (await s.send("approve", proposed.body.proposal.digest)).body.state,
    "approved",
  );
  const changed = structuredClone(s.config);
  changed.authentication.clientIds.push("after-export");
  assert.equal(
    (
      await s.manage("updateAuthority", {
        configuration: changed,
        expectedRevision: 0,
      })
    ).body.ok,
    true,
  );
  const checkpoint = { manifest: description.manifest };
  for (const [component, descriptor] of Object.entries(
    description.components,
  )) {
    const chunks = [];
    for (let index = 0; index < descriptor.parts; index++) {
      const receipt = await send(
        "organizationExportPart",
        { exportId: description.exportId, component, index },
        { description },
      );
      if (component === "trust" && index === 0)
        assert.ok(Buffer.byteLength(JSON.stringify(receipt)) > 65536);
      chunks.push(Buffer.from(receipt.part.data, "base64"));
    }
    const bytes = Buffer.concat(chunks);
    assert.equal(bytes.length, descriptor.bytes);
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      descriptor.sha256,
    );
    checkpoint[component] = JSON.parse(bytes);
  }
  const captured = validateOrganizationCheckpoint(
    checkpoint,
    profile.organization,
  );
  assert.equal(captured.authority.revision, 0);
  assert.equal(captured.administration.headSequence, 4);
  for (const section of ["actions", "authority", "administration"]) {
    const page = (
      await send(
        "organizationExportPage",
        {
          exportId: description.exportId,
          section,
          cursor: section === "actions" ? 0 : {},
        },
        { checkpoint: captured },
      )
    ).page.page;
    if (section === "actions") assert.equal(page.record.row.state, "pending");
    else assert.equal(page.complete, true);
  }
  for (const kind of ["default-rpc", "owner-http", "missing-operator"])
    assert.notEqual(
      (await s.h.send({ kind, raw: raw("organizationExportBegin") })).body?.ok,
      true,
    );
  for (const path of [
    "/organizationExportBegin",
    "/organizationExportPart",
    "/manage",
  ])
    assert.equal(
      (
        await s.h.send({
          kind: "public",
          url: profile.origin + path,
          method: "POST",
          body: raw("organizationExportBegin"),
        })
      ).status,
      404,
    );
  assert.equal(
    (await send("organizationExportClose", { exportId: description.exportId }))
      .closed.exportId,
    description.exportId,
  );
  assert.equal(
    (
      await s.manage("organizationExportPart", {
        exportId: description.exportId,
        component: "trust",
        index: 0,
      })
    ).body.error,
    "unavailable",
  );
  assert.equal((await s.manage("auditExport")).body.audit.headSequence, 6);
  const { mkdtemp, rm } = await import("node:fs/promises"),
    { join } = await import("node:path"),
    { tmpdir } = await import("node:os"),
    { collectOwnerOrganizationBundle } = await import(
      "../services/organization/cloudflare/organization-export-command.mjs"
    ),
    { verifyOrganizationBundle } = await import(
      "../services/organization/cloudflare/organization-bundle.mjs"
    );
  const directory = await mkdtemp(
    join(tmpdir(), "xeip-private-organization-export-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const collected = await collectOwnerOrganizationBundle({
    directory: join(directory, "bundle"),
    organization: profile.organization,
    session: {
      send: async (raw, exportContext) => {
        const command = JSON.parse(raw),
          response = await s.h.send({ raw });
        return validateOwnerReceipt(JSON.stringify(response.body), {
          ...command,
          operator: "fixture:operator",
          exportContext,
        });
      },
    },
  });
  assert.equal(collected.sourceClosed, true);
  assert.equal(collected.bundle.checkpoint.actions.cut, 2);
  assert.equal(
    (
      await verifyOrganizationBundle(join(directory, "bundle"), {
        organization: profile.organization,
        expectedDigest: collected.bundle.checkpoint.digest,
      })
    ).checksum,
    collected.bundle.checksum,
  );
  assert.equal((await s.manage("auditExport")).body.audit.headSequence, 6);
  assert.equal(s.mcp.state.calls.length, 0);
});

test("private organization export RPC cannot initialize state and sessions do not survive Worker restart", async (t) => {
  const h = await setup(t);
  assert.equal(
    (await h.send({ raw: raw("organizationExportBegin") })).body.error,
    "unavailable",
  );
  assert.equal(
    (await h.send({ raw: raw("status") })).body.status.state,
    "uninitialized",
  );
  const s = await flow(t),
    begin = (await s.manage("organizationExportBegin")).body;
  assert.equal(begin.ok, true, JSON.stringify(begin));
  await s.h.restart();
  assert.equal(
    (
      await s.manage("organizationExportPart", {
        exportId: begin.export.exportId,
        component: "trust",
        index: 0,
      })
    ).body.error,
    "unavailable",
  );
  assert.equal((await s.manage("organizationExportBegin")).body.ok, true);
});
test("signed Worker recovery journal produces an offline verified bundle with a consumed claim", async (t) => {
  const s = await flow(t, { recovery: true });
  const proposed = await s.send("propose"),
    digest = proposed.body.proposal.digest;
  assert.equal((await s.send("approve", digest)).body.state, "approved");
  assert.equal((await s.send("execute", digest)).body.state, "succeeded");
  const { mkdtemp, writeFile, rm } = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const { collectConfiguredRecovery } = await import(
    "../services/organization/cloudflare/recovery-archive-command.mjs"
  );
  const { verifyRecoveryActions } = await import(
    "../services/organization/cloudflare/recovery-action-archive.mjs"
  );
  const directory = await mkdtemp(
    join(tmpdir(), "xeip-native-recovery-bundle-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const configPath = join(directory, "journal.json");
  await writeFile(
    configPath,
    JSON.stringify({
      url: s.recovery.recovery.url,
      token: s.recovery.token,
      options: s.recovery.options,
    }),
    { mode: 0o600 },
  );
  const bundle = join(directory, "bundle");
  const manifest = await collectConfiguredRecovery({
    configPath,
    directory: bundle,
    request: (url, init) => s.recovery.outbound(new Request(url, init)),
  });
  assert.equal(manifest.head.sequence, 4);
  const { harness: restoreHarness } = await import(
    "./fixtures/cloudflare/lifecycle-harness.mjs"
  );
  const { readRecoveryFile, recoveryFilename } = await import(
    "../services/organization/cloudflare/recovery-archive.mjs"
  );
  const { decodeActionRecovery } = await import(
    "../services/organization/cloudflare/action-recovery-record.mjs"
  );
  const { runtimeConfiguration } = await import(
    "../services/organization/cloudflare/profile.mjs"
  );
  const restored = await restoreHarness({
    entryPoint: new URL(
      "./organization-cloudflare-action-restore-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "ActionRestoreFixture",
  });
  t.after(() => restored.close());
  const target = await restored.fixture();
  assert.equal(
    (await target.send({ operation: "restoreInitialize", manifest })).status,
    200,
  );
  let last;
  for (let sequence = 1; sequence <= manifest.head.sequence; sequence++) {
    const { value } = await readRecoveryFile(
      join(bundle, recoveryFilename(sequence)),
    );
    assert.equal(
      (await target.send({ operation: "restoreApply", value })).status,
      200,
    );
    last = decodeActionRecovery(value, s.recovery.options).record;
  }
  const verified = await target.send({ operation: "restoreVerify" });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.phase, "verified");
  assert.equal(verified.body.blocked, true);
  assert.deepEqual((await target.sql("SELECT * FROM xeip_actions")).body.rows, [
    JSON.parse(JSON.stringify(last.row)),
  ]);
  assert.deepEqual(
    (await target.sql("SELECT * FROM xeip_audit ORDER BY sequence")).body.rows,
    JSON.parse(JSON.stringify(last.history)),
  );
  const configuration = runtimeConfiguration(s.env);
  assert.equal(
    (
      await target.send({
        operation: "regularStore",
        organization: configuration.organization,
      })
    ).status,
    503,
  );
  assert.equal(
    (await target.send({ operation: "open", configuration })).body.state,
    "failed",
  );
  assert.equal((await target.send({ operation: "ready" })).body.ready, false);
  const checked = await verifyRecoveryActions(bundle);
  assert.equal(checked.actions, 1);
  assert.equal(checked.states.succeeded, 1);
  assert.equal(checked.consumedClaims, 1);
  assert.equal(s.mcp.state.calls.length, 1);
  assert.equal(s.recovery.requests.filter((v) => v === "append").length, 4);
  await s.h.restart();
  assert.equal((await s.send("execute", digest)).status, 409);
  assert.equal(s.mcp.state.calls.length, 1);
});
