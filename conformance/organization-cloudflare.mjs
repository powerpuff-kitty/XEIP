/** Real local SQLite Durable Object conformance; no Cloudflare account or deployment. */
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
let mf,
  directory,
  scriptPath,
  sequence = 0;
async function start() {
  mf = new Miniflare({
    name: "xeip-ledger-conformance",
    host: "127.0.0.1",
    port: 0,
    modules: true,
    modulesRoot: directory,
    scriptPath,
    compatibilityDate: "2026-07-30",
    compatibilityFlags: ["nodejs_compat"],
    durableObjects: { LEDGER: { className: "LedgerFixture", useSQLite: true } },
    durableObjectsPersist: join(directory, "storage"),
  });
  await mf.ready;
}
before(async () => {
  directory = await mkdtemp(join(tmpdir(), "xeip-cloudflare-ledger-"));
  scriptPath = join(directory, "worker.mjs");
  await build({
    entryPoints: [
      new URL("./organization-cloudflare-worker.mjs", import.meta.url).pathname,
    ],
    outfile: scriptPath,
    bundle: true,
    format: "esm",
    platform: "neutral",
    external: ["cloudflare:workers", "node:crypto"],
    // Only this synthetic fixture bundle gets a controllable wall clock.
    // The platform clock and production source files remain unchanged.
    define: { "Date.now": "__xeipFixtureNow" },
    banner: {
      js: "function __xeipFixtureNow() { return globalThis.__xeipFixtureClock ?? Date.now(); }",
    },
    logLevel: "silent",
  });
  await start();
});
after(async () => {
  await mf?.dispose();
  if (directory) await rm(directory, { recursive: true, force: true });
});
async function fixture(name = "case-" + ++sequence) {
  const namespace = await mf.getDurableObjectNamespace("LEDGER");
  const stub = namespace.get(namespace.idFromName(name));
  const send = async (input) => {
    const response = await stub.fetch("https://fixture.invalid/", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return { status: response.status, body: await response.json() };
  };
  return {
    name,
    send,
    sql: async (query, ...bindings) =>
      send({ operation: "sql", query, bindings }),
  };
}
test("storage is scoped to one organization and schema checksum", async () => {
  const f = await fixture();
  assert.equal(
    (
      await f.send({
        operation: "initialize",
        organization: "fixture-organization",
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await f.send({
        operation: "initialize",
        organization: "another-organization",
      })
    ).status,
    409,
  );
  assert.equal(
    (await f.sql("UPDATE xeip_schema SET checksum=?", "0".repeat(64))).status,
    200,
  );
  assert.equal(
    (
      await f.send({
        operation: "initialize",
        organization: "fixture-organization",
      })
    ).status,
    409,
  );
});
test("initialization is idempotent and installs required action/audit constraints", async () => {
  const f = await fixture();
  const tables = await f.sql(
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'xeip_%' ORDER BY name",
  );
  assert.deepEqual(
    tables.body.rows.map((x) => x.name),
    [
      "xeip_action_recovery",
      "xeip_action_restore",
      "xeip_actions",
      "xeip_audit",
      "xeip_authority_events",
      "xeip_authority_state",
      "xeip_metadata",
      "xeip_organization_restore",
      "xeip_owner_events",
      "xeip_schema",
      "xeip_service_state",
      "xeip_trust_checkpoints",
      "xeip_trust_chunks",
      "xeip_trust_state",
    ],
  );
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) VALUES ('s','r',?,'{}',0,'executing')",
        "a".repeat(64),
      )
    ).status,
    409,
  );
  assert.equal((await f.sql("SELECT * FROM xeip_actions")).body.rows.length, 0);
});
test("the conformance worker exposes no public HTTP ingress", async () => {
  assert.equal(
    (await mf.dispatchFetch("https://fixture.invalid/v1/actions")).status,
    404,
  );
});
test("missing schema protections are rejected on reopen", async () => {
  const f = await fixture();
  assert.equal((await f.sql("DROP TRIGGER xeip_action_delete")).status, 200);
  assert.equal(
    (
      await f.send({
        operation: "initialize",
        organization: "fixture-organization",
      })
    ).status,
    409,
  );
});
const now = () => Math.floor(Date.now() / 1000);
const propose = (f, id = "request-1", options = {}) =>
  f.send({
    operation: "propose",
    principal: "agent",
    request: {
      id,
      session: "operations",
      target: "internal",
      tool: "lookup",
      arguments: { value: 1 },
      expiresAt: now() + 300,
      ...options,
    },
  });
const command = (
  f,
  operation,
  proposal,
  principal = operation === "claim" ? "agent" : "human",
  extra = {},
) =>
  f.send({
    operation,
    principal,
    session: proposal.action.session,
    id: proposal.action.id,
    digest: proposal.digest,
    ...extra,
  });
test("exact proposal, approval, claim and completion append atomic audit records", async () => {
  const f = await fixture(),
    created = await propose(f);
  assert.equal(created.status, 200);
  const p = created.body.proposal;
  assert.equal(created.body.state, "pending");
  const approved = await command(f, "decide", p, "human", {
    decision: "approve",
  });
  assert.equal(approved.status, 200);
  assert.equal(approved.body.state, "approved");
  const claimed = await command(f, "claim", p);
  assert.equal(claimed.status, 200);
  assert.equal(claimed.body.state, "executing");
  assert.match(claimed.body.claimId, /^[0-9a-f-]{36}$/);
  assert.equal(claimed.body.approver.subject, "human");
  const completed = await f.send({
    operation: "finish",
    session: p.action.session,
    id: p.action.id,
    claimId: claimed.body.claimId,
    outcome: "succeeded",
    result: { value: 2 },
  });
  assert.equal(completed.status, 200);
  assert.equal(completed.body.state, "succeeded");
  const read = await command(f, "inspect", p, "human");
  assert.equal(read.status, 200);
  assert.equal(Object.hasOwn(read.body, "claimId"), false);
  assert.deepEqual(read.body.result, { value: 2 });
  assert.deepEqual(
    (
      await f.sql("SELECT event FROM xeip_audit ORDER BY sequence")
    ).body.rows.map((x) => x.event),
    ["proposed", "approved", "claimed", "succeeded"],
  );
});
test("idempotent proposal does not duplicate audit and reused IDs bind exact content", async () => {
  const f = await fixture(),
    expiresAt = now() + 300;
  const first = await propose(f, "same", { expiresAt }),
    second = await propose(f, "same", { expiresAt });
  assert.equal(first.status, 200);
  assert.deepEqual(second, first);
  assert.equal(
    (await propose(f, "same", { expiresAt, arguments: { value: 2 } })).body
      .error,
    "StoreConflict",
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_audit")).body.rows[0]
      .count,
    1,
  );
});
test("rejection and revocation are terminal and prevent claims", async () => {
  for (const operation of ["reject", "revoke"]) {
    const f = await fixture(),
      created = await propose(f);
    assert.equal(created.status, 200);
    const p = created.body.proposal;
    const result =
      operation === "reject"
        ? await command(f, "decide", p, "human", { decision: "reject" })
        : await command(f, "revoke", p);
    assert.equal(result.status, 200);
    assert.equal(
      result.body.state,
      operation === "reject" ? "rejected" : "revoked",
    );
    assert.equal((await command(f, "claim", p)).status, 409);
    assert.equal(
      (await command(f, "decide", p, "human", { decision: "approve" })).status,
      409,
    );
  }
});
test("self approval, wrong digest, unknown session and unauthorized inspection are denied", async () => {
  const f = await fixture(),
    created = await propose(f);
  assert.equal(created.status, 200);
  const p = created.body.proposal;
  assert.equal(
    (await command(f, "decide", p, "self", { decision: "approve" })).body.error,
    "PolicyDenied",
  );
  assert.equal(
    (await command(f, "decide", p, "entity-clone", { decision: "approve" }))
      .body.error,
    "PolicyDenied",
  );
  assert.equal(
    (
      await command(f, "decide", { ...p, digest: "0".repeat(64) }, "human", {
        decision: "approve",
      })
    ).body.error,
    "StoreConflict",
  );
  assert.equal(
    (await command(f, "inspect", p, "stranger")).body.error,
    "PolicyDenied",
  );
  assert.equal(
    (await propose(f, "wrong-session", { session: "private" })).body.error,
    "PolicyDenied",
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_audit")).body.rows[0]
      .count,
    1,
  );
});
test("quota preserves existing work and does not delete replay history", async () => {
  const f = await fixture();
  await f.send({ operation: "controls", maxActions: 1, reopen: true });
  const created = await propose(f);
  assert.equal(created.status, 200);
  const p = created.body.proposal;
  assert.equal((await propose(f, "second")).body.error, "StoreConflict");
  assert.equal(
    (await command(f, "decide", p, "human", { decision: "approve" })).status,
    200,
  );
  assert.equal((await command(f, "inspect", p)).status, 200);
  assert.equal(
    (await f.sql("SELECT action_count FROM xeip_metadata")).body.rows[0]
      .action_count,
    1,
  );
});
test("terminal completion is immutable, exactly idempotent, and capability-bound", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal;
  await command(f, "decide", p, "human", { decision: "approve" });
  const claim = (await command(f, "claim", p)).body;
  const finish = {
    operation: "finish",
    session: "operations",
    id: "request-1",
    claimId: claim.claimId,
    outcome: "succeeded",
    result: { ok: true },
  };
  const first = await f.send(finish);
  assert.equal(first.status, 200);
  assert.deepEqual(await f.send(finish), first);
  for (const change of [
    { result: { ok: false } },
    { outcome: "failed" },
    { claimId: crypto.randomUUID() },
  ])
    assert.equal(
      (await f.send({ ...finish, ...change })).body.error,
      "StoreConflict",
    );
  for (const query of [
    "UPDATE xeip_actions SET canonical='{}'",
    "UPDATE xeip_actions SET state='approved',version=version+1",
    "DELETE FROM xeip_actions",
    "UPDATE xeip_audit SET actor='{}'",
    "DELETE FROM xeip_audit",
  ])
    assert.equal((await f.sql(query)).status, 409);
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_audit")).body.rows[0]
      .count,
    4,
  );
});
test("approval expiry is bounded by the human token while inspection survives expiry", async () => {
  const f = await fixture(),
    current = now(),
    deadline = current + 10;
  await f.send({ operation: "controls", clock: current * 1000 });
  try {
    const p = (await propose(f)).body.proposal;
    const approval = await command(f, "decide", p, "human", {
      decision: "approve",
      principalExpires: deadline,
    });
    assert.equal(approval.status, 200, JSON.stringify(approval.body));
    assert.equal(
      (await f.sql("SELECT approval_expires_at FROM xeip_actions")).body.rows[0]
        .approval_expires_at,
      deadline,
    );
    await f.send({ operation: "controls", clock: (deadline - 1) * 1000 });
    assert.equal((await command(f, "inspect", p)).body.state, "approved");
    await f.send({ operation: "controls", clock: deadline * 1000 });
    assert.equal((await command(f, "claim", p)).body.error, "PolicyDenied");
    assert.equal((await command(f, "inspect", p)).status, 200);
    assert.equal(
      (await f.sql("SELECT claim_id FROM xeip_actions")).body.rows[0].claim_id,
      null,
    );
  } finally {
    await f.send({ operation: "controls", clock: null });
  }
});
test("invalid outcomes, oversized results and mutable principals fail without writing", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal;
  await command(f, "decide", p, "human", { decision: "approve" });
  const claim = (await command(f, "claim", p)).body;
  const finish = {
    operation: "finish",
    session: "operations",
    id: "request-1",
    claimId: claim.claimId,
    outcome: "succeeded",
  };
  for (const change of [
    { outcome: "pending" },
    { outcome: "indeterminate", result: { secret: "unknown" } },
    { result: "x".repeat(131073) },
  ])
    assert.equal(
      (await f.send({ ...finish, ...change })).body.error,
      "StoreConflict",
    );
  assert.equal((await command(f, "inspect", p)).body.state, "executing");
  assert.equal(
    (await command(f, "inspect", p, "human", { mutable: true })).body.error,
    "PolicyDenied",
  );
});
const controls = (f, options = {}) =>
  f.send({ operation: "controls", ...options });
async function until(f, predicate) {
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    const result = await controls(f);
    if (predicate(result.body)) return result.body;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("fixture did not reach the expected interleaving");
}
async function approved(f) {
  const p = (await propose(f)).body.proposal;
  assert.equal(
    (await command(f, "decide", p, "human", { decision: "approve" })).status,
    200,
  );
  return p;
}
test("concurrent decisions and claims produce exactly one winner each", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal;
  let prior = (await controls(f, { hold: "decide" })).body.entered;
  const decisions = ["approve", "reject"].map((decision) =>
    command(f, "decide", p, "human", { decision }),
  );
  await until(f, (c) => c.entered === prior + 2);
  await controls(f, { hold: null });
  const results = await Promise.all(decisions);
  assert.equal(results.filter((r) => r.status === 200).length, 1);
  assert.equal(
    results.filter((r) => r.body.error === "StoreConflict").length,
    1,
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_audit")).body.rows[0]
      .count,
    2,
  );
  const g = await fixture(),
    q = await approved(g);
  prior = (await controls(g, { hold: "claim" })).body.entered;
  const claims = [command(g, "claim", q), command(g, "claim", q)];
  await until(g, (c) => c.entered === prior + 2);
  await controls(g, { hold: null });
  const claimed = await Promise.all(claims);
  assert.equal(claimed.filter((r) => r.status === 200).length, 1);
  assert.equal(
    claimed.filter((r) => r.body.error === "StoreConflict").length,
    1,
  );
  assert.equal(
    (
      await g.sql(
        "SELECT COUNT(*) AS count FROM xeip_audit WHERE event='claimed'",
      )
    ).body.rows[0].count,
    1,
  );
});
test("local authority and action changes during authorization invalidate the snapshot", async () => {
  for (const change of [
    { bump: true },
    { blocked: true },
    { revoked: ["z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"] },
  ]) {
    const f = await fixture(),
      p = await approved(f),
      prior = (await controls(f, { hold: "claim" })).body.entered;
    const pending = command(f, "claim", p);
    await until(f, (c) => c.entered === prior + 1);
    await controls(f, { ...change, hold: null });
    assert.equal((await pending).body.error, "PolicyDenied");
    assert.equal(
      (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
      "approved",
    );
  }
  const f = await fixture(),
    p = await approved(f),
    prior = (await controls(f, { hold: "claim" })).body.entered;
  const pending = command(f, "claim", p);
  await until(f, (c) => c.entered === prior + 1);
  assert.equal((await command(f, "revoke", p)).status, 200);
  await controls(f, { hold: null });
  assert.equal((await pending).body.error, "StoreConflict");
  assert.equal((await command(f, "inspect", p)).body.state, "revoked");
});
test("revocation during durability wait denies a committed claim capability", async () => {
  const f = await fixture(),
    p = await approved(f),
    prior = (await controls(f, { holdSync: true })).body.syncEntered;
  const pending = command(f, "claim", p);
  await until(f, (c) => c.syncEntered === prior + 1);
  await controls(f, { bump: true, holdSync: false });
  assert.equal((await pending).body.error, "PolicyDenied");
  const read = await command(f, "inspect", p);
  assert.equal(read.body.state, "executing");
  assert.equal(Object.hasOwn(read.body, "claimId"), false);
  assert.equal((await command(f, "claim", p)).body.error, "StoreConflict");
});
test("audit failure rolls back the action, audit and quota then quarantines the adapter", async () => {
  const f = await fixture();
  await controls(f, { fault: "audit" });
  assert.equal((await propose(f)).body.error, "StoreUnavailable");
  assert.deepEqual(
    (await f.sql("SELECT action_count FROM xeip_metadata")).body.rows,
    [{ action_count: 0 }],
  );
  assert.equal((await f.sql("SELECT * FROM xeip_actions")).body.rows.length, 0);
  assert.equal((await f.sql("SELECT * FROM xeip_audit")).body.rows.length, 0);
  assert.equal((await propose(f)).body.error, "StoreUnavailable");
  await controls(f, { reopen: true });
  assert.equal((await propose(f)).status, 200);
});
test("provider refusal, timeout and expiry during authorization cannot write late", async () => {
  const f = await fixture();
  await controls(f, { allowed: false });
  assert.equal((await propose(f)).body.error, "PolicyDenied");
  await controls(f, {
    allowed: true,
    hold: "propose",
    timeoutMs: 100,
    reopen: true,
  });
  assert.equal((await propose(f)).body.error, "StoreUnavailable");
  await controls(f, { hold: null });
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal((await f.sql("SELECT * FROM xeip_actions")).body.rows.length, 0);
  const p = (await propose(f)).body.proposal,
    prior = (
      await controls(f, { hold: "decide", timeoutMs: 3000, reopen: true })
    ).body.entered;
  const pending = command(f, "decide", p, "human", {
    decision: "approve",
    principalExpires: now() + 1,
  });
  await until(f, (c) => c.entered === prior + 1);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  await controls(f, { hold: null });
  assert.equal((await pending).body.error, "PolicyDenied");
  assert.equal((await command(f, "inspect", p)).body.state, "pending");
});
test("ambiguous claim synchronization never reaches the shared executor effect", async () => {
  const f = await fixture(),
    p = await approved(f);
  await controls(f, { fault: "sync" });
  assert.equal(
    (await command(f, "execute", p, "agent")).body.error,
    "StoreUnavailable",
  );
  assert.equal((await controls(f)).body.effects, 0);
  assert.equal((await command(f, "inspect", p)).body.error, "StoreUnavailable");
  await controls(f, { reopen: true });
  assert.equal((await command(f, "inspect", p)).body.state, "executing");
  assert.equal(
    (await command(f, "execute", p, "agent")).body.error,
    "StoreConflict",
  );
  assert.equal((await controls(f)).body.effects, 0);
});
test("effect authorization rechecks local authority after its await", async () => {
  const f = await fixture(),
    p = await approved(f),
    prior = (await controls(f, { hold: "effect" })).body.entered;
  const pending = command(f, "execute", p, "agent");
  await until(f, (c) => c.entered === prior + 2);
  await controls(f, { blocked: true, hold: null });
  const result = await pending;
  assert.equal(result.status, 200);
  assert.equal(result.body.state, "failed");
  assert.equal((await controls(f)).body.effects, 0);
});
test("completion remains recordable after caller authority disappears", async () => {
  const f = await fixture(),
    p = await approved(f),
    claim = (await command(f, "claim", p)).body;
  await controls(f, {
    allowed: false,
    blocked: true,
    revoked: [claim.approver.kid],
  });
  const result = await f.send({
    operation: "finish",
    session: "operations",
    id: "request-1",
    claimId: claim.claimId,
    outcome: "succeeded",
    result: { ok: true },
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.state, "succeeded");
});
test("post-send failure records indeterminate once and retries never repeat the effect", async () => {
  const f = await fixture(),
    p = await approved(f);
  await controls(f, { effectFailure: true });
  const result = await command(f, "execute", p, "agent");
  assert.equal(result.status, 200);
  assert.equal(result.body.state, "indeterminate");
  assert.equal(result.body.result, null);
  assert.equal((await controls(f)).body.effects, 1);
  assert.equal(
    (await command(f, "execute", p, "agent")).body.error,
    "StoreConflict",
  );
  assert.equal((await controls(f)).body.effects, 1);
});
test("completion audit failure cannot report success or repeat an already sent effect", async () => {
  const f = await fixture(),
    p = await approved(f);
  await controls(f, { fault: "finish-audit" });
  assert.equal(
    (await command(f, "execute", p, "agent")).body.error,
    "StoreUnavailable",
  );
  assert.equal((await controls(f)).body.effects, 1);
  assert.equal(
    (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
    "executing",
  );
  assert.deepEqual(
    (
      await f.sql("SELECT event FROM xeip_audit ORDER BY sequence")
    ).body.rows.map((r) => r.event),
    ["proposed", "approved", "claimed"],
  );
  await controls(f, { reopen: true });
  assert.equal(
    (await command(f, "execute", p, "agent")).body.error,
    "StoreConflict",
  );
  assert.equal((await controls(f)).body.effects, 1);
});
test("local runtime restart preserves consumed claims, audit and authority revision", async () => {
  const f = await fixture(),
    p = await approved(f),
    claim = await command(f, "claim", p);
  assert.equal(claim.status, 200);
  await controls(f, { bump: true });
  await mf.dispose();
  await start();
  const restored = await fixture(f.name);
  const read = await command(restored, "inspect", p);
  assert.equal(read.status, 200);
  assert.equal(read.body.state, "executing");
  assert.equal(Object.hasOwn(read.body, "claimId"), false);
  assert.equal((await controls(restored)).body.revision, 2);
  assert.equal(
    (await command(restored, "execute", p, "agent")).body.error,
    "StoreConflict",
  );
  assert.equal((await controls(restored)).body.effects, 0);
  assert.deepEqual(
    (
      await restored.sql("SELECT event FROM xeip_audit ORDER BY sequence")
    ).body.rows.map((r) => r.event),
    ["proposed", "approved", "claimed"],
  );
});

for (const [name, query] of [
  [
    "action",
    "INSERT OR REPLACE INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) SELECT session_id,request_id,digest,canonical,expires_at,'pending' FROM xeip_actions",
  ],
  [
    "audit",
    "INSERT OR REPLACE INTO xeip_audit SELECT sequence,session_id,request_id,digest,event,'{}',occurred_at FROM xeip_audit",
  ],
  [
    "organization",
    "INSERT OR REPLACE INTO xeip_metadata VALUES (1,'changed',1)",
  ],
])
  test(`replacement cannot overwrite immutable ${name} rows`, async () => {
    const f = await fixture(),
      p = await approved(f);
    assert.equal((await f.sql(query)).status, 409);
    assert.equal((await command(f, "inspect", p)).body.state, "approved");
    assert.equal(
      (await f.sql("SELECT action_count FROM xeip_metadata")).body.rows[0]
        .action_count,
      1,
    );
    assert.equal((await controls(f, { reopen: true })).status, 200);
  });
for (const [name, field, value] of [
  ["request identifier", "request_id", "mismatched"],
  ["session identifier", "session_id", "other"],
  ["action expiry", "expires_at", 0],
])
  test(`SQL rejects stored ${name} inconsistent with the canonical action`, async () => {
    const f = await fixture(),
      p = (await propose(f)).body.proposal;
    const row = (await f.sql("SELECT * FROM xeip_actions")).body.rows[0];
    row[field] = value;
    // A fresh object makes this a constraint check, not a duplicate-key denial.
    const other = await fixture();
    assert.equal(
      (
        await other.sql(
          "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) VALUES (?,?,?,?,?,'pending')",
          row.session_id,
          row.request_id,
          row.digest,
          row.canonical,
          row.expires_at,
        )
      ).status,
      409,
    );
  });
test("SQL rejects approval expiry inconsistent with its grant and non-pending initial states", async () => {
  const f = await fixture(),
    p = await approved(f),
    row = (await f.sql("SELECT * FROM xeip_actions")).body.rows[0];
  const other = await fixture();
  assert.equal(
    (
      await other.sql(
        "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state,approver,approval_expires_at) VALUES (?,?,?,?,?,'approved',?,?)",
        row.session_id,
        row.request_id,
        row.digest,
        row.canonical,
        row.expires_at,
        row.approver,
        row.approval_expires_at,
      )
    ).status,
    409,
  );
  const g = await fixture(),
    q = (await propose(g)).body.proposal;
  assert.equal(
    (
      await g.sql(
        "UPDATE xeip_actions SET state='approved',version=1,approver=?,approval_expires_at=0",
        row.approver,
      )
    ).status,
    409,
  );
  assert.equal((await command(g, "inspect", q)).body.state, "pending");
});
for (const [name, corruption] of [
  ["request identifier", { request_id: "mismatched" }],
  ["session identifier", { session_id: "other" }],
  ["action expiry", { expires_at: 0 }],
  ["approval expiry", { approval_expires_at: 0 }],
  ["canonical digest", { digest: "0".repeat(64) }],
  ["canonical JSON", { canonical: "{" }],
  ["result JSON", { result_canonical: "{" }],
])
  test(`an inconsistent stored ${name} quarantines the adapter before inspection or a claim`, async () => {
    const f = await fixture(),
      p = await approved(f);
    await controls(f, { readCorruption: corruption });
    const result = await command(f, "inspect", p);
    assert.equal(result.body.error, "StoreUnavailable");
    assert.equal(Object.hasOwn(result.body, "claimId"), false);
    assert.equal((await command(f, "claim", p)).body.error, "StoreUnavailable");
    await controls(f, { readCorruption: null });
    assert.equal(
      (await command(f, "inspect", p)).body.error,
      "StoreUnavailable",
    );
    assert.equal(
      (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
      "approved",
    );
    assert.equal((await controls(f, { reopen: true })).status, 200);
    assert.equal((await command(f, "inspect", p)).body.state, "approved");
  });
for (const state of ["executing", "succeeded"])
  test(`replacement cannot reset a consumed ${state} action`, async () => {
    const f = await fixture(),
      p = await approved(f),
      claim = (await command(f, "claim", p)).body;
    if (state === "succeeded")
      assert.equal(
        (
          await f.send({
            operation: "finish",
            session: "operations",
            id: "request-1",
            claimId: claim.claimId,
            outcome: "succeeded",
          })
        ).status,
        200,
      );
    assert.equal(
      (
        await f.sql(
          "INSERT OR REPLACE INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) SELECT session_id,request_id,digest,canonical,expires_at,'pending' FROM xeip_actions",
        )
      ).status,
      409,
    );
    assert.equal((await command(f, "inspect", p)).body.state, state);
  });
test("replacement through a colliding claim ID cannot delete an earlier claim", async () => {
  const f = await fixture(),
    p = await approved(f),
    q = (await propose(f, "second")).body.proposal;
  await command(f, "decide", q, "human", { decision: "approve" });
  const claim = (await command(f, "claim", p)).body;
  assert.equal(
    (
      await f.sql(
        "UPDATE OR REPLACE xeip_actions SET state='executing',version=version+1,claim_id=? WHERE request_id='second'",
        claim.claimId,
      )
    ).status,
    409,
  );
  assert.equal((await command(f, "inspect", p)).body.state, "executing");
  assert.equal((await command(f, "inspect", q)).body.state, "approved");
});

async function corruptAudit(f, query, ...bindings) {
  const triggers = (
    await f.sql(
      "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='xeip_audit'",
    )
  ).body.rows;
  for (const { name } of triggers)
    assert.equal((await f.sql("DROP TRIGGER " + name)).status, 200);
  assert.equal((await f.sql(query, ...bindings)).status, 200);
  for (const { sql } of triggers) assert.equal((await f.sql(sql)).status, 200);
}
for (const [name, query, value] of [
  ["missing proposal", "DELETE FROM xeip_audit WHERE event='proposed'"],
  [
    "extra transition",
    "INSERT INTO xeip_audit(session_id,request_id,digest,event,actor,occurred_at) SELECT session_id,request_id,digest,event,actor,occurred_at FROM xeip_audit WHERE event='approved'",
  ],
  [
    "wrong digest",
    "UPDATE xeip_audit SET digest=? WHERE event='approved'",
    "0".repeat(64),
  ],
  [
    "wrong approver",
    "UPDATE xeip_audit SET actor=? WHERE event='approved'",
    JSON.stringify({ subject: "different", entity: "invalid", kid: "invalid" }),
  ],
  [
    "noncanonical actor",
    "UPDATE xeip_audit SET actor=actor||' ' WHERE event='proposed'",
  ],
  [
    "negative time",
    "UPDATE xeip_audit SET occurred_at=-1 WHERE event='proposed'",
  ],
  [
    "invalid graph",
    "UPDATE xeip_audit SET event='rejected' WHERE event='approved'",
  ],
])
  test(
    "action history " + name + " quarantines reads and prevents effects",
    async () => {
      const f = await fixture(),
        p = await approved(f);
      await corruptAudit(f, query, ...(value === undefined ? [] : [value]));
      assert.equal(
        (await command(f, "inspect", p)).body.error,
        "StoreUnavailable",
      );
      assert.equal(
        (await command(f, "execute", p, "agent")).body.error,
        "StoreUnavailable",
      );
      assert.equal((await controls(f)).body.effects, 0);
      assert.equal(
        (await controls(f, { reopen: true })).body.error,
        "StoreUnavailable",
      );
    },
  );
test("completion history must identify the persisted claim", async () => {
  const f = await fixture(),
    p = await approved(f),
    claim = (await command(f, "claim", p)).body;
  const input = {
    operation: "finish",
    session: p.action.session,
    id: p.action.id,
    claimId: claim.claimId,
    outcome: "succeeded",
  };
  assert.equal((await f.send(input)).status, 200);
  await corruptAudit(
    f,
    "UPDATE xeip_audit SET actor=? WHERE event='succeeded'",
    JSON.stringify({
      claimId: "00000000-0000-0000-0000-000000000000",
      worker: "execution",
    }),
  );
  assert.equal((await f.send(input)).body.error, "StoreUnavailable");
});
test("reopen fails closed when the storage query reports an orphan audit", async () => {
  const f = await fixture();
  await approved(f);
  assert.equal(
    (await controls(f, { orphanAudit: true, reopen: true })).body.error,
    "StoreUnavailable",
  );
});

test("reopen validates every action beyond a key page and preserves valid pending history", async () => {
  const f = await fixture();
  for (let i = 0; i < 130; i++)
    assert.equal(
      (await propose(f, "page-" + String(i).padStart(3, "0"))).status,
      200,
    );
  assert.equal((await controls(f, { reopen: true })).status, 200);
  await corruptAudit(f, "DELETE FROM xeip_audit WHERE request_id='page-129'");
  assert.equal(
    (await controls(f, { reopen: true })).body.error,
    "StoreUnavailable",
  );
});
test("late history corruption during live authorization prevents the claim", async () => {
  const f = await fixture(),
    p = await approved(f);
  const entered = (await controls(f, { hold: "claim" })).body.entered;
  const pending = command(f, "claim", p);
  await until(f, (c) => c.entered > entered);
  await corruptAudit(
    f,
    "UPDATE xeip_audit SET event='rejected' WHERE event='approved'",
  );
  await controls(f, { hold: null });
  assert.equal((await pending).body.error, "StoreUnavailable");
  assert.equal(
    (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
    "approved",
  );
});
test("reconciliation preserves every valid outcome, unfinished claim and backward clock timestamp", async () => {
  const f = await fixture();
  const expected = new Map();
  for (const outcome of [
    "pending",
    "approved",
    "rejected",
    "revoked",
    "executing",
    "succeeded",
    "failed",
    "indeterminate",
  ]) {
    const p = (await propose(f, "valid-" + outcome)).body.proposal;
    if (!["pending", "revoked"].includes(outcome))
      assert.equal(
        (
          await command(f, "decide", p, "human", {
            decision: outcome === "rejected" ? "reject" : "approve",
          })
        ).status,
        200,
      );
    if (outcome === "revoked")
      assert.equal((await command(f, "revoke", p)).status, 200);
    if (
      ["executing", "succeeded", "failed", "indeterminate"].includes(outcome)
    ) {
      const claim = (await command(f, "claim", p)).body;
      if (outcome !== "executing")
        assert.equal(
          (
            await f.send({
              operation: "finish",
              session: p.action.session,
              id: p.action.id,
              claimId: claim.claimId,
              outcome,
            })
          ).status,
          200,
        );
    }
    expected.set(p, outcome);
  }
  await corruptAudit(
    f,
    "UPDATE xeip_audit SET occurred_at=0 WHERE event='claimed'",
  );
  assert.equal((await controls(f, { reopen: true })).status, 200);
  for (const [p, outcome] of expected)
    assert.equal((await command(f, "inspect", p)).body.state, outcome);
  for (const [p, outcome] of expected)
    if (["executing", "succeeded", "failed", "indeterminate"].includes(outcome))
      assert.equal((await command(f, "claim", p)).body.error, "StoreConflict");
});
test("reconciliation rejects a missing audit generated inside a mutation before acknowledging it", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal;
  // A test-only trigger silently suppresses the insert; the transaction must still fail closed.
  assert.equal(
    (
      await f.sql(
        "CREATE TRIGGER fixture_skip_audit BEFORE INSERT ON xeip_audit WHEN NEW.event='approved' BEGIN SELECT RAISE(IGNORE); END",
      )
    ).status,
    200,
  );
  assert.equal(
    (await command(f, "decide", p, "human", { decision: "approve" })).body
      .error,
    "StoreUnavailable",
  );
  assert.equal(
    (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
    "pending",
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS n FROM xeip_audit")).body.rows[0].n,
    1,
  );
});
test("trusted authority client IDs retain the existing grant byte limit across approval and reopen", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal;
  const accepted = await command(f, "decide", p, "human", {
    decision: "approve",
    principalClientId: "x".repeat(257),
  });
  assert.equal(accepted.status, 200);
  assert.equal((await controls(f, { reopen: true })).status, 200);
  assert.equal((await command(f, "inspect", p)).body.state, "approved");
  assert.equal((await command(f, "claim", p)).status, 200);
});
test("a nonidentical proposal retry still quarantines corrupt history at its existing key", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal;
  await corruptAudit(f, "DELETE FROM xeip_audit WHERE event='proposed'");
  assert.equal(
    (
      await propose(f, p.action.id, {
        expiresAt: p.action.expiresAt,
        arguments: { value: 2 },
      })
    ).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await propose(f, "other-request")).body.error,
    "StoreUnavailable",
  );
});

test("fixed action snapshots reconstruct earlier states and keep their digest as actions advance", async () => {
  const f = await fixture(),
    p = (await propose(f)).body.proposal,
    snapshots = [];
  for (const state of ["pending", "approved", "executing", "succeeded"]) {
    if (state === "approved")
      assert.equal(
        (await command(f, "decide", p, "human", { decision: "approve" }))
          .status,
        200,
      );
    if (state === "executing")
      assert.equal((await command(f, "claim", p)).status, 200);
    if (state === "succeeded") {
      const claim = (await f.sql("SELECT claim_id FROM xeip_actions")).body
        .rows[0].claim_id;
      assert.equal(
        (
          await f.send({
            operation: "finish",
            session: p.action.session,
            id: p.action.id,
            claimId: claim,
            outcome: "succeeded",
            result: { value: "completed" },
          })
        ).status,
        200,
      );
    }
    const captured = await f.send({ operation: "actionSnapshot" });
    assert.equal(captured.status, 200);
    snapshots.push([state, captured.body]);
  }
  await propose(f, "later");
  for (const [state, snapshot] of snapshots) {
    assert.equal(snapshot.actions, 1);
    assert.deepEqual(
      (await f.send({ operation: "actionSnapshot", cut: snapshot.cut })).body,
      snapshot,
    );
    const page = (
      await f.send({ operation: "actionPage", cut: snapshot.cut, after: 0 })
    ).body;
    assert.equal(page.record.row.state, state);
    assert.equal(page.record.row.version, page.record.history.length - 1);
    assert.equal(page.record.row.approver === null, state === "pending");
    assert.equal(
      page.record.row.claim_id === null,
      ["pending", "approved"].includes(state),
    );
    assert.equal(
      page.record.row.result_canonical,
      state === "succeeded" ? '\{"value":"completed"\}' : null,
    );
    assert.equal(
      (
        await f.send({
          operation: "actionPage",
          cut: snapshot.cut,
          after: page.next,
        })
      ).body.record,
      null,
    );
    const { digest, ...header } = snapshot;
    const { createHash } = await import("node:crypto");
    const { canonicalize } = await import(
      "../sdks/typescript/dist/identity.js"
    );
    assert.equal(
      createHash("sha256")
        .update(
          "XEIP action snapshot v1\n" +
            canonicalize(header) +
            "\n" +
            canonicalize(page.record) +
            "\n",
        )
        .digest("hex"),
      digest,
    );
  }
});
test("empty action snapshots and invalid cuts/cursors are bounded without mutations", async () => {
  const f = await fixture(),
    empty = await f.send({ operation: "actionSnapshot" });
  assert.equal(empty.status, 200);
  assert.equal(empty.body.cut, 0);
  assert.equal(empty.body.actions, 0);
  assert.equal(
    (await f.send({ operation: "actionPage", cut: 0, after: 0 })).body.record,
    null,
  );
  const p = await approved(f);
  for (const cut of [-1, 0.5, "1", Number.MAX_SAFE_INTEGER + 1, 100])
    assert.equal(
      (await f.send({ operation: "actionSnapshot", cut })).status,
      409,
    );
  for (const after of [-1, 0.5, "1", 2, 100])
    assert.equal(
      (await f.send({ operation: "actionPage", cut: 2, after })).status,
      409,
    );
  assert.equal((await command(f, "inspect", p)).body.state, "approved");
  assert.equal(
    (await f.send({ operation: "actionSnapshot", cut: 0 })).body.actions,
    0,
  );
});
test("action snapshot captures more than one key page without mixing later proposals or outcomes", async () => {
  const f = await fixture();
  let first;
  for (let i = 0; i < 130; i++) {
    const p = (await propose(f, "snap-" + i)).body.proposal;
    if (i === 0) first = p;
  }
  const head = (await f.send({ operation: "actionSnapshot" })).body;
  await command(f, "decide", first, "human", { decision: "approve" });
  await propose(f, "after-cut");
  const { createHash } = await import("node:crypto"),
    { canonicalize } = await import("../sdks/typescript/dist/identity.js");
  const { digest, ...header } = head,
    hash = createHash("sha256").update(
      "XEIP action snapshot v1\n" + canonicalize(header) + "\n",
    );
  let after = 0,
    count = 0;
  for (;;) {
    const r = await f.send({ operation: "actionPage", cut: head.cut, after });
    assert.equal(r.status, 200);
    if (!r.body.record) break;
    assert.equal(r.body.record.row.state, "pending");
    hash.update(canonicalize(r.body.record) + "\n");
    after = r.body.next;
    count++;
  }
  assert.equal(count, 130);
  assert.equal(hash.digest("hex"), digest);
});
test("action evidence exports escaped near-limit arguments and result without weakening validation", async () => {
  const f = await fixture(),
    p = (await propose(f, "large", { arguments: { value: '"'.repeat(30000) } }))
      .body.proposal;
  await command(f, "decide", p, "human", { decision: "approve" });
  const claim = (await command(f, "claim", p)).body;
  const result = { value: '"'.repeat(60000) };
  assert.equal(
    (
      await f.send({
        operation: "finish",
        session: p.action.session,
        id: p.action.id,
        claimId: claim.claimId,
        outcome: "succeeded",
        result,
      })
    ).status,
    200,
  );
  const head = (await f.send({ operation: "actionSnapshot" })).body,
    page = (await f.send({ operation: "actionPage", cut: head.cut, after: 0 }))
      .body;
  assert.ok(Buffer.byteLength(JSON.stringify(page)) > 300000);
  assert.ok(Buffer.byteLength(JSON.stringify(page)) < 491520);
  const { validateActionPage } = await import(
    "../services/organization/cloudflare/action-export.mjs"
  );
  validateActionPage(page, { cut: head.cut, after: 0 });
  for (const change of [
    (p) => p.record.row.version++,
    (p) => (p.record.row.digest = "0".repeat(64)),
    (p) => (p.record.history[3].sequence = head.cut + 1),
    (p) => (p.after = 1),
    (p) => p.next++,
    (p) => (p.record.extra = true),
  ]) {
    const copy = structuredClone(page);
    change(copy);
    assert.throws(() => validateActionPage(copy, { cut: head.cut, after: 0 }));
  }
  await corruptAudit(f, "DELETE FROM xeip_audit WHERE event='claimed'");
  assert.equal(
    (await f.send({ operation: "actionSnapshot" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await f.send({ operation: "actionPage", cut: head.cut, after: 0 })).body
      .error,
    "StoreUnavailable",
  );
});
