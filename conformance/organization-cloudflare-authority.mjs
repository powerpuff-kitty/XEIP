/** Real workerd/SQLite and JWT verifier with controlled issuer endpoints. */
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { fixture as providerFixture } from "../services/organization/test-fixtures/provider.mjs";
import {
  harness,
  identity,
  configuration,
  provisioning,
  command,
} from "./fixtures/cloudflare/authority-harness.mjs";
let runtime;
before(async () => {
  runtime = await harness();
});
after(async () => {
  await runtime?.close();
});
async function setup(t) {
  const provider = await providerFixture(t),
    actors = [identity("agent"), identity("human")],
    config = configuration(provider, actors),
    f = await runtime.fixture();
  const open = {
    operation: "open",
    gateway: actors[0].entity,
    initializeTrust: true,
    provisioning: provisioning(actors),
    configuration: config,
    secret: provider.config.introspectionClientSecret,
  };
  const token = () =>
    provider.token({
      sub: "agent",
      azp: "xeip-agent",
      resource_access: { "xeip-api": { roles: ["agent"] } },
    });
  return { provider, actors, config, f, open, token };
}
test("explicit authority initialization binds a real provider-authenticated subject to signed trust without persisting credentials", async (t) => {
  const { f, open, token, provider } = await setup(t);
  assert.equal((await f.send(open)).body.state, "ready");
  const bearer = await token(),
    auth = await f.send({
      operation: "authenticate",
      header: "Bearer " + bearer,
    });
  assert.equal(auth.body.principal?.subject, "agent", JSON.stringify(auth));
  assert.equal((await f.send({ operation: "revalidate" })).body.allowed, true);
  const persisted = JSON.stringify(
    (await f.sql("SELECT * FROM xeip_authority_state")).body,
  );
  assert.equal(persisted.includes(bearer), false);
  assert.equal(persisted.includes(open.secret), false);
  assert.equal(
    (await f.sql("SELECT revision FROM xeip_authority_events")).body.rows
      .length,
    1,
  );
  assert.equal(await runtime.publicStatus(), 404);
});
test("missing authority state cannot silently initialize on reopen", async (t) => {
  const { f, open } = await setup(t);
  delete open.configuration;
  assert.equal((await f.send(open)).body.error, "StoreUnavailable");
});
const authenticate = async (f, token, name = "principal") =>
  f.send({
    operation: "authenticate",
    header: "Bearer " + (await token()),
    name,
  });
const update = (f, config, revision = 0) =>
  f.send({
    operation: "update",
    configuration: config,
    expectedRevision: revision,
  });
for (const kind of ["inactive", "redirect", "outage"])
  test(`provider ${kind} cannot authenticate in workerd`, async (t) => {
    const { provider, f, open, token } = await setup(t);
    assert.equal((await f.send(open)).status, 200);
    if (kind === "inactive") provider.state.active = false;
    if (kind === "redirect") provider.state.jwksStatus = 302;
    if (kind === "outage") provider.state.introspectionStatus = 503;
    const r = await authenticate(f, token);
    if (kind === "inactive") assert.equal(r.body.principal, null);
    else assert.equal(r.body.error, "IdentityProviderUnavailable");
    if (kind === "redirect") assert.equal(provider.state.introspectionCalls, 0);
  });
test("cloned and released principals cannot revalidate", async (t) => {
  const { f, open, token } = await setup(t);
  await f.send(open);
  await authenticate(f, token);
  assert.equal(
    (await f.send({ operation: "revalidate", clone: true })).body.allowed,
    false,
  );
  assert.equal((await f.send({ operation: "revalidate" })).body.allowed, true);
  await f.send({ operation: "release" });
  assert.equal((await f.send({ operation: "revalidate" })).body.allowed, false);
});
test("policy and binding updates reject stale principals even when identical configuration is restored", async (t) => {
  const { f, open, token, config } = await setup(t);
  await f.send(open);
  await authenticate(f, token);
  assert.equal((await update(f, config)).body.revision, 1);
  assert.equal((await f.send({ operation: "revalidate" })).body.allowed, false);
  assert.equal((await authenticate(f, token)).body.principal.subject, "agent");
  const removed = structuredClone(config);
  removed.authentication.bindings = removed.authentication.bindings.filter(
    (b) => b.subject !== "agent",
  );
  assert.equal((await update(f, removed, 1)).body.revision, 2);
  assert.equal((await authenticate(f, token)).body.principal, null);
  assert.equal((await update(f, config, 2)).body.revision, 3);
  assert.equal((await f.send({ operation: "revalidate" })).body.allowed, false);
});
test("invalid secret-bearing or identity-domain replacements preserve usable authority; expected revision prevents lost updates", async (t) => {
  const { f, open, token, config } = await setup(t);
  await f.send(open);
  for (const patch of [
    { issuer: "https://other.invalid/realms/x" },
    { audience: "other" },
    { introspectionClientId: "other" },
    { introspectionClientSecret: "must-not-persist" },
  ]) {
    const candidate = structuredClone(config);
    Object.assign(candidate.authentication, patch);
    assert.equal((await update(f, candidate)).body.error, "PolicyDenied");
    assert.equal(
      (await authenticate(f, token)).body.principal.subject,
      "agent",
    );
  }
  assert.equal((await update(f, config, 99)).body.error, "StoreConflict");
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_authority_events")).body
      .rows[0].count,
    1,
  );
});
for (const fault of ["write", "sync"])
  test(`${fault} failure quarantines authority and reopen validates the committed revision`, async (t) => {
    const { f, open, config, token } = await setup(t);
    await f.send(open);
    await f.send({ operation: "controls", fault });
    assert.equal((await update(f, config)).body.error, "StoreUnavailable");
    assert.equal((await authenticate(f, token)).body.error, "StoreUnavailable");
    const restored = await f.send({
      operation: "open",
      gateway: open.gateway,
      secret: open.secret,
    });
    assert.equal(restored.body.revision, fault === "write" ? 0 : 1);
    assert.equal(
      (await authenticate(f, token)).body.principal.subject,
      "agent",
    );
  });
async function until(check) {
  for (let i = 0; i < 200; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw Error("condition timeout");
}
test("pending durable update gates authority, rejects concurrent updates and cannot reactivate after close", async (t) => {
  const { f, open, config, token } = await setup(t);
  await f.send(open);
  const before = (await f.send({ operation: "controls", holdSync: true })).body
    .syncEntered;
  const pending = update(f, config);
  await until(
    async () =>
      (await f.send({ operation: "controls" })).body.syncEntered > before,
  );
  assert.equal((await authenticate(f, token)).body.error, "StoreUnavailable");
  assert.equal((await update(f, config)).body.error, "StoreConflict");
  await f.send({ operation: "close" });
  await f.send({ operation: "controls", holdSync: false });
  assert.equal((await pending).body.error, "StoreUnavailable");
  assert.equal(
    (await f.send({ operation: "controls" })).body.authority.state,
    "closed",
  );
});
test("configuration update during provider authentication rejects its late principal", async (t) => {
  const { provider, f, open, config, token } = await setup(t);
  await f.send(open);
  let entered = false,
    release;
  const held = new Promise((r) => {
    release = r;
  });
  provider.state.beforeIntrospection = async () => {
    entered = true;
    await held;
  };
  const pending = authenticate(f, token);
  await until(() => entered);
  try {
    assert.equal((await update(f, config)).status, 200);
  } finally {
    release();
  }
  assert.equal((await pending).body.principal, null);
});
test("configuration update during provider revalidation rejects its late success", async (t) => {
  const { provider, f, open, config, token } = await setup(t);
  await f.send(open);
  await authenticate(f, token);
  let entered = false,
    release;
  const held = new Promise((r) => {
    release = r;
  });
  provider.state.beforeIntrospection = async () => {
    entered = true;
    await held;
  };
  const pending = f.send({ operation: "revalidate" });
  await until(() => entered);
  try {
    assert.equal((await update(f, config)).status, 200);
  } finally {
    release();
  }
  assert.equal((await pending).body.allowed, false);
});
test("authority SQL refuses replacement, event rewriting and revision rollback", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  await update(f, config);
  for (const sql of [
    "DELETE FROM xeip_authority_state",
    "DELETE FROM xeip_authority_events",
    "UPDATE xeip_authority_state SET revision=0",
    "UPDATE xeip_authority_events SET checksum=checksum",
    "INSERT OR REPLACE INTO xeip_authority_state SELECT * FROM xeip_authority_state",
    "INSERT OR REPLACE INTO xeip_authority_events SELECT * FROM xeip_authority_events",
  ])
    assert.notEqual((await f.sql(sql)).status, 200, sql);
});
test("corrupt snapshot checksum cannot reopen or reinitialize", async (t) => {
  const { f, open } = await setup(t);
  await f.send(open);
  await f.sql(
    "UPDATE xeip_authority_state SET revision=revision+1,checksum=?",
    "f".repeat(64),
  );
  assert.equal(
    (
      await f.send({
        operation: "open",
        gateway: open.gateway,
        secret: open.secret,
      })
    ).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (
      await f.send({
        operation: "open",
        gateway: open.gateway,
        secret: open.secret,
        configuration: open.configuration,
      })
    ).body.error,
    "StoreConflict",
  );
});
test("complete workerd restart retains updated bindings and rejects previous principal objects", async (t) => {
  const { f, open, config, token } = await setup(t);
  await f.send(open);
  await authenticate(f, token);
  const removed = structuredClone(config);
  removed.authentication.bindings = removed.authentication.bindings.filter(
    (b) => b.subject !== "agent",
  );
  await update(f, removed);
  await runtime.restart();
  const next = await runtime.fixture(f.name);
  assert.equal(
    (
      await next.send({
        operation: "open",
        gateway: open.gateway,
        secret: open.secret,
      })
    ).body.revision,
    1,
  );
  assert.equal((await authenticate(next, token)).body.principal, null);
  assert.equal(
    (await next.send({ operation: "revalidate" })).body.allowed,
    false,
  );
});

test("signed controller lifecycle uses live authority and produces one durable effect", async (t) => {
  const { f, open, token, provider, actors } = await setup(t);
  await f.send(open);
  const agentToken = await token(),
    humanToken = await provider.token({ sub: "human" });
  const send = (actor, bearer, operation, id, digest) =>
    f.send({
      operation: "controller",
      header: "Bearer " + bearer,
      envelope: command(actor, actors[0].entity, operation, id, digest),
    });
  const proposed = await send(actors[0], agentToken, "propose", "first");
  assert.equal(proposed.body.state, "pending", JSON.stringify(proposed));
  const digest = proposed.body.proposal.digest;
  assert.equal(
    (await send(actors[1], humanToken, "approve", "first", digest)).body.state,
    "approved",
  );
  assert.equal(
    (await send(actors[0], agentToken, "execute", "first", digest)).body.state,
    "succeeded",
  );
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
  assert.equal(
    (await send(actors[0], agentToken, "execute", "first", digest)).body.error,
    "OperationError",
  );
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
  assert.deepEqual(
    (
      await f.sql("SELECT event FROM xeip_audit ORDER BY sequence")
    ).body.rows.map((r) => r.event),
    ["proposed", "approved", "claimed", "succeeded"],
  );
});
async function approved(t) {
  const s = await setup(t);
  assert.equal((await s.f.send(s.open)).status, 200);
  const agentToken = await s.token(),
    humanToken = await s.provider.token({ sub: "human" });
  const send = (actor, bearer, operation, id = "race", digest) =>
    s.f.send({
      operation: "controller",
      header: "Bearer " + bearer,
      envelope: command(actor, s.actors[0].entity, operation, id, digest),
    });
  const proposal = await send(s.actors[0], agentToken, "propose");
  assert.equal(proposal.body.state, "pending", JSON.stringify(proposal));
  const digest = proposal.body.proposal.digest;
  assert.equal(
    (await send(s.actors[1], humanToken, "approve", "race", digest)).body.state,
    "approved",
  );
  return {
    ...s,
    digest,
    execute: () => send(s.actors[0], agentToken, "execute", "race", digest),
    send,
    agentToken,
  };
}
for (const phase of ["claim", "effect"])
  for (const change of ["policy", "binding", "trust", "provider"])
    test(`${change} changes during ${phase} stop the effect`, async (t) => {
      const s = await approved(t),
        { f, config, actors, provider } = s;
      const field = phase === "claim" ? "phaseEntered" : "effectEntered";
      const initial = (
        await f.send({
          operation: "controls",
          ...(phase === "claim"
            ? { holdPhase: "claim" }
            : { holdEffect: true }),
        })
      ).body[field];
      const pending = s.execute();
      await until(
        async () =>
          (await f.send({ operation: "controls" })).body[field] > initial,
      );
      try {
        if (change === "provider") provider.state.active = false;
        else if (change === "trust")
          assert.equal(
            (
              await f.send({
                operation: "trust-update",
                provisioning: provisioning(actors, 2, "human"),
              })
            ).status,
            200,
          );
        else {
          const next = structuredClone(config);
          if (change === "policy") next.policy.sessions[0].approvers = [];
          else
            next.authentication.bindings = next.authentication.bindings.filter(
              (b) => b.subject !== "human",
            );
          assert.equal((await update(f, next)).status, 200);
        }
      } finally {
        await f.send({
          operation: "controls",
          holdPhase: null,
          holdEffect: false,
        });
      }
      const result = await pending;
      if (phase === "claim")
        assert.equal(result.body.status, 403, JSON.stringify(result));
      else assert.equal(result.body.state, "failed", JSON.stringify(result));
      assert.equal((await f.send({ operation: "controls" })).body.effects, 0);
      assert.equal(
        (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
        phase === "claim" ? "approved" : "failed",
      );
    });
test("request guard denial prevents writes and new facades cannot escape shared ledger quarantine", async (t) => {
  const s = await setup(t);
  await s.f.send(s.open);
  const bearer = await s.token();
  const send = (id) =>
    s.f.send({
      operation: "controller",
      header: "Bearer " + bearer,
      envelope: command(s.actors[0], s.actors[0].entity, "propose", id),
    });
  await s.f.send({ operation: "controls", denyGuard: true });
  assert.equal((await send("denied")).body.status, 403);
  assert.equal(
    (await s.f.sql("SELECT COUNT(*) AS count FROM xeip_actions")).body.rows[0]
      .count,
    0,
  );
  await s.f.send({ operation: "controls", denyGuard: false, fault: "ledger" });
  assert.equal((await send("faulted")).body.status, 503);
  assert.equal((await send("new-facade")).body.status, 503);
  assert.equal(
    (await s.f.sql("SELECT COUNT(*) AS count FROM xeip_actions")).body.rows[0]
      .count,
    0,
  );
});
test("v2 upgrade preserves signed trust, a consumed claim and exact action audit history", async (t) => {
  const s = await approved(t);
  assert.equal((await s.execute()).body.state, "succeeded");
  const rows = async (table) =>
    (await s.f.sql("SELECT * FROM " + table)).body.rows;
  const trust = (await rows("xeip_trust_state"))[0],
    checkpoints = await rows("xeip_trust_checkpoints"),
    action = (await rows("xeip_actions"))[0],
    audit = await rows("xeip_audit");
  const target = await runtime.fixture();
  assert.equal(
    (
      await target.send({
        operation: "seed-v2",
        trust,
        checkpoints,
        action,
        audit,
      })
    ).status,
    200,
  );
  assert.equal(
    (await target.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    2,
  );
  assert.equal(
    (
      await target.send({
        operation: "open",
        gateway: s.open.gateway,
        secret: s.open.secret,
        configuration: s.config,
      })
    ).status,
    200,
  );
  assert.equal(
    (await target.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  assert.deepEqual(
    (await target.sql("SELECT * FROM xeip_trust_state")).body.rows,
    [trust],
  );
  assert.deepEqual(
    (await target.sql("SELECT * FROM xeip_trust_checkpoints")).body.rows,
    checkpoints,
  );
  assert.deepEqual((await target.sql("SELECT * FROM xeip_actions")).body.rows, [
    action,
  ]);
  assert.deepEqual(
    (await target.sql("SELECT * FROM xeip_audit")).body.rows,
    audit,
  );
});
test("timeout during configuration synchronization never activates a late candidate", async (t) => {
  const { f, open, config, token } = await setup(t);
  open.timeoutMs = 100;
  await f.send(open);
  await f.send({ operation: "controls", holdSync: true });
  assert.equal((await update(f, config)).body.error, "StoreUnavailable");
  await f.send({ operation: "controls", holdSync: false });
  assert.equal((await authenticate(f, token)).body.error, "StoreUnavailable");
});

test("recording an already sent result remains possible after authority revocation", async (t) => {
  const s = await approved(t),
    { f, config } = s;
  await f.send({ operation: "controls", holdAfterEffect: true });
  let settled = false;
  const pending = s.execute().then((r) => {
    settled = true;
    return r;
  });
  await until(
    async () => (await f.send({ operation: "controls" })).body.effects === 1,
  );
  assert.equal(
    settled,
    false,
    "result must remain pending until after revocation",
  );
  const next = structuredClone(config);
  next.policy.sessions[0].agents = [];
  try {
    assert.equal((await update(f, next)).status, 200);
  } finally {
    await f.send({ operation: "controls", holdAfterEffect: false });
  }
  assert.equal((await pending).body.state, "succeeded");
  assert.equal(
    (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
    "succeeded",
  );
});
test("release during remote revalidation prevents late provider success", async (t) => {
  const { provider, f, open, token } = await setup(t);
  await f.send(open);
  await authenticate(f, token);
  let entered = false,
    release;
  const held = new Promise((r) => {
    release = r;
  });
  provider.state.beforeIntrospection = async () => {
    entered = true;
    await held;
  };
  const pending = f.send({ operation: "revalidate" });
  await until(() => entered);
  await f.send({ operation: "release" });
  release();
  assert.equal((await pending).body.allowed, false);
});
test("tampered signed request and mismatched provider identity produce no action", async (t) => {
  const { f, open, token, provider, actors } = await setup(t);
  await f.send(open);
  const signed = command(actors[0], actors[0].entity, "propose", "tampered"),
    edited = JSON.parse(signed);
  edited.body.data.request.arguments.value = "changed";
  for (const [bearer, envelope] of [
    [await token(), JSON.stringify(edited)],
    [await provider.token({ sub: "human" }), signed],
  ])
    assert.equal(
      (
        await f.send({
          operation: "controller",
          header: "Bearer " + bearer,
          envelope,
        })
      ).body.status,
      403,
    );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_actions")).body.rows[0]
      .count,
    0,
  );
});

test("historical authority-event corruption prevents both reopen and further updates", async (t) => {
  for (const operation of ["open", "update"]) {
    const { f, open, config } = await setup(t);
    await f.send(open);
    await update(f, config);
    const trigger = (
      await f.sql(
        "SELECT sql FROM sqlite_master WHERE name='xeip_authority_event_update'",
      )
    ).body.rows[0].sql;
    await f.sql("DROP TRIGGER xeip_authority_event_update");
    await f.sql(
      "UPDATE xeip_authority_events SET checksum=? WHERE revision=0",
      "0".repeat(64),
    );
    await f.sql(trigger);
    const result =
      operation === "open"
        ? await f.send({
            operation: "open",
            gateway: open.gateway,
            secret: open.secret,
          })
        : await update(f, config, 1);
    assert.equal(result.body.error, "StoreUnavailable", JSON.stringify(result));
  }
});
test("fresh signed actions remain executable after a legitimate target policy update", async (t) => {
  const { f, open, token, provider, actors, config } = await setup(t);
  await f.send(open);
  const next = structuredClone(config);
  next.policy.targets[0].revision = "2";
  assert.equal((await update(f, next)).status, 200);
  const agentToken = await token(),
    humanToken = await provider.token({ sub: "human" });
  const send = (actor, bearer, operation, digest) =>
    f.send({
      operation: "controller",
      header: "Bearer " + bearer,
      envelope: command(actor, actors[0].entity, operation, "updated", digest),
    });
  const proposed = await send(actors[0], agentToken, "propose");
  assert.equal(proposed.body.state, "pending");
  assert.equal(proposed.body.proposal.action.target.revision, "2");
  const digest = proposed.body.proposal.digest;
  assert.equal(
    (await send(actors[1], humanToken, "approve", digest)).body.state,
    "approved",
  );
  assert.equal(
    (await send(actors[0], agentToken, "execute", digest)).body.state,
    "succeeded",
  );
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
});

test("configuration history validates across SQL batches and detects later-page corruption", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  const advanced = await f.send({
    operation: "batch-update",
    count: 257,
    configuration: config,
  });
  assert.equal(advanced.body.revision, 257, JSON.stringify(advanced));
  assert.equal(
    (
      await f.send({
        operation: "open",
        gateway: open.gateway,
        secret: open.secret,
      })
    ).body.revision,
    257,
  );
  const capture = await checkpoint(f);
  assert.equal(capture.status, 200);
  const verifier = new AuthorityHistoryVerifier(
    capture.body,
    "authority-fixture",
    { limit: 256 },
  );
  const firstPage = await history(f, capture.body, verifier.cursor());
  assert.equal(firstPage.status, 200);
  assert.equal(firstPage.body.records.length, 256);
  verifier.accept(firstPage.body);
  assert.equal(verifier.complete(), false);
  const lastPage = await history(f, capture.body, verifier.cursor());
  assert.equal(lastPage.status, 200);
  assert.equal(lastPage.body.records.length, 2);
  verifier.accept(lastPage.body);
  assert.equal(verifier.finish().revision, 257);
  const trigger = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_authority_event_update'",
    )
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_authority_event_update");
  await f.sql(
    "UPDATE xeip_authority_events SET checksum=? WHERE revision=256",
    "0".repeat(64),
  );
  await f.sql(trigger);
  assert.equal(
    (
      await f.send({
        operation: "open",
        gateway: open.gateway,
        secret: open.secret,
      })
    ).body.error,
    "StoreUnavailable",
  );
});

import { createHash } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import {
  validateAuthorityCheckpoint,
  AuthorityHistoryVerifier,
} from "../services/organization/cloudflare/authority-checkpoint.mjs";
const zeroChecksum = "0".repeat(64);
const checkpoint = (f) => f.send({ operation: "checkpoint" });
const history = (f, c, cursor) =>
  f.send({ operation: "history-page", checkpoint: c, cursor });
function sealAuthority(c) {
  const { digest, ...body } = c;
  c.digest = createHash("sha256")
    .update("XEIP authority checkpoint v1\n" + canonicalize(body))
    .digest("hex");
  return c;
}
function initialCheckpoint(config) {
  const configurationDigest = createHash("sha256")
    .update(canonicalize(config))
    .digest("hex");
  const checksum = createHash("sha256")
    .update(
      "XEIP durable authority history v1\n" +
        canonicalize({
          revision: 0,
          configurationDigest,
          previousChecksum: zeroChecksum,
        }),
    )
    .digest("hex");
  return sealAuthority({
    schema: "xeip.authority-checkpoint/1",
    organization: "authority-fixture",
    configuration: structuredClone(config),
    revision: 0,
    previousChecksum: zeroChecksum,
    checksum,
  });
}
test("authority recovery checkpoint validates isolated public configuration and rejects secret or scope changes", async (t) => {
  const { config } = await setup(t),
    c = initialCheckpoint(config);
  const verified = validateAuthorityCheckpoint(c, "authority-fixture");
  c.configuration.authentication.clientIds.push("changed");
  assert.deepEqual(
    verified.configuration.authentication.clientIds,
    config.authentication.clientIds,
  );
  for (const mutate of [
    (c) => (c.organization = "other"),
    (c) =>
      (c.configuration.authentication.introspectionClientSecret =
        "must-not-export"),
    (c) => (c.previousChecksum = "a".repeat(64)),
    (c) => (c.configuration.policy.sessions = []),
    (c) => (c.revision = -1),
    (c) => (c.extra = true),
  ]) {
    const candidate = initialCheckpoint(config);
    mutate(candidate);
    sealAuthority(candidate);
    assert.throws(
      () => validateAuthorityCheckpoint(candidate, "authority-fixture"),
      TypeError,
    );
  }
  const secretConfig = structuredClone(config);
  secretConfig.authentication.introspectionClientSecret = "must-not-export";
  const rehashedSecret = initialCheckpoint(secretConfig);
  assert.throws(
    () => validateAuthorityCheckpoint(rehashedSecret, "authority-fixture"),
    TypeError,
  );
  const relabeled = initialCheckpoint(config);
  relabeled.organization = "other";
  assert.throws(
    () => validateAuthorityCheckpoint(relabeled, "other"),
    TypeError,
  );
});
test("authority recovery checkpoint captures every revision across bounded pages without exporting secrets or changing rows", async (t) => {
  const { f, open, config, provider } = await setup(t);
  assert.equal((await f.send(open)).status, 200);
  for (let revision = 0; revision < 4; revision++) {
    const changed = structuredClone(config);
    changed.authentication.clientIds.push("additional-" + revision);
    assert.equal((await update(f, changed, revision)).status, 200);
  }
  const before = (await f.sql("SELECT * FROM xeip_authority_state")).body.rows;
  const events = (
    await f.sql("SELECT * FROM xeip_authority_events ORDER BY revision")
  ).body.rows;
  const response = await checkpoint(f);
  assert.equal(response.status, 200);
  const c = validateAuthorityCheckpoint(response.body, "authority-fixture");
  assert.equal(c.revision, 4);
  assert.equal(c.checksum, before[0].checksum);
  assert.equal(canonicalize(c.configuration), before[0].configuration);
  assert.equal(JSON.stringify(c).includes(open.secret), false);
  const verifier = new AuthorityHistoryVerifier(c, "authority-fixture", {
    limit: 2,
  });
  assert.throws(() => verifier.finish(), TypeError);
  const all = [];
  while (!verifier.complete()) {
    const result = await history(f, c, verifier.cursor());
    assert.equal(result.status, 200);
    verifier.accept(result.body);
    all.push(...result.body.records);
  }
  assert.deepEqual(
    all.map((e) => ({
      revision: e.revision,
      configuration_digest: e.configurationDigest,
      previous_checksum: e.previousChecksum,
      checksum: e.checksum,
    })),
    events,
  );
  assert.equal(verifier.finish().digest, c.digest);
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_authority_state")).body.rows,
    before,
  );
  assert.equal(provider.state.introspectionCalls, 0);
});
test("authority recovery checkpoint detects skipped, reordered, truncated, forked and mismatched pages", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  await update(f, config);
  await update(f, config, 1);
  const c = (await checkpoint(f)).body;
  const cursor = { after: -1, previousChecksum: zeroChecksum, limit: 2 };
  const page = (await history(f, c, cursor)).body;
  for (const mutate of [
    (p) => p.records.shift(),
    (p) => p.records.reverse(),
    (p) => (p.records[1].previousChecksum = "a".repeat(64)),
    (p) => (p.records[0].configurationDigest = "b".repeat(64)),
    (p) => (p.complete = true),
    (p) => (p.next = 2),
    (p) => (p.checkpointDigest = "c".repeat(64)),
    (p) => (p.extra = true),
  ]) {
    const verifier = new AuthorityHistoryVerifier(c, "authority-fixture", {
      limit: 2,
    });
    const bad = structuredClone(page);
    mutate(bad);
    assert.throws(() => verifier.accept(bad), TypeError);
    assert.equal(verifier.cursor().after, -1);
    verifier.accept(page);
    assert.equal(verifier.complete(), false);
    assert.throws(() => verifier.finish(), TypeError);
    assert.throws(() => verifier.accept(page), TypeError);
    const last = (await history(f, c, verifier.cursor())).body;
    verifier.accept(last);
    assert.equal(verifier.complete(), true);
    assert.throws(() => verifier.accept(last), TypeError);
  }
});
test("authority recovery checkpoint conflicts after a legitimate update without quarantining current authority", async (t) => {
  const { f, open, config, token } = await setup(t);
  await f.send(open);
  const c = (await checkpoint(f)).body;
  await update(f, config);
  assert.equal(
    (
      await history(f, c, {
        after: -1,
        previousChecksum: zeroChecksum,
        limit: 2,
      })
    ).body.error,
    "StoreConflict",
  );
  assert.equal((await authenticate(f, token)).body.principal.subject, "agent");
  assert.equal((await checkpoint(f)).body.revision, 1);
});
test("authority recovery checkpoint refuses invalid cursors without damaging active authority", async (t) => {
  const { f, open, token } = await setup(t);
  await f.send(open);
  const captured = await checkpoint(f);
  assert.equal(captured.status, 200);
  const c = captured.body;
  for (const cursor of [
    { after: null, previousChecksum: zeroChecksum, limit: 1 },
    { after: -1, previousChecksum: null, limit: 1 },
    { after: -1, previousChecksum: zeroChecksum, limit: null },
    { after: -2, previousChecksum: zeroChecksum, limit: 1 },
    { after: -1, previousChecksum: zeroChecksum, limit: 257 },
    { after: 1, previousChecksum: zeroChecksum, limit: 1 },
    { after: -1, previousChecksum: "a".repeat(64), limit: 1 },
    { after: -1, previousChecksum: zeroChecksum, limit: 0 },
  ])
    assert.equal((await history(f, c, cursor)).body.error, "TypeError");
  assert.equal((await authenticate(f, token)).body.principal.subject, "agent");
});
test("authority recovery checkpoint refuses capture while synchronization is pending and after closure", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  const c = (await checkpoint(f)).body;
  const before = (await f.send({ operation: "controls", holdSync: true })).body
    .syncEntered;
  const pending = update(f, config);
  try {
    await until(
      async () =>
        (await f.send({ operation: "controls" })).body.syncEntered > before,
    );
    assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
    assert.equal((await history(f, c)).body.error, "StoreUnavailable");
  } finally {
    await f.send({ operation: "controls", holdSync: false });
    await pending;
  }
  assert.equal((await checkpoint(f)).status, 200);
  await f.send({ operation: "close" });
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
});
for (const operation of ["checkpoint", "capture-reader"])
  test(`authority ${operation} quarantines altered schema and corrupt historical events`, async (t) => {
    for (const kind of ["schema", "history"]) {
      const { f, open, token } = await setup(t);
      await f.send(open);
      if (kind === "schema") {
        assert.equal(
          (await f.sql("DROP TRIGGER xeip_authority_event_delete")).status,
          200,
        );
      } else {
        const trigger = (
          await f.sql(
            "SELECT sql FROM sqlite_master WHERE name='xeip_authority_event_update'",
          )
        ).body.rows[0].sql;
        assert.equal(
          (await f.sql("DROP TRIGGER xeip_authority_event_update")).status,
          200,
        );
        assert.equal(
          (
            await f.sql(
              "UPDATE xeip_authority_events SET checksum=? WHERE revision=0",
              "a".repeat(64),
            )
          ).status,
          200,
        );
        assert.equal((await f.sql(trigger)).status, 200);
      }
      assert.equal(
        (await f.send({ operation })).body.error,
        "StoreUnavailable",
      );
      assert.equal(
        (await authenticate(f, token)).body.error,
        "StoreUnavailable",
      );
    }
  });
test("authority recovery checkpoint rejects a valid persisted head not accepted by its live instance", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  const current = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: current })).status,
    200,
  );
  const configurationDigest = createHash("sha256")
    .update(canonicalize(config))
    .digest("hex");
  const nextChecksum = createHash("sha256")
    .update(
      "XEIP durable authority history v1\n" +
        canonicalize({
          revision: 1,
          configurationDigest,
          previousChecksum: current.checksum,
        }),
    )
    .digest("hex");
  assert.equal(
    (
      await f.sql(
        "UPDATE xeip_authority_state SET revision=1,checksum=?",
        nextChecksum,
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_authority_events VALUES (1,?,?,?)",
        configurationDigest,
        current.checksum,
        nextChecksum,
      )
    ).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
  const reopened = await f.send({
    operation: "open",
    gateway: open.gateway,
    secret: open.secret,
  });
  assert.equal(reopened.body.revision, 1);
  assert.equal((await checkpoint(f)).body.checksum, nextChecksum);
});

test("fixed-cut export retains captured authority pages after later configuration updates", async (t) => {
  const { f, open, config } = await setup(t);
  assert.equal((await f.send(open)).status, 200);
  const changed = structuredClone(config);
  changed.authentication.clientIds.push("captured-client");
  assert.equal((await update(f, changed, 0)).body.revision, 1);
  const captured = (await checkpoint(f)).body;
  const expectedRows = (
    await f.sql(
      "SELECT revision,configuration_digest,previous_checksum,checksum FROM xeip_authority_events ORDER BY revision",
    )
  ).body.rows;
  assert.equal((await update(f, config, 1)).body.revision, 2);
  const current = (await checkpoint(f)).body;
  assert.equal((await history(f, captured)).body.error, "StoreConflict");
  const first = await f.send({
    operation: "history-page-at",
    checkpoint: captured,
    cursor: { limit: 1 },
  });
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.checkpointDigest, captured.digest);
  assert.equal(first.body.complete, false);
  assert.equal(first.body.next, 0);
  assert.deepEqual(first.body.records, [
    {
      revision: 0,
      configurationDigest: expectedRows[0].configuration_digest,
      previousChecksum: expectedRows[0].previous_checksum,
      checksum: expectedRows[0].checksum,
    },
  ]);
  const last = await f.send({
    operation: "history-page-at",
    checkpoint: captured,
    cursor: {
      after: 0,
      previousChecksum: first.body.records[0].checksum,
      limit: 128,
    },
  });
  assert.equal(last.status, 200, JSON.stringify(last.body));
  assert.equal(last.body.complete, true);
  assert.equal(last.body.next, 1);
  assert.deepEqual(last.body.records, [
    {
      revision: 1,
      configurationDigest: expectedRows[1].configuration_digest,
      previousChecksum: expectedRows[1].previous_checksum,
      checksum: expectedRows[1].checksum,
    },
  ]);
  assert.deepEqual((await checkpoint(f)).body, current);
});

test("fixed-cut export rejects an unrelated valid authority checkpoint without quarantining the source", async (t) => {
  const { f, open, config } = await setup(t);
  assert.equal((await f.send(open)).status, 200);
  const current = (await checkpoint(f)).body;
  const other = structuredClone(config);
  other.authentication.clientIds.push("unrelated-history");
  const forged = initialCheckpoint(other);
  assert.doesNotThrow(() =>
    validateAuthorityCheckpoint(forged, "authority-fixture"),
  );
  const response = await f.send({
    operation: "history-page-at",
    checkpoint: forged,
  });
  assert.equal(response.body.error, "StoreConflict");
  assert.deepEqual((await checkpoint(f)).body, current);
  assert.equal((await update(f, config, 0)).body.revision, 1);
});

test("fixed-cut export quarantines corrupted retained authority history before returning a page", async (t) => {
  const { f, open, config } = await setup(t);
  assert.equal((await f.send(open)).status, 200);
  const captured = (await checkpoint(f)).body;
  assert.equal((await update(f, config, 0)).body.revision, 1);
  const trigger = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_authority_event_update'",
    )
  ).body.rows[0].sql;
  assert.equal(
    (await f.sql("DROP TRIGGER xeip_authority_event_update")).status,
    200,
  );
  assert.equal(
    (
      await f.sql(
        "UPDATE xeip_authority_events SET checksum=? WHERE revision=0",
        "a".repeat(64),
      )
    ).status,
    200,
  );
  assert.equal((await f.sql(trigger)).status, 200);
  const response = await f.send({
    operation: "history-page-at",
    checkpoint: captured,
  });
  assert.equal(response.body.error, "StoreUnavailable");
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
});

test("scoped authority reader exports retained revisions with linear history row work", async (t) => {
  const { f, open, config } = await setup(t);
  assert.equal((await f.send(open)).status, 200);
  assert.equal(
    (
      await f.send({
        operation: "batch-update",
        configuration: config,
        count: 129,
      })
    ).body.revision,
    129,
  );
  const captured = (await checkpoint(f)).body;
  const expected = (
    await f.sql(
      "SELECT revision,configuration_digest,previous_checksum,checksum FROM xeip_authority_events ORDER BY revision",
    )
  ).body.rows;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: captured }))
      .status,
    200,
  );
  await f.send({ operation: "controls", historyRows: 0 });
  let after = -1,
    previousChecksum = "0".repeat(64),
    pages = 0;
  const records = [];
  do {
    const result = await f.send({
      operation: "reader-page",
      cursor: { after, previousChecksum, limit: 16 },
    });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    records.push(...result.body.records);
    after = result.body.next;
    previousChecksum = result.body.records.at(-1).checksum;
    pages++;
    assert.equal(result.body.complete, after === 129);
  } while (after < 129);
  assert.deepEqual(
    records,
    expected.map((row) => ({
      revision: row.revision,
      configurationDigest: row.configuration_digest,
      previousChecksum: row.previous_checksum,
      checksum: row.checksum,
    })),
  );
  const cost = (await f.send({ operation: "controls" })).body.historyRows;
  assert.ok(
    cost <= 130 + 4 * pages,
    `read ${cost} historical rows for ${records.length} exported revisions`,
  );
});

test("scoped authority reader preserves its cut after policy updates and closes without disabling live authority", async (t) => {
  const { f, open, config, token } = await setup(t);
  await f.send(open);
  await update(f, config, 0);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: captured }))
      .status,
    200,
  );
  const first = await f.send({
    operation: "reader-page",
    cursor: { limit: 1 },
  });
  assert.equal(first.status, 200);
  const next = structuredClone(config);
  next.authentication.clientIds.push("later-client");
  assert.equal((await update(f, next, 1)).body.revision, 2);
  const last = await f.send({
    operation: "reader-page",
    cursor: {
      after: 0,
      previousChecksum: first.body.records[0].checksum,
      limit: 128,
    },
  });
  assert.equal(last.status, 200);
  assert.equal(last.body.records.length, 1);
  assert.equal(last.body.next, 1);
  assert.equal(last.body.complete, true);
  assert.equal(last.body.records[0].checksum, captured.checksum);
  await f.send({ operation: "reader-close" });
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
  assert.equal((await authenticate(f, token)).body.principal.subject, "agent");
});

test("scoped authority reader quarantines corruption in an unread revision", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  await update(f, config, 0);
  await update(f, config, 1);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: captured }))
      .status,
    200,
  );
  const first = await f.send({
    operation: "reader-page",
    cursor: { limit: 1 },
  });
  assert.equal(first.status, 200);
  const trigger = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_authority_event_update'",
    )
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_authority_event_update");
  await f.sql(
    "UPDATE xeip_authority_events SET checksum=? WHERE revision=1",
    "a".repeat(64),
  );
  await f.sql(trigger);
  const bad = await f.send({
    operation: "reader-page",
    cursor: {
      after: 0,
      previousChecksum: first.body.records[0].checksum,
      limit: 128,
    },
  });
  assert.equal(bad.body.error, "StoreUnavailable");
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
});

test("scoped authority reader refuses malformed cursors without damaging current policy", async (t) => {
  const { f, open, config, token } = await setup(t);
  await f.send(open);
  await update(f, config, 0);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: captured }))
      .status,
    200,
  );
  for (const cursor of [
    null,
    { after: -2 },
    { after: 0, previousChecksum: "a".repeat(64) },
  ])
    assert.equal(
      (await f.send({ operation: "reader-page", cursor })).body.error,
      "TypeError",
    );
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.complete,
    true,
  );
  assert.equal((await authenticate(f, token)).body.principal.subject, "agent");
});

test("scoped authority reader cannot revive after its owning authority is closed and replaced", async (t) => {
  const { f, open } = await setup(t);
  await f.send(open);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: captured }))
      .status,
    200,
  );
  await f.send({ operation: "close" });
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (
      await f.send({
        operation: "open",
        gateway: open.gateway,
        secret: open.secret,
      })
    ).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
});

test("scoped authority reader quarantines a changed previously verified captured anchor", async (t) => {
  const { f, open, config } = await setup(t);
  await f.send(open);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "history-reader", checkpoint: captured }))
      .status,
    200,
  );
  await update(f, config, 0);
  const trigger = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_authority_event_update'",
    )
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_authority_event_update");
  await f.sql(
    "UPDATE xeip_authority_events SET checksum=? WHERE revision=0",
    "a".repeat(64),
  );
  await f.sql(trigger);
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
});

test("authority capture creates a fixed-cut reader with one full history scan", async (t) => {
  const { f, open, config } = await setup(t);
  assert.equal((await f.send(open)).status, 200);
  assert.equal(
    (
      await f.send({
        operation: "batch-update",
        configuration: config,
        count: 129,
      })
    ).body.revision,
    129,
  );
  await f.send({ operation: "controls", historyRows: 0 });
  const captured = await f.send({ operation: "capture-reader" });
  assert.equal(captured.status, 200, JSON.stringify(captured.body));
  const cost = (await f.send({ operation: "controls" })).body.historyRows;
  assert.ok(
    cost >= 130 && cost <= 134,
    `read ${cost} rows for one complete capture`,
  );
  assert.equal(captured.body.revision, 129);
  await update(f, config, 129);
  const last = await f.send({
    operation: "reader-page",
    cursor: {
      after: 128,
      previousChecksum: captured.body.previousChecksum,
      limit: 16,
    },
  });
  assert.equal(last.status, 200, JSON.stringify(last.body));
  assert.equal(last.body.complete, true);
  assert.equal(last.body.next, 129);
  assert.equal(last.body.checkpointDigest, captured.body.digest);
  await f.send({ operation: "reader-close" });
  assert.equal(
    (await f.send({ operation: "reader-page" })).body.error,
    "StoreUnavailable",
  );
});
