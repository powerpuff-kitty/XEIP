/** Local real SQLite/signed-trust conformance. No cloud resources or real effects. */
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
    name: "xeip-trust-conformance",
    host: "127.0.0.1",
    port: 0,
    modules: true,
    modulesRoot: directory,
    scriptPath,
    compatibilityDate: "2026-07-30",
    compatibilityFlags: ["nodejs_compat"],
    durableObjects: { TRUST: { className: "TrustFixture", useSQLite: true } },
    durableObjectsPersist: join(directory, "storage"),
  });
  await mf.ready;
}
before(async () => {
  directory = await mkdtemp(join(tmpdir(), "xeip-cloudflare-trust-"));
  scriptPath = join(directory, "worker.mjs");
  await build({
    entryPoints: [
      new URL("./organization-cloudflare-trust-worker.mjs", import.meta.url)
        .pathname,
    ],
    outfile: scriptPath,
    bundle: true,
    format: "esm",
    platform: "neutral",
    external: ["cloudflare:workers", "node:*"],
    logLevel: "silent",
  });
  await start();
});
after(async () => {
  await mf?.dispose();
  if (directory) await rm(directory, { recursive: true, force: true });
});
async function fixture(name = "case-" + ++sequence) {
  const namespace = await mf.getDurableObjectNamespace("TRUST"),
    stub = namespace.get(namespace.idFromName(name));
  const send = async (input) => {
    const r = await stub.fetch("https://fixture.invalid/", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return { status: r.status, body: await r.json() };
  };
  return {
    name,
    send,
    sql: (query, ...bindings) => send({ operation: "sql", query, bindings }),
  };
}
test("checked version-1 upgrade preserves the consumed action and exact audit history", async () => {
  const f = await fixture(),
    seed = await f.send({ operation: "initialize-v1" });
  assert.equal(seed.status, 200);
  const actions = (await f.sql("SELECT * FROM xeip_actions")).body.rows,
    audit = (await f.sql("SELECT * FROM xeip_audit ORDER BY sequence")).body
      .rows;
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    1,
  );
  assert.equal((await f.send({ operation: "initialize" })).status, 200);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_actions")).body.rows,
    actions,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_audit ORDER BY sequence")).body.rows,
    audit,
  );
  assert.equal(
    (
      await f.sql(
        "UPDATE xeip_actions SET state='approved',version=version+1,claim_id=NULL",
      )
    ).status,
    409,
  );
  assert.equal((await f.send({ operation: "initialize" })).status, 200);
});
test("migration refuses altered version-1 schema and does not add trust tables", async () => {
  const f = await fixture();
  assert.equal((await f.send({ operation: "initialize-v1" })).status, 200);
  await f.sql("DROP TRIGGER xeip_action_new");
  assert.equal(
    (await f.send({ operation: "initialize" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (
      await f.sql(
        "SELECT name FROM sqlite_master WHERE name='xeip_trust_state'",
      )
    ).body.rows.length,
    0,
  );
});
test("fresh schema includes guarded trust state and retained checkpoints", async () => {
  const f = await fixture();
  assert.equal((await f.send({ operation: "initialize" })).status, 200);
  const names = (
    await f.sql(
      "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'xeip_trust_%' ORDER BY name",
    )
  ).body.rows.map((r) => r.name);
  assert.deepEqual(names, [
    "xeip_trust_checkpoints",
    "xeip_trust_chunks",
    "xeip_trust_state",
  ]);
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_trust_checkpoints(entity,anchor,generation,key_digest,serial,status_digest) VALUES (?,?,1,?,1,?)",
        "entity",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
      )
    ).status,
    200,
  );
  for (const query of [
    "DELETE FROM xeip_trust_checkpoints",
    "UPDATE xeip_trust_checkpoints SET generation=0",
    "UPDATE xeip_trust_checkpoints SET serial=0",
    "UPDATE xeip_trust_checkpoints SET anchor='" + "d".repeat(64) + "'",
    "UPDATE xeip_trust_checkpoints SET key_digest='" + "d".repeat(64) + "'",
    "UPDATE xeip_trust_checkpoints SET status_digest='" + "d".repeat(64) + "'",
    "INSERT OR REPLACE INTO xeip_trust_checkpoints SELECT * FROM xeip_trust_checkpoints",
  ])
    assert.equal((await f.sql(query)).status, 409, query);
});
test("trust fixture has no public Worker ingress", async () =>
  assert.equal(
    (await mf.dispatchFetch("https://fixture.invalid/")).status,
    404,
  ));
test("trust state rejects replacement, deletion, configuration drift and nonmonotonic updates", async () => {
  const f = await fixture();
  await f.send({ operation: "initialize" });
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_trust_state VALUES (1,?,?,0,10,?,?)",
        '{"maxAgeSeconds":60}',
        '{"keyDocuments":[],"statusDocuments":[]}',
        "a".repeat(64),
        "b".repeat(64),
      )
    ).status,
    200,
  );
  for (const query of [
    "INSERT OR REPLACE INTO xeip_trust_state SELECT * FROM xeip_trust_state",
    "DELETE FROM xeip_trust_state",
    "UPDATE xeip_trust_state SET revision=1,configuration='{}'",
    "UPDATE xeip_trust_state SET revision=1,accepted_at=9",
    "UPDATE xeip_trust_state SET revision=2",
  ])
    assert.equal((await f.sql(query)).status, 409, query);
  assert.equal(
    (await f.sql("UPDATE xeip_trust_state SET revision=1,accepted_at=11"))
      .status,
    200,
  );
  await f.sql("DROP TRIGGER xeip_trust_state_insert");
  assert.equal(
    (await f.send({ operation: "initialize" })).body.error,
    "StoreUnavailable",
  );
});
test("a migration persistence failure rolls back new tables and preserves version-1 history", async () => {
  const f = await fixture();
  await f.send({ operation: "initialize-v1" });
  const before = (await f.sql("SELECT * FROM xeip_actions")).body.rows;
  assert.equal(
    (await f.send({ operation: "initialize", failMigration: true })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    1,
  );
  assert.equal(
    (
      await f.sql(
        "SELECT name FROM sqlite_master WHERE name LIKE 'xeip_trust_%'",
      )
    ).body.rows.length,
    0,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_actions")).body.rows,
    before,
  );
  assert.equal((await f.send({ operation: "initialize" })).status, 200);
});

import { readFileSync } from "node:fs";
import { signStatusDocument } from "../tools/identity-status.mjs";
import { signEntityEnvelope } from "../packages/identity/entity-envelope.mjs";
import { keyDocumentChainDigest } from "../tools/key-document.mjs";
const vectors = JSON.parse(
  readFileSync(
    new URL("./fixtures/entity-envelope/vectors.json", import.meta.url),
  ),
);
const base = vectors.vectors[0].options;
const rootSeed = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const now = () => Math.floor(Date.now() / 1000);
const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
const configuration = { maxAgeSeconds: 60, knownExtensions: ["app.action"] };
const principal = { entity: vectors.envelope.sender, kid: vectors.kid };
function provisioning(serial = 1, revoked = [], issuedAt = utc(now())) {
  return {
    keyDocuments: base.keyDocuments.map((document) => ({
      document: structuredClone(document),
      anchor: structuredClone(base.anchor),
    })),
    statusDocuments: [
      {
        document: signStatusDocument(
          { ...base.statusDocument, serial, revoked, issuedAt, signatures: [] },
          { privateKey: rootSeed, kid: base.keyDocuments[0].genesis },
        ),
      },
    ],
  };
}
const open = (f, initialize = true, config = configuration) =>
  f.send({ operation: "trust-open", initialize, configuration: config });
const update = (f, p) => f.send({ operation: "trust-update", provisioning: p });
const allows = (f) => f.send({ operation: "trust-allows", principal });
test("trust requires explicit initialization and an existing valid snapshot on reopen", async () => {
  const f = await fixture();
  assert.equal((await open(f, false)).body.error, "StoreUnavailable");
  const fresh = await open(f);
  assert.equal(fresh.status, 200);
  assert.equal(fresh.body.state, "empty");
  assert.equal(fresh.body.revision, 0);
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal((await open(f, true)).body.error, "StoreConflict");
  assert.equal((await open(f, false)).body.state, "empty");
  assert.equal(
    (await open(f, false, { ...configuration, maxAgeSeconds: 120 })).body.error,
    "StoreUnavailable",
  );
});
test("durable trust uses actual signatures, exact key membership and critical extensions", async () => {
  const f = await fixture();
  assert.equal((await open(f)).status, 200);
  const p = provisioning();
  assert.equal((await update(f, p)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
  assert.equal(
    (await f.send({ operation: "trust-verify", envelope: vectors.signed })).body
      .valid,
    true,
  );
  const unknown = signEntityEnvelope(
    {
      ...vectors.envelope,
      extensions: { ...vectors.envelope.extensions, "app.unknown": true },
    },
    {
      privateKey: Buffer.from(vectors.seed, "hex"),
      kid: vectors.kid,
      criticalExtensions: ["app.unknown"],
    },
  );
  assert.equal(
    (await f.send({ operation: "trust-verify", envelope: unknown })).body.valid,
    false,
  );
  const edited = structuredClone(vectors.signed);
  edited.body = { ...edited.body, changed: true };
  assert.equal(
    (await f.send({ operation: "trust-verify", envelope: edited })).body.valid,
    false,
  );
  assert.equal(
    (
      await f.send({
        operation: "trust-allows",
        principal: { ...principal, entity: "urn:xeip:entity:unknown" },
      })
    ).body.allowed,
    false,
  );
  assert.equal(
    (await update(f, provisioning(2, [{ kid: vectors.kid, generation: 1 }])))
      .status,
    200,
  );
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal(
    (await f.send({ operation: "trust-verify", envelope: vectors.signed })).body
      .valid,
    false,
  );
});
test("invalid signatures and rollback/fork updates leave prior authority unchanged", async () => {
  const f = await fixture();
  await open(f);
  const p = provisioning(2);
  assert.equal((await update(f, p)).status, 200);
  const bad = provisioning(3);
  bad.statusDocuments[0].document.signatures[0].sig = "A".repeat(86);
  for (const candidate of [
    bad,
    provisioning(1),
    provisioning(2, [{ kid: vectors.kid, generation: 1 }]),
  ]) {
    assert.equal((await update(f, candidate)).body.error, "PolicyDenied");
    assert.equal((await allows(f)).body.allowed, true);
    assert.equal(
      (await f.send({ operation: "trust-status" })).body.revision,
      1,
    );
  }
});
test("removal preserves historical checkpoints and rejects stale re-enrollment or anchor substitution", async () => {
  const f = await fixture();
  await open(f);
  const p = provisioning(2);
  await update(f, p);
  assert.equal(
    (await update(f, { keyDocuments: [], statusDocuments: [] })).status,
    200,
  );
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal((await update(f, provisioning(1))).body.error, "PolicyDenied");
  assert.equal((await update(f, p)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
  const changed = structuredClone(p);
  changed.keyDocuments[0].anchor = {
    genesisDigest: keyDocumentChainDigest(changed.keyDocuments[0].document),
  };
  assert.equal((await update(f, changed)).body.error, "PolicyDenied");
  assert.equal((await allows(f)).body.allowed, true);
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_trust_checkpoints")).body
      .rows[0].count,
    1,
  );
});
test("stale persisted trust opens without authorizing and can accept a fresh signed replacement", async () => {
  const f = await fixture(),
    config = { ...configuration, maxAgeSeconds: 1 };
  await open(f, true, config);
  assert.equal((await update(f, provisioning())).status, 200);
  await new Promise((resolve) => setTimeout(resolve, 2100));
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal((await open(f, false, config)).body.state, "stale");
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal((await update(f, provisioning(2))).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});
const controls = (f, values = {}) =>
  f.send({ operation: "controls", ...values });
async function until(f, predicate) {
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    const c = (await controls(f)).body;
    if (predicate(c)) return c;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("expected trust interleaving not reached");
}
test("trust update blocks old authority until durability and rejects concurrent updates", async () => {
  const f = await fixture();
  await open(f);
  await update(f, provisioning());
  const before = (await controls(f, { holdSync: true })).body,
    revoked = provisioning(2, [{ kid: vectors.kid, generation: 1 }]);
  const pending = update(f, revoked);
  await until(f, (c) => c.syncEntered === before.syncEntered + 1);
  assert.equal((await allows(f)).body.allowed, false);
  assert.notEqual((await controls(f)).body.revision, before.revision);
  assert.equal((await update(f, provisioning(3))).body.error, "StoreConflict");
  await controls(f, { holdSync: false });
  assert.equal((await pending).status, 200);
  assert.equal((await allows(f)).body.allowed, false);
});
test("SQL failure rolls back trust and checkpoint writes and quarantines until reopen", async () => {
  const f = await fixture();
  await open(f);
  const p = provisioning();
  await update(f, p);
  await controls(f, { fault: "trust-write" });
  assert.equal(
    (await update(f, provisioning(2, [{ kid: vectors.kid, generation: 1 }])))
      .body.error,
    "StoreUnavailable",
  );
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal(
    (await f.send({ operation: "trust-status" })).body.state,
    "failed",
  );
  assert.equal(
    (await f.sql("SELECT serial FROM xeip_trust_checkpoints")).body.rows[0]
      .serial,
    1,
  );
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});
test("ambiguous trust sync fails closed and reopen preserves the committed revocation", async () => {
  const f = await fixture();
  await open(f);
  await update(f, provisioning());
  await controls(f, { fault: "trust-sync" });
  assert.equal(
    (await update(f, provisioning(2, [{ kid: vectors.kid, generation: 1 }])))
      .body.error,
    "StoreUnavailable",
  );
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal(
    (await f.send({ operation: "trust-verify", envelope: vectors.signed })).body
      .valid,
    false,
  );
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal((await update(f, provisioning())).body.error, "PolicyDenied");
});
test("a timed-out sync cannot activate trust later", async () => {
  const f = await fixture();
  await f.send({
    operation: "trust-open",
    initialize: true,
    configuration,
    timeoutMs: 100,
  });
  await controls(f, { holdSync: true });
  assert.equal(
    (await update(f, provisioning())).body.error,
    "StoreUnavailable",
  );
  assert.equal((await allows(f)).body.allowed, false);
  await controls(f, { holdSync: false });
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal(
    (await f.send({ operation: "trust-status" })).body.state,
    "failed",
  );
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});
test("closing during a committed update prevents late activation", async () => {
  const f = await fixture();
  await open(f);
  await update(f, provisioning());
  const before = (await controls(f, { holdSync: true })).body;
  const pending = update(f, provisioning(2));
  await until(f, (c) => c.syncEntered === before.syncEntered + 1);
  assert.equal(
    (await f.send({ operation: "trust-close" })).body.state,
    "closed",
  );
  await controls(f, { holdSync: false });
  assert.equal((await pending).body.error, "StoreUnavailable");
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal(
    (await f.send({ operation: "trust-status" })).body.state,
    "closed",
  );
});
test("caller mutation during update cannot alter committed active trust", async () => {
  const f = await fixture();
  await open(f);
  assert.equal(
    (
      await f.send({
        operation: "trust-update-mutate",
        provisioning: provisioning(),
        kid: vectors.kid,
      })
    ).status,
    200,
  );
  assert.equal((await allows(f)).body.allowed, true);
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});
test("corrupt state or checkpoint-set content fails reopen without resetting trust", async () => {
  for (const query of [
    "UPDATE xeip_trust_state SET revision=revision+1,checksum='" +
      "0".repeat(64) +
      "'",
    "UPDATE xeip_trust_checkpoints SET serial=serial+1,status_digest='" +
      "0".repeat(64) +
      "'",
  ]) {
    const f = await fixture();
    await open(f);
    await update(f, provisioning());
    assert.equal((await f.sql(query)).status, 200);
    assert.equal((await open(f, false)).body.error, "StoreUnavailable");
    assert.equal((await open(f, true)).body.error, "StoreConflict");
  }
});
import { signKeyDocument } from "../tools/key-document.mjs";
function generations(fork = false) {
  const p = provisioning(2),
    genesis = p.keyDocuments[0].document;
  if (fork) {
    genesis.devices = [];
    genesis.signatures = [];
    p.keyDocuments[0].document = signKeyDocument(genesis, {
      privateKey: rootSeed,
      kid: genesis.genesis,
    });
  }
  const first = p.keyDocuments[0].document;
  const next = signKeyDocument(
    {
      ...first,
      generation: 2,
      previous: keyDocumentChainDigest(first),
      signatures: [],
    },
    { privateKey: rootSeed, kid: first.genesis },
  );
  p.keyDocuments.push({ document: next });
  return p;
}
test("valid newer chains advance while higher-tip historical forks and generation rollback fail", async () => {
  const f = await fixture();
  await open(f);
  await update(f, provisioning());
  assert.equal((await update(f, generations(true))).body.error, "PolicyDenied");
  assert.equal((await allows(f)).body.allowed, true);
  assert.equal((await update(f, generations())).status, 200);
  assert.equal((await update(f, provisioning(3))).body.error, "PolicyDenied");
  assert.equal(
    (await f.sql("SELECT generation,serial FROM xeip_trust_checkpoints")).body
      .rows[0].generation,
    2,
  );
});
test("future, stale and oversized provisioning is refused without changing active trust", async () => {
  const f = await fixture();
  await open(f);
  await update(f, provisioning());
  for (const p of [
    provisioning(2, [], utc(now() + 60)),
    provisioning(2, [], utc(now() - 61)),
    { ...provisioning(2), padding: "x".repeat(8388608) },
  ])
    assert.equal((await update(f, p)).body.error, "PolicyDenied");
  assert.equal((await allows(f)).body.allowed, true);
});
function bothEntities(serial = 1, revokeHuman = false) {
  const p = provisioning(
      serial,
      revokeHuman ? [{ kid: base.keyDocuments[0].genesis, generation: 1 }] : [],
    ),
    entity = "urn:xeip:entity:" + vectors.kid;
  const document = signKeyDocument(
    {
      xeip: "xeip.keydoc/0.1",
      entity,
      genesis: vectors.kid,
      generation: 1,
      issuedAt: utc(now()),
      roots: [vectors.kid],
      devices: [],
      signatures: [],
    },
    { privateKey: Buffer.from(vectors.seed, "hex"), kid: vectors.kid },
  );
  p.keyDocuments.push({ document, anchor: { genesisKid: vectors.kid } });
  p.statusDocuments.push({
    document: signStatusDocument(
      {
        xeip: "xeip.status/0.1",
        entity,
        serial,
        issuedAt: utc(now()),
        revoked: [],
        signatures: [],
      },
      { privateKey: Buffer.from(vectors.seed, "hex"), kid: vectors.kid },
    ),
  });
  return p;
}
const ledger = (f, method, p, extra = {}) =>
  f.send({
    operation: "ledger",
    method,
    principal: method === "decide" ? "human" : "agent",
    session: p?.action.session,
    id: p?.action.id,
    digest: p?.digest,
    ...extra,
  });
async function approved(f) {
  await open(f);
  const identities = bothEntities();
  assert.equal((await update(f, identities)).status, 200);
  const result = await ledger(f, "propose", null, {
    request: {
      id: "action",
      session: "operations",
      target: "internal",
      tool: "lookup",
      arguments: { value: 1 },
      expiresAt: now() + 300,
    },
  });
  assert.equal(result.status, 200);
  const p = result.body.proposal;
  assert.equal((await ledger(f, "decide", p)).status, 200);
  return { p, identities };
}
function revokeHuman(identities) {
  const p = structuredClone(identities),
    old = p.statusDocuments[0].document;
  p.statusDocuments[0].document = signStatusDocument(
    {
      ...old,
      serial: old.serial + 1,
      revoked: [{ kid: base.keyDocuments[0].genesis, generation: 1 }],
      signatures: [],
    },
    { privateKey: rootSeed, kid: base.keyDocuments[0].genesis },
  );
  return p;
}
for (const phase of ["claim", "effect"])
  test(`persisted signed revocation during ${phase} authorization prevents the effect`, async () => {
    const f = await fixture(),
      { p, identities } = await approved(f),
      before = (await controls(f, { holdProvider: phase })).body
        .providerEntered;
    const pending = ledger(f, "execute", p);
    await until(
      f,
      (c) => c.providerEntered === before + (phase === "claim" ? 1 : 2),
    );
    assert.equal((await update(f, revokeHuman(identities))).status, 200);
    await controls(f, { holdProvider: null });
    const result = await pending;
    if (phase === "claim") assert.equal(result.body.error, "PolicyDenied");
    else {
      assert.equal(result.status, 200);
      assert.equal(result.body.state, "failed");
    }
    assert.equal((await controls(f)).body.effects, 0);
  });
test("internal action completion remains durable after signed trust revocation", async () => {
  const f = await fixture(),
    { p, identities } = await approved(f),
    claimed = await ledger(f, "claim", p);
  assert.equal(claimed.status, 200);
  await update(f, revokeHuman(identities));
  assert.equal(
    (await ledger(f, "finish", p, { claimId: claimed.body.claimId })).body
      .state,
    "succeeded",
  );
});
test("full local runtime restart preserves trust revocation and rollback history", async () => {
  const f = await fixture();
  await open(f);
  await update(f, provisioning(2, [{ kid: vectors.kid, generation: 1 }]));
  await mf.dispose();
  await start();
  const restored = await fixture(f.name);
  assert.equal((await open(restored, false)).status, 200);
  assert.equal((await allows(restored)).body.allowed, false);
  assert.equal(
    (await update(restored, provisioning())).body.error,
    "PolicyDenied",
  );
  assert.equal((await restored.send({ operation: "controls" })).status, 200);
});

// Storage representation must preserve the logical signed-byte contract.
test("trust chunk representation preserves large UTF-8 data within bounded rows", async () => {
  const { encodeProvisioning, resolveProvisioning } = await import(
    "../services/organization/cloudflare/trust-chunks.mjs"
  );
  for (const value of ["{}", JSON.stringify({ value: "🔑".repeat(700000) })]) {
    const encoded = encodeProvisioning(value, 7);
    assert.ok(Buffer.byteLength(encoded.stored) <= 262144);
    assert.ok(
      encoded.chunks.every((row) => Buffer.byteLength(row.data) <= 349528),
    );
    assert.equal(resolveProvisioning(encoded.stored, 7, encoded.chunks), value);
    if (value.length > 262144) assert.ok(encoded.chunks.length > 1);
  }
});
test("signed trust larger than a SQL row remains durable and authorizes after reopen", async () => {
  const f = await fixture();
  assert.equal((await open(f)).status, 200);
  const p = provisioning();
  const signature = p.keyDocuments[0].document.signatures[0];
  p.keyDocuments[0].document.signatures = Array.from({ length: 16000 }, () => ({
    ...signature,
  }));
  assert.ok(Buffer.byteLength(JSON.stringify(p)) > 2100000);
  assert.equal(
    (
      await f.send({
        operation: "trust-update",
        provisioning: provisioning(),
        signatureCopies: 16000,
      })
    ).status,
    200,
  );
  assert.equal((await allows(f)).body.allowed, true);
  const rows = (
    await f.sql(
      "SELECT revision,part,length(CAST(data AS BLOB)) AS bytes FROM xeip_trust_chunks ORDER BY part",
    )
  ).body.rows;
  assert.ok(rows.length > 1);
  assert.ok(rows.every((row) => row.bytes <= 349528 && row.revision === 1));
  assert.ok(
    (
      await f.sql(
        "SELECT length(CAST(provisioning AS BLOB)) AS bytes FROM xeip_trust_state",
      )
    ).body.rows[0].bytes < 1024,
  );
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});

test("trust chunk codec enforces the 8 MiB boundary and rejects malformed representations", async () => {
  const { encodeProvisioning, resolveProvisioning } = await import(
    "../services/organization/cloudflare/trust-chunks.mjs"
  );
  const atLimit = JSON.stringify("x".repeat(8388606)),
    encoded = encodeProvisioning(atLimit, 2);
  assert.equal(encoded.chunks.length, 32);
  assert.equal(resolveProvisioning(encoded.stored, 2, encoded.chunks), atLimit);
  assert.throws(() => encodeProvisioning(atLimit + " ", 2));
  assert.throws(() => encodeProvisioning("\ud800", 2));
  const sample = encodeProvisioning(JSON.stringify("x".repeat(270000)), 2);
  for (const mutate of [
    (e) => e.chunks.pop(),
    (e) => e.chunks.push({ ...e.chunks[0] }),
    (e) => e.chunks.reverse(),
    (e) => e.chunks[0].revision++,
    (e) => e.chunks[0].part++,
    (e) => (e.chunks[0].data = " " + e.chunks[0].data),
    (e) => (e.chunks[0].data = "A" + e.chunks[0].data.slice(1)),
    (e) => (e.chunks[0].extra = true),
    (e) => (e.stored = " " + e.stored),
    (e) => (e.stored = e.stored.replace('"parts":2', '"parts":1')),
    (e) => (e.stored = e.stored.replace('"schema":', '"extra":true,"schema":')),
  ]) {
    const changed = structuredClone(sample);
    mutate(changed);
    assert.throws(() => resolveProvisioning(changed.stored, 2, changed.chunks));
  }
  assert.throws(() => resolveProvisioning("{}", 2, sample.chunks));
  assert.throws(() => resolveProvisioning(sample.stored, -1, sample.chunks));
});

test("trust chunk decoding rejects invalid UTF-8 even with a matching digest", async () => {
  const { createHash } = await import("node:crypto");
  const { canonicalize } = await import("../sdks/typescript/dist/identity.js");
  const { encodeProvisioning, resolveProvisioning } = await import(
    "../services/organization/cloudflare/trust-chunks.mjs"
  );
  const e = encodeProvisioning(JSON.stringify("x".repeat(270000)), 1);
  const buffers = e.chunks.map((row) => Buffer.from(row.data, "base64"));
  buffers[0][20] = 255;
  e.chunks[0].data = buffers[0].toString("base64");
  const d = JSON.parse(e.stored);
  d.digest = createHash("sha256").update(Buffer.concat(buffers)).digest("hex");
  assert.throws(() => resolveProvisioning(canonicalize(d), 1, e.chunks));
});
const largeUpdate = (f, serial = 1) =>
  f.send({
    operation: "trust-update",
    provisioning: provisioning(serial),
    signatureCopies: 2000,
  });

test("chunked and inline trust updates replace only representation data and keep checkpoints", async () => {
  const f = await fixture();
  await open(f);
  assert.equal((await largeUpdate(f)).status, 200);
  const checkpoint = (await f.sql("SELECT * FROM xeip_trust_checkpoints")).body
    .rows[0];
  assert.equal(
    (await update(f, { keyDocuments: [], statusDocuments: [] })).status,
    200,
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_trust_chunks")).body
      .rows[0].count,
    0,
  );
  assert.equal(
    (await f.sql("SELECT serial FROM xeip_trust_checkpoints")).body.rows[0]
      .serial,
    1,
  );
  assert.equal((await largeUpdate(f, 3)).status, 200);
  const rows = (
    await f.sql("SELECT revision,part FROM xeip_trust_chunks ORDER BY part")
  ).body.rows;
  assert.ok(rows.length > 1 && rows.every((row) => row.revision === 3));
  assert.equal(
    (await f.sql("SELECT anchor FROM xeip_trust_checkpoints")).body.rows[0]
      .anchor,
    checkpoint.anchor,
  );
  for (const query of [
    "UPDATE xeip_trust_chunks SET data='AAAA'",
    "DELETE FROM xeip_trust_chunks",
    "INSERT OR REPLACE INTO xeip_trust_chunks SELECT * FROM xeip_trust_chunks",
    "INSERT INTO xeip_trust_chunks SELECT revision-1,part,data FROM xeip_trust_chunks",
    "INSERT INTO xeip_trust_chunks SELECT revision,31,data FROM xeip_trust_chunks LIMIT 1",
  ])
    assert.equal((await f.sql(query)).status, 409, query);
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});

for (const fault of ["chunk-write", "trust-sync"])
  test(
    "chunked trust " +
      fault +
      " preserves rollback or quarantines ambiguous durability",
    async () => {
      const f = await fixture();
      await open(f);
      await largeUpdate(f);
      const before = (await f.sql("SELECT * FROM xeip_trust_state")).body.rows;
      await f.send({ operation: "controls", fault });
      assert.equal((await largeUpdate(f, 2)).body.error, "StoreUnavailable");
      assert.equal((await allows(f)).body.allowed, false);
      const rows = (await f.sql("SELECT * FROM xeip_trust_state")).body.rows;
      if (fault === "chunk-write") assert.deepEqual(rows, before);
      else assert.equal(rows[0].revision, 2);
      assert.equal((await open(f, false)).status, 200);
      assert.equal((await allows(f)).body.allowed, true);
      assert.equal(
        (await f.sql("SELECT serial FROM xeip_trust_checkpoints")).body.rows[0]
          .serial,
        fault === "chunk-write" ? 1 : 2,
      );
    },
  );

for (const [name, trigger, query] of [
  [
    "missing",
    "xeip_trust_chunk_delete",
    "DELETE FROM xeip_trust_chunks WHERE part=0",
  ],
  [
    "changed",
    "xeip_trust_chunk_update",
    "UPDATE xeip_trust_chunks SET data='AAAA' WHERE part=0",
  ],
  [
    "old revision",
    "xeip_trust_chunk_update",
    "UPDATE xeip_trust_chunks SET revision=0 WHERE part=0",
  ],
  [
    "extra",
    "xeip_trust_chunk_new",
    "INSERT INTO xeip_trust_chunks SELECT revision,31,data FROM xeip_trust_chunks LIMIT 1",
  ],
])
  test(
    name + " trust chunks quarantine reopen without resetting checkpoints",
    async () => {
      const f = await fixture();
      await open(f);
      await largeUpdate(f);
      const before = (await f.sql("SELECT * FROM xeip_trust_checkpoints")).body
        .rows;
      const definition = (
        await f.sql("SELECT sql FROM sqlite_master WHERE name=?", trigger)
      ).body.rows[0].sql;
      await f.sql("DROP TRIGGER " + trigger);
      assert.equal((await f.sql(query)).status, 200);
      await f.sql(definition);
      assert.equal((await open(f, false)).body.error, "StoreUnavailable");
      assert.deepEqual(
        (await f.sql("SELECT * FROM xeip_trust_checkpoints")).body.rows,
        before,
      );
    },
  );

async function legacyTrustFixture({ large = false, action = false } = {}) {
  const source = await fixture();
  await open(source);
  const p = provisioning();
  if (large) {
    const signature = p.keyDocuments[0].document.signatures[0];
    p.keyDocuments[0].document.signatures = Array.from(
      { length: 2000 },
      () => ({ ...signature }),
    );
  }
  assert.equal((await update(source, p)).status, 200);
  const state = (await source.sql("SELECT * FROM xeip_trust_state")).body
    .rows[0];
  const { canonicalize } = await import("../sdks/typescript/dist/identity.js");
  state.provisioning = canonicalize(p);
  if (large) assert.ok(Buffer.byteLength(state.provisioning) > 262144);
  const checkpoints = (await source.sql("SELECT * FROM xeip_trust_checkpoints"))
    .body.rows;
  const f = await fixture();
  assert.equal((await f.send({ operation: "initialize-v5" })).status, 200);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    5,
  );
  for (const row of checkpoints) {
    const names = Object.keys(row);
    assert.equal(
      (
        await f.sql(
          "INSERT INTO xeip_trust_checkpoints(" +
            names.join(",") +
            ") VALUES (" +
            names.map(() => "?").join(",") +
            ")",
          ...Object.values(row),
        )
      ).status,
      200,
    );
  }
  const initial = { ...state, revision: 0 },
    names = Object.keys(initial);
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_trust_state(" +
          names.join(",") +
          ") VALUES (" +
          names.map(() => "?").join(",") +
          ")",
        ...Object.values(initial),
      )
    ).status,
    200,
  );
  await f.sql("UPDATE xeip_trust_state SET revision=1");
  if (action) {
    const { ActionPolicy } = await import(
      "../services/organization/actions.mjs"
    );
    const actor = {
      ...principal,
      subject: "legacy-agent",
      roles: ["agent"],
      clientId: "fixture",
      expiresAt: now() + 300,
    };
    const policy = new ActionPolicy({
      targets: [
        {
          id: "legacy-tool",
          revision: "1",
          recipient: principal.entity,
          tools: ["lookup"],
        },
      ],
      sessions: [
        {
          id: "legacy-session",
          agents: [actor.subject],
          approvers: [],
          targets: ["legacy-tool"],
        },
      ],
    });
    const proposal = policy.propose(actor, {
      id: "legacy-action",
      session: "legacy-session",
      target: "legacy-tool",
      tool: "lookup",
      arguments: { preserved: true },
      expiresAt: now() + 120,
    });
    assert.equal(
      (
        await f.sql(
          "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) VALUES (?,?,?,?,?,'pending')",
          proposal.action.session,
          proposal.action.id,
          proposal.digest,
          canonicalize(proposal.action),
          proposal.action.expiresAt,
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await f.sql(
          "INSERT INTO xeip_audit(session_id,request_id,digest,event,actor,occurred_at) VALUES (?,?,?,'proposed',?,?)",
          proposal.action.session,
          proposal.action.id,
          proposal.digest,
          canonicalize({
            subject: actor.subject,
            entity: actor.entity,
            kid: actor.kid,
          }),
          now(),
        )
      ).status,
      200,
    );
  }
  return { f, state, checkpoints };
}
for (const large of [false, true])
  test(
    "version 5 trust migration preserves exact " +
      (large ? "large inline" : "small inline") +
      " state and checkpoint bytes",
    async () => {
      const { f, state, checkpoints } = await legacyTrustFixture({ large });
      const catalog = (
        await f.sql(
          "SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY type,name",
        )
      ).body.rows;
      assert.equal((await open(f, false)).status, 200);
      assert.equal(
        (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
        9,
      );
      assert.deepEqual(
        (await f.sql("SELECT * FROM xeip_trust_state")).body.rows,
        [state],
      );
      assert.deepEqual(
        (await f.sql("SELECT * FROM xeip_trust_checkpoints")).body.rows,
        checkpoints,
      );
      const next = (
        await f.sql(
          "SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY type,name",
        )
      ).body.rows;
      for (const row of catalog)
        assert.deepEqual(
          next.find((r) => r.name === row.name),
          row,
        );
      assert.equal((await allows(f)).body.allowed, true);
      const beforeDowngrade = (await f.sql("SELECT * FROM xeip_schema")).body
        .rows;
      assert.equal(
        (await f.send({ operation: "initialize-v5" })).body.error,
        "StoreUnavailable",
      );
      assert.deepEqual(
        (await f.sql("SELECT * FROM xeip_schema")).body.rows,
        beforeDowngrade,
      );
      assert.deepEqual(
        (await f.sql("SELECT * FROM xeip_trust_state")).body.rows,
        [state],
      );
    },
  );

test("failed chunk migration rolls back to exact version 5 and explicit retry succeeds", async () => {
  const { f } = await legacyTrustFixture({ large: true, action: true });
  const queries = [
    "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY type,name",
    ...[
      "xeip_schema",
      "xeip_trust_state",
      "xeip_trust_checkpoints",
      "xeip_actions",
      "xeip_audit",
    ].map((table) => "SELECT * FROM " + table),
  ];
  const before = [];
  for (const query of queries) before.push((await f.sql(query)).body.rows);
  await f.send({ operation: "controls", fault: "chunk-migration" });
  assert.equal((await open(f, false)).body.error, "StoreUnavailable");
  assert.equal((await controls(f)).body.chunkMigrationApplied, true);
  for (let i = 0; i < queries.length; i++)
    assert.deepEqual((await f.sql(queries[i])).body.rows, before[i]);
  assert.equal((await open(f, false)).status, 200);
  for (let i = 2; i < queries.length; i++)
    assert.deepEqual((await f.sql(queries[i])).body.rows, before[i]);
});

test("orphan trust chunks cannot be adopted by explicit initialization", async () => {
  const f = await fixture();
  await f.send({ operation: "initialize" });
  const definition = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_trust_chunk_new'",
    )
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_trust_chunk_new");
  assert.equal(
    (await f.sql("INSERT INTO xeip_trust_chunks VALUES(0,0,'AAAA')")).status,
    200,
  );
  await f.sql(definition);
  assert.equal((await open(f)).body.error, "StoreUnavailable");
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_trust_state")).body.rows,
    [],
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS count FROM xeip_trust_chunks")).body
      .rows[0].count,
    1,
  );
});

test("closing during chunk durability wait cannot activate the new trust", async () => {
  const f = await fixture();
  await open(f);
  const before = (await controls(f, { holdSync: true })).body;
  const pending = largeUpdate(f);
  try {
    await until(f, (c) => c.syncEntered === before.syncEntered + 1);
    assert.equal((await allows(f)).body.allowed, false);
    assert.equal(
      (await f.send({ operation: "trust-close" })).body.state,
      "closed",
    );
  } finally {
    await controls(f, { holdSync: false });
  }
  assert.equal((await pending).body.error, "StoreUnavailable");
  assert.equal((await allows(f)).body.allowed, false);
  assert.equal((await open(f, false)).status, 200);
  assert.equal((await allows(f)).body.allowed, true);
});

import { createHash } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { validateTrustCheckpoint } from "../services/organization/cloudflare/trust-checkpoint.mjs";
// Independent fixture hash describes the existing durable row, not the new codec.
function sealCheckpoint(value) {
  value.checksum = createHash("sha256")
    .update(
      "XEIP durable trust state v1\n" +
        canonicalize({
          configuration: canonicalize(value.configuration),
          provisioning: canonicalize(value.provisioning),
          revision: value.revision,
          acceptedAt: value.acceptedAt,
          checkpointsDigest: createHash("sha256")
            .update(canonicalize(value.records))
            .digest("hex"),
        }),
    )
    .digest("hex");
  return value;
}
function emptyCheckpoint() {
  return sealCheckpoint({
    schema: "xeip.trust-checkpoint/1",
    organization: "trust-fixture",
    configuration: structuredClone(configuration),
    provisioning: { keyDocuments: [], statusDocuments: [] },
    revision: 0,
    acceptedAt: 1,
    records: {},
  });
}
test("historical trust checkpoint validates without changing acceptance time or aliasing caller data", () => {
  const input = emptyCheckpoint(),
    result = validateTrustCheckpoint(input, "trust-fixture");
  assert.deepEqual(JSON.parse(JSON.stringify(result)), input);
  input.configuration.knownExtensions.push("changed");
  assert.deepEqual(result.configuration.knownExtensions, ["app.action"]);
  assert.equal(result.acceptedAt, 1);
});
test("historical trust checkpoint reuse keeps the validated result deeply immutable and organization-bound", () => {
  const input = emptyCheckpoint();
  input.records.removed = {
    anchor: "a".repeat(64),
    generation: 1,
    keyDigest: "b".repeat(64),
    serial: 0,
    statusDigest: "c".repeat(64),
  };
  sealCheckpoint(input);
  const result = validateTrustCheckpoint(input, "trust-fixture");
  // A mutable top-level result would let later consumers reuse altered metadata.
  assert.throws(() => {
    result.acceptedAt = 2;
  }, TypeError);
  assert.throws(() => {
    result.configuration.knownExtensions.push("changed");
  }, TypeError);
  assert.throws(() => {
    result.provisioning.keyDocuments.push({});
  }, TypeError);
  assert.throws(() => {
    result.records.removed.serial = 1;
  }, TypeError);
  input.records.removed.serial = 10;
  assert.equal(result.records.removed.serial, 0);
  // Idempotence is the allocation contract: downstream consumers reuse this isolated value.
  assert.equal(validateTrustCheckpoint(result, "trust-fixture"), result);
  assert.throws(() => validateTrustCheckpoint(result, "other"), TypeError);
});
test("historical trust encoding preserves canonical bytes and never trusts cloned or frozen lookalikes", async () => {
  const { encodeTrustCheckpoint } = await import(
    "../services/organization/cloudflare/trust-checkpoint.mjs"
  );
  assert.equal(typeof encodeTrustCheckpoint, "function");
  const input = emptyCheckpoint();
  const expected = canonicalize(input);
  const result = validateTrustCheckpoint(input, "trust-fixture");
  assert.equal(encodeTrustCheckpoint(result, "trust-fixture"), expected);
  assert.equal(encodeTrustCheckpoint(input, "trust-fixture"), expected);
  assert.throws(() => encodeTrustCheckpoint(result, "other"), TypeError);
  for (const mutate of [
    (v) => {
      v.acceptedAt++;
    },
    (v) => {
      v.checksum = "0".repeat(64);
    },
    (v) => {
      v.provisioning.keyDocuments.push({});
    },
    (v) => {
      v.configuration.knownExtensions.push("changed");
    },
    (v) => {
      v.records.bad = {};
    },
  ]) {
    const forged = structuredClone(result);
    mutate(forged);
    Object.freeze(forged);
    assert.throws(
      () => encodeTrustCheckpoint(forged, "trust-fixture"),
      TypeError,
    );
  }
  let reads = 0;
  const accessor = { ...result };
  Object.defineProperty(accessor, "checksum", {
    enumerable: true,
    get() {
      reads++;
      return result.checksum;
    },
  });
  assert.throws(
    () => encodeTrustCheckpoint(Object.freeze(accessor), "trust-fixture"),
    TypeError,
  );
  assert.equal(reads, 0);
  input.acceptedAt++;
  assert.throws(() => encodeTrustCheckpoint(input, "trust-fixture"), TypeError);
  assert.equal(encodeTrustCheckpoint(result, "trust-fixture"), expected);
});
test("historical trust checkpoint refuses scope, malformed metadata, unknown fields and damaged checksums", () => {
  for (const mutation of [
    (c) => (c.organization = "other"),
    (c) => (c.schema = "xeip.trust-checkpoint/2"),
    (c) => (c.revision = -1),
    (c) => (c.acceptedAt = 1.5),
    (c) => (c.secret = "forbidden"),
    (c) => (c.checksum = "0".repeat(64)),
    (c) => (c.configuration.extra = true),
    (c) => (c.provisioning.extra = true),
    (c) => (c.records.removed = {}),
  ]) {
    const c = emptyCheckpoint();
    mutation(c);
    assert.throws(() => validateTrustCheckpoint(c, "trust-fixture"), TypeError);
  }
  assert.throws(
    () => validateTrustCheckpoint(emptyCheckpoint(), ""),
    TypeError,
  );
});
test("historical trust checkpoint enforces nested capacity even with a recomputed checksum", () => {
  const c = emptyCheckpoint();
  c.configuration.knownExtensions = ["x".repeat(65536)];
  sealCheckpoint(c);
  assert.throws(() => validateTrustCheckpoint(c, "trust-fixture"), TypeError);
  const many = emptyCheckpoint();
  many.records = Object.fromEntries(
    Array.from({ length: 4097 }, (_, n) => [
      "removed" + n,
      {
        anchor: "a".repeat(64),
        generation: 1,
        keyDigest: "b".repeat(64),
        serial: 1,
        statusDigest: "c".repeat(64),
      },
    ]),
  );
  sealCheckpoint(many);
  assert.throws(
    () => validateTrustCheckpoint(many, "trust-fixture"),
    TypeError,
  );
});
for (const chunked of [false, true])
  test(`historical trust checkpoint captures ${chunked ? "chunked" : "inline"} signed documents and retains removed entities`, async () => {
    const f = await fixture();
    assert.equal((await open(f)).status, 200);
    assert.equal(
      (await (chunked ? largeUpdate(f) : update(f, provisioning()))).status,
      200,
    );
    const before = (await f.sql("SELECT * FROM xeip_trust_state")).body.rows[0];
    const captured = await f.send({ operation: "trust-checkpoint" });
    assert.equal(captured.status, 200);
    const c = validateTrustCheckpoint(captured.body, "trust-fixture");
    assert.equal(c.checksum, before.checksum);
    assert.equal(c.revision, 1);
    assert.equal(c.acceptedAt, before.accepted_at);
    assert.equal(
      c.provisioning.keyDocuments[0].document.signatures.length,
      chunked ? 2000 : 1,
    );
    assert.equal(c.records[principal.entity].serial, 1);
    assert.deepEqual(
      (await f.sql("SELECT * FROM xeip_trust_state")).body.rows[0],
      before,
    );
    const damaged = structuredClone(c);
    damaged.provisioning.statusDocuments[0].document.serial += 1;
    sealCheckpoint(damaged);
    assert.throws(
      () => validateTrustCheckpoint(damaged, "trust-fixture"),
      TypeError,
    );
    const mismatched = structuredClone(c);
    mismatched.records[principal.entity].serial += 1;
    sealCheckpoint(mismatched);
    assert.throws(
      () => validateTrustCheckpoint(mismatched, "trust-fixture"),
      TypeError,
    );
    assert.equal(
      (await update(f, { keyDocuments: [], statusDocuments: [] })).status,
      200,
    );
    const removed = validateTrustCheckpoint(
      (await f.send({ operation: "trust-checkpoint" })).body,
      "trust-fixture",
    );
    assert.equal(
      canonicalize(removed.provisioning),
      canonicalize({ keyDocuments: [], statusDocuments: [] }),
    );
    assert.deepEqual(removed.records, c.records);
  });
test("historical trust checkpoint refuses pending durability and closed instances", async () => {
  const f = await fixture();
  await open(f);
  const before = (await controls(f, { holdSync: true })).body;
  const pending = update(f, provisioning());
  try {
    await until(f, (c) => c.syncEntered === before.syncEntered + 1);
    assert.equal(
      (await f.send({ operation: "trust-checkpoint" })).body.error,
      "StoreUnavailable",
    );
  } finally {
    await controls(f, { holdSync: false });
    await pending;
  }
  assert.equal((await f.send({ operation: "trust-checkpoint" })).status, 200);
  await f.send({ operation: "trust-close" });
  assert.equal(
    (await f.send({ operation: "trust-checkpoint" })).body.error,
    "StoreUnavailable",
  );
});
test("historical trust checkpoint detects persisted corruption and altered schema", async () => {
  for (const query of [
    "UPDATE xeip_trust_checkpoints SET serial=serial+1",
    "DROP TRIGGER xeip_trust_checkpoint_delete",
  ]) {
    const f = await fixture();
    await open(f);
    await update(f, provisioning());
    assert.equal((await f.sql(query)).status, 200);
    assert.equal(
      (await f.send({ operation: "trust-checkpoint" })).body.error,
      "StoreUnavailable",
    );
    assert.equal((await allows(f)).body.allowed, false);
  }
});

test("historical trust checkpoint verifies expired signed history at its original acceptance time", async () => {
  const { prepareEntityTrust } = await import(
    "../packages/identity/trust-state.mjs"
  );
  const c = emptyCheckpoint();
  c.provisioning = provisioning(1, [], utc(base.nowSeconds));
  c.acceptedAt = base.nowSeconds;
  c.revision = 1;
  c.records = prepareEntityTrust(
    configuration,
    c.provisioning.keyDocuments,
    c.provisioning.statusDocuments,
    c.acceptedAt,
  ).checkpoints;
  sealCheckpoint(c);
  assert.throws(() =>
    prepareEntityTrust(
      configuration,
      c.provisioning.keyDocuments,
      c.provisioning.statusDocuments,
      c.acceptedAt + 61,
    ),
  );
  const recovered = validateTrustCheckpoint(c, "trust-fixture");
  assert.equal(recovered.acceptedAt, base.nowSeconds);
  assert.equal(
    recovered.provisioning.statusDocuments[0].document.issuedAt,
    utc(base.nowSeconds),
  );
});

for (const section of ["keyDocuments", "statusDocuments"])
  test(`historical trust checkpoint refuses invalid ${section} signatures despite recomputed outer checksums`, async () => {
    const { prepareEntityTrust } = await import(
      "../packages/identity/trust-state.mjs"
    );
    const input = emptyCheckpoint();
    input.provisioning = provisioning(1, [], utc(base.nowSeconds));
    input.acceptedAt = base.nowSeconds;
    input.revision = 1;
    input.records = prepareEntityTrust(
      configuration,
      input.provisioning.keyDocuments,
      input.provisioning.statusDocuments,
      input.acceptedAt,
    ).checkpoints;
    sealCheckpoint(input);
    const valid = validateTrustCheckpoint(input, "trust-fixture");
    const damaged = structuredClone(valid);
    for (const entry of damaged.provisioning[section])
      for (const signature of entry.document.signatures)
        signature.sig = "A".repeat(86);
    if (section === "keyDocuments") {
      assert.equal(damaged.provisioning.keyDocuments.length, 1);
      const document = damaged.provisioning.keyDocuments[0].document;
      // The full signed key document participates in the retained chain digest.
      damaged.records[document.entity].keyDigest = createHash("sha256")
        .update(canonicalize(document))
        .digest("hex");
    }
    // Retained digests and outer integrity agree with the tampered document;
    // the invalid signature itself must still prevent acceptance.
    sealCheckpoint(damaged);
    assert.notEqual(damaged.checksum, valid.checksum);
    assert.throws(
      () => validateTrustCheckpoint(damaged, "trust-fixture"),
      TypeError,
    );
  });

test("historical trust capture and reopen refuse noncanonical persisted provisioning with a matching row checksum", async () => {
  const { trustStateChecksum } = await import(
    "../services/organization/cloudflare/trust-checkpoint.mjs"
  );
  for (const operation of ["capture", "reopen"]) {
    const f = await fixture();
    assert.equal((await open(f)).status, 200);
    assert.equal((await update(f, provisioning())).status, 200);
    const row = (await f.sql("SELECT * FROM xeip_trust_state")).body.rows[0];
    const next = {
      ...row,
      revision: row.revision + 1,
      provisioning: " " + row.provisioning,
    };
    const checksum = trustStateChecksum(next);
    assert.equal(
      (
        await f.sql(
          "UPDATE xeip_trust_state SET revision=?,provisioning=?,checksum=? WHERE singleton=1",
          next.revision,
          next.provisioning,
          checksum,
        )
      ).status,
      200,
    );
    const result =
      operation === "capture"
        ? await f.send({ operation: "trust-checkpoint" })
        : await open(f, false);
    // Capture rejects drift from the live instance's accepted checksum;
    // reopen independently exercises persisted canonical-byte validation.
    assert.equal(result.body.error, "StoreUnavailable");
    if (operation === "capture")
      assert.equal((await allows(f)).body.allowed, false);
    const preserved = (await f.sql("SELECT * FROM xeip_trust_state")).body
      .rows[0];
    assert.equal(preserved.provisioning, next.provisioning);
    assert.equal(preserved.checksum, checksum);
  }
});
