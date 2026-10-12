import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
import { organizationBundleFixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { collectOrganizationBundle } from "../services/organization/cloudflare/organization-bundle.mjs";
let runtime;
before(async () => {
  runtime = await harness({
    entryPoint: new URL(
      "./organization-cloudflare-organization-restore-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "OrganizationRestoreFixture",
  });
});
after(async () => {
  await runtime?.close();
});
async function bundle(t, options = {}) {
  const source = organizationBundleFixture(options);
  const root = await fs.mkdtemp(join(tmpdir(), "xeip-organization-restore-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const directory = join(root, "bundle");
  const manifest = await collectOrganizationBundle({ directory, ...source });
  const names = (await fs.readdir(directory))
    .filter((n) => /^(actions|authority|administration)-/.test(n))
    .sort((a, b) => {
      const order = ["actions", "authority", "administration"];
      return (
        order.indexOf(a.split("-")[0]) - order.indexOf(b.split("-")[0]) ||
        a.localeCompare(b)
      );
    });
  const pages = await Promise.all(
    names.map(async (name) =>
      JSON.parse(await fs.readFile(join(directory, name), "utf8")),
    ),
  );
  return { ...source, manifest, pages, names };
}
const start = (f, b, operation = "organizationRestoreInitialize", settings) =>
  f.send({
    operation,
    organization: b.organization,
    checkpoint: b.checkpoint,
    manifest: b.manifest,
    settings,
  });
const apply = (f, b, i) =>
  f.send({
    operation: "organizationRestoreApply",
    sequence: i + 1,
    value: b.pages[i],
  });
test("complete restore preserves interleaved action history, consumed claims and all controls across restart", async (t) => {
  const b = await bundle(t, {
    actions: 4,
    states: ["succeeded", "executing", "rejected", "revoked"],
    revisions: 129,
    attempts: 17,
    trustRevision: 7,
  });
  let f = await runtime.fixture();
  const initialized = await start(f, b);
  assert.equal(initialized.status, 200, JSON.stringify(initialized));
  assert.equal(initialized.body.blocked, true);
  assert.equal(
    (await f.send({ operation: "regularStore", organization: b.organization }))
      .status,
    503,
  );
  assert.equal((await apply(f, b, 0)).status, 200);
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal((await start(f, b, "organizationRestoreOpen")).status, 200);
  assert.equal((await apply(f, b, 0)).status, 200, "identical last page retry");
  for (let i = 1; i < b.pages.length; i++)
    assert.equal((await apply(f, b, i)).status, 200, "page " + i);
  const receipt = await f.send({ operation: "organizationRestoreVerify" });
  assert.equal(receipt.status, 200, JSON.stringify(receipt));
  assert.equal(receipt.body.phase, "verified");
  assert.equal(receipt.body.blocked, true);
  assert.equal(receipt.body.bundleChecksum, b.manifest.checksum);
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_actions ORDER BY request_id")).body.rows,
    b.actionRows.map((r) => r.row),
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_audit ORDER BY sequence")).body.rows,
    b.actionRows
      .flatMap((r) => r.history)
      .sort((a, b) => a.sequence - b.sequence),
  );
  assert.equal(
    (await f.sql("SELECT revision FROM xeip_trust_state")).body.rows[0]
      .revision,
    7,
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS n FROM xeip_authority_events")).body
      .rows[0].n,
    130,
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS n FROM xeip_owner_events")).body.rows[0].n,
    17,
  );
  assert.equal((await f.send({ operation: "verifyNormal" })).status, 503);
  assert.equal(
    (
      await f.send({
        operation: "initializeNormal",
        organization: b.organization,
      })
    ).status,
    503,
  );
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal(
    (await start(f, b, "organizationRestoreOpen")).body.phase,
    "verified",
  );
  assert.equal(
    (await f.send({ operation: "regularStore", organization: b.organization }))
      .status,
    503,
  );
});
test("empty action/admin histories still require complete authority and empty administration pages", async (t) => {
  const b = await bundle(t, { actions: 0 });
  const f = await runtime.fixture();
  assert.equal((await start(f, b)).status, 200);
  assert.equal(
    (await f.send({ operation: "organizationRestoreVerify" })).status,
    409,
  );
  for (let i = 0; i < b.pages.length; i++)
    assert.equal((await apply(f, b, i)).status, 200);
  assert.equal(
    (await f.send({ operation: "organizationRestoreVerify" })).body.phase,
    "verified",
  );
});

const controls = (f, control = {}) =>
  f.send({ operation: "controls", control });
const normalBlocked = async (f, b) => {
  assert.equal(
    (
      await f.send({
        operation: "initializeNormal",
        organization: b.organization,
      })
    ).status,
    503,
  );
  assert.equal(
    (await f.send({ operation: "regularStore", organization: b.organization }))
      .status,
    503,
  );
};
const complete = async (f, b) => {
  for (let i = 0; i < b.pages.length; i++)
    assert.equal((await apply(f, b, i)).status, 200, "page " + i);
  assert.equal(
    (await f.send({ operation: "organizationRestoreVerify" })).body.phase,
    "verified",
  );
};
test("restore requires an empty target and explicit matching organization without changing existing tables", async (t) => {
  const b = await bundle(t);
  const f = await runtime.fixture();
  const foreign = await f.send({
    operation: "organizationRestoreInitialize",
    organization: "foreign",
    checkpoint: b.checkpoint,
    manifest: b.manifest,
  });
  assert.equal(foreign.status, 503);
  assert.equal(
    (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows.length,
    0,
  );
  await f.sql("CREATE TABLE unrelated(value TEXT)");
  await f.sql("INSERT INTO unrelated VALUES('preserved')");
  assert.equal((await start(f, b)).status, 409);
  assert.deepEqual((await f.sql("SELECT * FROM unrelated")).body.rows, [
    { value: "preserved" },
  ]);
  const existing = await runtime.fixture();
  await existing.send({
    operation: "initializeNormal",
    organization: b.organization,
  });
  const before = (await existing.sql("SELECT * FROM xeip_schema")).body.rows;
  assert.equal((await start(existing, b)).status, 409);
  assert.deepEqual(
    (await existing.sql("SELECT * FROM xeip_schema")).body.rows,
    before,
  );
});
test("schema8 upgrade preserves old schema; failed schema9 DDL rolls back before retry", async (t) => {
  const b = await bundle(t);
  const f = await runtime.fixture();
  assert.equal(
    (await f.send({ operation: "initializeV8", organization: b.organization }))
      .status,
    200,
  );
  const before = (
    await f.sql(
      "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY name",
    )
  ).body.rows;
  const schema = (await f.sql("SELECT * FROM xeip_schema")).body.rows;
  await controls(f, { failQuery: "UPDATE xeip_schema SET version=9" });
  assert.equal(
    (
      await f.send({
        operation: "initializeNormal",
        organization: b.organization,
      })
    ).status,
    503,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_schema")).body.rows,
    schema,
  );
  assert.deepEqual(
    (
      await f.sql(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY name",
      )
    ).body.rows,
    before,
  );
  await controls(f, { failQuery: null });
  assert.equal(
    (
      await f.send({
        operation: "initializeNormal",
        organization: b.organization,
      })
    ).status,
    200,
  );
  assert.deepEqual(
    (
      await f.sql(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' AND name NOT GLOB 'xeip_organization_restore*' ORDER BY name",
      )
    ).body.rows,
    before,
  );
  assert.equal(
    (await f.send({ operation: "initializeV8", organization: b.organization }))
      .status,
    503,
  );
});
test("organization fence rejects replacement, removal and invalid progress even after verification", async (t) => {
  const b = await bundle(t, { actions: 0 });
  const f = await runtime.fixture();
  await start(f, b);
  for (const query of [
    "DELETE FROM xeip_organization_restore",
    "INSERT OR REPLACE INTO xeip_organization_restore SELECT * FROM xeip_organization_restore",
    "UPDATE xeip_organization_restore SET intent='{}'",
    "UPDATE xeip_organization_restore SET sequence=2",
  ])
    assert.notEqual((await f.sql(query)).status, 200);
  await complete(f, b);
  assert.notEqual(
    (await f.sql("UPDATE xeip_organization_restore SET phase='restoring'"))
      .status,
    200,
  );
  assert.notEqual(
    (await f.sql("UPDATE xeip_organization_restore SET sequence=sequence+1"))
      .status,
    200,
  );
  await normalBlocked(f, b);
});
for (const query of [
  "INSERT INTO xeip_trust_state",
  "INSERT INTO xeip_authority_state",
  "CREATE TRIGGER xeip_trust_state_insert",
])
  test(
    "initial control load rolls back all rows and suspended triggers on " +
      query,
    async (t) => {
      const b = await bundle(t, { trustRevision: 4, revisions: 2 });
      const f = await runtime.fixture();
      await controls(f, { failQuery: query });
      assert.equal((await start(f, b)).status, 503);
      assert.equal(
        (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
          .body.rows.length,
        0,
      );
      await controls(f, { failQuery: null });
      assert.equal((await start(f, b)).status, 200);
      await complete(f, b);
    },
  );
for (const [query, page] of [
  ["INSERT INTO xeip_audit", 0],
  ["UPDATE xeip_organization_restore SET sequence", 0],
  ["INSERT INTO xeip_authority_events", 1],
  ["CREATE TRIGGER xeip_authority_event_new", 1],
  ["INSERT INTO xeip_owner_events", 2],
])
  test(
    "page transaction rolls back data and exact trigger catalog on " + query,
    async (t) => {
      const b = await bundle(t, {
        actions: 1,
        states: ["succeeded"],
        attempts: 1,
      });
      const f = await runtime.fixture();
      await start(f, b);
      for (let i = 0; i < page; i++) await apply(f, b, i);
      const catalog = (
        await f.sql(
          "SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY name",
        )
      ).body.rows;
      const progress = (await f.sql("SELECT * FROM xeip_organization_restore"))
        .body.rows;
      await controls(f, { failQuery: query });
      assert.equal((await apply(f, b, page)).status, 503);
      assert.deepEqual(
        (await f.sql("SELECT * FROM xeip_organization_restore")).body.rows,
        progress,
      );
      assert.deepEqual(
        (
          await f.sql(
            "SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY name",
          )
        ).body.rows,
        catalog,
      );
      assert.equal(
        (await f.send({ operation: "organizationRestoreStatus" })).status,
        503,
      );
      await controls(f, { failQuery: null });
      assert.equal((await start(f, b, "organizationRestoreOpen")).status, 200);
      for (let i = page; i < b.pages.length; i++)
        assert.equal((await apply(f, b, i)).status, 200);
      assert.equal(
        (await f.send({ operation: "organizationRestoreVerify" })).body.phase,
        "verified",
      );
      await normalBlocked(f, b);
    },
  );
for (const stage of ["initialize", "apply", "verify"])
  test(
    "uncertain " +
      stage +
      " synchronization requires explicit reconciliation and never activates",
    async (t) => {
      const b = await bundle(t, { actions: 1 });
      const f = await runtime.fixture();
      if (stage !== "initialize") await start(f, b);
      if (stage === "verify")
        for (let i = 0; i < b.pages.length; i++) await apply(f, b, i);
      const n = (await controls(f)).body.syncs + 1;
      await controls(f, { failSync: n });
      const result =
        stage === "initialize"
          ? await start(f, b)
          : stage === "apply"
            ? await apply(f, b, 0)
            : await f.send({ operation: "organizationRestoreVerify" });
      assert.equal(result.status, 503);
      await normalBlocked(f, b);
      await controls(f, { failSync: 0 });
      const reopened = await start(f, b, "organizationRestoreOpen");
      assert.equal(reopened.status, 200);
      for (let i = reopened.body.sequence; i < b.pages.length; i++)
        assert.equal((await apply(f, b, i)).status, 200);
      assert.equal(
        (await f.send({ operation: "organizationRestoreVerify" })).body.phase,
        "verified",
      );
    },
  );
for (const stage of ["initialize", "apply"])
  test(
    "ambiguous " +
      stage +
      " commit is retained and adopted only by exact-intent reopen",
    async (t) => {
      const b = await bundle(t, { actions: 1 });
      const f = await runtime.fixture();
      if (stage === "apply") await start(f, b);
      await controls(f, { failTransaction: "after" });
      assert.equal(
        (stage === "initialize" ? await start(f, b) : await apply(f, b, 0))
          .status,
        503,
      );
      await controls(f, { failTransaction: null });
      const result = await start(f, b, "organizationRestoreOpen");
      assert.equal(result.status, 200);
      assert.equal(result.body.sequence, stage === "apply" ? 1 : 0);
      await normalBlocked(f, b);
    },
  );
test("out of order pages conflict without harming healthy progress; changed last-page retry quarantines", async (t) => {
  const b = await bundle(t);
  const f = await runtime.fixture();
  await start(f, b);
  assert.equal((await apply(f, b, 1)).status, 409);
  assert.equal((await apply(f, b, 0)).status, 200);
  assert.equal((await apply(f, b, 0)).status, 200);
  const damaged = structuredClone(b.pages[0]);
  damaged.row.state = "revoked";
  assert.equal(
    (
      await f.send({
        operation: "organizationRestoreApply",
        sequence: 1,
        value: damaged,
      })
    ).status,
    503,
  );
  assert.equal(
    (await f.send({ operation: "organizationRestoreStatus" })).status,
    503,
  );
  assert.equal((await start(f, b, "organizationRestoreOpen")).status, 200);
});
for (const [name, trigger, query] of [
  [
    "control",
    "xeip_trust_state_update",
    "UPDATE xeip_trust_state SET checksum='" + "1".repeat(64) + "'",
  ],
  [
    "action",
    "xeip_action_update",
    "UPDATE xeip_actions SET result_canonical='{}'",
  ],
  ["audit", "xeip_audit_delete", "DELETE FROM xeip_audit WHERE sequence=1"],
  [
    "authority",
    "xeip_authority_event_delete",
    "DELETE FROM xeip_authority_events WHERE revision=0",
  ],
  [
    "administration",
    "xeip_owner_delete",
    "DELETE FROM xeip_owner_events WHERE sequence=1",
  ],
  [
    "progress",
    "xeip_organization_restore_update",
    "UPDATE xeip_organization_restore SET checksum='" + "1".repeat(64) + "'",
  ],
])
  test(
    "restored " +
      name +
      " corruption is detected even after exact trigger recreation",
    async (t) => {
      const b = await bundle(t, {
        actions: 1,
        states: ["succeeded"],
        attempts: 1,
      });
      const f = await runtime.fixture();
      await start(f, b);
      await complete(f, b);
      const sql = (
        await f.sql("SELECT sql FROM sqlite_master WHERE name=?", trigger)
      ).body.rows[0].sql;
      assert.equal((await f.sql("DROP TRIGGER " + trigger)).status, 200);
      assert.equal((await f.sql(query)).status, 200);
      assert.equal((await f.sql(sql)).status, 200);
      assert.equal(
        (await f.send({ operation: "organizationRestoreVerify" })).status,
        503,
      );
      assert.equal((await start(f, b, "organizationRestoreOpen")).status, 503);
      await normalBlocked(f, b);
    },
  );
for (const kind of ["close", "timeout"])
  test(
    kind + " during synchronization cannot be undone by late completion",
    async (t) => {
      const b = await bundle(t, { actions: 1 });
      const f = await runtime.fixture();
      await start(f, b, "organizationRestoreInitialize", {
        timeoutMs: kind === "timeout" ? 100 : 10000,
      });
      const n = (await controls(f)).body.syncs + 1;
      await controls(f, { holdSync: n });
      const pending = apply(f, b, 0);
      let result;
      try {
        const end = Date.now() + 5000;
        while ((await controls(f)).body.syncs !== n) {
          assert.ok(Date.now() < end);
          await new Promise((r) => setTimeout(r, 5));
        }
        assert.equal(
          (await f.send({ operation: "organizationRestoreStatus" })).status,
          409,
        );
        assert.equal((await apply(f, b, 0)).status, 409);
        if (kind === "close")
          await f.send({ operation: "organizationRestoreClose" });
        else result = await pending;
      } finally {
        await controls(f, { holdSync: 0 });
      }
      result ??= await pending;
      assert.equal(result.status, 503);
      assert.equal(
        (await f.send({ operation: "organizationRestoreStatus" })).status,
        503,
      );
      await normalBlocked(f, b);
      assert.equal(
        (await start(f, b, "organizationRestoreOpen")).body.sequence,
        1,
      );
    },
  );

test("restore preserves chunked signed trust at original acceptance time and removed-entity rollback records", async (t) => {
  const { identity, provisioning, now } = await import(
    "./fixtures/cloudflare/authority-harness.mjs"
  );
  const { prepareEntityTrust } = await import(
    "../packages/identity/trust-state.mjs"
  );
  const { resolveProvisioning } = await import(
    "../services/organization/cloudflare/trust-chunks.mjs"
  );
  const { canonicalize } = await import("../sdks/typescript/dist/identity.js");
  const actors = [identity("agent"), identity("removed")],
    configuration = { maxAgeSeconds: 300, knownExtensions: [] },
    acceptedAt = now();
  const original = provisioning(actors);
  const prepared = prepareEntityTrust(
    configuration,
    original.keyDocuments,
    original.statusDocuments,
    acceptedAt,
  );
  const current = structuredClone(original);
  current.keyDocuments.splice(1);
  current.statusDocuments.splice(1);
  const signatures = current.keyDocuments[0].document.signatures;
  current.keyDocuments[0].document.signatures = Array.from(
    { length: 2000 },
    () => structuredClone(signatures[0]),
  );
  const records = { ...prepared.checkpoints };
  // Retained records are historical, independently bounded beyond the generic JSON node budget.
  for (let i = 0; i < 3000; i++)
    records["retained:" + i] = {
      anchor: "0".repeat(64),
      generation: 1,
      keyDigest: "0".repeat(64),
      serial: 0,
      statusDigest: "0".repeat(64),
    };
  // Duplicate signatures change the signed-document content digest but not its valid identity.
  Object.assign(
    records,
    prepareEntityTrust(
      configuration,
      current.keyDocuments,
      current.statusDocuments,
      acceptedAt,
    ).checkpoints,
  );
  const b = await bundle(t, {
    actions: 0,
    historicalTrust: {
      configuration,
      provisioning: current,
      revision: 19,
      acceptedAt,
      records,
    },
  });
  let f = await runtime.fixture();
  const initialized = await start(f, b);
  assert.equal(initialized.status, 200, JSON.stringify(initialized));
  const trust = (await f.sql("SELECT * FROM xeip_trust_state")).body.rows[0],
    chunks = (await f.sql("SELECT * FROM xeip_trust_chunks ORDER BY part")).body
      .rows;
  assert.ok(chunks.length > 1);
  assert.equal(trust.accepted_at, acceptedAt);
  assert.equal(trust.revision, 19);
  assert.equal(
    resolveProvisioning(trust.provisioning, 19, chunks),
    canonicalize(current),
  );
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS n FROM xeip_trust_checkpoints")).body
      .rows[0].n,
    3002,
  );
  assert.equal(
    (
      await f.sql(
        "SELECT serial FROM xeip_trust_checkpoints WHERE entity=?",
        actors[1].entity,
      )
    ).body.rows[0].serial,
    1,
  );
  await complete(f, b);
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal(
    (await start(f, b, "organizationRestoreOpen")).body.phase,
    "verified",
  );
  await normalBlocked(f, b);
});
test("changed valid bundle intent and bad file commitment cannot adopt or verify the candidate", async (t) => {
  const { createHash } = await import("node:crypto");
  const { canonicalize } = await import("../sdks/typescript/dist/identity.js");
  const b = await bundle(t, { actions: 1 });
  const f = await runtime.fixture();
  await start(f, b);
  const { checksum, ...body } = b.manifest;
  body.filesChecksum = "1".repeat(64);
  const different = {
    ...b,
    manifest: {
      ...body,
      checksum: createHash("sha256")
        .update("XEIP organization bundle v1\n" + canonicalize(body))
        .digest("hex"),
    },
  };
  assert.equal(
    (await start(f, different, "organizationRestoreOpen")).status,
    503,
  );
  assert.equal((await start(f, b, "organizationRestoreOpen")).status, 200);
  const bad = await runtime.fixture();
  assert.equal((await start(bad, different)).status, 200);
  for (let i = 0; i < b.pages.length; i++)
    assert.equal((await apply(bad, b, i)).status, 200);
  assert.equal(
    (await bad.send({ operation: "organizationRestoreVerify" })).status,
    503,
  );
  await normalBlocked(bad, b);
});
