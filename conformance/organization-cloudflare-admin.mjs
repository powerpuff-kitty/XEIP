import { auditChecksum } from "../services/organization/cloudflare/admin-audit.mjs";
import { before, after, test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
let runtime;
before(async () => {
  runtime = await harness({
    entryPoint: new URL(
      "./organization-cloudflare-admin-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "AdminFixture",
  });
});
after(async () => {
  await runtime?.close();
});
const metadata = () => ({
  operator: "operations:alice",
  requestId: randomUUID(),
  operation: "refreshTrust",
  commandDigest: "a".repeat(64),
});
const state = (revision = 0) => ({
  state: "initialized",
  trustRevision: revision,
  authorityRevision: 0,
});
const open = (f, options = {}) =>
  f.send({ operation: "open", initialize: true, ...options });
const start = (f, options = {}) =>
  f.send({
    operation: "start",
    metadata: metadata(),
    state: state(),
    ...options,
  });
const finish = (f, options = {}) =>
  f.send({
    operation: "finish",
    outcome: "completed",
    state: state(1),
    ...options,
  });
const exported = async (f, options) =>
  (await f.send({ operation: "export", options })).body;
test("empty audit open cannot implicitly initialize storage", async () => {
  const f = await runtime.fixture();
  assert.equal(
    (await open(f, { initialize: false })).body.error,
    "StoreUnavailable",
  );
  assert.deepEqual(
    (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
});
test("journal persists ordered redacted attempts/results across real workerd restart", async () => {
  const f = await runtime.fixture(),
    m = metadata();
  assert.equal((await open(f)).body.headSequence, 0);
  assert.equal((await start(f, { metadata: m })).status, 200);
  assert.equal((await finish(f)).status, 200);
  const page = await exported(f);
  assert.equal(page.headSequence, 2);
  assert.equal(page.next, 2);
  assert.equal(page.records[0].event.operator, m.operator);
  assert.equal(page.records[0].event.outcome, "started");
  assert.equal(page.records[1].event.outcome, "completed");
  assert.equal(
    page.records[1].event.attemptId,
    page.records[0].event.attemptId,
  );
  assert.deepEqual(page.records[1].event.after, state(1));
  assert.equal(page.records[1].previous, page.records[0].checksum);
  await runtime.restart();
  const reopened = await runtime.fixture(f.name);
  assert.equal((await open(reopened, { initialize: false })).status, 200);
  assert.deepEqual(await exported(reopened), page);
});
test("journal requires durable start before finish and hides unflushed writes from export", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f, { sync: false });
  assert.equal((await finish(f)).body.error, "StoreConflict");
  assert.equal(
    (await f.send({ operation: "export" })).body.error,
    "StoreConflict",
  );
  await f.send({ operation: "sync" });
  assert.equal((await finish(f)).status, 200);
});
test("completion tickets cannot be forged, reused or transferred across reopen", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  assert.equal((await finish(f, { forged: true })).body.error, "StoreConflict");
  await finish(f);
  assert.equal((await finish(f)).body.error, "StoreConflict");
  await start(f);
  await open(f, { initialize: false });
  assert.equal((await finish(f)).body.error, "StoreConflict");
  assert.equal((await exported(f)).records.at(-1).event.outcome, "started");
});
test("journal preserves unresolved attempts and permits new distinct attempts without replay", async () => {
  const f = await runtime.fixture();
  await open(f);
  const m = metadata();
  await start(f, { metadata: m });
  await runtime.restart();
  const r = await runtime.fixture(f.name);
  await open(r, { initialize: false });
  await start(r, { metadata: m });
  await finish(r, { outcome: "conflict" });
  const rows = (await exported(r)).records;
  assert.equal(rows.length, 3);
  assert.notEqual(rows[0].event.attemptId, rows[1].event.attemptId);
  assert.equal(rows[2].event.outcome, "conflict");
});
test("capacity reserves a terminal record and refuses new work without pruning", async () => {
  const f = await runtime.fixture();
  await open(f, { maxRecords: 2 });
  await start(f);
  await finish(f);
  assert.equal((await start(f)).body.error, "StoreConflict");
  assert.equal((await exported(f)).records.length, 2);
});
test("private export is cursor-bounded with stable chain links and captured head", async () => {
  const f = await runtime.fixture();
  await open(f);
  for (let n = 0; n < 10; n++) {
    await start(f);
    await finish(f);
  }
  const a = await exported(f),
    b = await exported(f, { after: a.next, limit: 4 });
  assert.equal(a.records.length, 16);
  assert.equal(a.headSequence, 20);
  assert.equal(b.records.length, 4);
  assert.equal(b.records[0].previous, a.records.at(-1).checksum);
  assert.equal(b.next, 20);
  for (const options of [
    { after: -1 },
    { limit: 17 },
    { limit: 0 },
    { after: 1.5 },
    { after: 21 },
    { extra: true },
  ]) {
    assert.equal(
      (await f.send({ operation: "export", options })).body.error,
      "TypeError",
    );
  }
});
test("journal rejects unexpected fields, arbitrary outcomes and invalid scalar values before writes", async () => {
  const f = await runtime.fixture();
  await open(f);
  for (const m of [
    { ...metadata(), secret: "sentinel" },
    { ...metadata(), operator: "bad\nactor" },
    { ...metadata(), commandDigest: "x" },
    { ...metadata(), operation: "reset" },
  ]) {
    assert.equal((await start(f, { metadata: m })).body.error, "TypeError");
  }
  for (const value of [
    { ...state(), secret: "sentinel" },
    { ...state(), trustRevision: -1 },
    { ...state(), state: "sentinel" },
  ]) {
    assert.equal((await start(f, { state: value })).body.error, "TypeError");
  }
  assert.equal((await exported(f)).headSequence, 0);
  await start(f);
  assert.equal(
    (await finish(f, { outcome: "sentinel-secret" })).body.error,
    "TypeError",
  );
  assert.equal((await finish(f)).status, 200);
});
test("failed synchronization quarantines subsequent reads and writes without erasing uncertain data", async () => {
  const f = await runtime.fixture();
  await open(f);
  await f.send({ operation: "controls", values: { failSync: true } });
  assert.equal((await start(f)).body.error, "StoreUnavailable");
  assert.equal((await exported(f)).error, "StoreUnavailable");
  assert.equal((await finish(f)).body.error, "StoreUnavailable");
  await f.send({ operation: "controls", values: { failSync: false } });
  assert.equal((await open(f, { initialize: false })).body.headSequence, 1);
});
test("journal append failure rolls back and quarantines its instance", async () => {
  const f = await runtime.fixture();
  await open(f);
  await f.send({
    operation: "controls",
    values: { failQuery: "INSERT INTO xeip_owner_events" },
  });
  assert.equal((await start(f)).body.error, "StoreUnavailable");
  assert.equal((await exported(f)).error, "StoreUnavailable");
  await f.send({ operation: "controls", values: { failQuery: null } });
  assert.equal((await open(f, { initialize: false })).body.headSequence, 0);
});
test("SQL forbids journal update, deletion and replacement", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  for (const sql of [
    "UPDATE xeip_owner_events SET sequence=4 WHERE sequence=1",
    "DELETE FROM xeip_owner_events WHERE sequence=1",
    "INSERT OR REPLACE INTO xeip_owner_events SELECT * FROM xeip_owner_events WHERE sequence=1",
  ]) {
    assert.equal((await f.sql(sql)).status, 409);
  }
  assert.equal((await exported(f)).headSequence, 2);
});
test("historical row corruption is detected before further writes and on reopen", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const trigger = (
    await f.sql("SELECT sql FROM sqlite_master WHERE name='xeip_owner_update'")
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_owner_update");
  await f.sql(
    "UPDATE xeip_owner_events SET checksum=? WHERE sequence=1",
    "0".repeat(64),
  );
  await f.sql(trigger);
  assert.equal((await start(f)).body.error, "StoreUnavailable");
  assert.equal(
    (await open(f, { initialize: false })).body.error,
    "StoreUnavailable",
  );
});
test("clock rollback cannot reorder timestamps", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await f.send({ operation: "controls", values: { clock: 1 } });
  await finish(f);
  const rows = (await exported(f)).records;
  assert.equal(rows[1].event.occurredAt, rows[0].event.occurredAt);
});

test("v4 migration preserves prior data without inventing historical attribution", async () => {
  const f = await runtime.fixture();
  await f.send({ operation: "v4" });
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    4,
  );
  const before = (await f.sql("SELECT * FROM xeip_metadata")).body.rows;
  assert.equal((await open(f)).body.headSequence, 0);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_metadata")).body.rows,
    before,
  );
});
test("missing immutability triggers quarantine the journal before append", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  await f.sql("DROP TRIGGER xeip_owner_delete");
  assert.equal((await start(f)).body.error, "StoreUnavailable");
});

test("history verification crosses SQL page boundaries without skipping chain links", async () => {
  const f = await runtime.fixture();
  await open(f);
  for (let n = 0; n < 130; n++) {
    await start(f);
    await finish(f);
  }
  const page = await exported(f, { after: 254, limit: 6 });
  assert.deepEqual(
    page.records.map((r) => r.sequence),
    [255, 256, 257, 258, 259, 260],
  );
  assert.equal(page.headChecksum, page.records.at(-1).checksum);
  await open(f, { initialize: false });
  assert.deepEqual(await exported(f, { after: 254, limit: 6 }), page);
  const { AdminHistoryVerifier } = await checkpointCodec();
  const c = (await checkpoint(f)).body,
    verifier = new AdminHistoryVerifier(c, "audit-fixture");
  const collected = [];
  while (!verifier.complete()) {
    const captured = await historyPage(f, c, verifier.cursor());
    assert.equal(captured.status, 200);
    verifier.accept(captured.body);
    collected.push(...captured.body.records);
  }
  assert.equal(verifier.finish().attempts, 130);
  assert.equal(verifier.finish().unresolved, 0);
  assert.equal(collected.length, 260);
  const stored = (
    await f.sql(
      "SELECT sequence,canonical,previous,checksum FROM xeip_owner_events ORDER BY sequence",
    )
  ).body.rows;
  assert.deepEqual(
    collected.map(({ event, ...r }) => ({
      ...r,
      canonical: canonicalize(event),
    })),
    stored,
  );
});

for (const kind of ["started", "terminal"])
  test(`next-sequence SQL REPLACE cannot delete an existing ${kind} event through a unique-index conflict`, async () => {
    const f = await runtime.fixture();
    await open(f);
    await start(f);
    if (kind === "terminal") await finish(f);
    const original = (
      await f.sql("SELECT * FROM xeip_owner_events ORDER BY sequence")
    ).body.rows;
    const row = original.at(-1),
      sequence = row.sequence + 1;
    const replacement = await f.sql(
      "INSERT OR REPLACE INTO xeip_owner_events(sequence,attempt_id,outcome,canonical,previous,checksum) VALUES (?,?,?,?,?,?)",
      sequence,
      row.attempt_id,
      row.outcome,
      row.canonical,
      row.checksum,
      auditChecksum(sequence, row.checksum, row.canonical),
    );
    assert.equal(replacement.status, 409, JSON.stringify(replacement));
    assert.deepEqual(
      (await f.sql("SELECT * FROM xeip_owner_events ORDER BY sequence")).body
        .rows,
      original,
    );
    assert.equal((await exported(f)).headSequence, original.length);
  });

const checkpoint = (f) => f.send({ operation: "checkpoint" });
const historyPage = (f, checkpoint, options) =>
  f.send({ operation: "historyPage", checkpoint, options });
test("administrative recovery checkpoint preserves empty and completed source history", async () => {
  const f = await runtime.fixture();
  await open(f);
  const empty = await checkpoint(f);
  assert.equal(empty.status, 200);
  assert.equal(empty.body.schema, "xeip.admin-checkpoint/1");
  assert.equal(empty.body.organization, "audit-fixture");
  assert.equal(empty.body.headSequence, 0);
  assert.equal(empty.body.headChecksum, "0".repeat(64));
  assert.deepEqual((await historyPage(f, empty.body)).body.records, []);
  await start(f);
  await finish(f);
  const before = (
    await f.sql("SELECT * FROM xeip_owner_events ORDER BY sequence")
  ).body.rows;
  const c = await checkpoint(f);
  assert.equal(c.status, 200);
  const page = await historyPage(f, c.body);
  assert.equal(page.status, 200);
  assert.deepEqual(page.body.records, (await exported(f)).records);
  assert.equal(page.body.complete, true);
  assert.equal(page.body.next, 2);
  assert.equal(c.body.headChecksum, before.at(-1).checksum);
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_owner_events ORDER BY sequence")).body
      .rows,
    before,
  );
});
test("administrative recovery checkpoint refuses active and unflushed mutations but preserves unresolved attempts after reopen", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f, { sync: false });
  assert.equal((await checkpoint(f)).body.error, "StoreConflict");
  await f.send({ operation: "sync" });
  assert.equal((await checkpoint(f)).body.error, "StoreConflict");
  await open(f, { initialize: false });
  const c = await checkpoint(f);
  assert.equal(c.status, 200);
  assert.equal(c.body.headSequence, 1);
  assert.equal(
    (await historyPage(f, c.body)).body.records[0].event.outcome,
    "started",
  );
  await start(f);
  await finish(f, { sync: false });
  assert.equal((await checkpoint(f)).body.error, "StoreConflict");
  await f.send({ operation: "sync" });
  assert.equal((await checkpoint(f)).body.headSequence, 3);
});
test("administrative recovery checkpoint conflicts on a changed head without disabling current history", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const old = (await checkpoint(f)).body;
  await start(f);
  await finish(f);
  assert.equal((await historyPage(f, old)).body.error, "StoreConflict");
  const current = await checkpoint(f);
  assert.equal(current.body.headSequence, 4);
  assert.equal((await historyPage(f, current.body)).status, 200);
});

const checkpointCodec = () =>
  import("../services/organization/cloudflare/admin-checkpoint.mjs");
const sealAdmin = (body) => ({
  ...body,
  digest: createHash("sha256")
    .update("XEIP admin checkpoint v1\n" + canonicalize(body))
    .digest("hex"),
});
function attempt() {
  const begun = {
    ...metadata(),
    attemptId: randomUUID(),
    outcome: "started",
    occurredAt: 1000,
    before: state(),
  };
  return {
    begun,
    ended: {
      ...begun,
      outcome: "completed",
      occurredAt: 1001,
      after: state(1),
    },
  };
}
function history(events) {
  let previous = "0".repeat(64);
  const records = events.map((event, i) => {
    const sequence = i + 1,
      checksum = auditChecksum(sequence, previous, canonicalize(event));
    const record = { sequence, event, previous, checksum };
    previous = checksum;
    return record;
  });
  const checkpoint = sealAdmin({
    schema: "xeip.admin-checkpoint/1",
    organization: "audit-fixture",
    headSequence: records.length,
    headChecksum: previous,
  });
  return {
    checkpoint,
    records,
    page(after, limit = 2) {
      const slice = records.slice(after, after + limit),
        next = after + slice.length;
      return {
        schema: "xeip.admin-history-page/1",
        checkpointDigest: checkpoint.digest,
        after,
        records: structuredClone(slice),
        next,
        complete: next === records.length,
      };
    },
  };
}
test("administrative checkpoint codec validates scope and complete history with unresolved attempts across pages", async () => {
  const { AdminHistoryVerifier, validateAdminCheckpoint } =
    await checkpointCodec();
  const a = attempt(),
    b = attempt(),
    c = attempt();
  c.begun.occurredAt = 1001;
  const h = history([a.begun, b.begun, a.ended, c.begun, b.ended]);
  const v = new AdminHistoryVerifier(h.checkpoint, "audit-fixture", {
    limit: 2,
  });
  assert.throws(() => v.finish(), TypeError);
  v.accept(h.page(0));
  assert.throws(() => v.accept(h.page(0)), TypeError);
  assert.equal(v.cursor().after, 2);
  v.accept(h.page(2));
  v.accept(h.page(4));
  assert.deepEqual(v.finish(), {
    checkpoint: validateAdminCheckpoint(h.checkpoint, "audit-fixture"),
    attempts: 3,
    unresolved: 1,
  });
  assert.throws(() => v.accept(h.page(4)), TypeError);
  const empty = history([]),
    ev = new AdminHistoryVerifier(empty.checkpoint, "audit-fixture");
  assert.equal(ev.complete(), false);
  ev.accept(empty.page(0));
  assert.equal(ev.finish().attempts, 0);
  assert.equal(ev.finish().unresolved, 0);
  for (const altered of [
    { ...h.checkpoint, organization: "other" },
    { ...h.checkpoint, headSequence: -1 },
    { ...h.checkpoint, headSequence: 100001 },
    { ...h.checkpoint, headChecksum: "x" },
    { ...h.checkpoint, secret: "not-allowed" },
    { ...empty.checkpoint, headChecksum: "a".repeat(64) },
  ]) {
    const { digest, ...body } = altered;
    assert.throws(
      () => validateAdminCheckpoint(sealAdmin(body), "audit-fixture"),
      TypeError,
    );
  }
});
test("administrative history verifier rejects rehashed orphan, duplicate, mismatched and time-regressing events", async () => {
  const { AdminHistoryVerifier } = await checkpointCodec(),
    a = attempt(),
    b = attempt();
  for (const events of [
    [a.ended],
    [a.begun, a.begun],
    [a.begun, a.ended, a.ended],
    [a.begun, { ...a.ended, commandDigest: "b".repeat(64) }],
    [a.begun, { ...a.ended, operator: "operations:mallory" }],
    [a.begun, { ...a.ended, before: state(99) }],
    [a.begun, b.begun, { ...a.ended, occurredAt: 999 }],
  ]) {
    const h = history(events),
      v = new AdminHistoryVerifier(h.checkpoint, "audit-fixture", { limit: 1 });
    assert.throws(() => {
      while (!v.complete()) v.accept(h.page(v.cursor().after, 1));
      v.finish();
    }, TypeError);
  }
});
test("administrative history verifier refuses malformed pages and commits no partial verifier state", async () => {
  const { AdminHistoryVerifier } = await checkpointCodec(),
    a = attempt(),
    b = attempt(),
    c = attempt(),
    d = attempt();
  c.begun.occurredAt = 1001;
  const h = history([a.begun, b.begun, a.ended, c.begun, b.ended]);
  const v = new AdminHistoryVerifier(h.checkpoint, "audit-fixture", {
    limit: 2,
  });
  for (const alter of [
    (p) => p.records.pop(),
    (p) => p.records[0].sequence++,
    (p) => (p.records[0].previous = "a".repeat(64)),
    (p) => (p.complete = true),
    (p) => p.next++,
    (p) => (p.extra = true),
    (p) => (p.checkpointDigest = "b".repeat(64)),
    (p) => (p.records[0].event.secret = "not-allowed"),
    (p) => (p.records[0].event.operator = "x".repeat(65536)),
  ]) {
    const p = h.page(0);
    alter(p);
    assert.throws(() => v.accept(p), TypeError);
    assert.equal(v.cursor().after, 0);
  }
  v.accept(h.page(0));
  const bad = h.page(2);
  bad.records[0].event = { ...d.begun, occurredAt: 9000 };
  bad.records[0].checksum = auditChecksum(
    3,
    bad.records[0].previous,
    canonicalize(bad.records[0].event),
  );
  bad.records[1].previous = bad.records[0].checksum;
  bad.records[1].event = {
    ...a.ended,
    occurredAt: 9000,
    commandDigest: "b".repeat(64),
  };
  bad.records[1].checksum = auditChecksum(
    4,
    bad.records[1].previous,
    canonicalize(bad.records[1].event),
  );
  assert.throws(() => v.accept(bad), TypeError);
  assert.equal(v.cursor().after, 2);
  v.accept(h.page(2));
  v.accept(h.page(4));
  assert.equal(v.finish().attempts, 3);
  assert.equal(v.finish().unresolved, 1);
});

test("administrative recovery capture rejects malformed cursors and scope without quarantining healthy state", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const c = (await checkpoint(f)).body;
  for (const options of [
    null,
    { after: null },
    { limit: null },
    { after: -1 },
    { after: 3 },
    { after: 1 },
    { after: 1, previousChecksum: "a".repeat(64) },
    { previousChecksum: "a".repeat(64) },
    { limit: 0 },
    { limit: 17 },
    { extra: true },
  ]) {
    assert.equal((await historyPage(f, c, options)).body.error, "TypeError");
  }
  const { digest, ...body } = c;
  assert.equal(
    (await historyPage(f, sealAdmin({ ...body, organization: "other" }))).body
      .error,
    "TypeError",
  );
  assert.equal((await historyPage(f, c)).status, 200);
  assert.equal((await checkpoint(f)).body.digest, c.digest);
});
for (const operation of ["checkpoint", "captureReader"])
  for (const corruption of ["history", "organization", "schema", "query"])
    test(`administrative ${operation} quarantines ${corruption} corruption`, async () => {
      const f = await runtime.fixture();
      await open(f);
      await start(f);
      await finish(f);
      const c = (await checkpoint(f)).body;
      if (corruption === "query")
        await f.send({
          operation: "controls",
          values: {
            failQuery:
              operation === "captureReader"
                ? "SELECT e.sequence,e.attempt_id"
                : "SELECT sequence,canonical",
          },
        });
      if (corruption === "history" || corruption === "organization") {
        const name =
          corruption === "history" ? "xeip_owner_update" : "xeip_scope_update";
        const trigger = (
          await f.sql("SELECT sql FROM sqlite_master WHERE name=?", name)
        ).body.rows[0].sql;
        assert.equal((await f.sql("DROP TRIGGER " + name)).status, 200);
        const mutation =
          corruption === "history"
            ? await f.sql(
                "UPDATE xeip_owner_events SET checksum=? WHERE sequence=1",
                "a".repeat(64),
              )
            : await f.sql("UPDATE xeip_metadata SET organization_id='other'");
        assert.equal(mutation.status, 200);
        assert.equal((await f.sql(trigger)).status, 200);
      } else if (corruption === "schema")
        assert.equal(
          (await f.sql("DROP TRIGGER xeip_owner_delete")).status,
          200,
        );
      const result =
        operation === "captureReader"
          ? await f.send({ operation })
          : corruption === "query"
            ? await historyPage(f, c)
            : await checkpoint(f);
      assert.equal(result.body.error, "StoreUnavailable");
      await f.send({ operation: "controls", values: { failQuery: null } });
      assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
    });
test("administrative recovery capture cannot advertise a failed synchronization", async () => {
  const f = await runtime.fixture();
  await open(f);
  await f.send({ operation: "controls", values: { failSync: true } });
  assert.equal((await start(f)).body.error, "StoreUnavailable");
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
  await f.send({ operation: "controls", values: { failSync: false } });
  assert.equal((await open(f, { initialize: false })).status, 200);
  const c = (await checkpoint(f)).body;
  assert.equal(c.headSequence, 1);
  assert.equal(
    (await historyPage(f, c)).body.records[0].event.outcome,
    "started",
  );
});

test("administrative record extraction preserves the original checksum wire format", () => {
  const event = {
    operator: "operations:alice",
    requestId: "11111111-1111-4111-8111-111111111111",
    operation: "refreshTrust",
    commandDigest: "a".repeat(64),
    attemptId: "22222222-2222-4222-8222-222222222222",
    outcome: "started",
    occurredAt: 1000,
    before: { state: "initialized", trustRevision: 0, authorityRevision: 0 },
  };
  // Derived from the pre-extraction source retained in the lifecycle verification tar.
  assert.equal(
    auditChecksum(1, "0".repeat(64), canonicalize(event)),
    "f65f1fac729c252c09a3b21801c18f48652266bc0714da44fd7a5db6fe53a786",
  );
});

test("fixed-cut export keeps a captured empty administrative history empty after new commands", async () => {
  const f = await runtime.fixture();
  assert.equal((await open(f)).status, 200);
  const captured = (await checkpoint(f)).body;
  assert.equal((await start(f)).status, 200);
  assert.equal((await finish(f)).status, 200);
  const current = (await checkpoint(f)).body;
  assert.equal(current.headSequence, 2);
  assert.equal((await historyPage(f, captured)).body.error, "StoreConflict");
  const result = await f.send({
    operation: "historyPageAt",
    checkpoint: captured,
  });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.checkpointDigest, captured.digest);
  assert.deepEqual(result.body.records, []);
  assert.equal(result.body.next, 0);
  assert.equal(result.body.complete, true);
  assert.deepEqual((await checkpoint(f)).body, current);
});

test("fixed-cut export retains unresolved administrative attempts and excludes newer history across pages", async () => {
  const f = await runtime.fixture();
  assert.equal((await open(f)).status, 200);
  for (let index = 0; index < 2; index++) {
    assert.equal((await start(f)).status, 200);
    assert.equal((await finish(f)).status, 200);
  }
  assert.equal((await start(f)).status, 200);
  assert.equal((await open(f, { initialize: false })).status, 200);
  const captured = (await checkpoint(f)).body;
  assert.equal(captured.headSequence, 5);
  const expected = (await historyPage(f, captured)).body.records;
  assert.equal(expected.at(-1).event.outcome, "started");
  assert.equal((await start(f)).status, 200);
  assert.equal((await finish(f)).status, 200);
  const current = (await checkpoint(f)).body;
  assert.equal(current.headSequence, 7);
  let after = 0,
    previousChecksum = "0".repeat(64);
  const records = [];
  for (const size of [2, 2, 1]) {
    const result = await f.send({
      operation: "historyPageAt",
      checkpoint: captured,
      options: { after, previousChecksum, limit: 2 },
    });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.checkpointDigest, captured.digest);
    assert.equal(result.body.records.length, size);
    records.push(...result.body.records);
    after += size;
    assert.equal(result.body.next, after);
    assert.equal(result.body.complete, after === 5);
    previousChecksum = result.body.records.at(-1).checksum;
  }
  assert.deepEqual(records, expected);
  assert.equal(previousChecksum, captured.headChecksum);
  assert.deepEqual((await checkpoint(f)).body, current);
});

test("fixed-cut export rejects unrelated and future administrative heads without quarantining the source", async () => {
  const f = await runtime.fixture();
  assert.equal((await open(f)).status, 200);
  assert.equal((await start(f)).status, 200);
  assert.equal((await finish(f)).status, 200);
  const current = (await checkpoint(f)).body;
  const { digest, ...body } = current;
  for (const candidate of [
    sealAdmin({ ...body, headChecksum: "a".repeat(64) }),
    sealAdmin({ ...body, headSequence: 3, headChecksum: "b".repeat(64) }),
  ]) {
    const response = await f.send({
      operation: "historyPageAt",
      checkpoint: candidate,
    });
    assert.equal(response.body.error, "StoreConflict");
    assert.deepEqual((await checkpoint(f)).body, current);
  }
  assert.equal((await start(f)).status, 200);
  assert.equal((await finish(f)).status, 200);
  assert.equal((await checkpoint(f)).body.headSequence, 4);
});

test("fixed-cut export quarantines corrupted retained administrative history before returning a page", async () => {
  const f = await runtime.fixture();
  assert.equal((await open(f)).status, 200);
  assert.equal((await start(f)).status, 200);
  assert.equal((await finish(f)).status, 200);
  const captured = (await checkpoint(f)).body;
  assert.equal((await start(f)).status, 200);
  assert.equal((await finish(f)).status, 200);
  const trigger = (
    await f.sql("SELECT sql FROM sqlite_master WHERE name='xeip_owner_update'")
  ).body.rows[0].sql;
  assert.equal((await f.sql("DROP TRIGGER xeip_owner_update")).status, 200);
  assert.equal(
    (
      await f.sql(
        "UPDATE xeip_owner_events SET checksum=? WHERE sequence=1",
        "a".repeat(64),
      )
    ).status,
    200,
  );
  assert.equal((await f.sql(trigger)).status, 200);
  const response = await f.send({
    operation: "historyPageAt",
    checkpoint: captured,
  });
  assert.equal(response.body.error, "StoreUnavailable");
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
});

test("scoped administrative reader exports every retained record with linear history row work", async () => {
  const { organizationBundleFixture } = await import(
    "./fixtures/cloudflare/organization-bundle-harness.mjs"
  );
  const { adminRows } = organizationBundleFixture({
    actions: 0,
    attempts: 1000,
  });
  const f = await runtime.fixture();
  assert.equal((await open(f)).status, 200);
  assert.equal(
    (await f.send({ operation: "seedHistory", records: adminRows })).status,
    200,
  );
  assert.equal((await open(f, { initialize: false })).status, 200);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  await f.send({ operation: "controls", values: { historyRows: 0 } });
  const records = [];
  let after = 0,
    previousChecksum = "0".repeat(64),
    pages = 0;
  do {
    const result = await f.send({
      operation: "readerPage",
      options: { after, previousChecksum, limit: 16 },
    });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    records.push(...result.body.records);
    after = result.body.next;
    previousChecksum = result.body.records.at(-1).checksum;
    pages++;
    assert.equal(result.body.complete, after === 1000);
  } while (after < 1000);
  assert.deepEqual(records, adminRows);
  const cost = (await f.send({ operation: "controls" })).body.historyRows;
  assert.ok(
    cost <= 1000 + 4 * pages,
    `read ${cost} historical rows for ${records.length} exported records`,
  );
});

test("scoped administrative reader follows its captured cut across later commands and remains closed", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  const first = await f.send({
    operation: "readerPage",
    options: { limit: 1 },
  });
  assert.equal(first.status, 200);
  await start(f);
  await finish(f);
  const last = await f.send({
    operation: "readerPage",
    options: {
      after: 1,
      previousChecksum: first.body.records[0].checksum,
      limit: 16,
    },
  });
  assert.equal(last.status, 200);
  assert.equal(last.body.records.length, 1);
  assert.equal(last.body.next, 2);
  assert.equal(last.body.complete, true);
  assert.equal(last.body.records[0].checksum, captured.headChecksum);
  await f.send({ operation: "readerClose" });
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreUnavailable",
  );
  assert.equal((await checkpoint(f)).body.headSequence, 4);
});

test("scoped administrative reader refuses corruption in an unread page without returning a complete cut", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  await start(f);
  await finish(f);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  const first = await f.send({
    operation: "readerPage",
    options: { limit: 2 },
  });
  assert.equal(first.status, 200);
  assert.equal(first.body.complete, false);
  const trigger = (
    await f.sql("SELECT sql FROM sqlite_master WHERE name='xeip_owner_update'")
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_owner_update");
  await f.sql(
    "UPDATE xeip_owner_events SET checksum=? WHERE sequence=3",
    "a".repeat(64),
  );
  await f.sql(trigger);
  const bad = await f.send({
    operation: "readerPage",
    options: {
      after: 2,
      previousChecksum: first.body.records.at(-1).checksum,
      limit: 16,
    },
  });
  assert.equal(bad.body.error, "StoreUnavailable");
  assert.equal((await checkpoint(f)).body.error, "StoreUnavailable");
});

test("scoped administrative reader preserves healthy state after malformed cursors and pending commands", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  for (const options of [
    null,
    { limit: 0 },
    { after: 1, previousChecksum: "f".repeat(64) },
  ])
    assert.equal(
      (await f.send({ operation: "readerPage", options })).body.error,
      "TypeError",
    );
  await start(f);
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreConflict",
  );
  await finish(f);
  const result = await f.send({ operation: "readerPage" });
  assert.equal(result.status, 200);
  assert.equal(result.body.records.length, 2);
  assert.equal(result.body.next, 2);
  assert.equal(result.body.records.at(-1).checksum, captured.headChecksum);
});

test("scoped administrative reader cannot adopt a head advanced by another journal instance", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  await open(f, { initialize: false });
  await start(f);
  await finish(f);
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreUnavailable",
  );
  assert.equal((await checkpoint(f)).body.headSequence, 4);
});

test("scoped administrative reader keeps an empty cut after the live journal gains records", async () => {
  const f = await runtime.fixture();
  await open(f);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  await start(f);
  await finish(f);
  const result = await f.send({ operation: "readerPage" });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.records, []);
  assert.equal(result.body.next, 0);
  assert.equal(result.body.complete, true);
  assert.equal(result.body.checkpointDigest, captured.digest);
});

test("scoped administrative reader quarantines a changed previously verified captured anchor", async () => {
  const f = await runtime.fixture();
  await open(f);
  await start(f);
  await finish(f);
  const captured = (await checkpoint(f)).body;
  assert.equal(
    (await f.send({ operation: "historyReader", checkpoint: captured })).status,
    200,
  );
  await start(f);
  await finish(f);
  const trigger = (
    await f.sql("SELECT sql FROM sqlite_master WHERE name='xeip_owner_update'")
  ).body.rows[0].sql;
  await f.sql("DROP TRIGGER xeip_owner_update");
  await f.sql(
    "UPDATE xeip_owner_events SET checksum=? WHERE sequence=2",
    "a".repeat(64),
  );
  await f.sql(trigger);
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreUnavailable",
  );
});

for (const [field, mutate] of [
  [
    "operator",
    (e) => {
      e.operator = "operations:other";
    },
  ],
  [
    "requestId",
    (e) => {
      e.requestId = randomUUID();
    },
  ],
  [
    "operation",
    (e) => {
      e.operation = "initialize";
    },
  ],
  [
    "commandDigest",
    (e) => {
      e.commandDigest = "b".repeat(64);
    },
  ],
  [
    "before.state",
    (e) => {
      e.before.state = "initializing";
    },
  ],
  [
    "before.trustRevision",
    (e) => {
      e.before.trustRevision = 9;
    },
  ],
  [
    "before.authorityRevision",
    (e) => {
      e.before.authorityRevision = null;
    },
  ],
]) {
  test(`journal rejects a rehashed terminal mismatch in ${field}`, async () => {
    const f = await runtime.fixture();
    await open(f);
    await start(f);
    await finish(f);
    const row = (
      await f.sql("SELECT * FROM xeip_owner_events WHERE sequence=2")
    ).body.rows[0];
    const event = JSON.parse(row.canonical);
    mutate(event);
    const encoded = canonicalize(event);
    const trigger = (
      await f.sql(
        "SELECT sql FROM sqlite_master WHERE name='xeip_owner_update'",
      )
    ).body.rows[0].sql;
    await f.sql("DROP TRIGGER xeip_owner_update");
    assert.equal(
      (
        await f.sql(
          "UPDATE xeip_owner_events SET canonical=?,checksum=? WHERE sequence=2",
          encoded,
          auditChecksum(2, row.previous, encoded),
        )
      ).status,
      200,
    );
    await f.sql(trigger);
    assert.equal(
      (await open(f, { initialize: false })).body.error,
      "StoreUnavailable",
    );
  });
}
for (const format of ["whitespace", "key-order", "escaped-scalar"]) {
  test(`journal rejects rehashed noncanonical ${format} event bytes`, async () => {
    const f = await runtime.fixture();
    await open(f);
    await start(f);
    await finish(f);
    const row = (
      await f.sql("SELECT * FROM xeip_owner_events WHERE sequence=2")
    ).body.rows[0];
    const encoded =
      format === "whitespace"
        ? " " + row.canonical
        : format === "key-order"
          ? JSON.stringify(
              Object.fromEntries(
                Object.entries(JSON.parse(row.canonical)).reverse(),
              ),
            )
          : row.canonical.replace('"completed"', '"\\u0063ompleted"');
    assert.notEqual(encoded, row.canonical);
    const trigger = (
      await f.sql(
        "SELECT sql FROM sqlite_master WHERE name='xeip_owner_update'",
      )
    ).body.rows[0].sql;
    await f.sql("DROP TRIGGER xeip_owner_update");
    assert.equal(
      (
        await f.sql(
          "UPDATE xeip_owner_events SET canonical=?,checksum=? WHERE sequence=2",
          encoded,
          auditChecksum(2, row.previous, encoded),
        )
      ).status,
      200,
    );
    await f.sql(trigger);
    assert.equal(
      (await open(f, { initialize: false })).body.error,
      "StoreUnavailable",
    );
  });
}

test("administrative capture creates a fixed-cut reader with one full history scan", async () => {
  const { organizationBundleFixture } = await import(
    "./fixtures/cloudflare/organization-bundle-harness.mjs"
  );
  const { adminRows } = organizationBundleFixture({
    actions: 0,
    attempts: 1000,
  });
  const f = await runtime.fixture();
  await open(f);
  assert.equal(
    (await f.send({ operation: "seedHistory", records: adminRows })).status,
    200,
  );
  await open(f, { initialize: false });
  await f.send({ operation: "controls", values: { historyRows: 0 } });
  const captured = await f.send({ operation: "captureReader" });
  assert.equal(captured.status, 200, JSON.stringify(captured.body));
  const cost = (await f.send({ operation: "controls" })).body.historyRows;
  assert.ok(
    cost >= 1000 && cost <= 1004,
    `read ${cost} rows for one complete capture`,
  );
  assert.equal(captured.body.headSequence, 1000);
  assert.equal(captured.body.headChecksum, adminRows.at(-1).checksum);
  await start(f);
  await finish(f);
  const last = await f.send({
    operation: "readerPage",
    options: {
      after: 984,
      previousChecksum: adminRows[983].checksum,
      limit: 16,
    },
  });
  assert.equal(last.status, 200, JSON.stringify(last.body));
  assert.equal(last.body.complete, true);
  assert.equal(last.body.next, 1000);
  assert.equal(last.body.checkpointDigest, captured.body.digest);
  await f.send({ operation: "readerClose" });
  assert.equal(
    (await f.send({ operation: "readerPage" })).body.error,
    "StoreUnavailable",
  );
});
