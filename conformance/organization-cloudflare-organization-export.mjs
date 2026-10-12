import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { organizationBundleFixture as fixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import {
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/errors.mjs";
import {
  actionSnapshotHasher,
  validateActionPage,
} from "../services/organization/cloudflare/action-export.mjs";
import { organizationManifest } from "../services/organization/cloudflare/organization-checkpoint.mjs";

const owner = "fixture:owner",
  other = "fixture:other",
  zero = "0".repeat(64);
const load = () =>
  import("../services/organization/cloudflare/organization-export.mjs");
function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function harness(t, source = fixture(), options = {}) {
  const { OrganizationExports } = await load();
  const state = { now: 0, closed: 0, unavailable: false };
  const captured = {
    checkpoint: source.checkpoint,
    readPage: (request) =>
      state.readPage
        ? state.readPage(request)
        : source.readPage(source.checkpoint.manifest, request),
    assertUsable() {
      if (state.unavailable) throw new StoreUnavailable();
    },
    close() {
      state.closed++;
    },
  };
  const exports = new OrganizationExports({
    organization: source.organization,
    capture: async () => captured,
    now: () => state.now,
    ...options,
  });
  t.after(() => exports.close());
  return { exports, state, captured, source };
}

test("organization export reconstructs exact canonical components from bounded parts", async (t) => {
  const records = Object.fromEntries(
    Array.from({ length: 3000 }, (_, i) => [
      "retained:" + i,
      {
        anchor: zero,
        generation: 1,
        keyDigest: zero,
        serial: 0,
        statusDigest: zero,
      },
    ]),
  );
  const { exports, source } = await harness(t, fixture({ records }));
  const begin = await exports.begin(owner);
  assert.match(begin.exportId, /^[a-f0-9-]{36}$/);
  assert.equal(begin.manifest.digest, source.checkpoint.manifest.digest);
  assert.deepEqual(Object.keys(begin.components).sort(), [
    "administration",
    "authority",
    "lifecycle",
    "trust",
  ]);
  assert.ok(begin.components.trust.parts > 1);
  for (const component of Object.keys(begin.components)) {
    const descriptor = begin.components[component],
      parts = [];
    for (let index = 0; index < descriptor.parts; index++) {
      const part = exports.part(owner, begin.exportId, component, index);
      assert.equal(part.exportId, begin.exportId);
      assert.equal(part.checkpointDigest, begin.manifest.digest);
      assert.equal(part.component, component);
      assert.equal(part.index, index);
      const bytes = Buffer.from(part.data, "base64");
      assert.equal(bytes.toString("base64"), part.data);
      assert.ok(bytes.length > 0 && bytes.length <= 262144);
      assert.ok(Buffer.byteLength(JSON.stringify(part)) < 524288);
      parts.push(bytes);
    }
    const bytes = Buffer.concat(parts);
    assert.equal(
      bytes.toString(),
      canonicalize(source.checkpoint[component]) + "\n",
    );
    assert.equal(bytes.length, descriptor.bytes);
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      descriptor.sha256,
    );
  }
});

test("organization export reserves one slot during capture and binds reads and close to its operator", async (t) => {
  const wait = deferred();
  const h = await harness(t, fixture(), { capture: () => wait.promise });
  const pending = h.exports.begin(owner);
  await assert.rejects(h.exports.begin(other), StoreConflict);
  wait.resolve(h.captured);
  const begin = await pending;
  for (const id of [begin.exportId, "not-an-export"])
    assert.throws(
      () => h.exports.part(other, id, "trust", 0),
      StoreUnavailable,
    );
  assert.throws(() => h.exports.end(other, begin.exportId), StoreUnavailable);
  assert.ok(h.exports.part(owner, begin.exportId, "trust", 0).data);
  h.exports.end(owner, begin.exportId);
  assert.equal(h.state.closed, 1);
  assert.throws(
    () => h.exports.part(owner, begin.exportId, "trust", 0),
    StoreUnavailable,
  );
  const next = await h.exports.begin(owner);
  assert.notEqual(next.exportId, begin.exportId);
});

test("organization export invalid requests and foreign operators cannot renew the idle deadline", async (t) => {
  const h = await harness(t),
    begin = await h.exports.begin(owner);
  h.state.now = 29999;
  for (const [component, index] of [
    ["../trust", 0],
    ["trust", -1],
    ["trust", 1],
    ["trust", 0.5],
  ])
    assert.throws(
      () => h.exports.part(owner, begin.exportId, component, index),
      TypeError,
    );
  assert.throws(
    () => h.exports.part(other, begin.exportId, "trust", 0),
    StoreUnavailable,
  );
  await assert.rejects(
    h.exports.page(owner, begin.exportId, { section: "actions", cursor: -1 }),
    TypeError,
  );
  h.state.now = 30000;
  assert.throws(
    () => h.exports.part(owner, begin.exportId, "trust", 0),
    StoreUnavailable,
  );
  assert.equal(h.state.closed, 1);
  assert.notEqual((await h.exports.begin(owner)).exportId, begin.exportId);
});

test("organization export successful reads renew idle expiry but never its absolute lifetime", async (t) => {
  const h = await harness(t),
    begin = await h.exports.begin(owner);
  for (let now = 29000; now < 3600000; now += 29000) {
    h.state.now = now;
    assert.ok(h.exports.part(owner, begin.exportId, "trust", 0).data);
  }
  h.state.now = 3600000;
  assert.throws(
    () => h.exports.part(owner, begin.exportId, "trust", 0),
    StoreUnavailable,
  );
  assert.equal(h.state.closed, 1);
});

test("organization export timer releases buffers and readers without further requests", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const h = await harness(t);
  await h.exports.begin(owner);
  h.state.now = 30000;
  t.mock.timers.tick(30000);
  assert.equal(h.state.closed, 1);
  await h.exports.begin(owner);
});

test("organization export source close rejects pending capture and disposes its late result", async (t) => {
  const wait = deferred(),
    h = await harness(t, fixture(), { capture: () => wait.promise });
  const pending = h.exports.begin(owner);
  await Promise.resolve();
  h.exports.close();
  await assert.rejects(pending, StoreUnavailable);
  wait.resolve(h.captured);
  await new Promise((done) => setImmediate(done));
  assert.equal(h.state.closed, 1);
  await assert.rejects(h.exports.begin(owner), StoreUnavailable);
});

test("organization export captures validated source scope and releases rejected evidence", async (t) => {
  const h = await harness(t, fixture(), { organization: "foreign" });
  await assert.rejects(h.exports.begin(owner), StoreUnavailable);
  assert.equal(h.state.closed, 1);
});

test("organization export validates history evidence before returning or renewing it", async (t) => {
  const h = await harness(t, fixture({ revisions: 1, attempts: 2 }));
  const begin = await h.exports.begin(owner);
  const page = await h.exports.page(owner, begin.exportId, {
    section: "authority",
    cursor: {},
  });
  assert.equal(page.exportId, begin.exportId);
  assert.equal(page.checkpointDigest, begin.manifest.digest);
  assert.deepEqual(
    page.page.records.map((r) => r.revision),
    [0, 1],
  );
  h.state.readPage = async () => ({
    checkpointDigest: zero,
    section: "actions",
    page: {},
  });
  await assert.rejects(
    h.exports.page(owner, begin.exportId, { section: "actions", cursor: 0 }),
    StoreUnavailable,
  );
  assert.equal(h.state.closed, 1);
  assert.throws(
    () => h.exports.part(owner, begin.exportId, "trust", 0),
    StoreUnavailable,
  );
});

test("organization export source failure invalidates cached parts immediately", async (t) => {
  const h = await harness(t),
    begin = await h.exports.begin(owner);
  h.state.unavailable = true;
  assert.throws(
    () => h.exports.part(owner, begin.exportId, "trust", 0),
    StoreUnavailable,
  );
  assert.equal(h.state.closed, 1);
});

test("organization export discards a history response arriving after close", async (t) => {
  const wait = deferred(),
    h = await harness(t),
    begin = await h.exports.begin(owner);
  h.state.readPage = () => wait.promise;
  const pending = h.exports.page(owner, begin.exportId, {
    section: "actions",
    cursor: 0,
  });
  h.exports.end(owner, begin.exportId);
  await assert.rejects(pending, StoreUnavailable);
  wait.resolve(
    await h.source.readPage(h.source.checkpoint.manifest, {
      section: "actions",
      cursor: 0,
    }),
  );
  await new Promise((done) => setImmediate(done));
  assert.equal(h.state.closed, 1);
});

test("organization export preserves a healthy session after a caller predecessor conflict", async (t) => {
  const h = await harness(t),
    begin = await h.exports.begin(owner);
  h.state.readPage = async () => {
    throw new TypeError("invalid predecessor");
  };
  await assert.rejects(
    h.exports.page(owner, begin.exportId, {
      section: "authority",
      cursor: { after: 0, previousChecksum: "a".repeat(64) },
    }),
    TypeError,
  );
  delete h.state.readPage;
  assert.equal(
    (
      await h.exports.page(owner, begin.exportId, {
        section: "authority",
        cursor: {},
      })
    ).page.complete,
    true,
  );
});

test("organization export pending history read cannot be prolonged by overlapping part requests", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const wait = deferred(),
    h = await harness(t),
    begin = await h.exports.begin(owner);
  h.state.readPage = () => wait.promise;
  const pending = h.exports.page(owner, begin.exportId, {
    section: "actions",
    cursor: 0,
  });
  h.state.now = 29999;
  assert.throws(
    () => h.exports.part(owner, begin.exportId, "trust", 0),
    StoreConflict,
  );
  await assert.rejects(
    h.exports.page(owner, begin.exportId, { section: "actions", cursor: 0 }),
    StoreConflict,
  );
  h.state.now = 30000;
  t.mock.timers.tick(30000);
  await assert.rejects(pending, StoreUnavailable);
  assert.equal(h.state.closed, 1);
});

test("organization export expired capture cannot displace its replacement on late completion", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const wait = deferred();
  let first = true;
  const h = await harness(t, fixture(), {
    capture: () => {
      if (first) {
        first = false;
        return wait.promise;
      }
      return Promise.resolve({ ...h.captured, close() {} });
    },
  });
  const pending = h.exports.begin(owner);
  await Promise.resolve();
  h.state.now = 30000;
  t.mock.timers.tick(30000);
  await assert.rejects(pending, StoreUnavailable);
  const replacement = await h.exports.begin(other);
  wait.resolve(h.captured);
  await new Promise((done) => setImmediate(done));
  assert.equal(h.state.closed, 1);
  assert.ok(h.exports.part(other, replacement.exportId, "trust", 0).data);
});

test("organization export never starts source capture after synchronous source closure", async (t) => {
  let captures = 0;
  const h = await harness(t, fixture(), {
    capture: async () => {
      captures++;
      return h.captured;
    },
  });
  const pending = h.exports.begin(owner);
  h.exports.close();
  await assert.rejects(pending, StoreUnavailable);
  assert.equal(captures, 0);
});

test("organization export preserves valid action evidence above 256 KiB", async (t) => {
  const source = fixture({ actions: 1, states: ["succeeded"] });
  const record = source.actionRows[0],
    request = JSON.parse(record.row.canonical);
  request.arguments.private = '"'.repeat(30000);
  record.row.canonical = canonicalize(request);
  record.row.digest = createHash("sha256")
    .update("XEIP organization action v1\n" + record.row.canonical)
    .digest("hex");
  for (const event of record.history) event.digest = record.row.digest;
  record.row.result_canonical = canonicalize({
    content: [{ type: "text", text: '"'.repeat(60000) }],
  });
  const page = { cut: 4, after: 0, next: 1, record };
  validateActionPage(page, { cut: 4, after: 0 });
  assert.ok(Buffer.byteLength(canonicalize(page)) > 262144);
  const { digest: _, ...header } = source.checkpoint.manifest.actions;
  const digest = actionSnapshotHasher(header)
    .update(canonicalize(record) + "\n")
    .digest("hex");
  source.checkpoint = {
    ...source.checkpoint,
    manifest: organizationManifest(source.checkpoint, { ...header, digest }),
  };
  const h = await harness(t, source),
    begin = await h.exports.begin(owner);
  h.state.readPage = async () => ({
    checkpointDigest: begin.manifest.digest,
    section: "actions",
    page,
  });
  const exported = await h.exports.page(owner, begin.exportId, {
    section: "actions",
    cursor: 0,
  });
  assert.equal(
    exported.page.record.row.result_canonical,
    record.row.result_canonical,
  );
  assert.ok(Buffer.byteLength(canonicalize(exported)) < 524288);
});
