import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { LocalAdmission } from "./admission.mjs";
import { createRelayCore } from "./relay-core.mjs";
import { DurableStore } from "./durable.mjs";
import { ReplayWindow } from "./replay.mjs";
import { createRelay } from "./server.mjs";

const token = "a".repeat(43), entity = "urn:xeip:entity:audit", session = "urn:xeip:session:audit";
const message = id => ({ xeip: "0.1", id: "urn:xeip:message:" + id, kind: "message", sender: entity,
  session, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: id } });
const admission = () => new LocalAdmission({ credentials: [{ entity, token }],
  sessions: [{ xeip: "0.1", id: session, mode: "group", members: [entity], createdAt: new Date().toISOString() }] });
function directory(t) {
  const dir = mkdtempSync(join(tmpdir(), "xeip-acceptance-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function mockFs(t, name, replacement) {
  const original = fs[name];
  t.mock.method(fs, name, replacement(original));
  syncBuiltinESMExports();
  return () => { fs[name].mock.restore(); syncBuiltinESMExports(); };
}

test("short filesystem writes preserve complete records and manifests through compaction", t => {
  const dir = directory(t);
  const restore = mockFs(t, "writeSync", original => (fd, data, offset = 0, length = data.length - offset) => {
    if (!Buffer.isBuffer(data)) return original(fd, data);
    return original(fd, data, offset, Math.min(length, 17));
  });
  t.after(restore);
  const store = new DurableStore({ dir, fsync: "always" });
  t.after(() => store.close());
  store.append(session, message("short"));
  store.compact();
  store.close();
  const recovered = new DurableStore({ dir, fsync: "always" });
  t.after(() => recovered.close());
  assert.deepEqual(recovered.since(session, 0).entries.map(e => e.message.id), ["urn:xeip:message:short"]);
});

for (const failure of ["write", "zero-write", "fsync", "directory-fsync"]) {
  test(`${failure} failure is unavailable until recovery and never exposes failed acceptance`, t => {
    const dir = directory(t);
    const core = createRelayCore({ admission: admission(), replay: {}, durable: { dir, fsync: "always" } });
    t.after(() => core.durableStore.close());
    const principal = core.authenticate("Bearer " + token);
    assert.equal(core.routeMessage(principal, message("committed")).status, 202);
    const segment = fs.readdirSync(dir).find(name => /^segment-/.test(name));
    const inode = fs.statSync(join(dir, segment)).ino;
    const name = failure.includes("fsync") ? "fsyncSync" : "writeSync";
    const restore = mockFs(t, name, original => (fd, ...args) => {
      const stat = fs.fstatSync(fd);
      if (failure === "directory-fsync" ? stat.isDirectory() : stat.ino === inode) {
        if (failure === "zero-write") return 0;
        throw Object.assign(new Error("injected disk failure"), { code: "EIO" });
      }
      return original(fd, ...args);
    });
    try {
      const raw = message("failed");
      assert.equal(core.routeMessage(principal, raw).status, 503);
      assert.equal(core.routeMessage(principal, raw).status, 503);
      assert.equal(core.durableStore.status(), "degraded");
      assert.deepEqual(core.store.since(session, 0).entries.map(e => e.message.id), ["urn:xeip:message:committed"]);
    } finally { restore(); }
    core.durableStore.close();
    const recovered = new DurableStore({ dir, fsync: "always" });
    t.after(() => recovered.close());
    assert.equal(recovered.lookup(session, 1).message.id, "urn:xeip:message:committed");
    // A late fsync error is ambiguous: its complete record may be recovered.
    if (failure !== "fsync") {
      assert.equal(recovered.since(session, 0).gap, true);
      recovered.append(session, message("next"));
      assert.equal(recovered.since(session, 0).gap, true);
      assert.equal(recovered.since(session, 1).gap, true);
      assert.deepEqual(recovered.since(session, 1).entries.map(e => e.seq), [3]);
      assert.equal(recovered.since(session, 3).gap, false);
    }
  });
}

test("replay commits only after the acceptance operation succeeds", () => {
  const replay = new ReplayWindow();
  const raw = message("retry");
  assert.throws(() => replay.accept(raw, 1, () => { throw new Error("storage failed"); }), /storage failed/);
  let writes = 0;
  assert.equal(replay.accept(raw, 2, () => writes++).status, "new");
  assert.equal(replay.accept(raw, 3, () => writes++).status, "duplicate");
  assert.equal(writes, 1);
});

for (const automatic of [false, true]) {
  test(`${automatic ? "automatic" : "explicit"} compaction failure prevents orphaned accepted writes`, t => {
    const dir = directory(t);
    const store = new DurableStore({ dir, fsync: "batch", maxEntriesPerSession: 1, maxBytes: 1024 });
    t.after(() => store.close());
    const first = message("compaction-first");
    first.body.data = "x".repeat(400);
    store.append(session, first);
    const before = fs.readFileSync(join(dir, "manifest.json"), "utf8");
    mkdirSync(join(dir, "manifest.json.tmp"));
    if (automatic) store.append(session, message("compaction-second"));
    else assert.throws(() => store.compact());
    rmSync(join(dir, "manifest.json.tmp"), { recursive: true });
    assert.equal(store.status(), "degraded");
    assert.throws(() => store.append(session, message("orphan")), /reopen/);
    store.close();
    assert.equal(fs.readFileSync(join(dir, "manifest.json"), "utf8"), before);
    const recovered = new DurableStore({ dir, fsync: "batch", maxEntriesPerSession: 1, maxBytes: 1024 });
    t.after(() => recovered.close());
    assert.deepEqual(recovered.since(session, 0).entries.map(e => e.message.id),
      [automatic ? "urn:xeip:message:compaction-second" : first.id]);
  });
}

test("a failed append neither exposes the failed message nor evicts an accepted one", t => {
  const dir = directory(t);
  const store = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 1 });
  t.after(() => store.close());
  store.append(session, message("committed"));
  mkdirSync(join(dir, "manifest.json.tmp"));
  assert.throws(() => store.append(session, message("failed")));
  assert.deepEqual(store.since(session, 0).entries.map(e => e.message.id), ["urn:xeip:message:committed"]);
  assert.equal(store.lookup(session, 2), null);
  assert.equal(store.status(), "degraded");
  rmSync(join(dir, "manifest.json.tmp"), { recursive: true });
  assert.throws(() => store.append(session, message("failed")), /reopen/);
  store.close();
  const recovered = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 1 });
  t.after(() => recovered.close());
  assert.deepEqual(recovered.since(session, 0).entries.map(e => e.message.id), ["urn:xeip:message:committed"]);
});

test("durable failure never becomes a successful duplicate and recovery accepts the retry", t => {
  const dir = directory(t);
  const core = createRelayCore({ admission: admission(), replay: {}, durable: { dir, fsync: "always" } });
  t.after(() => core.durableStore.close());
  const principal = core.authenticate("Bearer " + token), raw = message("retry");
  mkdirSync(join(dir, "manifest.json.tmp"));
  assert.equal(core.routeMessage(principal, raw).status, 503);
  rmSync(join(dir, "manifest.json.tmp"), { recursive: true });
  assert.equal(core.routeMessage(principal, raw).status, 503);
  assert.equal(core.store.since(session, 0).entries.length, 0);
  core.durableStore.close();
  const recovered = createRelayCore({ admission: admission(), replay: {}, durable: { dir, fsync: "always" } });
  t.after(() => recovered.durableStore.close());
  const accepted = recovered.routeMessage(recovered.authenticate("Bearer " + token), raw);
  assert.equal(accepted.status, 202);
  assert.equal(accepted.body.duplicate, false);
  assert.deepEqual(recovered.store.since(session, 0).entries.map(e => e.message.id), [raw.id]);
});

test("HTTP exposes degraded storage and never acknowledges a failed durable retry", async t => {
  const dir = directory(t);
  const server = createRelay({ admission: admission(), replay: {}, durable: { dir, fsync: "always" } });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const base = "http://127.0.0.1:" + server.address().port;
  const raw = message("http");
  const send = () => fetch(base + "/messages", { method: "POST", headers: {
    Authorization: "Bearer " + token, "Content-Type": "application/json"
  }, body: JSON.stringify(raw), signal: AbortSignal.timeout(5000) });
  mkdirSync(join(dir, "manifest.json.tmp"));
  const first = await send();
  assert.equal(first.status, 503);
  assert.deepEqual(await first.json(), { error: "durable storage unavailable; reopen required" });
  rmSync(join(dir, "manifest.json.tmp"), { recursive: true });
  const retry = await send();
  assert.equal(retry.status, 503);
  await retry.body.cancel();
  assert.equal((await (await fetch(base + "/health")).json()).durable.state, "degraded");
});
