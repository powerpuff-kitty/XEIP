import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelay } from "./server.mjs";
import { LocalAdmission } from "./admission.mjs";
import { BATCH_FSYNC, DurableStore, ReceiptLog, LOCAL_DURABLE_PROFILE } from "./durable.mjs";
import { ReceiptLedger } from "./receipts.mjs";
import { digestHex } from "./primitives.mjs";

const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b";
const room = "urn:xeip:session:ab";
const principal = entity => ({ entity });
const d = digestHex;
const secret = () => randomBytes(32).toString("base64url");

function makeDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "xeip-durable-receipts-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// In-memory stand-in for ReceiptLog so the ledger reload rules can be exercised
// with synthetic wall expiries and bounds, independently of the file format.
class FakeBackend {
  records = [];
  load() { return this.records.map(record => ({ ...record })); }
  append(record) { this.records.push({ ...record }); }
  compact(records) { this.records = records.map(record => ({ ...record })); }
}

const persisted = (entity, session, id, seq, expiresAt) =>
  ({ principal: d(entity), session: d(session), id: d(id), seq, expiresAt });

const record = (seq, expiresAt) => ({ ...persisted(a, room, "urn:xeip:message:" + seq, seq, expiresAt) });

test("receipt log round-trips digest-only records and reopens them", t => {
  const dir = makeDir(t);
  const line = record(7, Date.now() + 60000);
  const log = new ReceiptLog({ dir, fsync: "always" });
  assert.equal(log.status, "ok");
  log.append(line);
  log.close();
  const text = readFileSync(log.path, "utf8");
  assert.equal(text.includes("urn:xeip"), false, "on-disk data is digest-only");
  const reopened = new ReceiptLog({ dir });
  assert.equal(reopened.status, "ok");
  assert.deepEqual(reopened.load(), [line]);
  reopened.close();
});

test("receipt log drops a torn tail and reports recovered", t => {
  const dir = makeDir(t);
  const first = record(1, Date.now() + 60000);
  const second = record(2, Date.now() + 60000);
  const log = new ReceiptLog({ dir, fsync: "always" });
  log.append(first);
  log.append(second);
  log.close();
  truncateSync(log.path, statSync(log.path).size - 1);
  const reopened = new ReceiptLog({ dir });
  assert.equal(reopened.status, "recovered");
  assert.deepEqual(reopened.load(), [first]);
  reopened.close();
});

test("receipt log fails closed on interior corruption and preserves the file", t => {
  const dir = makeDir(t);
  const log = new ReceiptLog({ dir, fsync: "always" });
  log.append(record(1, Date.now() + 60000));
  log.append(record(2, Date.now() + 60000));
  log.close();
  const buffer = readFileSync(log.path);
  buffer[36] ^= 0xff; // first (non-tail) record payload
  writeFileSync(log.path, buffer);

  const reopened = new ReceiptLog({ dir });
  assert.equal(reopened.status, "degraded");
  assert.deepEqual(reopened.load(), []);
  assert.ok(existsSync(log.path + ".corrupt"), "the unreadable log is moved aside");

  // Appending after a fail-closed load starts a clean, readable log.
  const fresh = record(3, Date.now() + 60000);
  reopened.append(fresh);
  reopened.close();
  const third = new ReceiptLog({ dir });
  assert.equal(third.status, "ok");
  assert.deepEqual(third.load(), [fresh]);
  third.close();
});

test("receipt log rejects invalid configuration", t => {
  const dir = makeDir(t);
  for (const configuration of [null, [], "bad", { extra: true }, { dir, fsync: "sometimes" }]) {
    assert.throws(() => new ReceiptLog(configuration));
  }
  assert.throws(() => new ReceiptLog());
  assert.throws(() => new ReceiptLog({ dir: "" }));
  assert.throws(() => new ReceiptLog({ dir, maxBytes: 0 }));
  assert.throws(() => new ReceiptLog({ dir, compactAfter: 0 }));
});

test("a structurally invalid but checksum-valid record is quarantined and the log recovers", t => {
  const dir = makeDir(t);
  const good = record(1, Date.now() + 60000);
  const log = new ReceiptLog({ dir, fsync: "always" });
  log.append(good);
  log.append({ bogus: true }); // checksum-valid framing, schema-invalid payload
  log.close();

  const reopened = new ReceiptLog({ dir });
  assert.equal(reopened.status, "degraded");
  assert.deepEqual(reopened.load(), []);
  assert.ok(existsSync(log.path + ".corrupt"), "the poisoned log is moved aside");
  reopened.close();

  // The next start sees a clean, empty log rather than poisoning forever.
  const recovered = new ReceiptLog({ dir });
  assert.equal(recovered.status, "ok");
  assert.deepEqual(recovered.load(), []);
  recovered.close();
});

test("fsync policy mirrors the delivery batch interval", t => {
  const always = new ReceiptLog({ dir: makeDir(t), fsync: "always" });
  always.append(record(1, Date.now() + 60000));
  assert.equal(always.fsyncs, 1, "always fsyncs each line");
  always.close();

  const batch = new ReceiptLog({ dir: makeDir(t), fsync: "batch" });
  for (let seq = 1; seq < BATCH_FSYNC; seq++) batch.append(record(seq, Date.now() + 60000));
  assert.equal(batch.fsyncs, 0, "batch waits for the interval");
  batch.append(record(BATCH_FSYNC, Date.now() + 60000));
  assert.equal(batch.fsyncs, 1, "batch fsyncs on the interval");
  batch.close();

  const never = new ReceiptLog({ dir: makeDir(t), fsync: "never" });
  for (let seq = 1; seq <= BATCH_FSYNC; seq++) never.append(record(seq, Date.now() + 60000));
  never.close();
  assert.equal(never.fsyncs, 0, "never never fsyncs");
});

test("repeated re-acks keep the on-disk receipt log bounded", t => {
  const dir = makeDir(t);
  const log = new ReceiptLog({ dir, fsync: "never", maxBytes: 4096, compactAfter: 16 });
  const ledger = new ReceiptLedger({}, log);
  for (let index = 0; index < 500; index++) {
    assert.deepEqual(ledger.record(principal(a), room, 1, "urn:xeip:message:one", index),
      { duplicate: index > 0 });
  }
  assert.ok(statSync(log.path).size <= 4096, "the log stays within its hard byte budget");
  log.close();

  // The single live receipt survived the online compactions and reloads.
  const reopened = new ReceiptLog({ dir });
  assert.equal(reopened.status, "ok");
  const reloaded = new ReceiptLedger({}, reopened);
  assert.deepEqual(reloaded.record(principal(a), room, 1, "urn:xeip:message:one", 1000), { duplicate: true });
  reopened.close();
});

test("a ledger reloaded from a backend reports an idempotent duplicate", () => {
  const backend = new FakeBackend();
  const first = new ReceiptLedger({}, backend);
  assert.deepEqual(first.record(principal(a), room, 1, "urn:xeip:message:one", 0), { duplicate: false });
  const second = new ReceiptLedger({}, backend);
  assert.deepEqual(second.record(principal(a), room, 1, "urn:xeip:message:one", 0), { duplicate: true });
  assert.deepEqual(second.record(principal(b), room, 1, "urn:xeip:message:one", 0), { duplicate: false });
});

test("an expired receipt is gone after reload", () => {
  const backend = new FakeBackend();
  backend.records.push(persisted(a, room, "urn:xeip:message:one", 1, Date.now() - 1000));
  const ledger = new ReceiptLedger({}, backend);
  assert.deepEqual(ledger.record(principal(a), room, 1, "urn:xeip:message:one", 0), { duplicate: false });
});

test("reload rebuilds the per-(session, principal) and per-principal bounds", () => {
  const wall = Date.now();
  const pair = new FakeBackend();
  for (const seq of [1, 2, 3]) pair.records.push(persisted(a, room, "urn:xeip:message:" + seq, seq, wall + seq * 1000));
  const bounded = new ReceiptLedger({ maxPerSession: 2 }, pair);
  assert.deepEqual(bounded.record(principal(a), room, 1, "urn:xeip:message:1", 0), { duplicate: false });
  assert.deepEqual(bounded.record(principal(a), room, 3, "urn:xeip:message:3", 0), { duplicate: true });

  const perPrincipal = new FakeBackend();
  const sessions = ["urn:xeip:session:one", "urn:xeip:session:two", "urn:xeip:session:three"];
  sessions.forEach((session, index) => perPrincipal.records.push(persisted(a, session, "urn:xeip:message:x", 1, wall + (index + 1) * 1000)));
  const capped = new ReceiptLedger({ maxPerSession: 10, maxPerPrincipal: 2 }, perPrincipal);
  assert.deepEqual(capped.record(principal(a), sessions[0], 1, "urn:xeip:message:x", 0), { duplicate: false });
  assert.deepEqual(capped.record(principal(a), sessions[2], 1, "urn:xeip:message:x", 0), { duplicate: true });
});

// --- end-to-end relay restart over the durable directory ---

async function start(t, dir) {
  const credentials = new Map([a, b].map(entity => [entity, secret()]));
  const admission = new LocalAdmission({
    credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [{ xeip: "0.1", id: room, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" }]
  });
  const server = createRelay({ admission, durable: { dir, fsync: "always" }, receipts: {} });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const base = "http://127.0.0.1:" + server.address().port;
  let stopped = false;
  const state = {
    base,
    stop: async () => {
      if (stopped) return;
      stopped = true;
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  };
  t.after(state.stop);
  state.post = envelope => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + credentials.get(a), "Content-Type": "application/json" },
    body: JSON.stringify(envelope), signal: AbortSignal.timeout(5000) });
  state.receipt = (actor, document) => fetch(base + "/receipts", { method: "POST",
    headers: { Authorization: "Bearer " + credentials.get(actor), "Content-Type": "application/json" },
    body: JSON.stringify(document), signal: AbortSignal.timeout(5000) });
  return state;
}

const envelope = () => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender: a, recipient: b,
  session: room, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "hello" } });

test("a receipt survives a relay restart and stays idempotent and digest-only", async t => {
  const dir = makeDir(t);
  const target = envelope();
  const first = await start(t, dir);
  const accepted = await first.post(target);
  assert.equal(accepted.status, 202);
  const { seq } = await accepted.json();
  assert.deepEqual(await (await first.receipt(b, { session: room, seq })).json(),
    { acknowledged: true, session: room, seq, duplicate: false });
  await first.stop();

  const second = await start(t, dir);
  const health = await (await fetch(second.base + "/health")).json();
  assert.equal(health.durableProfile, LOCAL_DURABLE_PROFILE);
  assert.equal(health.durable.state, "ok");
  assert.deepEqual(await (await second.receipt(b, { session: room, seq })).json(),
    { acknowledged: true, session: room, seq, duplicate: true });

  const onDisk = readFileSync(join(dir, "receipts.log"), "utf8");
  assert.equal(onDisk.includes("hello"), false, "no envelope copy on disk");
  assert.equal(onDisk.includes(target.id), false, "the message id is digested");
  await second.stop();
});

test("a torn receipt log tail is recovered across restart", async t => {
  const dir = makeDir(t);
  const first = await start(t, dir);
  const firstSeq = (await (await first.post(envelope())).json()).seq;
  const secondSeq = (await (await first.post(envelope())).json()).seq;
  assert.equal((await first.receipt(b, { session: room, seq: firstSeq })).status, 202);
  assert.equal((await first.receipt(b, { session: room, seq: secondSeq })).status, 202);
  await first.stop();

  const file = join(dir, "receipts.log");
  truncateSync(file, statSync(file).size - 1);

  const second = await start(t, dir);
  const health = await (await fetch(second.base + "/health")).json();
  assert.equal(health.durable.state, "recovered");
  assert.equal((await (await second.receipt(b, { session: room, seq: firstSeq })).json()).duplicate, true);
  assert.equal((await (await second.receipt(b, { session: room, seq: secondSeq })).json()).duplicate, false);
  await second.stop();
});

test("a corrupt receipt log does not crash startup and fails closed", async t => {
  const dir = makeDir(t);
  const first = await start(t, dir);
  const firstSeq = (await (await first.post(envelope())).json()).seq;
  const secondSeq = (await (await first.post(envelope())).json()).seq;
  assert.equal((await first.receipt(b, { session: room, seq: firstSeq })).status, 202);
  assert.equal((await first.receipt(b, { session: room, seq: secondSeq })).status, 202);
  await first.stop();

  const file = join(dir, "receipts.log");
  const buffer = readFileSync(file);
  buffer[36] ^= 0xff; // interior record payload
  writeFileSync(file, buffer);

  const second = await start(t, dir);
  const health = await (await fetch(second.base + "/health")).json();
  assert.equal(health.durable.state, "degraded");
  // Receipts are gone (failed closed); correlation still succeeds, so it is a
  // fresh first record rather than a duplicate.
  assert.equal((await (await second.receipt(b, { session: room, seq: firstSeq })).json()).duplicate, false);
  await second.stop();
});

test("an invalid receipts config does not leak the durable lock", t => {
  const dir = makeDir(t);
  const credentials = new Map([a, b].map(entity => [entity, secret()]));
  const admission = new LocalAdmission({
    credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [{ xeip: "0.1", id: room, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" }]
  });
  // Constructing the ledger throws after the durable store took its lock; the
  // core must close the store so the directory is not left locked or held open.
  assert.throws(() => createRelay({ admission, durable: { dir }, receipts: { windowMs: 0 } }), /receipts/);
  const store = new DurableStore({ dir, fsync: "always" });
  assert.equal(store.status(), "ok");
  store.close();
});

test("openReceiptLog is created once and shares the store directory", t => {
  const dir = makeDir(t);
  const store = new DurableStore({ dir, fsync: "always" });
  const log = store.openReceiptLog();
  assert.equal(store.openReceiptLog(), log);
  assert.equal(log.path, join(dir, "receipts.log"));
  store.close();
});
