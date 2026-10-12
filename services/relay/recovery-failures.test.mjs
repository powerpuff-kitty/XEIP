import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DurableStore, ReceiptLog } from "./durable.mjs";
import { ReceiptLedger } from "./receipts.mjs";
import { LocalAdmission } from "./admission.mjs";
import { createRelay } from "./server.mjs";

const session = "urn:test:session", principal = { entity: "urn:test:entity" };
const record = seq => ({ principal: "p", session: "s", id: "m" + seq, seq, expiresAt: Date.now() + 60000 });
function directory(t) {
  const dir = fs.mkdtempSync(join(tmpdir(), "xeip-recovery-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function fault(t, method, matches) {
  const original = fs[method];
  const mocked = t.mock.method(fs, method, (...args) => {
    if (matches(...args)) throw Object.assign(new Error("injected disk failure"), { code: "EIO" });
    return original(...args);
  });
  syncBuiltinESMExports();
  return () => { mocked.mock.restore(); syncBuiltinESMExports(); };
}

for (const receipts of [false, true]) {
  test(`${receipts ? "receipt" : "delivery"} recovery refuses a torn tail it cannot truncate`, t => {
    const dir = directory(t);
    const store = receipts ? new ReceiptLog({ dir, fsync: "always" }) : new DurableStore({ dir, fsync: "always" });
    if (receipts) store.append(record(1));
    else store.append(session, { id: "urn:test:message" });
    store.close();
    const file = receipts ? join(dir, "receipts.log") : join(dir, fs.readdirSync(dir).find(name => name.startsWith("segment-")));
    fs.appendFileSync(file, Buffer.from([0, 0, 0]));
    const restore = fault(t, "truncateSync", path => path === file);
    try {
      assert.throws(() => receipts ? new ReceiptLog({ dir }) : new DurableStore({ dir }), /injected disk failure/);
      assert.equal(fs.existsSync(join(dir, "LOCK")), false);
    } finally { restore(); }
    const recovered = receipts ? new ReceiptLog({ dir }) : new DurableStore({ dir });
    t.after(() => recovered.close());
    assert.equal(receipts ? recovered.load().length : recovered.since(session, 0).entries.length, 1);
  });
}

for (const operation of ["read", "quarantine"]) {
  test(`receipt recovery refuses a failed ${operation}`, t => {
    const dir = directory(t), file = join(dir, "receipts.log");
    const log = new ReceiptLog({ dir });
    log.append(record(1)); log.append(record(2)); log.close();
    if (operation === "quarantine") {
      const bytes = fs.readFileSync(file); bytes[36] ^= 255; fs.writeFileSync(file, bytes);
    }
    const restore = fault(t, operation === "read" ? "readFileSync" : "renameSync", path => path === file);
    try { assert.throws(() => new ReceiptLog({ dir }), /injected disk failure/); }
    finally { restore(); }
  });
}

for (const operation of ["append", "compact"]) {
  test(`receipt ${operation} faults stop later writes and report degraded health`, t => {
    const dir = directory(t), log = new ReceiptLog({ dir, fsync: "always" });
    t.after(() => log.close());
    log.append(record(1));
    const restore = fault(t, "writeSync", () => true);
    try { assert.throws(() => operation === "append" ? log.append(record(2)) : log.compact([record(1)]), /injected/); }
    finally { restore(); }
    assert.equal(log.status, "degraded");
    assert.throws(() => log.append(record(3)), /reopen/);
    assert.throws(() => log.compact([]), /reopen/);
    log.close();
    const recovered = new ReceiptLog({ dir });
    t.after(() => recovered.close());
    assert.deepEqual(recovered.load().map(r => r.seq), [1]);
  });
}

test("a failed receipt persistence operation neither commits a duplicate nor evicts earlier receipts", t => {
  const dir = directory(t), log = new ReceiptLog({ dir, fsync: "always" });
  t.after(() => log.close());
  const ledger = new ReceiptLedger({ maxPerSession: 1 }, log);
  ledger.record(principal, session, 1, "urn:test:first");
  const mock = t.mock.method(log, "append", () => { throw new Error("injected failure before write"); });
  assert.throws(() => ledger.record(principal, session, 2, "urn:test:second"));
  mock.mock.restore();
  assert.equal(ledger.record(principal, session, 1, "urn:test:first").duplicate, true);
  assert.equal(ledger.record(principal, session, 2, "urn:test:second").duplicate, false);
});

test("HTTP receipt storage failure returns 503 on the first attempt and retry with degraded health", async t => {
  const dir = directory(t), token = "r".repeat(43);
  const admission = new LocalAdmission({ credentials: [{ entity: principal.entity, token }],
    sessions: [{ xeip: "0.1", id: session, mode: "group", members: [principal.entity], createdAt: new Date().toISOString() }] });
  const server = createRelay({ admission, durable: { dir, fsync: "always" }, receipts: {} });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const base = "http://127.0.0.1:" + server.address().port;
  const post = (path, body) => fetch(base + path, { method: "POST", headers: {
    Authorization: "Bearer " + token, "Content-Type": "application/json"
  }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
  const accepted = await post("/messages", { xeip: "0.1", id: "urn:test:message", kind: "message", sender: principal.entity,
    session, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "test" } });
  assert.equal(accepted.status, 202); await accepted.body.cancel();
  const inode = fs.statSync(join(dir, "receipts.log")).ino;
  const restore = fault(t, "writeSync", fd => fs.fstatSync(fd).ino === inode);
  try {
    const response = await post("/receipts", { session, seq: 1 });
    assert.equal(response.status, 503); await response.body.cancel();
  } finally { restore(); }
  const retry = await post("/receipts", { session, seq: 1 });
  assert.equal(retry.status, 503); await retry.body.cancel();
  assert.equal((await (await fetch(base + "/health")).json()).durable.state, "degraded");
});

test("a full receipt log does not hide a required compaction failure", t => {
  const dir = directory(t), log = new ReceiptLog({ dir, maxBytes: 1 });
  t.after(() => log.close());
  const ledger = new ReceiptLedger({}, log);
  fs.mkdirSync(join(dir, "receipts.log.tmp"));
  assert.throws(() => ledger.record(principal, session, 1, "urn:test:first"));
  assert.equal(log.status, "degraded");
  assert.equal(fs.statSync(join(dir, "receipts.log")).size, 0);
});

test("failed required compaction preserves receipt entries and does not commit a duplicate", t => {
  const dir = directory(t), log = new ReceiptLog({ dir });
  t.after(() => log.close());
  const ledger = new ReceiptLedger({ maxPerSession: 1 }, log);
  ledger.record(principal, session, 1, "urn:test:first");
  const append = t.mock.method(log, "append", () => "full");
  const compact = t.mock.method(log, "compact", () => { throw new Error("injected compaction failure"); });
  assert.throws(() => ledger.record(principal, session, 2, "urn:test:second"), /injected/);
  append.mock.restore(); compact.mock.restore();
  assert.equal(ledger.record(principal, session, 1, "urn:test:first").duplicate, true);
  assert.equal(ledger.record(principal, session, 2, "urn:test:second").duplicate, false);
});

test("failed lock initialization releases only the newly acquired lock", t => {
  const dir = directory(t);
  const restore = fault(t, "writeSync", () => true);
  try { assert.throws(() => new DurableStore({ dir }), /injected/); }
  finally { restore(); }
  assert.equal(fs.existsSync(join(dir, "LOCK")), false);
  const store = new DurableStore({ dir });
  t.after(() => store.close());
  assert.throws(() => new DurableStore({ dir }), /locked/);
  assert.equal(fs.existsSync(join(dir, "LOCK")), true);
});

test("receipt initialization closes its descriptor if stat fails", t => {
  const dir = directory(t);
  let descriptor;
  const restore = fault(t, "fstatSync", fd => { descriptor = fd; return true; });
  try { assert.throws(() => new ReceiptLog({ dir }), /injected/); }
  finally { restore(); }
  assert.throws(() => fs.fstatSync(descriptor), { code: "EBADF" });
});
