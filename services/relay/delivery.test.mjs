import test from "node:test";
import assert from "node:assert/strict";
import { DeliveryLog } from "./delivery.mjs";

const message = (id = "one") => ({ xeip: "0.1", id: "urn:xeip:message:" + id, kind: "message",
  sender: "urn:xeip:entity:a", recipient: "urn:xeip:entity:b", session: "urn:xeip:session:ab",
  timestamp: "2026-10-09T00:00:00Z", body: { contentType: "text/plain", data: id } });
const sessionA = "urn:xeip:session:ab";
const sessionB = "urn:xeip:session:cd";

test("requires bounded integer delivery configuration", () => {
  for (const configuration of [null, [], "bad", { extra: true }, { windowMs: 0 }, { windowMs: 3600001 },
    { windowMs: 1.5 }, { maxPerSession: 0 }, { maxPerSession: 4097 }, { maxSessions: 0 },
    { maxSessions: 1025 }, { maxSessions: "2" }]) assert.throws(() => new DeliveryLog(configuration));
});

test("assigns monotonic per-session sequences that are independent across sessions", () => {
  const log = new DeliveryLog();
  assert.equal(log.append(sessionA, message("a1"), 0), 1);
  assert.equal(log.append(sessionA, message("a2"), 0), 2);
  assert.equal(log.append(sessionB, message("b1"), 0), 1);
  assert.equal(log.append(sessionA, message("a3"), 0), 3);
});

test("resumes contiguous entries after a cursor without a gap", () => {
  const log = new DeliveryLog();
  log.append(sessionA, message("a1"), 0);
  log.append(sessionA, message("a2"), 0);
  log.append(sessionA, message("a3"), 0);
  assert.deepEqual(log.since(sessionA, 0).entries.map(entry => entry.seq), [1, 2, 3]);
  assert.equal(log.since(sessionA, 0).gap, false);
  assert.deepEqual(log.since(sessionA, 2).entries.map(entry => entry.seq), [3]);
  assert.equal(log.since(sessionA, 2).gap, false);
  assert.deepEqual(log.since(sessionA, 3).entries, []);
  assert.equal(log.since(sessionA, 3).gap, false);
  assert.deepEqual(log.since("urn:xeip:session:unknown", 7), { entries: [], gap: false, from: 8 });
});

test("reports a gap when the cursor predates the oldest retained entry", () => {
  const log = new DeliveryLog({ maxPerSession: 1, maxSessions: 8 });
  log.append(sessionA, message("a1"), 0);
  log.append(sessionA, message("a2"), 0);
  const resumed = log.since(sessionA, 0);
  assert.equal(resumed.gap, true);
  assert.equal(resumed.from, 2);
  assert.deepEqual(resumed.entries.map(entry => entry.seq), [2]);
  assert.equal(log.since(sessionA, 1).gap, false);
});

test("expires entries by a fixed monotonic window without moving the clock backwards", () => {
  const log = new DeliveryLog({ windowMs: 100, maxPerSession: 8 });
  assert.equal(log.append(sessionA, message("a1"), 0), 1);
  assert.equal(log.append(sessionA, message("a2"), 50), 2);
  assert.equal(log.since(sessionA, 0, 50).entries.length, 2);
  assert.equal(log.append(sessionA, message("a3"), 200), 3);
  const resumed = log.since(sessionA, 0, 200);
  assert.equal(resumed.from, 3);
  assert.equal(resumed.gap, true);
  assert.deepEqual(resumed.entries.map(entry => entry.seq), [3]);
  // A later append with a smaller elapsed value must not resurrect expired entries.
  log.append(sessionA, message("a4"), 150);
  assert.deepEqual(log.since(sessionA, 0, 200).entries.map(entry => entry.seq), [3, 4]);
});

test("reclaims entries past the window on resume even without a new append", () => {
  const log = new DeliveryLog({ windowMs: 100, maxPerSession: 8 });
  log.append(sessionA, message("a1"), 0);
  assert.deepEqual(log.since(sessionA, 0, 99).entries.map(entry => entry.seq), [1]);
  const expired = log.since(sessionA, 0, 100);
  assert.deepEqual(expired.entries, []);
  assert.equal(expired.gap, true);
  assert.equal(expired.from, 2);
  for (const elapsed of [NaN, Infinity, -1, "1"]) assert.throws(() => log.since(sessionA, 0, elapsed));
});

test("bounds retained entries per session and evicts least-recently-used sessions", () => {
  const log = new DeliveryLog({ maxPerSession: 2, maxSessions: 1 });
  log.append(sessionA, message("a1"), 0);
  log.append(sessionA, message("a2"), 0);
  log.append(sessionA, message("a3"), 0);
  assert.deepEqual(log.since(sessionA, 0).entries.map(entry => entry.seq), [2, 3]);
  log.append(sessionB, message("b1"), 1);
  assert.deepEqual(log.since(sessionA, 0), { entries: [], gap: true, from: 4 });
  assert.deepEqual(log.since(sessionB, 0).entries.map(entry => entry.message.body.data), ["b1"]);
});

test("reports a gap and preserves sequence after a session is evicted", () => {
  const log = new DeliveryLog({ maxSessions: 1, maxPerSession: 4 });
  assert.equal(log.append(sessionA, message("a1"), 0), 1);
  assert.equal(log.append(sessionB, message("b1"), 0), 1); // evicts A after seq 1
  assert.deepEqual(log.since(sessionA, 0, 0), { entries: [], gap: true, from: 2 });
  assert.equal(log.append(sessionA, message("a2"), 0), 2); // continues monotonically
  assert.deepEqual(log.since(sessionA, 1, 0).entries.map(entry => entry.seq), [2]);
});

test("resuming a session keeps it from least-recently-used eviction", () => {
  const log = new DeliveryLog({ maxSessions: 2, maxPerSession: 4 });
  log.append(sessionA, message("a1"), 0);
  log.append(sessionB, message("b1"), 0);
  log.since(sessionA, 0, 0); // touch A so A is more recent than B
  log.append("urn:xeip:session:ef", message("c1"), 0);
  assert.equal(log.since(sessionA, 0, 0).entries.length, 1);
  assert.equal(log.since(sessionB, 0, 0).gap, true);
});

test("looks up retained entries by sequence and id without changing retention", () => {
  const log = new DeliveryLog({ windowMs: 100, maxPerSession: 4 });
  log.append(sessionA, message("a1"), 0);
  log.append(sessionA, message("a2"), 0);
  assert.equal(log.lookup(sessionA, 1, 0).message.id, "urn:xeip:message:a1");
  assert.equal(log.lookup(sessionA, 99, 0), null);
  assert.equal(log.lookup("urn:xeip:session:unknown", 1, 0), null);
  assert.equal(log.lookupById(sessionA, "urn:xeip:message:a2", 0).seq, 2);
  assert.equal(log.lookupById(sessionA, "urn:xeip:message:missing", 0), null);
  assert.deepEqual(log.lookupAllById(sessionA, "urn:xeip:message:a1", 0).map(entry => entry.seq), [1]);
  // A lookup is not activity and must not reclaim or reorder retained entries.
  assert.deepEqual(log.since(sessionA, 0, 0).entries.map(entry => entry.seq), [1, 2]);
  for (const elapsed of [NaN, Infinity, -1, "1"]) {
    assert.throws(() => log.lookup(sessionA, 1, elapsed));
    assert.throws(() => log.lookupById(sessionA, "urn:xeip:message:a1", elapsed));
  }
});

test("reports every retained id match and excludes entries past the window", () => {
  const log = new DeliveryLog({ windowMs: 100, maxPerSession: 8 });
  log.append(sessionA, message("same"), 0);
  log.append(sessionA, message("other"), 0);
  log.append(sessionA, message("same"), 0);
  assert.deepEqual(log.lookupAllById(sessionA, "urn:xeip:message:same", 0).map(entry => entry.seq), [1, 3]);
  assert.equal(log.lookup(sessionA, 1, 100), null);
  assert.equal(log.lookupAllById(sessionA, "urn:xeip:message:same", 100).length, 0);
});

test("copies limits and rejects invalid elapsed time", () => {
  const configuration = { windowMs: 1000, maxPerSession: 2, maxSessions: 2 };
  const log = new DeliveryLog(configuration);
  configuration.windowMs = 1;
  const published = log.limits;
  published.maxPerSession = 100; published.maxSessions = 100;
  log.append(sessionA, message("a1"), 0);
  log.append(sessionA, message("a2"), 0);
  log.append(sessionA, message("a3"), 0);
  assert.equal(log.since(sessionA, 0).entries.length, 2);
  for (const elapsed of [NaN, Infinity, -1, "1", Number.MAX_VALUE]) assert.throws(() => log.append(sessionA, message(), elapsed));
});
