import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DurableStore, LOCAL_DURABLE_PROFILE } from "./durable.mjs";

const T = Date.now();
const sessionA = "urn:xeip:session:ab";
const sessionB = "urn:xeip:session:cd";
const message = (id = "one") => ({ xeip: "0.1", id: "urn:xeip:message:" + id, kind: "message",
  sender: "urn:xeip:entity:a", recipient: "urn:xeip:entity:b", session: sessionA,
  timestamp: "2026-10-09T00:00:00Z", body: { contentType: "text/plain", data: id } });

function makeDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "xeip-durable-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
const segmentFile = dir => join(dir, readdirSync(dir).find(name => name.startsWith("segment-")));
const diskText = dir => readdirSync(dir).filter(name => name.startsWith("segment-"))
  .map(name => readFileSync(join(dir, name), "utf8")).join("\n");

test("advertises the durable profile and rejects invalid configuration", t => {
  const dir = makeDir(t);
  assert.equal(LOCAL_DURABLE_PROFILE, "xeip.local-durable/0.1");
  for (const configuration of [null, [], "bad", { extra: true }, { retentionMs: 1 },
    { dir, backend: "sqlite" }, { dir, retentionMs: 0 }, { dir, retentionMs: 2592000001 },
    { dir, maxEntriesPerSession: 0 }, { dir, maxSessions: 0 }, { dir, maxBytes: 0 },
    { dir, fsync: "sometimes" }, { dir, lock: "shared-readonly" }]) {
    assert.throws(() => new DurableStore(configuration));
  }
});

test("persists monotonic per-session sequences and replays since/lookup", t => {
  const dir = makeDir(t);
  const store = new DurableStore({ dir, fsync: "always" });
  assert.equal(store.append(sessionA, message("a1"), T), 1);
  assert.equal(store.append(sessionA, message("a2"), T + 1), 2);
  assert.equal(store.append(sessionB, message("b1"), T + 2), 1);
  assert.equal(store.append(sessionA, message("a3"), T + 3), 3);
  assert.deepEqual(store.since(sessionA, 0, T + 3).entries.map(entry => entry.seq), [1, 2, 3]);
  assert.equal(store.since(sessionA, 0, T + 3).gap, false);
  assert.deepEqual(store.since(sessionA, 2, T + 3).entries.map(entry => entry.seq), [3]);
  assert.deepEqual(store.since("urn:xeip:session:unknown", 7, T + 3), { entries: [], gap: false, from: 8 });
  assert.equal(store.lookup(sessionA, 2, T + 3).message.id, "urn:xeip:message:a2");
  assert.equal(store.lookup(sessionA, 99, T + 3), null);
  assert.equal(store.lookupById(sessionA, "urn:xeip:message:a3", T + 3).seq, 3);
  assert.deepEqual(store.lookupAllById(sessionA, "urn:xeip:message:a1", T + 3).map(entry => entry.seq), [1]);
  assert.equal(store.status(), "ok");
  assert.deepEqual(store.limits, { retentionMs: 3600000, maxEntriesPerSession: 4096, maxSessions: 1024, maxBytes: 268435456 });
  assert.deepEqual(store.resumeLimits, { windowMs: 3600000, maxPerSession: 4096, maxSessions: 1024 });
  store.close();
});

test("applies retention, per-session, byte and session bounds with honest gaps", t => {
  const retention = new DurableStore({ dir: makeDir(t), fsync: "always", retentionMs: 100, maxEntriesPerSession: 8 });
  retention.append(sessionA, message("a1"), T);
  retention.append(sessionA, message("a2"), T + 50);
  assert.equal(retention.since(sessionA, 0, T + 50).entries.length, 2);
  retention.append(sessionA, message("a3"), T + 200);
  const afterWindow = retention.since(sessionA, 0, T + 200);
  assert.deepEqual(afterWindow.entries.map(entry => entry.seq), [3]);
  assert.equal(afterWindow.gap, true);
  assert.equal(afterWindow.from, 3);
  retention.close();

  const perSession = new DurableStore({ dir: makeDir(t), fsync: "always", maxEntriesPerSession: 2 });
  for (let index = 1; index <= 3; index++) perSession.append(sessionA, message("s" + index), T + index);
  const bounded = perSession.since(sessionA, 0, T + 3);
  assert.deepEqual(bounded.entries.map(entry => entry.seq), [2, 3]);
  assert.equal(bounded.from, 2);
  assert.equal(bounded.gap, true);
  perSession.close();

  // A one-byte budget keeps only the newest envelope; the evicted seq is a gap.
  const bytes = new DurableStore({ dir: makeDir(t), fsync: "always", maxBytes: 1 });
  bytes.append(sessionA, message("b1"), T);
  const second = bytes.append(sessionA, message("b2"), T + 1);
  assert.equal(second, 2);
  const byteBounded = bytes.since(sessionA, 0, T + 1);
  assert.deepEqual(byteBounded.entries.map(entry => entry.seq), [2]);
  assert.equal(byteBounded.gap, true);
  assert.equal(byteBounded.from, 2);
  bytes.close();

  const sessions = new DurableStore({ dir: makeDir(t), fsync: "always", maxSessions: 1 });
  assert.equal(sessions.append(sessionA, message("c1"), T), 1);
  assert.equal(sessions.append(sessionB, message("d1"), T + 1), 1); // evicts A
  assert.deepEqual(sessions.since(sessionB, 0, T + 1).entries.map(entry => entry.seq), [1]);
  const evicted = sessions.since(sessionA, 0, T + 1);
  assert.equal(evicted.gap, true);
  assert.equal(evicted.from, 2);
  assert.equal(sessions.append(sessionA, message("c2"), T + 2), 2); // continues monotonically
  sessions.close();
});

test("drops a torn tail, reports recovered and continues the sequence", t => {
  const dir = makeDir(t);
  const store = new DurableStore({ dir, fsync: "always" });
  store.append(sessionA, message("a1"), T);
  store.append(sessionA, message("a2"), T + 1);
  store.close();

  const file = segmentFile(dir);
  truncateSync(file, statSync(file).size - 1);

  const recovered = new DurableStore({ dir, fsync: "always" });
  assert.equal(recovered.status(), "recovered");
  assert.deepEqual(recovered.since(sessionA, 0, T + 2).entries.map(entry => entry.seq), [1]);
  // The torn record's reserved sequence is a hole, never reused.
  assert.equal(recovered.append(sessionA, message("a3"), T + 2), 3);
  assert.deepEqual(recovered.since(sessionA, 0, T + 3).entries.map(entry => entry.seq), [1, 3]);
  recovered.close();
});

test("fails closed on interior corruption but tolerates a tail checksum edit", t => {
  const dir = makeDir(t);
  const store = new DurableStore({ dir, fsync: "always" });
  store.append(sessionA, message("a1"), T);
  store.append(sessionA, message("a2"), T + 1);
  store.close();

  const file = segmentFile(dir);
  const buffer = readFileSync(file);
  buffer[36 + 4] ^= 0xff; // payload byte of the first (non-tail) record
  writeFileSync(file, buffer);
  assert.throws(() => new DurableStore({ dir }), /interior corruption/);

  // A checksum edit confined to the final record is a torn tail, not interior.
  const tailDir = makeDir(t);
  const tail = new DurableStore({ dir: tailDir, fsync: "always" });
  tail.append(sessionA, message("a1"), T);
  tail.append(sessionA, message("a2"), T + 1);
  tail.close();
  const tailFile = segmentFile(tailDir);
  const tailBuffer = readFileSync(tailFile);
  tailBuffer[tailBuffer.length - 1] ^= 0xff;
  writeFileSync(tailFile, tailBuffer);
  const tolerant = new DurableStore({ dir: tailDir });
  assert.equal(tolerant.status(), "recovered");
  assert.deepEqual(tolerant.since(sessionA, 0, T + 2).entries.map(entry => entry.seq), [1]);
  tolerant.close();
});

test("a second store on the same directory resumes and continues the sequence", t => {
  const dir = makeDir(t);
  const first = new DurableStore({ dir, fsync: "always" });
  first.append(sessionA, message("a1"), T);
  first.append(sessionA, message("a2"), T + 1);
  first.close();

  const second = new DurableStore({ dir, fsync: "always" });
  assert.equal(second.status(), "ok");
  assert.deepEqual(second.since(sessionA, 0, T + 1).entries.map(entry => entry.seq), [1, 2]);
  assert.equal(second.append(sessionA, message("a3"), T + 2), 3);
  assert.deepEqual(second.since(sessionA, 1, T + 2).entries.map(entry => entry.seq), [2, 3]);
  second.close();

  const third = new DurableStore({ dir });
  assert.deepEqual(third.since(sessionA, 0, T + 2).entries.map(entry => entry.seq), [1, 2, 3]);
  assert.equal(third.append(sessionA, message("a4"), T + 3), 4);
  third.close();
});

test("compaction reclaims per-session-evicted bytes and preserves the high-water mark", t => {
  const dir = makeDir(t);
  const store = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 2 });
  for (let index = 1; index <= 3; index++) store.append(sessionA, message("p" + index), T + index);
  // seq 1 is logically evicted but, before compaction, still occupies disk.
  assert.ok(diskText(dir).includes("urn:xeip:message:p1"));
  store.compact();
  assert.ok(!diskText(dir).includes("urn:xeip:message:p1"), "evicted record was reclaimed");
  assert.ok(diskText(dir).includes("urn:xeip:message:p2"));
  assert.ok(diskText(dir).includes("urn:xeip:message:p3"));
  store.close();

  const fresh = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 2 });
  const resumed = fresh.since(sessionA, 0, T + 3);
  assert.deepEqual(resumed.entries.map(entry => entry.seq), [2, 3]);
  assert.equal(resumed.from, 2);
  assert.equal(resumed.gap, true);
  assert.equal(fresh.append(sessionA, message("p4"), T + 4), 4);
  fresh.close();
});

test("compaction enforces maxBytes on disk and the retained set survives restart", t => {
  const dir = makeDir(t);
  const recordBytes = 4 + 32 + Buffer.byteLength(JSON.stringify(
    { session: sessionA, seq: 1, at: T, message: message("z1") }), "utf8");
  const maxBytes = 2 * recordBytes + 1;
  const store = new DurableStore({ dir, fsync: "always", maxBytes });
  for (let index = 1; index <= 5; index++) store.append(sessionA, message("z" + index), T + index);
  store.compact();
  const onDisk = diskText(dir);
  for (const gone of [1, 2, 3]) assert.ok(!onDisk.includes("urn:xeip:message:z" + gone));
  for (const kept of [4, 5]) assert.ok(onDisk.includes("urn:xeip:message:z" + kept));
  store.close();

  const fresh = new DurableStore({ dir, fsync: "always", maxBytes });
  assert.deepEqual(fresh.since(sessionA, 0, T + 5).entries.map(entry => entry.seq), [4, 5]);
  assert.equal(fresh.append(sessionA, message("z6"), T + 6), 6);
  fresh.close();
});

test("compaction triggers automatically once dead bytes dominate the byte budget", t => {
  const dir = makeDir(t);
  const recordBytes = 4 + 32 + Buffer.byteLength(JSON.stringify(
    { session: sessionA, seq: 1, at: T, message: message("z1") }), "utf8");
  const store = new DurableStore({ dir, fsync: "always", maxBytes: 2 * recordBytes + 1 });
  for (let index = 1; index <= 6; index++) store.append(sessionA, message("z" + index), T + index);
  const onDisk = diskText(dir);
  for (const gone of [1, 2, 3, 4]) assert.ok(!onDisk.includes("urn:xeip:message:z" + gone));
  assert.ok(onDisk.includes("urn:xeip:message:z5"));
  assert.ok(onDisk.includes("urn:xeip:message:z6"));
  store.close();
});

test("recovers from an interrupted compaction without losing live records or reusing a seq", t => {
  for (const fault of ["after-write", "after-manifest", "torn"]) {
    const dir = makeDir(t);
    const store = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 2 });
    store.append(sessionA, message("k1"), T);
    store.append(sessionA, message("k2"), T + 1);
    store.append(sessionA, message("k3"), T + 2); // k1 evicted
    assert.throws(() => store.compact({ fault }), /compaction interrupted/);

    const recovered = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 2 });
    assert.equal(recovered.status(), "ok");
    assert.deepEqual(recovered.since(sessionA, 0, T + 3).entries.map(entry => entry.seq), [2, 3]);
    assert.equal(recovered.append(sessionA, message("k4"), T + 3), 4);
    assert.deepEqual(recovered.since(sessionA, 0, T + 4).entries.map(entry => entry.seq), [3, 4]);
    recovered.close();
  }
});

test("close reclaims dead segments without an explicit compact call", t => {
  const dir = makeDir(t);
  const store = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 1 });
  store.append(sessionA, message("q1"), T);
  store.append(sessionA, message("q2"), T + 1);
  assert.ok(diskText(dir).includes("urn:xeip:message:q1"));
  store.close();
  assert.ok(!diskText(dir).includes("urn:xeip:message:q1"));

  const fresh = new DurableStore({ dir, fsync: "always", maxEntriesPerSession: 1 });
  assert.deepEqual(fresh.since(sessionA, 0, T + 1).entries.map(entry => entry.seq), [2]);
  assert.equal(fresh.append(sessionA, message("q3"), T + 2), 3);
  fresh.close();
});

test("compact rejects invalid options and a closed store", t => {
  const store = new DurableStore({ dir: makeDir(t), fsync: "always" });
  assert.throws(() => store.compact(null), TypeError);
  assert.throws(() => store.compact([]), TypeError);
  assert.throws(() => store.compact({ fault: "whenever" }), RangeError);
  store.close();
  assert.throws(() => store.compact(), /closed/);
});
