import test from "node:test";
import assert from "node:assert/strict";
import { ReceiptLedger, LOCAL_RECEIPTS_PROFILE } from "./receipts.mjs";

const principal = entity => ({ entity });
const a = principal("urn:xeip:entity:a");
const b = principal("urn:xeip:entity:b");
const s1 = "urn:xeip:session:one";
const s2 = "urn:xeip:session:two";
const s3 = "urn:xeip:session:three";

test("requires bounded integer receipt configuration", () => {
  for (const configuration of [null, [], "bad", { extra: true }, { windowMs: 0 }, { windowMs: 3600001 },
    { windowMs: 1.5 }, { maxPerSession: 0 }, { maxPerSession: 4097 }, { maxPerSession: "2" },
    { maxPerPrincipal: 0 }, { maxPerPrincipal: 8193 }, { maxPerPrincipal: "2" }]) {
    assert.throws(() => new ReceiptLedger(configuration));
  }
});

test("applies the documented defaults and copies its limits", () => {
  assert.equal(LOCAL_RECEIPTS_PROFILE, "xeip.local-receipts/0.1");
  assert.deepEqual(new ReceiptLedger().limits, { windowMs: 300000, maxPerSession: 512, maxPerPrincipal: 4096 });
  const configuration = { windowMs: 1000, maxPerSession: 2, maxPerPrincipal: 3 };
  const ledger = new ReceiptLedger(configuration);
  configuration.windowMs = 1;
  const published = ledger.limits;
  published.maxPerSession = 100; published.maxPerPrincipal = 100;
  assert.deepEqual(ledger.limits, { windowMs: 1000, maxPerSession: 2, maxPerPrincipal: 3 });
});

test("is idempotent per (principal, session, seq) and isolates principals", () => {
  const ledger = new ReceiptLedger();
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: false });
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: true });
  assert.deepEqual(ledger.record(b, s1, 1, "urn:xeip:message:one", 0), { duplicate: false });
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: true });
  assert.deepEqual(ledger.record(a, s2, 1, "urn:xeip:message:one", 0), { duplicate: false });
});

test("bounds receipts per (session, principal) and evicts the oldest", () => {
  const ledger = new ReceiptLedger({ maxPerSession: 2 });
  ledger.record(a, s1, 1, "urn:xeip:message:one", 0);
  ledger.record(a, s1, 2, "urn:xeip:message:two", 0);
  ledger.record(a, s1, 3, "urn:xeip:message:three", 0);
  // The oldest of the three was evicted while the two newest remain.
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: false });
  assert.deepEqual(ledger.record(a, s1, 3, "urn:xeip:message:three", 0), { duplicate: true });
  // The bound is per pair: another principal in the same session is unaffected.
  assert.deepEqual(ledger.record(b, s1, 1, "urn:xeip:message:one", 0), { duplicate: false });
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: true });
});

test("bounds receipts per principal across sessions and evicts the oldest", () => {
  const ledger = new ReceiptLedger({ maxPerSession: 10, maxPerPrincipal: 2 });
  ledger.record(a, s1, 1, "urn:xeip:message:one", 0);
  ledger.record(a, s2, 1, "urn:xeip:message:two", 0);
  ledger.record(a, s3, 1, "urn:xeip:message:three", 0);
  // The oldest across sessions was evicted while the two newest remain.
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: false });
  assert.deepEqual(ledger.record(a, s3, 1, "urn:xeip:message:three", 0), { duplicate: true });
  // A different principal keeps its own full budget.
  ledger.record(b, s1, 1, "urn:xeip:message:one", 0);
  ledger.record(b, s2, 1, "urn:xeip:message:two", 0);
  ledger.record(b, s3, 1, "urn:xeip:message:three", 0);
  assert.deepEqual(ledger.record(b, s1, 1, "urn:xeip:message:one", 0), { duplicate: false });
  assert.deepEqual(ledger.record(b, s3, 1, "urn:xeip:message:three", 0), { duplicate: true });
});

test("expires receipts on a monotonic window and never moves the clock backwards", () => {
  const ledger = new ReceiptLedger({ windowMs: 100 });
  ledger.record(a, s1, 1, "urn:xeip:message:one", 0);
  ledger.record(a, s1, 2, "urn:xeip:message:two", 0);
  // Advancing the clock to 99 keeps both; the new record does not refresh theirs.
  ledger.record(a, s1, 3, "urn:xeip:message:three", 99);
  assert.deepEqual(ledger.record(a, s1, 1, "urn:xeip:message:one", 100), { duplicate: false });
  assert.deepEqual(ledger.record(a, s1, 2, "urn:xeip:message:two", 100), { duplicate: false });
  // A smaller elapsed value must not move the clock backwards and resurrect records.
  const other = new ReceiptLedger({ windowMs: 100 });
  other.record(a, s1, 1, "urn:xeip:message:one", 100);
  other.record(a, s1, 2, "urn:xeip:message:two", 50);
  assert.deepEqual(other.record(a, s1, 1, "urn:xeip:message:one", 0), { duplicate: true });
});

test("rejects invalid elapsed time and invalid record arguments", () => {
  const ledger = new ReceiptLedger();
  for (const elapsed of [NaN, Infinity, -1, "1", Number.MAX_VALUE]) {
    assert.throws(() => ledger.record(a, s1, 1, "urn:xeip:message:one", elapsed));
  }
  for (const [session, seq, id] of [[1, 1, "urn:xeip:message:one"], [s1, -1, "urn:xeip:message:one"],
    [s1, 1.5, "urn:xeip:message:one"], [s1, 1, 7]]) {
    assert.throws(() => ledger.record(a, session, seq, id, 0));
  }
  assert.throws(() => ledger.record(null, s1, 1, "urn:xeip:message:one", 0));
  assert.throws(() => ledger.record({}, s1, 1, "urn:xeip:message:one", 0));
});
