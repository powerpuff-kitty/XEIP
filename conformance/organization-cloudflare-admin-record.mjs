import { test } from "node:test";
import assert from "node:assert/strict";
import * as records from "../services/organization/cloudflare/admin-record.mjs";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
const event = () => ({
  operator: "ops:alice",
  requestId: "00000000-0000-4000-8000-000000000001",
  operation: "refreshTrust",
  commandDigest: "a".repeat(64),
  attemptId: "00000000-0000-4000-8000-000000000002",
  outcome: "started",
  occurredAt: 1000,
  before: { state: "initialized", trustRevision: 0, authorityRevision: null },
});
const started =
  '{"attemptId":"00000000-0000-4000-8000-000000000002","before":{"authorityRevision":null,"state":"initialized","trustRevision":0},"commandDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","occurredAt":1000,"operation":"refreshTrust","operator":"ops:alice","outcome":"started","requestId":"00000000-0000-4000-8000-000000000001"}';
test("audit encoding preserves literal canonical start and terminal bytes", () => {
  const value = event();
  assert.equal(records.encodeAuditEvent(value).encoded, started);
  for (const outcome of [
    "completed",
    "conflict",
    "invalid_request",
    "unavailable",
  ]) {
    const terminal = {
      ...value,
      outcome,
      after: { state: "initialized", trustRevision: 1, authorityRevision: 0 },
    };
    const expected =
      '{"after":{"authorityRevision":0,"state":"initialized","trustRevision":1},' +
      started
        .slice(1)
        .replace('"outcome":"started"', '"outcome":"' + outcome + '"');
    const result = records.encodeAuditEvent(terminal);
    assert.equal(result.encoded, expected);
    assert.deepEqual(result.event, terminal);
  }
});
test("audit encoding rejects malformed metadata and event shape before returning bytes", () => {
  assert.equal(typeof records.encodeAuditEvent, "function");
  for (const mutate of [
    (v) => {
      v.extra = true;
    },
    (v) => {
      delete v.before;
    },
    (v) => {
      v.operator = "ops:\ud800";
    },
    (v) => {
      v.operator = "a".repeat(129);
    },
    (v) => {
      v.requestId = "invalid";
    },
    (v) => {
      v.commandDigest = "G".repeat(64);
    },
    (v) => {
      v.operation = "read";
    },
    (v) => {
      v.outcome = "unknown";
    },
    (v) => {
      v.occurredAt = Infinity;
    },
    (v) => {
      v.before.trustRevision = -1;
    },
    (v) => {
      v.before.extra = true;
    },
    (v) => {
      v.after = { ...v.before };
    },
    (v) => {
      v.outcome = "completed";
    },
  ]) {
    const value = event();
    mutate(value);
    assert.throws(() => records.encodeAuditEvent(value));
  }
});
test("audit encoding matches independent JCS across boundary integers and property order", () => {
  for (const revision of [null, 0, -0, 1, Number.MAX_SAFE_INTEGER]) {
    for (const occurredAt of [0, -0, 1, Number.MAX_SAFE_INTEGER]) {
      const value = event();
      value.occurredAt = occurredAt;
      value.before.trustRevision = revision;
      const reordered = Object.fromEntries(Object.entries(value).reverse());
      assert.equal(
        records.encodeAuditEvent(reordered).encoded,
        canonicalize(value),
      );
      assert.deepEqual(records.auditEvent(reordered), value);
    }
  }
});
