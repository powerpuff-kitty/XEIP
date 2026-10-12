import { test } from "node:test";
import assert from "node:assert/strict";
import { snapshot } from "./actions.mjs";
test("provisioning can opt into a bounded larger node budget without relaxing action defaults", () => {
  const records = Array.from({ length: 9000 }, () => 0);
  assert.throws(
    () => snapshot(records, 65536),
    /JSON limit|invalid JSON array/,
  );
  assert.equal(snapshot(records, 65536, 262144).length, 9000);
  assert.throws(() => snapshot(records, 100, 262144));
  let deep = null;
  for (let i = 0; i < 34; i++) deep = { next: deep };
  assert.throws(() => snapshot(deep, 65536, 262144));
});
test("snapshot node budgets reject unbounded or invalid overrides", () => {
  for (const value of [0, -1, 1.5, 262145, Infinity, NaN, "262144"])
    assert.throws(() => snapshot({}, 65536, value));
});
