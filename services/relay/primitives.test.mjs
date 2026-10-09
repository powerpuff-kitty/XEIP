import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { BoundedMap, advanceElapsed, boundedInteger, boundedOption, digestBytes, digestHex, requireOptions } from "./primitives.mjs";

test("digestHex and digestBytes match node:crypto SHA-256", () => {
  assert.equal(digestHex("hello"), createHash("sha256").update("hello", "utf8").digest("hex"));
  assert.deepEqual(digestBytes("hello"), createHash("sha256").update("hello", "utf8").digest());
  assert.equal(digestHex("").length, 64);
});

test("advanceElapsed is monotonic and validates bounds", () => {
  assert.equal(advanceElapsed(5, 3), 5);
  assert.equal(advanceElapsed(5, 9), 9);
  assert.equal(advanceElapsed(0, 100, { windowMs: 50, max: 200, label: "delivery" }), 100);
  for (const elapsed of [NaN, Infinity, -1, "1"]) assert.throws(() => advanceElapsed(0, elapsed), RangeError);
  assert.throws(() => advanceElapsed(0, 151, { windowMs: 50, max: 200 }), RangeError);
  assert.equal(advanceElapsed(0, 5, { label: "receipt" }), 5);
  assert.equal(advanceElapsed(0, Number.MAX_VALUE, { max: Infinity }), Number.MAX_VALUE);
});

test("requireOptions enforces object shape and allowed keys", () => {
  requireOptions({ a: 1 }, ["a"], "bad");
  for (const configuration of [null, [], "x", 3, { b: 1 }]) {
    assert.throws(() => requireOptions(configuration, ["a"], "bad config"), /bad config/);
  }
});

test("boundedInteger and boundedOption validate ranges and defaults", () => {
  assert.equal(boundedInteger(5, 1, 10), true);
  assert.equal(boundedInteger(0, 1, 10), false);
  assert.equal(boundedInteger(1.5, 1, 10), false);
  assert.equal(boundedOption({}, "n", { default: 7, min: 1, max: 10 }), 7);
  assert.equal(boundedOption({ n: 3 }, "n", { default: 7, min: 1, max: 10 }), 3);
  assert.throws(() => boundedOption({ n: 0 }, "n", { default: 7, min: 1, max: 10, message: "range" }), /range/);
});

test("BoundedMap evicts the least-recently-used key and reports it", () => {
  const evicted = [];
  const map = new BoundedMap(2, { onEvict: (key) => evicted.push(key) });
  map.set("a", 1).set("b", 2).set("c", 3);
  assert.deepEqual([...map.keys()], ["b", "c"]);
  assert.deepEqual(evicted, ["a"]);
  // Re-setting an existing key refreshes recency.
  map.set("b", 20);
  map.set("d", 4);
  assert.deepEqual([...map.keys()], ["b", "d"]);
  assert.deepEqual(evicted, ["a", "c"]);
  // touch moves an existing key to most-recent; missing keys return false.
  map.touch("b");
  map.set("e", 5);
  assert.deepEqual([...map.keys()], ["b", "e"]);
  assert.equal(map.touch("missing"), false);
  assert.equal(map.has("d"), false);
  assert.equal(map.size, 2);
  map.delete("b");
  assert.equal(map.has("b"), false);
});

test("BoundedMap(max: Infinity) never evicts and rejects invalid sizes", () => {
  const map = new BoundedMap(Infinity);
  for (let i = 0; i < 100; i++) map.set(i, i);
  assert.equal(map.size, 100);
  assert.throws(() => new BoundedMap(-1), RangeError);
  assert.throws(() => new BoundedMap(1.5), RangeError);
});
