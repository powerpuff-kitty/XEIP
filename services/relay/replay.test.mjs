import test from "node:test";
import assert from "node:assert/strict";
import { ReplayWindow } from "./replay.mjs";

const envelope = (extra = {}) => ({ xeip: "0.1", id: "urn:xeip:message:one", kind: "message",
  sender: "urn:xeip:entity:a", recipient: "urn:xeip:entity:b", session: "urn:xeip:session:ab",
  timestamp: "2026-10-09T00:00:00Z", body: { contentType: "application/json", data: { text: "🐈", values: [1, null, true] } }, ...extra });

test("requires bounded integer replay configuration", () => {
  for (const configuration of [null, [], "bad", { extra: true }, { windowMs: 0 }, { windowMs: 3600001 },
    { windowMs: 1.5 }, { windowMs: null }, { maxEntries: 0 }, { maxEntries: 4097 },
    { maxEntries: Infinity }, { maxEntries: "2" }]) assert.throws(() => new ReplayWindow(configuration));
});

test("suppresses repeated scope and keeps different senders, sessions and exact IDs independent", () => {
  const window = new ReplayWindow(), original = envelope();
  assert.deepEqual(window.accept(original, 0), { status: "new" });
  assert.deepEqual(window.accept(envelope(), 1), { status: "duplicate" });
  for (const patch of [{ sender: "urn:xeip:entity:c" }, { session: "urn:xeip:session:other" },
    { id: "urn:xeip:message:%6fne" },
    { session: original.session + ":urn", sender: "xeip:entity:a" }]) {
    assert.deepEqual(window.accept(envelope(patch), 2), { status: "new" });
  }
  assert.deepEqual(window.accept(original, 3), { status: "duplicate" });
});

test("compares all parsed content while ignoring object property order", () => {
  const window = new ReplayWindow();
  const original = envelope({ extensions: JSON.parse('{"__proto__":{"a":1},"example.org/value":{"z":2,"a":1}}') });
  window.accept(original, 0);
  const reordered = { ...Object.fromEntries(Object.entries(original).reverse()),
    body: { data: { values: [1, null, true], text: "🐈" }, contentType: "application/json" },
    extensions: JSON.parse('{"example.org/value":{"a":1,"z":2},"__proto__":{"a":1}}') };
  assert.deepEqual(window.accept(reordered, 1), { status: "duplicate" });
  for (const patch of [{ kind: "command" }, { recipient: undefined }, { timestamp: "2026-10-09T00:00:01Z" },
    { replyTo: "urn:xeip:message:previous" }, { expiresAt: "2026-10-10T00:00:00Z" },
    { extensions: { "example.org/value": { a: 1, z: 3 } } },
    { body: { contentType: "application/json", data: { text: "🐈", values: [true, null, 1] } } }]) {
    const candidate = { ...original, ...patch };
    // Real wire serialization omits absent optional fields.
    assert.deepEqual(window.accept(JSON.parse(JSON.stringify(candidate)), 2), { status: "conflict" });
  }
  assert.deepEqual(window.accept(original, 3), { status: "duplicate" });
});

test("expires at the fixed boundary without extending the window on retry or conflict", () => {
  const window = new ReplayWindow({ windowMs: 200, maxEntries: 1 });
  assert.deepEqual(window.accept(envelope(), 1000), { status: "new" });
  assert.deepEqual(window.accept(envelope(), 1198), { status: "duplicate" });
  assert.deepEqual(window.accept(envelope({ kind: "command" }), 1199), { status: "conflict" });
  assert.deepEqual(window.accept(envelope(), 1200), { status: "new" });
  assert.deepEqual(window.accept(envelope(), 1399), { status: "duplicate" });
});

test("refuses new IDs while full without evicting live records and frees expired capacity", () => {
  const window = new ReplayWindow({ windowMs: 2000, maxEntries: 2 });
  const one = envelope(), two = envelope({ id: "urn:xeip:message:two" }), three = envelope({ id: "urn:xeip:message:three" });
  assert.deepEqual(window.accept(one, 0), { status: "new" });
  assert.deepEqual(window.accept(two, 1), { status: "new" });
  assert.deepEqual(window.accept(three, 2), { status: "full", retryAfter: 2 });
  assert.deepEqual(window.accept(one, 3), { status: "duplicate" });
  assert.deepEqual(window.accept(envelope({ kind: "command" }), 4), { status: "conflict" });
  assert.deepEqual(window.accept(three, 1001), { status: "full", retryAfter: 1 });
  assert.deepEqual(window.accept(three, 2000), { status: "new" });
  assert.deepEqual(window.accept(two, 2000), { status: "duplicate" });
});

test("copies limits so caller mutation cannot shorten protection or increase capacity", () => {
  const configuration = { windowMs: 2000, maxEntries: 1 };
  const window = new ReplayWindow(configuration);
  window.accept(envelope(), 0);
  configuration.windowMs = 1; configuration.maxEntries = 100;
  const published = window.limits; published.windowMs = 1; published.maxEntries = 100;
  assert.deepEqual(window.accept(envelope(), 100), { status: "duplicate" });
  assert.deepEqual(window.accept(envelope({ id: "urn:xeip:message:two" }), 100), { status: "full", retryAfter: 2 });
});

test("rejects invalid elapsed time and never moves its expiry clock backwards", () => {
  const window = new ReplayWindow({ windowMs: 100 });
  for (const elapsed of [NaN, Infinity, -1, "1", Number.MAX_VALUE]) assert.throws(() => window.accept(envelope(), elapsed));
  assert.deepEqual(window.accept(envelope(), 100), { status: "new" });
  assert.deepEqual(window.accept(envelope(), 50), { status: "duplicate" });
  assert.deepEqual(window.accept(envelope(), 199), { status: "duplicate" });
  assert.deepEqual(window.accept(envelope(), 200), { status: "new" });
});
