import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LocalAdmission } from "./admission.mjs";
import { LOCAL_REPLAY_PROFILE } from "./replay.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b", c = "urn:xeip:entity:c";
const room = "urn:xeip:session:ab", other = "urn:xeip:session:abc";
const secret = () => randomBytes(32).toString("base64url");
const envelope = (extra = {}) => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender: a, recipient: b, session: room, timestamp: new Date().toISOString(),
  body: { contentType: "application/json", data: { text: "🐈", values: [1, null, true] } }, ...extra });

async function setup(t, options = { replay: {} }) {
  const credentials = new Map([a, b, c].map(entity => [entity, secret()]));
  const admission = new LocalAdmission({ credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [room, other].map(id => ({ xeip: "0.1", id, mode: "group", members: id === room ? [a, b] : [a, b, c],
      createdAt: "2026-10-09T00:00:00Z" })) });
  const server = createRelay({ admission, ...options });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  const subscriptions = [];
  t.after(async () => {
    for (const stream of subscriptions) stream.abort.abort();
    await Promise.allSettled(subscriptions.map(stream => stream.worker));
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  });
  const post = (actor, message, raw) => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + credentials.get(actor), "Content-Type": "application/json" },
    body: raw ?? JSON.stringify(message), signal: AbortSignal.timeout(5000) });
  const subscribe = async (actor = b, session = room) => {
    const abort = new AbortController(), stream = { abort, received: [] };
    const url = new URL("/events", base); url.searchParams.set("session", session); url.searchParams.set("entity", actor);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + credentials.get(actor) }, signal: abort.signal });
    assert.equal(response.status, 200);
    subscriptions.push(stream);
    stream.worker = (async () => {
      const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
      try {
        while (true) {
          const next = await reader.read(); if (next.done) break;
          for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) {
            if (frame.event === "xeip.message") stream.received.push(JSON.parse(frame.data));
          }
        }
      } catch (error) { if (!abort.signal.aborted) throw error; }
      finally { await reader.cancel().catch(() => {}); }
    })();
    stream.worker.catch(() => {});
    stream.close = async () => { abort.abort(); await stream.worker; };
    return stream;
  };
  return { server, base, admission, credentials, post, subscribe };
}
async function waitFor(stream, count) {
  const deadline = Date.now() + 15000;
  while (stream.received.length < count) {
    if (Date.now() >= deadline) throw new Error("expected message frame did not arrive");
    await delay(10);
  }
}
async function accepted(post, actor, message, expected) {
  const response = await post(actor, message); assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), expected);
}

test("replay selection requires admission and validates configuration", () => {
  const admission = new LocalAdmission({ credentials: [{ entity: a, token: secret() }], sessions: [] });
  assert.throws(() => createRelay({ token: "shared-token-long-enough", replay: {} }));
  for (const replay of [null, false, { extra: true }, { maxEntries: 4097 }, { windowMs: 0 }]) {
    assert.throws(() => createRelay({ admission, replay }));
  }
});

test("advertises a copied replay contract without changing admission-only forwarding", async t => {
  const limits = { windowMs: 20000, maxEntries: 3 };
  const replay = await setup(t, { replay: limits }); limits.windowMs = 1; limits.maxEntries = 200;
  const health = await (await fetch(replay.base + "/health")).json();
  assert.equal(health.deliveryProfile, LOCAL_REPLAY_PROFILE);
  assert.deepEqual(health.replay, { windowMs: 20000, maxEntries: 3 });
  const baseline = await setup(t, {}), target = await baseline.subscribe(), message = envelope();
  await accepted(baseline.post, a, message, { accepted: true, delivered: 1 });
  await accepted(baseline.post, a, message, { accepted: true, delivered: 1 });
  await waitFor(target, 2); assert.deepEqual(target.received, [message, message]);
});

test("suppresses identical/reordered retries and rejects conflicting content without emitting frames", async t => {
  const { post, subscribe } = await setup(t), target = await subscribe(), message = envelope();
  await accepted(post, a, message, { accepted: true, delivered: 1, duplicate: false });
  const reordered = Object.fromEntries(Object.entries(message).reverse());
  await accepted(post, a, reordered, { accepted: true, delivered: 0, duplicate: true });
  const conflict = await post(a, { ...message, kind: "command" });
  assert.equal(conflict.status, 409); assert.deepEqual(await conflict.json(), { error: "message ID conflict" });
  const marker = envelope(); await accepted(post, a, marker, { accepted: true, delivered: 1, duplicate: false });
  await waitFor(target, 2); assert.deepEqual(target.received, [message, marker]);
});

test("simultaneous identical POSTs reserve one acceptance before any stream writes", async t => {
  const { post, subscribe } = await setup(t), target = await subscribe(), message = envelope();
  const responses = await Promise.all(Array.from({ length: 8 }, () => post(a, message)));
  for (const response of responses) assert.equal(response.status, 202);
  const receipts = await Promise.all(responses.map(response => response.json()));
  assert.equal(receipts.filter(receipt => receipt.duplicate === false).length, 1);
  assert.equal(receipts.filter(receipt => receipt.duplicate === true && receipt.delivered === 0).length, 7);
  assert.equal(receipts.reduce((total, receipt) => total + receipt.delivered, 0), 1);
  const marker = envelope(); await accepted(post, a, marker, { accepted: true, delivered: 1, duplicate: false });
  await waitFor(target, 2); assert.deepEqual(target.received, [message, marker]);
});

test("a lost HTTP acceptance response can be retried without another recipient frame", async t => {
  const { post, subscribe, server } = await setup(t), target = await subscribe(), message = envelope();
  // Drop only the first POST response at the native socket boundary, after real routing.
  // The policy, ledger, body parsing and subscriber writes remain real.
  server.prependOnceListener("request", (_request, response) => {
    response.end = function () { this.destroy(); return this; };
  });
  await assert.rejects(post(a, message));
  await waitFor(target, 1);
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
  const marker = envelope(); await accepted(post, a, marker, { accepted: true, delivered: 1, duplicate: false });
  await waitFor(target, 2); assert.deepEqual(target.received, [message, marker]);
});

test("sender and session scopes cannot poison another entity's reuse of the same ID", async t => {
  const { post } = await setup(t), message = envelope();
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
  await accepted(post, b, { ...message, sender: b, recipient: a }, { accepted: true, delivered: 0, duplicate: false });
  await accepted(post, a, { ...message, session: other }, { accepted: true, delivered: 0, duplicate: false });
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
});

test("full ledgers refuse new IDs without evicting accepted IDs or writing new frames", async t => {
  const { post, subscribe } = await setup(t, { replay: { maxEntries: 1 } });
  const target = await subscribe(), message = envelope();
  await accepted(post, a, message, { accepted: true, delivered: 1, duplicate: false });
  const blocked = await post(a, envelope());
  assert.equal(blocked.status, 503); assert.match(blocked.headers.get("retry-after"), /^[1-9][0-9]*$/);
  assert.deepEqual(await blocked.json(), { error: "replay window full" });
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
  await waitFor(target, 1); assert.deepEqual(target.received, [message]);
});

test("unauthorized, expired, invalid and oversized-frame inputs cannot reserve ledger capacity", async t => {
  const { post } = await setup(t, { replay: { maxEntries: 1 } }), message = envelope();
  for (const [actor, candidate, status] of [[c, message, 403], [a, { ...message, sender: b }, 403],
    [a, { ...message, recipient: c }, 403], [a, { ...message, expiresAt: "2000-01-01T00:00:00Z" }, 422],
    [a, { ...message, xeip: "bad" }, 422]]) {
    const rejected = await post(actor, candidate); assert.equal(rejected.status, status); await rejected.body.cancel();
  }
  const compact = JSON.stringify({ ...message, body: { contentType: "application/json", data: "MARK" } })
    .replace('"MARK"', "[" + Array(11000).fill("1e15").join(",") + "]");
  const tooLarge = await post(a, null, compact); assert.equal(tooLarge.status, 413); await tooLarge.body.cancel();
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
});

test("authorization is rechecked on retries and token rotation does not clear accepted scope", async t => {
  const { post, admission, credentials } = await setup(t), message = envelope();
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
  admission.setMembers(room, [b]);
  const forbidden = await post(a, message); assert.equal(forbidden.status, 403); await forbidden.body.cancel();
  admission.setMembers(room, [a, b]); admission.rotateCredential(a, secret());
  const revoked = await post(a, message); assert.equal(revoked.status, 401); await revoked.body.cancel();
  const token = secret(); admission.rotateCredential(a, token); credentials.set(a, token);
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
  admission.setMembers(room, [a]);
  const recipientDenied = await post(a, message); assert.equal(recipientDenied.status, 403); await recipientDenied.body.cancel();
});

test("remembered zero-write acceptance cannot become offline delivery on reconnect", async t => {
  const { post, subscribe } = await setup(t), message = envelope();
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
  const target = await subscribe();
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
  const marker = envelope(); await accepted(post, a, marker, { accepted: true, delivered: 1, duplicate: false });
  await waitFor(target, 1); assert.deepEqual(target.received, [marker]);
  await target.close(); const reconnected = await subscribe();
  await accepted(post, a, marker, { accepted: true, delivered: 0, duplicate: true });
  const next = envelope(); await accepted(post, a, next, { accepted: true, delivered: 1, duplicate: false });
  await waitFor(reconnected, 1); assert.deepEqual(reconnected.received, [next]);
});

test("closing and relistening the same server retains accepted IDs", async t => {
  const { post, server } = await setup(t), message = envelope(), port = server.address().port;
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  await new Promise(resolve => server.listen(port, "127.0.0.1", resolve));
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
});

test("new factory instances cannot provide durable suppression for an earlier acceptance", async t => {
  const message = envelope(), first = await setup(t);
  await accepted(first.post, a, message, { accepted: true, delivered: 0, duplicate: false });
  const restarted = await setup(t);
  await accepted(restarted.post, a, message, { accepted: true, delivered: 0, duplicate: false });
});

test("an accepted message that expires is rejected before duplicate lookup", { timeout: 15000 }, async t => {
  const { post } = await setup(t), message = envelope({ expiresAt: new Date(Date.now() + 1000).toISOString() });
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
  // Wall-clock expiry with margin, still strictly past the 1s deadline.
  await delay(1500);
  const expired = await post(a, message);
  assert.equal(expired.status, 422); await expired.body.cancel();
});

test("a live relay releases capacity after fixed monotonic expiry", { timeout: 15000 }, async t => {
  const { post } = await setup(t, { replay: { windowMs: 1000, maxEntries: 1 } }), message = envelope();
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: true });
  // Advance past the fixed monotonic window with margin.
  await delay(1500);
  await accepted(post, a, message, { accepted: true, delivered: 0, duplicate: false });
});
