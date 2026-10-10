import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LOCAL_DELIVERY_PROFILE } from "./delivery.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const TOKEN = "test-token-very-long-and-secret";
const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b";
const room = "urn:xeip:session:ab";
const envelope = (extra = {}) => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender: a, session: room, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello" }, ...extra });

async function setup(t, delivery = {}) {
  const server = createRelay({ token: TOKEN, delivery });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  const streams = [];
  t.after(async () => {
    for (const stream of streams) stream.abort.abort();
    await Promise.allSettled(streams.map(stream => stream.worker));
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const post = message => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(message), signal: AbortSignal.timeout(5000) });
  const subscribe = async (entity = b, { session = room, after, header } = {}) => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", session);
    url.searchParams.set("entity", entity);
    if (after !== undefined) url.searchParams.set("after", after);
    const headers = { Authorization: "Bearer " + TOKEN };
    if (header !== undefined) headers["Last-Event-ID"] = header;
    const response = await fetch(url, { headers, signal: abort.signal });
    const stream = { response, frames: [], abort };
    streams.push(stream);
    stream.worker = (async () => {
      if (response.status !== 200) { await response.body.cancel().catch(() => {}); return; }
      const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
      try {
        while (true) {
          const next = await reader.read(); if (next.done) break;
          for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) stream.frames.push(frame);
        }
      } catch (error) { if (!abort.signal.aborted) throw error; }
      finally { await reader.cancel().catch(() => {}); }
    })();
    stream.worker.catch(() => {});
    stream.close = async () => { abort.abort(); await stream.worker; };
    return stream;
  };
  return { server, base, post, subscribe };
}
async function waitFor(stream, predicate, label) {
  const deadline = Date.now() + 15000;
  while (!predicate(stream.frames)) {
    if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
    await delay(10);
  }
}
const messages = frames => frames.filter(frame => frame.event === "xeip.message");

test("advertises the resume profile and rejects invalid delivery configuration", async t => {
  for (const delivery of [null, false, { extra: true }, { windowMs: 0 }, { maxPerSession: 0 },
    { maxSessions: 0 }, { maxSessions: 1025 }]) {
    assert.throws(() => createRelay({ token: TOKEN, delivery }));
  }
  const limits = { windowMs: 60000, maxPerSession: 4, maxSessions: 3 };
  const { base } = await setup(t, limits);
  limits.windowMs = 1; limits.maxPerSession = 100;
  const health = await (await fetch(base + "/health")).json();
  assert.equal(health.resumeProfile, LOCAL_DELIVERY_PROFILE);
  assert.deepEqual(health.resume, { windowMs: 60000, maxPerSession: 4, maxSessions: 3 });
});

test("assigns per-session sequence numbers and resumes after a cursor without duplication", async t => {
  const { post, subscribe } = await setup(t);
  const first = envelope(), second = envelope();
  assert.deepEqual(await (await post(first)).json(), { accepted: true, delivered: 0, seq: 1 });
  assert.deepEqual(await (await post(second)).json(), { accepted: true, delivered: 0, seq: 2 });
  const resumed = await subscribe(b, { header: "1" });
  await waitFor(resumed, frames => messages(frames).length === 1, "resume replay");
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2"]);
  assert.deepEqual(JSON.parse(messages(resumed.frames)[0].data), second);
  const third = envelope();
  assert.deepEqual(await (await post(third)).json(), { accepted: true, delivered: 1, seq: 3 });
  await waitFor(resumed, frames => messages(frames).length === 2, "live after resume");
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2", "3"]);
  await resumed.close();
});

test("supports the after query, emits a gap, and rejects malformed or unsupported cursors", async t => {
  const { base, post, subscribe } = await setup(t, { maxPerSession: 1 });
  await post(envelope()); await post(envelope());
  const resumed = await subscribe(b, { after: "0" });
  await waitFor(resumed, frames => messages(frames).length === 1, "gap replay");
  const gap = resumed.frames.find(frame => frame.event === "xeip.gap");
  assert.ok(gap, "gap event emitted");
  assert.deepEqual(JSON.parse(gap.data), { session: room, from: 2 });
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2"]);
  await resumed.close();

  const malformed = await fetch(base + "/events?session=" + encodeURIComponent(room) + "&entity=" + encodeURIComponent(b) + "&after=abc", {
    headers: { Authorization: "Bearer " + TOKEN } });
  assert.equal(malformed.status, 400);
  await malformed.body.cancel();

  const withoutProfile = createRelay({ token: TOKEN });
  await new Promise(resolve => withoutProfile.listen(0, "127.0.0.1", resolve));
  const noProfileBase = "http://127.0.0.1:" + withoutProfile.address().port;
  const unsupported = await fetch(noProfileBase + "/events?session=" + encodeURIComponent(room) + "&entity=" + encodeURIComponent(b) + "&after=1", {
    headers: { Authorization: "Bearer " + TOKEN } });
  assert.equal(unsupported.status, 400);
  await unsupported.body.cancel();
  withoutProfile.closeAllConnections(); await new Promise(resolve => withoutProfile.close(resolve));
});

test("does not replay messages older than the fixed retention window", async t => {
  const { post, subscribe } = await setup(t, { windowMs: 120 });
  await post(envelope());
  // Advance past the fixed window with margin; the window is measured on the
  // monotonic clock, so a longer sleep still proves expiry rather than a race.
  await delay(400);
  const resumed = await subscribe(b, { after: "0" });
  await waitFor(resumed, frames => frames.some(frame => frame.event === "xeip.gap"), "gap after window");
  assert.deepEqual(messages(resumed.frames), []);
  assert.deepEqual(JSON.parse(resumed.frames.find(frame => frame.event === "xeip.gap").data), { session: room, from: 2 });
  await resumed.close();
});

test("filters the resume backlog by recipient", async t => {
  const { post, subscribe } = await setup(t);
  await post(envelope({ recipient: b, id: "urn:uuid:" + randomUUID() }));
  await post(envelope({ recipient: a, id: "urn:uuid:" + randomUUID() }));
  const third = envelope({ recipient: b });
  await post(third);
  const resumed = await subscribe(b, { after: "0" });
  await waitFor(resumed, frames => messages(frames).length === 2, "recipient-filtered replay");
  const bodies = messages(resumed.frames).map(frame => JSON.parse(frame.data));
  assert.ok(bodies.every(message => message.recipient === b));
  assert.deepEqual(bodies[1], third);
  await resumed.close();
});
