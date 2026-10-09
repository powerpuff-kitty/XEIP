import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LOCAL_DURABLE_PROFILE } from "./durable.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const TOKEN = "test-token-very-long-and-secret";
const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b";
const room = "urn:xeip:session:ab";
const envelope = (extra = {}) => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender: a, session: room, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello" }, ...extra });

function makeDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "xeip-durable-http-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// Starts a real relay whose durable store lives in `dir`. Tests stop and
// restart against the same directory to prove restart survival.
async function start(t, dir, options = {}) {
  const server = createRelay({ token: TOKEN, durable: { dir, fsync: "always", ...options } });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const base = "http://127.0.0.1:" + server.address().port;
  const streams = [];
  let stopped = false;
  const state = {
    base,
    streams,
    stop: async () => {
      if (stopped) return;
      stopped = true;
      for (const stream of streams) stream.abort.abort();
      await Promise.allSettled(streams.map(stream => stream.worker));
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  };
  t.after(state.stop);
  state.post = message => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(message), signal: AbortSignal.timeout(5000) });
  state.subscribe = async (entity = b, { session = room, after, header } = {}) => {
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
  return state;
}

async function waitFor(stream, predicate, label) {
  const deadline = Date.now() + 4000;
  while (!predicate(stream.frames)) {
    if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
    await delay(10);
  }
}
const messages = frames => frames.filter(frame => frame.event === "xeip.message");

test("rejects delivery and durable together and advertises durable health", async t => {
  const dir = makeDir(t);
  assert.throws(() => createRelay({ token: TOKEN, delivery: {}, durable: { dir } }), /either delivery or durable/);
  const relay = await start(t, dir);
  const health = await (await fetch(relay.base + "/health")).json();
  assert.equal(health.durableProfile, LOCAL_DURABLE_PROFILE);
  assert.equal(health.resumeProfile, "xeip.local-delivery/0.1");
  assert.equal(health.durable.backend, "segments");
  assert.equal(health.durable.state, "ok");
  assert.equal(health.durable.fsync, "always");
  assert.equal(health.durable.maxEntriesPerSession, 4096);
  assert.equal(health.durable.maxSessions, 1024);
  assert.equal(health.durable.maxBytes, 268435456);
  assert.equal(health.durable.retentionMs, 3600000);
  await relay.stop();
});

test("resumes a retained backlog and continues the sequence across restart", async t => {
  const dir = makeDir(t);
  const first = await start(t, dir);
  const firstMessage = envelope(), secondMessage = envelope();
  assert.deepEqual(await (await first.post(firstMessage)).json(), { accepted: true, delivered: 0, seq: 1 });
  assert.deepEqual(await (await first.post(secondMessage)).json(), { accepted: true, delivered: 0, seq: 2 });
  await first.stop();

  const second = await start(t, dir);
  const health = await (await fetch(second.base + "/health")).json();
  assert.equal(health.durable.state, "ok");

  const resumed = await second.subscribe(b, { after: "1" });
  await waitFor(resumed, frames => messages(frames).length === 1, "restart replay");
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2"]);
  assert.deepEqual(JSON.parse(messages(resumed.frames)[0].data), secondMessage);

  // A live message after restart continues the persisted sequence and counts.
  const third = envelope();
  assert.deepEqual(await (await second.post(third)).json(), { accepted: true, delivered: 1, seq: 3 });
  await waitFor(resumed, frames => messages(frames).length === 2, "live after restart");
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2", "3"]);
  assert.equal(messages(resumed.frames)[1].data, JSON.stringify(third));
  await resumed.close();
  await second.stop();
});

test("resumes with Last-Event-ID and reports a persisted gap with monotonic seq", async t => {
  const dir = makeDir(t);
  const first = await start(t, dir, { maxEntriesPerSession: 1 });
  await first.post(envelope()); // seq 1, evicted when seq 2 arrives
  await first.post(envelope()); // seq 2
  await first.stop();

  const second = await start(t, dir, { maxEntriesPerSession: 1 });
  const resumed = await second.subscribe(b, { header: "0" });
  await waitFor(resumed, frames => frames.some(frame => frame.event === "xeip.gap"), "gap after eviction");
  assert.deepEqual(JSON.parse(resumed.frames.find(frame => frame.event === "xeip.gap").data), { session: room, from: 2 });
  await waitFor(resumed, frames => messages(frames).length === 1, "retained backlog");
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2"]);

  // The evicted sequence is never reused: the next acceptance is seq 3.
  assert.deepEqual(await (await second.post(envelope())).json(), { accepted: true, delivered: 1, seq: 3 });
  await waitFor(resumed, frames => messages(frames).length === 2, "live after gap");
  assert.deepEqual(messages(resumed.frames).map(frame => frame.id), ["2", "3"]);
  await resumed.close();
  await second.stop();
});
