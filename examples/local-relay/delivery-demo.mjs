/** Simulated local disconnect/resume; no AI model, device action or persistence. */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRelay } from "../../services/relay/server.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const TOKEN = "delivery-demo-shared-token-000000000000";
const agent = "urn:xeip:entity:agent";
const session = "urn:xeip:session:delivery-demo";
// A deliberately tiny retention bound so the demo can show an explicit gap.
const server = createRelay({ token: TOKEN, delivery: { maxPerSession: 2, maxSessions: 4 } });
await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
const base = "http://127.0.0.1:" + server.address().port;
const subscriptions = [];

const envelope = () => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender: "urn:xeip:entity:human",
  recipient: agent, session, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "update" } });
const post = message => fetch(base + "/messages", { method: "POST",
  headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
  body: JSON.stringify(message), signal: AbortSignal.timeout(4000) });
async function subscribe(after) {
  const controller = new AbortController();
  const url = new URL("/events", base);
  url.searchParams.set("session", session); url.searchParams.set("entity", agent);
  if (after !== undefined) url.searchParams.set("after", String(after));
  const response = await fetch(url, { headers: { Authorization: "Bearer " + TOKEN }, signal: controller.signal });
  assert.equal(response.status, 200);
  const subscription = { controller, frames: [], gap: undefined };
  subscriptions.push(subscription);
  subscription.worker = (async () => {
    const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
    try {
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
          if (frame.event === "xeip.message") subscription.frames.push({ id: Number(frame.id), message: JSON.parse(frame.data) });
          else if (frame.event === "xeip.gap") subscription.gap = JSON.parse(frame.data);
        }
      }
    } catch (error) { if (!controller.signal.aborted) throw error; }
    finally { await reader.cancel().catch(() => {}); }
  })();
  subscription.worker.catch(() => {});
  return subscription;
}
async function waitUntil(predicate) {
  const deadline = Date.now() + 4000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for local delivery demo");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

try {
  const live = await subscribe();
  const first = envelope();
  const firstResponse = await post(first);
  assert.equal(firstResponse.status, 202);
  assert.equal((await firstResponse.json()).seq, 1);
  await waitUntil(() => live.frames.length === 1);
  assert.deepEqual(live.frames.map(frame => frame.id), [1]);
  assert.equal(live.frames[0].message.id, first.id);
  assert.equal(live.gap, undefined);
  live.controller.abort(); await live.worker;

  // While disconnected, sequences 2-4 are accepted and the window retains only 3-4.
  for (let index = 0; index < 3; index++) {
    const response = await post(envelope());
    assert.equal(response.status, 202);
    assert.equal((await response.json()).seq, index + 2);
  }
  const resumed = await subscribe(1);
  await waitUntil(() => resumed.frames.length === 2);
  assert.deepEqual(resumed.gap, { session, from: 3 });
  assert.deepEqual(resumed.frames.map(frame => frame.id), [3, 4]);

  // A live message after resume advances the same cursor without duplication.
  const fresh = envelope();
  const freshResponse = await post(fresh);
  const freshSeq = (await freshResponse.json()).seq;
  assert.equal(freshSeq, 5);
  await waitUntil(() => resumed.frames.length === 3);
  assert.equal(resumed.frames[2].id, freshSeq);
  assert.equal(resumed.frames[2].message.id, fresh.id);

  const invalid = await fetch(base + "/events?session=" + encodeURIComponent(session) + "&entity=" + encodeURIComponent(agent) + "&after=nope", {
    headers: { Authorization: "Bearer " + TOKEN } });
  assert.equal(invalid.status, 400); await invalid.body.cancel();

  console.log("PASS local delivery: per-session sequence, cursor resume, explicit gap on eviction, live continuation and invalid-cursor rejection");
} finally {
  for (const subscription of subscriptions) subscription.controller.abort();
  await Promise.allSettled(subscriptions.map(value => value.worker));
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
