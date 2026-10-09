/** Simulated restart-surviving local delivery; no AI model or device action. */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelay } from "../../services/relay/server.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const TOKEN = "durable-demo-shared-token-000000000000";
const agent = "urn:xeip:entity:agent";
const session = "urn:xeip:session:durable-demo";
// A throwaway store directory; the demo removes it on exit.
const dir = mkdtempSync(join(tmpdir(), "xeip-durable-demo-"));
const subscriptions = [];
let relay;

const envelope = () => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender: "urn:xeip:entity:human", recipient: agent, session, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "update" } });

async function startRelay() {
  const server = createRelay({ token: TOKEN, durable: { dir, fsync: "always", maxEntriesPerSession: 3, maxSessions: 8 } });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return { server, base: "http://127.0.0.1:" + server.address().port };
}
async function stopRelay(instance) {
  instance.server.closeAllConnections();
  await new Promise(resolve => instance.server.close(resolve));
}
const post = message => fetch(relay.base + "/messages", { method: "POST",
  headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
  body: JSON.stringify(message), signal: AbortSignal.timeout(4000) });

async function subscribe(after) {
  const controller = new AbortController();
  const url = new URL("/events", relay.base);
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
    if (Date.now() >= deadline) throw new Error("timed out waiting for durable demo");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

try {
  relay = await startRelay();
  const live = await subscribe();
  const first = envelope();
  assert.equal((await (await post(first)).json()).seq, 1);
  await waitUntil(() => live.frames.length === 1);
  assert.equal(live.frames[0].message.id, first.id);
  live.controller.abort(); await live.worker;

  // While disconnected, sequences 2-5 are accepted; only 3-5 stay retained.
  for (let sequence = 2; sequence <= 5; sequence++) {
    assert.equal((await (await post(envelope())).json()).seq, sequence);
  }
  // Restart the relay on the same directory: sequence and backlog must survive.
  await stopRelay(relay);
  relay = await startRelay();
  const health = await (await fetch(relay.base + "/health")).json();
  assert.equal(health.durableProfile, "xeip.local-durable/0.1");
  assert.equal(health.durable.state, "ok");

  const resumed = await subscribe(1);
  await waitUntil(() => resumed.frames.length === 3);
  assert.deepEqual(resumed.gap, { session, from: 3 });
  assert.deepEqual(resumed.frames.map(frame => frame.id), [3, 4, 5]);

  // A live message after restart continues the persisted sequence.
  assert.equal((await (await post(envelope())).json()).seq, 6);
  await waitUntil(() => resumed.frames.length === 4);
  assert.equal(resumed.frames[3].id, 6);

  console.log("PASS local durable: persisted sequence, restart resume with explicit gap, live continuation and cleanup");
} finally {
  for (const subscription of subscriptions) subscription.controller.abort();
  await Promise.allSettled(subscriptions.map(value => value.worker));
  if (relay) await stopRelay(relay);
  rmSync(dir, { recursive: true, force: true });
}
