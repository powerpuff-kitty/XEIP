/** Simulated local rate/connection limits; no AI model, device action or persistence. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { createRelay } from "../../services/relay/server.mjs";
import { LocalAdmission } from "../../services/relay/admission.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const human = "urn:xeip:entity:human";
const agent = "urn:xeip:entity:agent";
const session = "urn:xeip:session:limits-demo";
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// Ephemeral credentials are generated locally and never printed.
function admissionPolicy() {
  const credentials = new Map([human, agent].map(entity => [entity, randomBytes(32).toString("base64url")]));
  const admission = new LocalAdmission({
    credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [{ xeip: "0.1", id: session, mode: "group", members: [human, agent], createdAt: new Date().toISOString() }]
  });
  const auth = entity => ({ Authorization: "Bearer " + credentials.get(entity) });
  return { admission, auth };
}

async function startRelay(limits) {
  const { admission, auth } = admissionPolicy();
  const server = createRelay({ admission, limits });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const base = "http://127.0.0.1:" + server.address().port;
  const streams = [];
  const envelope = sender => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender,
    recipient: sender === human ? agent : human, session, timestamp: new Date().toISOString(),
    body: { contentType: "text/plain", data: "status" } });
  const post = entity => fetch(base + "/messages", { method: "POST",
    headers: { ...auth(entity), "Content-Type": "application/json" },
    body: JSON.stringify(envelope(entity)), signal: AbortSignal.timeout(4000) });
  const subscribe = async entity => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", session); url.searchParams.set("entity", entity);
    const response = await fetch(url, { headers: auth(entity), signal: abort.signal });
    const stream = { response, abort, close: () => abort.abort() };
    if (response.status === 200) {
      streams.push(stream);
      const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
      stream.worker = (async () => {
        try {
          while (true) {
            const next = await reader.read(); if (next.done) break;
            parser.push(decoder.decode(next.value, { stream: true }));
          }
        } catch { /* aborted */ }
        finally { await reader.cancel().catch(() => {}); }
      })();
      stream.worker.catch(() => {});
    }
    return stream;
  };
  return { server, base, post, subscribe, streams };
}

async function stopRelay(instance) {
  for (const stream of instance.streams) stream.abort.abort();
  await Promise.allSettled(instance.streams.map(stream => stream.worker));
  instance.server.closeAllConnections();
  await new Promise(resolve => instance.server.close(resolve));
}

// Phase 1: per-key token bucket, its 429, isolation and monotonic refill.
const rateRelay = await startRelay({ requestsPerSecond: 5, burst: 2, maxConnections: 4, maxSubscriptions: 4 });
try {
  const health = await (await fetch(rateRelay.base + "/health")).json();
  assert.equal(health.limitsProfile, "xeip.local-limits/0.1");
  assert.deepEqual(health.limits, { requestsPerSecond: 5, burst: 2, maxConnections: 4, maxSubscriptions: 4, keyBy: "principal" });

  assert.equal((await rateRelay.post(human)).status, 202);
  assert.equal((await rateRelay.post(human)).status, 202);
  const limited = await rateRelay.post(human);
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "1");
  assert.deepEqual(await limited.json(), { error: "rate limit exceeded" });
  // A different principal has its own bucket.
  assert.equal((await rateRelay.post(agent)).status, 202);
  // Refill on a monotonic clock: after a short wait the human bucket recovers.
  await sleep(250);
  assert.equal((await rateRelay.post(human)).status, 202);
} finally {
  await stopRelay(rateRelay);
}

// Phase 2: shared subscription cap, released when a stream closes.
const capRelay = await startRelay({ requestsPerSecond: 100, burst: 100, maxConnections: 4, maxSubscriptions: 2 });
try {
  const first = await capRelay.subscribe(human);
  assert.equal(first.response.status, 200);
  const second = await capRelay.subscribe(agent);
  assert.equal(second.response.status, 200);
  const denied = await capRelay.subscribe(human);
  assert.equal(denied.response.status, 429);
  assert.deepEqual(await denied.response.json(), { error: "subscription limit exceeded" });

  await first.close();
  if (first.worker) await first.worker;
  await sleep(50);
  const reopened = await capRelay.subscribe(human);
  assert.equal(reopened.response.status, 200);
  await reopened.close();
  if (reopened.worker) await reopened.worker;
} finally {
  await stopRelay(capRelay);
}

console.log("PASS local limits: health profile, per-principal burst/429 with Retry-After, refill, subscription cap and release");
