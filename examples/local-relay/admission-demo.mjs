/** Simulated local participants; no AI model, device action or persistent credentials. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { createRelay } from "../../services/relay/server.mjs";
import { LocalAdmission } from "../../services/relay/admission.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { validateEnvelope } from "../../sdks/typescript/src/validation.js";

const entities = ["human", "agent", "camera"].map(name => "urn:xeip:entity:" + name);
const [human, agent, camera] = entities;
const replay = process.argv.includes("--replay");
const session = "urn:xeip:session:admission-demo";
const credentials = new Map(entities.map(entity => [entity, randomBytes(32).toString("base64url")]));
const admission = new LocalAdmission({
  credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
  sessions: [{ xeip: "0.1", id: session, mode: "group", members: entities, createdAt: new Date().toISOString() }]
});
const server = createRelay({ admission, ...(replay ? { replay: {} } : {}) });
await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
const base = "http://127.0.0.1:" + server.address().port;
const headers = entity => ({ Authorization: "Bearer " + credentials.get(entity) });
const subscriptions = [];

async function subscribe(entity) {
  const controller = new AbortController();
  const url = new URL("/events", base);
  url.searchParams.set("session", session); url.searchParams.set("entity", entity);
  const response = await fetch(url, { headers: headers(entity), signal: controller.signal });
  assert.equal(response.status, 200);
  const subscription = { controller, received: [], ended: false };
  subscriptions.push(subscription);
  subscription.worker = (async () => {
    const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
          if (frame.event !== "xeip.message") continue;
          const message = JSON.parse(frame.data); validateEnvelope(message);
          subscription.received.push(message);
        }
      }
    } catch (error) {
      // Native revocation destroys the stream; other failures must still surface.
      if (!controller.signal.aborted && !subscription.expectRevocation) throw error;
    } finally { subscription.ended = true; await reader.cancel().catch(() => {}); }
  })();
  subscription.worker.catch(() => {}); // Cleanup always awaits the original worker.
  return subscription;
}
function envelope(sender, recipient, kind, data, contentType = "text/plain") {
  return { xeip: "0.1", id: "urn:uuid:" + randomUUID(), sender, recipient, session, kind,
    timestamp: new Date().toISOString(), body: { contentType, data } };
}
function post(actor, message) {
  return fetch(base + "/messages", { method: "POST", headers: { ...headers(actor), "Content-Type": "application/json" },
    body: JSON.stringify(message), signal: AbortSignal.timeout(4000) });
}
async function waitUntil(predicate) {
  const deadline = Date.now() + 4000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for local admission demo");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

try {
  // Sequential registration keeps earlier streams owned even if a later connection fails.
  const h = await subscribe(human), a = await subscribe(agent), c = await subscribe(camera);
  const exchanges = [
    [envelope(human, agent, "message", "Can you check the camera?"), a],
    [envelope(agent, camera, "message", "Please report your storage state."), c],
    [envelope(camera, human, "event", { storageFreePct: 3 }, "application/json"), h]
  ];
  for (const [message, recipient] of exchanges) {
    const response = await post(message.sender, message);
    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), { accepted: true, delivered: 1, ...(replay ? { duplicate: false } : {}) });
    await waitUntil(() => recipient.received.some(value => value.id === message.id));
    if (replay) {
      const retry = await post(message.sender, message);
      assert.equal(retry.status, 202);
      assert.deepEqual(await retry.json(), { accepted: true, delivered: 0, duplicate: true });
      const conflict = await post(message.sender, { ...message, body: { ...message.body, data: "changed retry" } });
      assert.equal(conflict.status, 409); await conflict.body.cancel();
    }
  }
  assert.deepEqual(subscriptions.map(value => value.received.length), [1, 1, 1]);
  let activeAgent = a;
  if (replay) {
    a.controller.abort(); await a.worker;
    activeAgent = await subscribe(agent);
    const retry = await post(human, exchanges[0][0]);
    assert.deepEqual(await retry.json(), { accepted: true, delivered: 0, duplicate: true });
    const fresh = envelope(human, agent, "message", "A new message after reconnect.");
    const response = await post(human, fresh);
    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), { accepted: true, delivered: 1, duplicate: false });
    await waitUntil(() => activeAgent.received.some(value => value.id === fresh.id));
    assert.deepEqual(activeAgent.received, [fresh]);
  }
  const spoof = await post(human, envelope(agent, camera, "command", "spoof"));
  assert.equal(spoof.status, 403); await spoof.body.cancel();
  activeAgent.expectRevocation = true; admission.revokeCredential(agent);
  await waitUntil(() => activeAgent.ended); await activeAgent.worker;
  const reconnect = new URL("/events", base);
  reconnect.searchParams.set("session", session); reconnect.searchParams.set("entity", agent);
  const denied = await fetch(reconnect, { headers: headers(agent), signal: AbortSignal.timeout(4000) });
  assert.equal(denied.status, 401); await denied.body.cancel();
  console.log(replay
    ? "PASS local replay: identical retries suppressed, changed-content retries rejected, reconnect receives only a fresh message, revocation enforced"
    : "PASS local admission: 3 credential-bound participants, 3 targeted messages, spoof rejected, revoked stream closed and reconnect denied");
} finally {
  for (const subscription of subscriptions) subscription.controller.abort();
  await Promise.allSettled(subscriptions.map(value => value.worker));
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
