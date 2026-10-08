/**
 * End-to-end *simulated* human → agent → machine XEIP demo.
 * Requires an already-running local relay. No AI model or real device is invoked.
 */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { validateEnvelope } from "../../sdks/typescript/src/validation.js";

const base = "http://127.0.0.1:" + (process.env.XEIP_PORT ?? "8787");
const token = process.env.XEIP_DEV_TOKEN;
if (!token || token.length < 16) throw new Error("set XEIP_DEV_TOKEN (>=16 characters)");
const session = "urn:xeip:session:demo";
const human = "urn:xeip:entity:human-01";
const agent = "urn:xeip:entity:agent-01";
const camera = "urn:xeip:entity:camera-01";
const auth = { Authorization: "Bearer " + token };

function envelope(sender, recipient, kind, data, contentType = "text/plain") {
  return {
    xeip: "0.1",
    id: "urn:uuid:" + randomUUID(),
    kind, sender, recipient, session,
    timestamp: new Date().toISOString(),
    body: { contentType, data }
  };
}
async function subscribe(entity) {
  const controller = new AbortController();
  const url = new URL(base + "/events");
  url.searchParams.set("session", session);
  url.searchParams.set("entity", entity);
  const response = await fetch(url, { headers: auth, signal: controller.signal });
  if (!response.ok || !response.body) throw new Error("stream failed for " + entity);
  const received = [];
  const worker = (async () => {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const parser = new SseParser();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
          if (frame.event !== "xeip.message") continue;
          const message = JSON.parse(frame.data);
          validateEnvelope(message);
          received.push(message);
        }
      }
    } catch (error) {
      if (!controller.signal.aborted) throw error;
    } finally { await reader.cancel().catch(() => {}); }
  })();
  return { received, close: () => controller.abort(), worker };
}
async function send(message) {
  const response = await fetch(base + "/messages", {
    method: "POST",
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify(message)
  });
  if (response.status !== 202) throw new Error("message rejected: " + response.status);
  const receipt = await response.json();
  if (receipt.delivered !== 1) throw new Error("expected exactly one live recipient, got " + receipt.delivered);
}
async function waitUntil(predicate) {
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for XEIP recipient");
}

const subscriptions = await Promise.all([subscribe(human), subscribe(agent), subscribe(camera)]);
try {
  const [h, a, c] = subscriptions;
  const question = envelope(human, agent, "message", "Can you check the camera?");
  await send(question);
  await waitUntil(() => a.received.some(m => m.id === question.id));
  const request = envelope(agent, camera, "message", "Please report your storage state.");
  await send(request);
  await waitUntil(() => c.received.some(m => m.id === request.id));
  const status = envelope(camera, human, "event", { storageFreePct: 3, recording: false }, "application/json");
  await send(status);
  await waitUntil(() => h.received.some(m => m.id === status.id));
  assert.equal(h.received.length, 1);
  assert.equal(a.received.length, 1);
  assert.equal(c.received.length, 1);
  console.log("PASS XEIP human → agent → machine → human: 3 typed messages, targeted routing, 1 active recipient each");
} finally {
  for (const subscription of subscriptions) subscription.close();
  await Promise.allSettled(subscriptions.map(s => s.worker));
}
