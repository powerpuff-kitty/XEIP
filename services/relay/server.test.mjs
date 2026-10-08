import test from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "./server.mjs";
import { randomUUID } from "node:crypto";

const TOKEN = "test-token-very-long-and-secret";
const session = "urn:xeip:session:test";
const sender = "urn:xeip:entity:human";
const agent = "urn:xeip:entity:agent";
const machine = "urn:xeip:entity:machine";

async function withRelay(run) {
  const server = createRelay({ token: TOKEN });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  try { await run(base); }
  finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
function makeMessage(overrides = {}) {
  return {
    xeip: "0.1",
    id: "urn:uuid:" + randomUUID(),
    kind: "message",
    sender,
    recipient: agent,
    session,
    timestamp: new Date().toISOString(),
    body: { contentType: "text/plain", data: "hello" },
    ...overrides
  };
}
async function post(base, message, extraHeaders = {}) {
  return fetch(base + "/messages", {
    method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json", ...extraHeaders },
    body: JSON.stringify(message)
  });
}
async function subscribe(base, entity, room = session) {
  const controller = new AbortController();
  const url = new URL(base + "/events");
  url.searchParams.set("session", room);
  url.searchParams.set("entity", entity);
  const response = await fetch(url, { headers: { Authorization: "Bearer " + TOKEN }, signal: controller.signal });
  assert.equal(response.status, 200);
  return { response, close: () => controller.abort() };
}

test("requires a strong development token and rejects unauthenticated clients", async () => {
  assert.throws(() => createRelay({ token: "short" }), /16/);
  await withRelay(async base => {
    const health = await fetch(base + "/health");
    assert.equal(health.status, 200);
    const denied = await fetch(base + "/messages", { method: "POST", body: "{}" });
    assert.equal(denied.status, 401);
    const unauthorizedStream = await fetch(base + "/events?session=x&entity=y");
    assert.equal(unauthorizedStream.status, 401);
  });
});

test("rejects malformed, unsupported, expired and oversized messages", async () => {
  await withRelay(async base => {
    assert.equal((await post(base, makeMessage({ xeip: "9.9" }))).status, 422);
    assert.equal((await post(base, makeMessage({ sender: "not-uri" }))).status, 422);
    assert.equal((await post(base, makeMessage({ expiresAt: "2020-01-01T00:00:00Z" }))).status, 422);
    assert.equal((await post(base, makeMessage({ extraField: "bad" }))).status, 422);
    assert.equal((await post(base, makeMessage({ body: { contentType: "text/plain" } }))).status, 422);
    assert.equal((await post(base, makeMessage({ body: { contentType: "text/plain", data: "x".repeat(70_000) } }))).status, 413);
  });
});

test("routes live messages only to the selected session and recipient", async () => {
  await withRelay(async base => {
    const target = await subscribe(base, agent);
    const other = await subscribe(base, machine);
    const differentSession = await subscribe(base, agent, "urn:xeip:session:elsewhere");
    try {
      const message = makeMessage();
      const response = await post(base, message);
      assert.equal(response.status, 202);
      const result = await response.json();
      assert.equal(result.delivered, 1);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      try {
        const reader = target.response.body.getReader();
        let data = "";
        while (!data.includes(message.id)) {
          const next = await Promise.race([
            reader.read(),
            new Promise((_, reject) => controller.signal.addEventListener("abort", () => reject(new Error("message not received")), { once: true }))
          ]);
          if (next.done) throw new Error("stream ended prematurely");
          data += new TextDecoder().decode(next.value);
        }
        assert.match(data, /event: xeip.message/);
      } finally { clearTimeout(timer); }
    } finally {
      target.close(); other.close(); differentSession.close();
    }
  });
});
