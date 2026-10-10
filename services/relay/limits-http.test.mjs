import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LocalAdmission } from "./admission.mjs";
import { LOCAL_LIMITS_PROFILE } from "./limits.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "./websocket.mjs";

const TOKEN = "limits-test-shared-token-000000";
const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b";
const session = "urn:xeip:session:limits";

const message = (sender = a, recipient = b) => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(),
  kind: "message", sender, recipient, session, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello" } });

async function setup(t, { admission = false, limits } = {}) {
  const credentials = new Map([a, b].map(entity => [entity, admission ? randomBytes(32).toString("base64url") : TOKEN]));
  const options = admission
    ? { admission: new LocalAdmission({
        credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
        sessions: [{ xeip: "0.1", id: session, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" }]
      }) }
    : { token: TOKEN };
  if (limits !== undefined) options.limits = limits;
  const server = createRelay(options);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  const streams = [];
  t.after(async () => {
    for (const stream of streams) stream.abort.abort();
    await Promise.allSettled(streams.map(stream => stream.worker));
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const auth = actor => ({ Authorization: "Bearer " + credentials.get(actor) });
  const post = (actor, envelope) => fetch(base + "/messages", { method: "POST",
    headers: { ...auth(actor), "Content-Type": "application/json" },
    body: JSON.stringify(envelope), signal: AbortSignal.timeout(5000) });
  const health = async () => (await fetch(base + "/health")).json();
  const subscribe = async (actor = a) => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", session); url.searchParams.set("entity", actor);
    const response = await fetch(url, { headers: auth(actor), signal: abort.signal });
    if (response.status !== 200) return { response, close: () => abort.abort() };
    const stream = { response, abort, frames: [] };
    streams.push(stream);
    stream.worker = (async () => {
      const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
      try {
        while (true) {
          const next = await reader.read(); if (next.done) break;
          for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) stream.frames.push(frame);
        }
      } catch { /* aborted */ }
      finally { await reader.cancel().catch(() => {}); }
    })();
    stream.worker.catch(() => {});
    stream.close = async () => { abort.abort(); await stream.worker; };
    return stream;
  };
  return { server, base, credentials, post, health, subscribe };
}

async function waitFor(predicate, label) {
  const deadline = Date.now() + 15000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
    await delay(10);
  }
}

// A limit slot is released asynchronously when the server observes the stream
// or connection close. Retry the real operation until it is accepted instead of
// sleeping a fixed interval that a loaded machine can outrun.
async function subscribeEventually(subscribe, actor, label, deadlineMs = 15000) {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const attempt = await subscribe(actor);
    if (attempt.response.status === 200) return attempt;
    assert.equal(attempt.response.status, 429, label);
    await attempt.response.arrayBuffer().catch(() => {});
    if (Date.now() >= deadline) throw new Error(label);
    await delay(25);
  }
}

async function openEventually(base, options, label, deadlineMs = 15000) {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    try { return await openWebSocket(base, options); }
    catch (error) {
      if (error.status !== 429) throw error;
      if (Date.now() >= deadline) throw new Error(label);
      await delay(25);
    }
  }
}

class TestSocket {
  constructor(socket) {
    this.socket = socket;
    this.messages = [];
    this.parser = new FrameParser({ maxFrame: 128 * 1024, maxMessage: 128 * 1024, expectMask: false });
    socket.on("data", chunk => {
      for (const event of this.parser.push(chunk)) {
        if (event.type === "message") this.messages.push(JSON.parse(event.text));
        else if (event.type === "ping") this.socket.write(encodeFrame(OPCODES.pong, event.payload, true, randomBytes(4)));
      }
    });
  }
  send(value) { if (!this.socket.destroyed) this.socket.write(encodeFrame(OPCODES.text, Buffer.from(JSON.stringify(value)), true, randomBytes(4))); }
  close() { if (!this.socket.destroyed) this.socket.write(encodeFrame(OPCODES.close, Buffer.alloc(0), true, randomBytes(4))); this.socket.end(); }
}

function openWebSocket(base, { token } = {}) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const url = new URL(base);
    const req = request({ host: url.hostname, port: url.port, path: "/ws",
      headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key,
        ...(token ? { Authorization: "Bearer " + token } : {}) } });
    req.once("upgrade", (response, socket, head) => {
      if (response.headers["sec-websocket-accept"] !== websocketAccept(key)) { socket.destroy(); return reject(new Error("invalid accept")); }
      const client = new TestSocket(socket);
      if (head.length > 0) socket.unshift(head);
      resolve(client);
    });
    req.once("response", response => { response.resume(); reject(Object.assign(new Error("HTTP " + response.statusCode), { status: response.statusCode })); });
    req.once("error", reject);
    req.end();
  });
}

test("advertises the limits profile and rejects invalid configuration", async t => {
  for (const limits of [null, false, { extra: true }, { requestsPerSecond: 0 }, { burst: 0 },
    { maxConnections: 0 }, { maxSubscriptions: 0 }, { keyBy: "session" }]) {
    assert.throws(() => createRelay({ token: TOKEN, limits }));
  }
  const { health } = await setup(t, { limits: { requestsPerSecond: 5, burst: 7, maxConnections: 8, maxSubscriptions: 9, keyBy: "peer" } });
  const body = await health();
  assert.equal(body.limitsProfile, LOCAL_LIMITS_PROFILE);
  assert.deepEqual(body.limits, { requestsPerSecond: 5, burst: 7, maxConnections: 8, maxSubscriptions: 9, keyBy: "peer" });
});

test("allows a burst, then returns 429 with Retry-After, and refills after time", async t => {
  const { post } = await setup(t, { limits: { requestsPerSecond: 1, burst: 2 } });
  assert.equal((await post(a, message())).status, 202);
  assert.equal((await post(a, message())).status, 202);
  const limited = await post(a, message());
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "1");
  assert.deepEqual(await limited.json(), { error: "rate limit exceeded" });
  // At one token per second the burst bucket needs a full second to refill.
  // Poll for the refill rather than assuming a fixed sleep survives CI load; a
  // bucket that never refills still fails once the deadline passes.
  const deadline = Date.now() + 15000;
  let refilled = await post(a, message());
  while (refilled.status !== 202) {
    assert.equal(refilled.status, 429);
    await refilled.arrayBuffer();
    if (Date.now() >= deadline) throw new Error("rate limit did not refill");
    await delay(50);
    refilled = await post(a, message());
  }
  assert.equal(refilled.status, 202);
});

test("isolates per-principal buckets in admission mode", async t => {
  const { post } = await setup(t, { admission: true, limits: { requestsPerSecond: 1, burst: 1 } });
  assert.equal((await post(a, message(a))).status, 202);
  assert.equal((await post(a, message(a))).status, 429);
  assert.equal((await post(b, message(b, a))).status, 202);
});

test("never limits health or the static console assets", async t => {
  const { base, post } = await setup(t, { limits: { requestsPerSecond: 1, burst: 1 } });
  assert.equal((await post(a, message())).status, 202);
  assert.equal((await post(a, message())).status, 429);
  for (let index = 0; index < 5; index++) assert.equal((await fetch(base + "/health")).status, 200);
  for (const path of ["/console", "/console.js", "/console.css"]) {
    assert.equal((await fetch(base + path)).status, 200, path);
  }
});

test("enforces the connection cap on streams and releases it on close", async t => {
  const { subscribe } = await setup(t, { limits: { requestsPerSecond: 100, burst: 100, maxConnections: 1, maxSubscriptions: 10 } });
  const first = await subscribe(a);
  assert.equal(first.response.status, 200);
  const second = await subscribe(a);
  assert.equal(second.response.status, 429);
  assert.deepEqual(await second.response.json(), { error: "connection limit exceeded" });
  await first.close();
  const third = await subscribeEventually(subscribe, a, "connection limit not released");
  assert.equal(third.response.status, 200);
  await third.close();
});

test("enforces the subscription cap on streams and releases it on close", async t => {
  const { subscribe } = await setup(t, { limits: { requestsPerSecond: 100, burst: 100, maxConnections: 10, maxSubscriptions: 1 } });
  const first = await subscribe(a);
  assert.equal(first.response.status, 200);
  const second = await subscribe(b);
  assert.equal(second.response.status, 429);
  assert.deepEqual(await second.response.json(), { error: "subscription limit exceeded" });
  await first.close();
  const third = await subscribeEventually(subscribe, b, "subscription limit not released");
  assert.equal(third.response.status, 200);
  await third.close();
});

test("enforces the connection cap on the WebSocket upgrade and releases it on close", async t => {
  const { base } = await setup(t, { limits: { requestsPerSecond: 100, burst: 100, maxConnections: 1, maxSubscriptions: 10 } });
  const first = await openWebSocket(base, { token: TOKEN });
  await assert.rejects(() => openWebSocket(base, { token: TOKEN }), error => error.status === 429);
  first.close();
  const third = await openEventually(base, { token: TOKEN }, "WebSocket connection limit not released");
  third.close();
});

test("enforces the subscription cap on WebSocket subscribe and releases it on close", async t => {
  const { base } = await setup(t, { limits: { requestsPerSecond: 100, burst: 100, maxConnections: 10, maxSubscriptions: 1 } });
  const first = await openWebSocket(base, { token: TOKEN });
  first.send({ type: "subscribe", session, entity: a });
  await waitFor(() => first.messages.some(value => value.type === "subscribed"), "first subscription");
  const second = await openWebSocket(base, { token: TOKEN });
  second.send({ type: "subscribe", session, entity: a });
  await waitFor(() => second.messages.some(value => value.type === "error"), "subscription denial");
  assert.equal(second.messages.find(value => value.type === "error").status, 429);
  first.close();
  // Retry the subscribe on the surviving connection until the closed one's
  // subscription slot is actually released.
  const deadline = Date.now() + 15000;
  for (;;) {
    const before = second.messages.length;
    second.send({ type: "subscribe", session, entity: a });
    await waitFor(() => second.messages.slice(before).some(value => value.type === "subscribed" || value.type === "error"), "release outcome");
    if (second.messages.slice(before).some(value => value.type === "subscribed")) break;
    if (Date.now() >= deadline) throw new Error("subscription slot not released");
    await delay(25);
  }
  second.close();
});

test("rate-limits WebSocket controls with a 429 error control", async t => {
  const { base } = await setup(t, { limits: { requestsPerSecond: 1, burst: 2, maxConnections: 10, maxSubscriptions: 10 } });
  const client = await openWebSocket(base, { token: TOKEN });
  client.send({ type: "send", message: message() });
  await waitFor(() => client.messages.some(value => value.type === "accepted"), "first control accepted");
  client.send({ type: "send", message: message() });
  await waitFor(() => client.messages.some(value => value.type === "error"), "control rate denial");
  assert.equal(client.messages.find(value => value.type === "error").status, 429);
  client.close();
});

test("keeps the original behavior when the limits profile is disabled", async t => {
  const { base, post, health, subscribe } = await setup(t, {});
  for (let index = 0; index < 5; index++) assert.equal((await post(a, message())).status, 202);
  const body = await health();
  assert.equal(body.limitsProfile, undefined);
  assert.equal(body.limits, undefined);
  const first = await subscribe(a);
  const second = await subscribe(a);
  assert.equal(first.response.status, 200);
  assert.equal(second.response.status, 200);
  await first.close();
  await second.close();
});
