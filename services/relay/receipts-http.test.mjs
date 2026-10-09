import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LocalAdmission } from "./admission.mjs";
import { LOCAL_RECEIPTS_PROFILE } from "./receipts.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "./websocket.mjs";

const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b", c = "urn:xeip:entity:c";
const room = "urn:xeip:session:ab", elsewhere = "urn:xeip:session:c";
const secret = () => randomBytes(32).toString("base64url");
const message = (extra = {}) => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender: a,
  recipient: b, session: room, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "hello" }, ...extra });

async function setup(t, { delivery = {}, receipts = {} } = {}) {
  const credentials = new Map([a, b, c].map(entity => [entity, secret()]));
  const admission = new LocalAdmission({
    credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [
      { xeip: "0.1", id: room, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" },
      { xeip: "0.1", id: elsewhere, mode: "group", members: [c], createdAt: "2026-10-09T00:00:00Z" }
    ]
  });
  const options = { admission, delivery };
  if (receipts !== null) options.receipts = receipts;
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
  const post = (actor, envelope) => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + credentials.get(actor), "Content-Type": "application/json" },
    body: JSON.stringify(envelope), signal: AbortSignal.timeout(5000) });
  const receipt = (actor, document, contentType = "application/json") => fetch(base + "/receipts", { method: "POST",
    headers: { Authorization: "Bearer " + credentials.get(actor), "Content-Type": contentType },
    body: JSON.stringify(document), signal: AbortSignal.timeout(5000) });
  const subscribe = async (actor, session = room) => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", session); url.searchParams.set("entity", actor);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + credentials.get(actor) }, signal: abort.signal });
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
      } catch { /* aborted */ }
      finally { await reader.cancel().catch(() => {}); }
    })();
    stream.worker.catch(() => {});
    return stream;
  };
  return { base, credentials, admission, post, receipt, subscribe };
}

async function waitFor(predicate, label) {
  const deadline = Date.now() + 4000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
    await delay(10);
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

test("requires admission and delivery and advertises the receipt profile", async t => {
  const credentials = new Map([a, b].map(entity => [entity, secret()]));
  const admission = new LocalAdmission({ credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [{ xeip: "0.1", id: room, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" }] });
  assert.throws(() => createRelay({ admission, receipts: {} }), /receipts/);
  assert.throws(() => createRelay({ token: "shared-demo-token-long-enough", delivery: {}, receipts: {} }), /receipts/);
  const { base } = await setup(t);
  const health = await (await fetch(base + "/health")).json();
  assert.equal(health.receiptProfile, LOCAL_RECEIPTS_PROFILE);
  assert.deepEqual(health.receipts, { windowMs: 300000, maxPerSession: 512, maxPerPrincipal: 4096 });
});

test("acknowledges a retained target by seq and is idempotent", async t => {
  const { post, receipt } = await setup(t);
  const target = message();
  const accepted = await post(a, target);
  assert.equal(accepted.status, 202);
  const { seq } = await accepted.json();
  const first = await receipt(b, { session: room, seq });
  assert.equal(first.status, 202);
  assert.deepEqual(await first.json(), { acknowledged: true, session: room, seq, duplicate: false });
  const repeat = await receipt(b, { session: room, seq, status: "received" });
  assert.equal(repeat.status, 202);
  assert.deepEqual(await repeat.json(), { acknowledged: true, session: room, seq, duplicate: true });
  const byId = await receipt(b, { session: room, id: target.id });
  assert.equal(byId.status, 202);
  assert.deepEqual(await byId.json(), { acknowledged: true, session: room, seq, duplicate: true });
});

test("rejects selector disagreement, unknown targets and malformed controls", async t => {
  const { base, post, receipt } = await setup(t);
  const accepted = await post(a, message());
  const { seq } = await accepted.json();
  const disagree = await receipt(b, { session: room, seq, id: "urn:uuid:" + randomUUID() });
  assert.equal(disagree.status, 409); await disagree.body.cancel();
  const unknown = await receipt(b, { session: room, seq: 9999 });
  assert.equal(unknown.status, 404); await unknown.body.cancel();
  const missing = await receipt(b, { session: room });
  assert.equal(missing.status, 400); await missing.body.cancel();
  const badStatus = await receipt(b, { session: room, seq, status: "completed" });
  assert.equal(badStatus.status, 400); await badStatus.body.cancel();
  const unknownField = await receipt(b, { session: room, seq, extra: true });
  assert.equal(unknownField.status, 400); await unknownField.body.cancel();
  const wrongType = await receipt(b, { session: room, seq }, "text/plain");
  assert.equal(wrongType.status, 415); await wrongType.body.cancel();
  const unauthenticated = await fetch(base + "/receipts", { method: "POST",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session: room, seq }) });
  assert.equal(unauthenticated.status, 401); await unauthenticated.body.cancel();
});

test("rejects an id-only receipt that matches more than one retained acceptance", async t => {
  const { post, receipt } = await setup(t);
  const target = message();
  await post(a, target);
  await post(a, target);
  const ambiguous = await receipt(b, { session: room, id: target.id });
  assert.equal(ambiguous.status, 409); await ambiguous.body.cancel();
});

test("denies a principal that is not an eligible recipient", async t => {
  const { post, receipt } = await setup(t);
  const accepted = await post(a, message());
  const { seq } = await accepted.json();
  const sender = await receipt(a, { session: room, seq });
  assert.equal(sender.status, 403); await sender.body.cancel();
  const outsider = await receipt(c, { session: room, seq });
  assert.equal(outsider.status, 403); await outsider.body.cancel();
});

test("returns 404 for a target evicted from the delivery log", async t => {
  const { post, receipt } = await setup(t, { delivery: { maxPerSession: 1 } });
  const accepted = await post(a, message());
  const { seq } = await accepted.json();
  await post(a, message());
  const evicted = await receipt(b, { session: room, seq });
  assert.equal(evicted.status, 404); await evicted.body.cancel();
});

test("rejects a receipt with 400 when the profile is omitted, on both transports", async t => {
  const { base, credentials, receipt } = await setup(t, { receipts: null });
  const response = await receipt(b, { session: room, seq: 1 });
  assert.equal(response.status, 400); await response.body.cancel();
  const health = await (await fetch(base + "/health")).json();
  assert.equal(health.receiptProfile, undefined);
  assert.equal(health.receipts, undefined);
  const client = await openWebSocket(base, { token: credentials.get(b) });
  client.send({ type: "receipt", session: room, seq: 1 });
  await waitFor(() => client.messages.some(value => value.type === "error"), "websocket disabled receipt");
  assert.equal(client.messages.find(value => value.type === "error").status, 400);
  client.close();
});

test("an id-only receipt ignores entries the principal is not eligible for", async t => {
  const { post, receipt } = await setup(t);
  const id = "urn:uuid:" + randomUUID();
  // a addresses the id to itself; b reuses the same id addressed to itself.
  assert.equal((await post(a, message({ id, recipient: a }))).status, 202);
  assert.equal((await post(b, message({ id, recipient: b, sender: b }))).status, 202);
  // Without eligibility filtering this id-only receipt would be 409 ambiguous.
  const ack = await receipt(b, { session: room, id });
  assert.equal(ack.status, 202);
  assert.equal((await ack.json()).acknowledged, true);
});

test("reports WebSocket receipt errors with the same statuses as HTTP", async t => {
  const { base, credentials, post } = await setup(t);
  const accepted = await post(a, message());
  const { seq } = await accepted.json();
  const sender = await openWebSocket(base, { token: credentials.get(a) });
  sender.send({ type: "receipt", session: room, seq });
  await waitFor(() => sender.messages.some(value => value.type === "error"), "ineligible WS receipt");
  assert.equal(sender.messages.find(value => value.type === "error").status, 403);
  sender.close();
  const recipient = await openWebSocket(base, { token: credentials.get(b) });
  recipient.send({ type: "receipt", session: room, seq: 9999 });
  await waitFor(() => recipient.messages.some(value => value.type === "error"), "unknown WS receipt");
  assert.equal(recipient.messages.find(value => value.type === "error").status, 404);
  recipient.close();
});

test("never writes a receipt to an SSE stream", async t => {
  const { post, receipt, subscribe } = await setup(t);
  const stream = await subscribe(b);
  const accepted = await post(a, message());
  const { seq } = await accepted.json();
  await waitFor(() => stream.frames.some(frame => frame.event === "xeip.message"), "message frame");
  const before = stream.frames.length;
  const ack = await receipt(b, { session: room, seq });
  assert.equal(ack.status, 202);
  await ack.body.cancel();
  await delay(100);
  assert.equal(stream.frames.length, before);
  assert.equal(stream.frames.some(frame => JSON.stringify(frame).includes("acknowledged")), false);
});

test("acknowledges a receipt over the WebSocket control", async t => {
  const { base, credentials, post } = await setup(t);
  const accepted = await post(a, message());
  const { seq } = await accepted.json();
  const client = await openWebSocket(base, { token: credentials.get(b) });
  client.send({ type: "receipt", session: room, seq });
  await waitFor(() => client.messages.some(value => value.type === "acknowledged"), "websocket acknowledgment");
  assert.deepEqual(client.messages.find(value => value.type === "acknowledged"),
    { type: "acknowledged", session: room, seq, duplicate: false });
  client.send({ type: "receipt", session: room, seq });
  await waitFor(() => client.messages.filter(value => value.type === "acknowledged").length === 2, "duplicate acknowledgment");
  assert.equal(client.messages.filter(value => value.type === "acknowledged")[1].duplicate, true);
  // Close before the relay teardown so the upgraded socket does not hold close() open.
  client.close();
});
