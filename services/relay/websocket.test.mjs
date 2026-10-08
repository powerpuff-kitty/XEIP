import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { EventEmitter } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LocalAdmission } from "./admission.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { CLOSE, FrameParser, OPCODES, WebSocketConnection, encodeFrame, websocketAccept } from "./websocket.mjs";

const TOKEN = "test-token-very-long-and-secret";
const a = "urn:xeip:entity:a";
const b = "urn:xeip:entity:b";
const c = "urn:xeip:entity:c";
const room = "urn:xeip:session:ab";
const other = "urn:xeip:session:abc";
const secret = () => randomBytes(32).toString("base64url");
const envelope = (extra = {}) => ({ xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender: a, recipient: b, session: room, timestamp: new Date().toISOString(),
  body: { contentType: "application/json", data: { text: "🐈", values: [1, null, true] } }, ...extra });

class TestSocket {
  constructor(socket) {
    this.socket = socket;
    this.parser = new FrameParser({ maxFrame: 128 * 1024, maxMessage: 128 * 1024, expectMask: false });
    this.messages = [];
    this.events = [];
    this.closeCode = null;
    socket.on("data", chunk => {
      for (const event of this.parser.push(chunk)) {
        if (event.type === "message") this.messages.push(JSON.parse(event.text));
        else if (event.type === "ping") this.#write(encodeFrame(OPCODES.pong, event.payload, true, randomBytes(4)));
        else if (event.type === "close") this.closeCode = event.code;
        this.events.push(event);
      }
    });
  }
  send(value) { this.#write(encodeFrame(OPCODES.text, Buffer.from(JSON.stringify(value)), true, randomBytes(4))); }
  raw(buffer) { this.#write(buffer); }
  ping(payload = Buffer.alloc(0)) { this.#write(encodeFrame(OPCODES.ping, payload, true, randomBytes(4))); }
  close() {
    if (!this.socket.destroyed) this.#write(encodeFrame(OPCODES.close, Buffer.alloc(0), true, randomBytes(4)));
    this.socket.end();
  }
  #write(buffer) { if (!this.socket.destroyed) this.socket.write(buffer); }
  async waitFor(predicate, label) {
    const deadline = Date.now() + 4000;
    while (!predicate()) {
      if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
      await delay(10);
    }
  }
}

function openWebSocket(base, { path = "/ws", token, origin, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const url = new URL(base);
    const req = request({
      host: url.hostname, port: url.port, path,
      headers: {
        Connection: "Upgrade", Upgrade: "websocket",
        "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key,
        ...(token ? { Authorization: "Bearer " + token } : {}),
        ...(origin ? { Origin: origin } : {}),
        ...headers
      }
    });
    req.once("upgrade", (response, socket, head) => {
      if (response.headers["sec-websocket-accept"] !== websocketAccept(key)) {
        socket.destroy();
        return reject(new Error("invalid Sec-WebSocket-Accept"));
      }
      const client = new TestSocket(socket);
      if (head.length > 0) socket.unshift(head);
      resolve(client);
    });
    req.once("response", response => {
      response.resume();
      reject(Object.assign(new Error("HTTP " + response.statusCode), { status: response.statusCode }));
    });
    req.once("error", reject);
    req.end();
  });
}

async function withRelay(t, options, run) {
  const server = createRelay(options);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  const sockets = [];
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const open = requestOptions => {
    const pending = openWebSocket(base, requestOptions);
    pending.then(socket => sockets.push(socket.socket)).catch(() => {});
    return pending;
  };
  await run(base, open);
}
function withAdmission(t, options, run) {
  const credentials = new Map([a, b, c].map(entity => [entity, secret()]));
  const admission = new LocalAdmission({
    credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [room, other].map(id => ({ xeip: "0.1", id, mode: "group",
      members: id === room ? [a, b] : [a, c], createdAt: "2026-10-09T00:00:00Z" }))
  });
  return withRelay(t, { admission, ...options }, (base, open) => run(base, open, credentials, admission));
}
async function subscribeSse(base, credentials, actor, sessionUri = room) {
  const controller = new AbortController();
  const received = [];
  const url = new URL(base + "/events");
  url.searchParams.set("session", sessionUri);
  url.searchParams.set("entity", actor);
  const response = await fetch(url, { headers: { Authorization: "Bearer " + credentials }, signal: controller.signal });
  assert.equal(response.status, 200);
  const worker = (async () => {
    const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) {
          if (frame.event === "xeip.message") received.push(JSON.parse(frame.data));
        }
      }
    } catch { /* aborted */ }
  })();
  worker.catch(() => {});
  return { received, close: async () => { controller.abort(); await worker.catch(() => {}); } };
}

test("advertises WebSocket transport and rejects unauthenticated or misrouted upgrades", async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    const health = await (await fetch(base + "/health")).json();
    assert.deepEqual(health.transports, ["http-sse", "websocket"]);
    await assert.rejects(open({}), error => error.status === 401);
    await assert.rejects(open({ token: "wrong-token-wrong-token" }), error => error.status === 401);
    await assert.rejects(open({ token: TOKEN, path: "/nope" }), error => error.status === 404);
  });
});

test("roundtrips the same envelope across WebSocket and HTTP/SSE in both directions", async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    const wsInbound = await open({ token: TOKEN });
    wsInbound.send({ type: "subscribe", session: room, entity: b });
    await wsInbound.waitFor(() => wsInbound.messages.some(m => m.type === "subscribed"), "subscribed");
    const wsInboundMessage = envelope();
    const posted = await fetch(base + "/messages", { method: "POST",
      headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify(wsInboundMessage) });
    assert.equal(posted.status, 202);
    await wsInbound.waitFor(() => wsInbound.messages.some(m => m.type === "message"), "ws delivery");
    const wsFrame = wsInbound.messages.find(m => m.type === "message");
    assert.deepEqual(wsFrame.message, wsInboundMessage);

    const sse = await subscribeSse(base, TOKEN, a);
    const wsOutbound = await open({ token: TOKEN });
    const wsOutboundMessage = envelope({ sender: b, recipient: a });
    wsOutbound.send({ type: "send", message: wsOutboundMessage });
    await wsOutbound.waitFor(() => wsOutbound.messages.some(m => m.type === "accepted"), "accepted");
    assert.deepEqual(wsOutbound.messages.find(m => m.type === "accepted"),
      { type: "accepted", delivered: 1 });
    await wsOutbound.waitFor(() => sse.received.length === 1, "sse delivery");
    assert.deepEqual(sse.received[0], wsOutboundMessage);
    await sse.close();
    wsInbound.close(); wsOutbound.close();
  });
});

test("binds WebSocket subscriptions and sends to authenticated entities only", async t => {
  await withAdmission(t, {}, async (base, open, credentials) => {
    const recipient = await open({ token: credentials.get(b) });
    recipient.send({ type: "subscribe", session: room, entity: b });
    await recipient.waitFor(() => recipient.messages.some(m => m.type === "subscribed"), "subscribed");

    const spoof = await open({ token: credentials.get(a) });
    spoof.send({ type: "subscribe", session: room, entity: c });
    await spoof.waitFor(() => spoof.messages.some(m => m.type === "error"), "forbidden subscription");
    assert.equal(spoof.messages.find(m => m.type === "error").status, 403);

    const crossSession = await open({ token: credentials.get(b) });
    crossSession.send({ type: "subscribe", session: other, entity: b });
    await crossSession.waitFor(() => crossSession.messages.some(m => m.type === "error"), "cross-session denial");
    assert.equal(crossSession.messages.find(m => m.type === "error").status, 403);

    const sender = await open({ token: credentials.get(a) });
    sender.send({ type: "send", message: envelope({ sender: c }) });
    await sender.waitFor(() => sender.messages.some(m => m.type === "error"), "sender binding");
    assert.equal(sender.messages.find(m => m.type === "error").status, 403);

    sender.send({ type: "send", message: envelope({ sender: a }) });
    await sender.waitFor(() => sender.messages.some(m => m.type === "accepted"), "accepted send");
    await recipient.waitFor(() => recipient.messages.some(m => m.type === "message"), "delivery");
    assert.equal(recipient.messages.find(m => m.type === "message").message.sender, a);
    recipient.close(); spoof.close(); crossSession.close(); sender.close();
  });
});

test("rejects a subscribe that uses a credential revoked after connect", async t => {
  await withAdmission(t, {}, async (base, open, credentials, admission) => {
    const client = await open({ token: credentials.get(a) });
    admission.revokeCredential(a);
    client.send({ type: "subscribe", session: room, entity: a });
    await client.waitFor(() => client.messages.some(m => m.type === "error") || client.closeCode !== null, "revoked subscribe");
    assert.equal(client.messages.find(m => m.type === "error")?.status, 401);
    await client.waitFor(() => client.closeCode !== null, "policy close");
    assert.equal(client.closeCode, CLOSE.policy);
  });
});

test("reassembles fragmented text messages and rejects unmasked client frames", async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    const client = await open({ token: TOKEN });
    const control = JSON.stringify({ type: "subscribe", session: room, entity: b });
    const mask = randomBytes(4);
    client.raw(encodeFrame(OPCODES.text, Buffer.from(control.slice(0, 10)), false, mask));
    client.raw(encodeFrame(OPCODES.continuation, Buffer.from(control.slice(10)), true, mask));
    await client.waitFor(() => client.messages.some(m => m.type === "subscribed"), "fragmented control");

    const unmasked = await open({ token: TOKEN });
    unmasked.raw(encodeFrame(OPCODES.text, Buffer.from(JSON.stringify({ type: "subscribe" }))));
    await unmasked.waitFor(() => unmasked.closeCode !== null, "unmasked close");
    assert.equal(unmasked.closeCode, CLOSE.protocol);
    client.close();
  });
});

test("closes on binary frames, invalid UTF-8 and oversized messages", async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    for (const [payload, opcode, code] of [
      [Buffer.from([1, 2, 3]), OPCODES.binary, CLOSE.unsupported],
      [Buffer.from([0xff, 0xfe, 0xfd]), OPCODES.text, CLOSE.invalidPayload],
      [Buffer.alloc(200 * 1024, 0x61), OPCODES.text, CLOSE.tooBig]
    ]) {
      const client = await open({ token: TOKEN });
      client.raw(encodeFrame(opcode, payload, true, randomBytes(4)));
      await client.waitFor(() => client.closeCode !== null, "expected close " + code);
      assert.equal(client.closeCode, code);
      client.socket.destroy();
    }
  });
});

test("returns typed control errors and bounds JSON nesting", async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    const client = await open({ token: TOKEN });
    client.raw(encodeFrame(OPCODES.text, Buffer.from("{not json"), true, randomBytes(4)));
    client.send({ type: "nonsense" });
    client.send({ type: "subscribe", session: "not-a-uri", entity: b });
    client.send({ type: "send", message: { id: "x" } });
    const deep = envelope({ body: { contentType: "application/json", data: null } });
    const nested = JSON.parse(JSON.stringify(deep));
    nested.body.data = JSON.parse("[".repeat(63) + "0" + "]".repeat(63));
    client.send({ type: "send", message: nested });
    await client.waitFor(() => client.messages.filter(m => m.type === "error").length >= 5, "control errors");
    const statuses = client.messages.filter(m => m.type === "error").map(m => m.status);
    assert.deepEqual(statuses, [400, 400, 400, 422, 413]);
    client.close();
  });
});

test("answers protocol pings and completes the close handshake", async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    const client = await open({ token: TOKEN });
    client.ping(Buffer.from("hb"));
    await client.waitFor(() => client.events.some(event => event.type === "pong"), "pong");
    assert.deepEqual(client.events.find(event => event.type === "pong").payload, Buffer.from("hb"));
    client.close();
    await client.waitFor(() => client.closeCode !== null, "close echo");
    assert.equal(client.closeCode, CLOSE.normal);
  });
});

test("bounds outbound buffering and closes a slow socket with 1013", () => {
  const written = [];
  const socket = new EventEmitter();
  socket.writableLength = 0;
  socket.destroyed = false;
  socket.setNoDelay = () => {};
  socket.write = buffer => { written.push(buffer); socket.writableLength += buffer.length; return false; };
  socket.end = () => { socket.destroyed = true; };
  socket.destroy = () => { socket.destroyed = true; };
  const connection = new WebSocketConnection(socket, Buffer.alloc(0), { maxPending: 50 });
  connection.sendText("x".repeat(20));
  connection.sendText("x".repeat(20));
  connection.sendText("x".repeat(20));
  assert.equal(connection.isOpen(), false);
  assert.equal(socket.destroyed, true);
  const closeFrame = written.find(buffer => (buffer[0] & 0x0f) === OPCODES.close);
  assert.ok(closeFrame, "close frame written");
  assert.equal(closeFrame.readUInt16BE(2), CLOSE.tryAgain);
});

test("resumes a WebSocket subscriber after a sequence cursor and reports gaps", async t => {
  await withRelay(t, { token: TOKEN, delivery: { maxPerSession: 1 } }, async (base, open) => {
    const sender = await open({ token: TOKEN });
    sender.send({ type: "send", message: envelope() });
    await sender.waitFor(() => sender.messages.some(m => m.type === "accepted"), "first accepted");
    assert.equal(sender.messages.find(m => m.type === "accepted").seq, 1);
    sender.send({ type: "send", message: envelope() });
    await sender.waitFor(() => sender.messages.filter(m => m.type === "accepted").length === 2, "second accepted");
    assert.equal(sender.messages.filter(m => m.type === "accepted")[1].seq, 2);

    const resumed = await open({ token: TOKEN });
    resumed.send({ type: "subscribe", session: room, entity: b, after: 0 });
    await resumed.waitFor(() => resumed.messages.some(m => m.type === "gap"), "gap control");
    await resumed.waitFor(() => resumed.messages.some(m => m.type === "message"), "replayed message");
    assert.equal(resumed.messages.find(m => m.type === "gap").from, 2);
    assert.equal(resumed.messages.find(m => m.type === "message").seq, 2);

    const next = await open({ token: TOKEN });
    next.send({ type: "subscribe", session: room, entity: b, after: 2 });
    await next.waitFor(() => next.messages.some(m => m.type === "subscribed"), "subscribed");
    await delay(50);
    assert.equal(next.messages.filter(m => m.type === "message").length, 0);
    sender.send({ type: "send", message: envelope() });
    await next.waitFor(() => next.messages.some(m => m.type === "message"), "live after cursor");
    assert.equal(next.messages.find(m => m.type === "message").seq, 3);
    sender.close(); resumed.close(); next.close();
  });
});

test("keeps routing to a healthy WebSocket subscriber while another is stalled", { timeout: 10000 }, async t => {
  await withRelay(t, { token: TOKEN }, async (base, open) => {
    const healthy = await open({ token: TOKEN });
    healthy.send({ type: "subscribe", session: room, entity: b });
    await healthy.waitFor(() => healthy.messages.some(m => m.type === "subscribed"), "healthy subscribed");
    const stalled = await open({ token: TOKEN });
    stalled.send({ type: "subscribe", session: room, entity: b });
    await stalled.waitFor(() => stalled.messages.some(m => m.type === "subscribed"), "stalled subscribed");
    stalled.socket.pause();
    for (let i = 0; i < 5; i++) {
      const response = await fetch(base + "/messages", { method: "POST",
        headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
        body: JSON.stringify(envelope()) });
      assert.equal(response.status, 202);
      await response.arrayBuffer();
    }
    await healthy.waitFor(() => healthy.messages.filter(m => m.type === "message").length === 5, "healthy delivery");
    assert.equal(healthy.messages.find(m => m.type === "message").message.session, room);
    stalled.socket.destroy();
    healthy.close();
  });
});
