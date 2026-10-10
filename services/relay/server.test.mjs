import test from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "./server.mjs";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "./websocket.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const TOKEN = "test-token-very-long-and-secret";
const session = "urn:xeip:session:test";
const sender = "urn:xeip:entity:human";
const agent = "urn:xeip:entity:agent";
const machine = "urn:xeip:entity:machine";

async function withRelay(run) {
  const server = createRelay({ token: TOKEN });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  try { await run(base, server); }
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

function requestStatus(base, headers = {}, path = "/health") {
  return new Promise((resolve, reject) => {
    const req = request(base, { path, headers }, res => {
      res.resume();
      res.once("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
    req.end();
  });
}

// Event-driven wait for an eventual condition. The deadline only bounds a
// genuine hang; a loaded CI machine converges to the same state, just later.
async function waitUntil(predicate, label, deadlineMs = 30000) {
  const deadline = Date.now() + deadlineMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
    await delay(10);
  }
}
const SLOW_DEADLINE = 40000;

class WsClient {
  constructor(socket) {
    this.socket = socket;
    this.parser = new FrameParser({ maxFrame: 128 * 1024, maxMessage: 128 * 1024, expectMask: false });
    this.messages = [];
    socket.on("data", chunk => {
      for (const event of this.parser.push(chunk)) {
        if (event.type === "message") this.messages.push(JSON.parse(event.text));
        else if (event.type === "ping") this.#write(encodeFrame(OPCODES.pong, event.payload, true, randomBytes(4)));
      }
    });
  }
  send(value) { this.#write(encodeFrame(OPCODES.text, Buffer.from(JSON.stringify(value)), true, randomBytes(4))); }
  close() { if (!this.socket.destroyed) this.socket.end(); }
  #write(buffer) { if (!this.socket.destroyed) this.socket.write(buffer); }
  async waitFor(predicate, label) {
    const deadline = Date.now() + 15000;
    while (!predicate()) {
      if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
      await delay(10);
    }
  }
}
function openWebSocket(base, token) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const url = new URL(base);
    const req = request({
      host: url.hostname, port: url.port, path: "/ws",
      headers: {
        Connection: "Upgrade", Upgrade: "websocket",
        "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key,
        Authorization: "Bearer " + token
      }
    });
    req.once("upgrade", (response, socket, head) => {
      if (response.headers["sec-websocket-accept"] !== websocketAccept(key)) {
        socket.destroy();
        return reject(new Error("invalid Sec-WebSocket-Accept"));
      }
      const client = new WsClient(socket);
      if (head.length > 0) socket.unshift(head);
      resolve(client);
    });
    req.once("response", response => { response.resume(); reject(new Error("HTTP " + response.statusCode)); });
    req.once("error", reject);
    req.end();
  });
}

test("rejects foreign Host headers before serving public or authenticated routes", async () => {
  await withRelay(async base => {
    for (const host of ["attacker.example", "127.0.0.1.attacker.example", "localhost.attacker.example", "localhost:99999"]) {
      for (const path of ["/health", "/console", "/events?session=" + session + "&entity=" + agent]) {
        assert.equal(await requestStatus(base, { Host: host, Authorization: "Bearer " + TOKEN }, path), 403, host + path);
      }
    }
    // Raw header arrays prevent the HTTP client replacing a falsy Host value.
    assert.equal(await requestStatus(base, ["Host", ""]), 403);
    assert.equal(await requestStatus(base, ["Host", "localhost", "Host", "attacker.example"]), 403);
    for (const host of ["localhost", "LOCALHOST:" + new URL(base).port, "[::1]:" + new URL(base).port]) {
      assert.equal(await requestStatus(base, { Host: host }), 200, host);
    }
    assert.equal(await requestStatus(base, {}, "http://attacker.example/health"), 400);
    assert.equal(await requestStatus(base, {}, "/\\attacker.example/health"), 400);
  });
});

test("rejects cross-origin browser requests while allowing same-origin and native clients", async () => {
  await withRelay(async base => {
    for (const origin of ["https://attacker.example", "null", base + "/path", base.replace("http:", "https:"), "http://localhost:" + new URL(base).port]) {
      assert.equal(await requestStatus(base, { Origin: origin }), 403, origin);
      assert.equal((await post(base, makeMessage(), { Origin: origin })).status, 403, origin);
    }
    assert.equal(await requestStatus(base, { Origin: base }), 200);
    assert.equal((await post(base, makeMessage(), { Origin: base })).status, 202);
    assert.equal((await post(base, makeMessage())).status, 202);
  });
});

test("requires the exact application/json media type instead of a prefix", async () => {
  await withRelay(async base => {
    for (const contentType of ["application/jsonp", "application/json-malformed", "text/plain"]) {
      assert.equal((await post(base, makeMessage(), { "Content-Type": contentType })).status, 415, contentType);
    }
    for (const contentType of ["application/json", "Application/JSON; charset=utf-8"]) {
      assert.equal((await post(base, makeMessage(), { "Content-Type": contentType })).status, 202, contentType);
    }
  });
});

test("rejects excessive JSON nesting and remains available for the next request", { timeout: 5000 }, async () => {
  await withRelay(async base => {
    const skeleton = JSON.stringify(makeMessage({ body: { contentType: "application/json", data: null } }));
    for (const depth of [10000, 63]) {
      const body = skeleton.replace('"data":null', '"data":' + "[".repeat(depth) + "0" + "]".repeat(depth));
      const response = await fetch(base + "/messages", {
        method: "POST", headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
        body, signal: AbortSignal.timeout(2000)
      });
      assert.equal(response.status, 413, "nested arrays: " + depth);
    }
    const boundary = skeleton.replace('"data":null', '"data":' + "[".repeat(62) + "0" + "]".repeat(62));
    assert.equal((await fetch(base + "/messages", {
      method: "POST", headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" }, body: boundary
    })).status, 202); // Envelope + body + 62 arrays = 64 containers.
    const accepted = await post(base, makeMessage());
    assert.equal(accepted.status, 202);
    assert.deepEqual(await accepted.json(), { accepted: true, delivered: 0 });
  });
});

test("rejects malformed UTF-8 JSON instead of replacing invalid bytes", async () => {
  await withRelay(async base => {
    const encoded = Buffer.from(JSON.stringify(makeMessage({ body: { contentType: "text/plain", data: "PLACEHOLDER" } })));
    const at = encoded.indexOf("PLACEHOLDER");
    const body = Buffer.concat([encoded.subarray(0, at), Buffer.from([0xc3, 0x28]), encoded.subarray(at + 11)]);
    const response = await fetch(base + "/messages", {
      method: "POST", headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" }, body
    });
    assert.equal(response.status, 400);
    assert.equal((await post(base, makeMessage({ body: { contentType: "text/plain", data: "Valid 🐈 é" } }))).status, 202);
  });
});

test("rejects JSON that expands beyond the SSE frame limit before writing to healthy streams", { timeout: 30000 }, async () => {
  await withRelay(async base => {
    const subscriber = await subscribe(base, agent);
    const timer = setTimeout(() => subscriber.close(), 25000);
    try {
      const skeleton = JSON.stringify(makeMessage({ body: { contentType: "application/json", data: null } }));
      const body = skeleton.replace('"data":null', '"data":[' + "1e15,".repeat(11999) + "1e15]");
      assert.ok(Buffer.byteLength(body) < 64 * 1024);
      const oversized = await fetch(base + "/messages", {
        method: "POST", headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" }, body
      });
      assert.equal(oversized.status, 413);
      const message = makeMessage();
      assert.deepEqual(await (await post(base, message)).json(), { accepted: true, delivered: 1 });
      const reader = subscriber.response.body.getReader();
      const decoder = new TextDecoder(), parser = new SseParser();
      let received;
      while (!received) {
        const chunk = await reader.read();
        if (chunk.done) throw new Error("healthy subscription ended early");
        for (const frame of parser.push(decoder.decode(chunk.value, { stream: true }))) {
          if (frame.event === "xeip.message") received = JSON.parse(frame.data);
        }
      }
      assert.deepEqual(received, message);
    } finally { clearTimeout(timer); subscriber.close(); }
  });
});

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

test("advertises protocol versions and reports a distinct unsupported-version error", async () => {
  await withRelay(async base => {
    const health = await (await fetch(base + "/health")).json();
    assert.deepEqual(health.protocolVersions, ["0.1"]);
    assert.equal(health.status, "ok");
    assert.equal(health.protocol, "xeip/0.1");
    for (const xeip of ["9.9", "0.2", "1.0"]) {
      const response = await post(base, makeMessage({ xeip }));
      assert.equal(response.status, 422, xeip);
      assert.deepEqual(await response.json(), { error: "unsupported version" }, xeip);
    }
    const missing = makeMessage();
    delete missing.xeip;
    for (const value of [missing, makeMessage({ xeip: "" }), makeMessage({ xeip: "0.1.0" }), makeMessage({ xeip: 1 })]) {
      const response = await post(base, value);
      assert.equal(response.status, 422, JSON.stringify(value.xeip));
      const body = await response.json();
      assert.notEqual(body.error, "unsupported version", JSON.stringify(value.xeip));
    }
    assert.equal((await post(base, makeMessage())).status, 202);
  });
});

test("WebSocket send reports the same distinct unsupported-version error", async () => {
  const server = createRelay({ token: TOKEN });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  let client;
  try {
    client = await openWebSocket(base, TOKEN);
    for (const [label, xeip, distinct] of [["9.9", "9.9", true], ["0.2", "0.2", true], ["empty", "", false], ["long form", "0.1.0", false]]) {
      client.send({ type: "send", message: makeMessage({ xeip }) });
      await client.waitFor(() => client.messages.length > 0, "websocket error " + label);
      const reply = client.messages.shift();
      assert.equal(reply.type, "error", label);
      assert.equal(reply.status, 422, label);
      if (distinct) assert.equal(reply.error, "unsupported version", label);
      else assert.notEqual(reply.error, "unsupported version", label);
    }
    const missing = makeMessage();
    delete missing.xeip;
    client.send({ type: "send", message: missing });
    await client.waitFor(() => client.messages.length > 0, "websocket error missing");
    const reply = client.messages.shift();
    assert.equal(reply.type, "error");
    assert.equal(reply.status, 422);
    assert.notEqual(reply.error, "unsupported version");
  } finally {
    client?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test("routes live messages only to the selected session and recipient", { timeout: 30000 }, async () => {
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
      const timer = setTimeout(() => controller.abort(), 25000);
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

test("uses opaque URI selectors, writes to every matching connection, and forwards duplicates", { timeout: 30000 }, async () => {
  await withRelay(async base => {
    const subscribers = [];
    const timer = setTimeout(() => subscribers.forEach(subscriber => subscriber.close()), 25000);
    try {
      const human = await subscribe(base, sender); subscribers.push(human);
      const first = await subscribe(base, agent); subscribers.push(first);
      subscribers.push(await subscribe(base, agent));
      subscribers.push(await subscribe(base, agent, "urn:xeip:session:%74est"));
      subscribers.push(await subscribe(base, "urn:xeip:entity:%61gent"));
      const message = makeMessage({ kind: "receipt", replyTo: "urn:xeip:message:unknown" });
      for (let repeat = 0; repeat < 2; repeat++) {
        assert.deepEqual(await (await post(base, message)).json(), { accepted: true, delivered: 2 });
      }
      const broadcast = makeMessage(); delete broadcast.recipient;
      assert.deepEqual(await (await post(base, broadcast)).json(), { accepted: true, delivered: 4 });
      async function readIds(subscription, count) {
        const reader = subscription.response.body.getReader();
        const decoder = new TextDecoder(), parser = new SseParser(), ids = [];
        while (ids.length < count) {
          const next = await reader.read();
          if (next.done) throw new Error("subscription ended early");
          for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) {
            if (frame.event === "xeip.message") ids.push(JSON.parse(frame.data).id);
          }
        }
        return ids;
      }
      assert.deepEqual(await readIds(first, 3), [message.id, message.id, broadcast.id]);
      assert.deepEqual(await readIds(human, 1), [broadcast.id]);
    } finally {
      clearTimeout(timer);
      subscribers.forEach(subscriber => subscriber.close());
    }
  });
});

test("serves a localhost-only console with strict browser security headers", async () => {
  await withRelay(async base => {
    const page = await fetch(base + "/console");
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy") ?? "", /connect-src 'self'/);
    const html = await page.text();
    assert.match(html, /PROTOCOL INSPECTOR/);
    assert.doesNotMatch(html, /test-token-very-long-and-secret/);
    const js = await fetch(base + "/console.js");
    assert.equal(js.status, 200);
    assert.match(await js.text(), /consumeSse/);
  });
});

const vectors = JSON.parse(readFileSync(new URL("../../conformance/vectors.json", import.meta.url)));
test("relay applies shared message conformance vectors", async () => {
  await withRelay(async base => {
    const fixture = JSON.parse(readFileSync(new URL("../../conformance/fixtures/message.valid.json", import.meta.url)));
    for (const vector of vectors.filter(v => v.schema === "message")) {
      const value = { ...fixture, ...vector.patch };
      for (const field of vector.remove ?? []) delete value[field];
      const response = await post(base, value);
      assert.equal(response.status, vector.valid ? 202 : 422, vector.name);
      await response.arrayBuffer();
    }
  });
});

test("disconnects a stalled subscriber and keeps routing to healthy clients", { timeout: 120000 }, async () => {
  await withRelay(async (base, server) => {
    let stream;
    server.on("request", (req, res) => { if (req.url.startsWith("/events")) stream = res; });
    const socket = connect({ port: server.address().port, host: "127.0.0.1" });
    try {
      await new Promise((resolve, reject) => {
        socket.once("error", reject);
        socket.once("data", () => { socket.pause(); resolve(); });
        socket.once("connect", () => socket.write(
          "GET /events?session=" + session + "&entity=" + agent + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + TOKEN + "\r\n\r\n"
        ));
      });
      const stalled = stream;
      const healthy = await subscribe(base, machine);
      const received = [];
      const reader = healthy.response.body.getReader();
      const worker = (async () => {
        const decoder = new TextDecoder(), parser = new SseParser();
        while (received.length < 100) {
          const { done, value } = await reader.read();
          if (done) throw new Error("healthy stream ended prematurely");
          for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
            if (frame.event === "xeip.message") received.push(JSON.parse(frame.data).id);
          }
        }
      })();
      // Observe errors immediately, while posting may still be in progress.
      worker.catch(() => {});
      const sent = [];
      let timer;
      try {
        for (let i = 0; i < 100; i++) {
          const message = makeMessage({ body: { contentType: "text/plain", data: "x".repeat(60000) } });
          delete message.recipient;
          sent.push(message.id);
          const response = await post(base, message);
          assert.equal(response.status, 202);
          await response.arrayBuffer();
        }
        // The relay destroys the response once the peer stops draining and the
        // bounded outbound queue fills. Poll for that eventual state instead of
        // racing a single assertion right after the last POST. The deadline
        // starts here so slow POSTs cannot consume the delivery budget.
        const deadline = Date.now() + SLOW_DEADLINE;
        await waitUntil(
          () => stalled.destroyed,
          "stalled stream must be disconnected before its queue grows without bound",
          Math.max(0, deadline - Date.now())
        );
        await Promise.race([
          worker,
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error("healthy subscriber did not receive all messages")), Math.max(0, deadline - Date.now()));
          })
        ]);
        assert.deepEqual(received, sent);
      } finally {
        clearTimeout(timer);
        healthy.close();
        await reader.cancel().catch(() => {});
        await worker.catch(() => {});
      }
    } finally { socket.destroy(); }
  });
});
