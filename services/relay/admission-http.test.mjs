import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { createRelay } from "./server.mjs";
import { LocalAdmission, LOCAL_ADMISSION_PROFILE } from "./admission.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";

const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b", c = "urn:xeip:entity:c";
const room = "urn:xeip:session:ab", elsewhere = "urn:xeip:session:c";
const secret = () => randomBytes(32).toString("base64url");
function message(extra = {}) {
  return { xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender: a, recipient: b,
    session: room, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "hello" }, ...extra };
}
async function setup(t, beforeRelay = () => {}) {
  const credentials = new Map([a, b, c].map(entity => [entity, secret()]));
  const policy = new LocalAdmission({ credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
    sessions: [
      { xeip: "0.1", id: room, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" },
      { xeip: "0.1", id: elsewhere, mode: "group", members: [c], createdAt: "2026-10-09T00:00:00Z" }
    ]
  });
  beforeRelay(policy);
  const server = createRelay({ admission: policy });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const base = "http://127.0.0.1:" + server.address().port;
  const subscribe = async (actor, session = room, selector = actor) => {
    const url = new URL("/events", base);
    url.searchParams.set("session", session); url.searchParams.set("entity", selector);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + credentials.get(actor) } });
    t.after(() => response.body?.cancel().catch(() => {}));
    return response;
  };
  const post = (actor, envelope) => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + credentials.get(actor), "Content-Type": "application/json" }, body: JSON.stringify(envelope) });
  return { policy, credentials, server, base, subscribe, post };
}

async function streamEnded(response) {
  const reader = response.body.getReader();
  let timer;
  const ended = (async () => {
    try { while (!(await reader.read()).done) {} } catch { /* Destroyed SSE socket is a terminal stream. */ }
  })();
  try {
    await Promise.race([ended, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("revoked stream stayed open")), 1000); })]);
  } finally { clearTimeout(timer); await reader.cancel().catch(() => {}); }
}

test("requires exactly one explicit relay authentication mode", () => {
  const admission = new LocalAdmission({ credentials: [{ entity: a, token: secret() }], sessions: [] });
  assert.throws(() => createRelay({ token: "shared-demo-token-long-enough", admission }), /mode/);
  assert.throws(() => createRelay({ admission: {} }), /LocalAdmission/);
});

test("binds sender and subscriptions to credentials without revealing forbidden rooms or recipients", async t => {
  const { base, subscribe, post } = await setup(t);
  const health = await (await fetch(base + "/health")).json();
  assert.equal(health.mode, "local-admission");
  assert.equal(health.profile, LOCAL_ADMISSION_PROFILE);
  for (const [actor, session, selector] of [[a, room, b], [c, room, c], [a, elsewhere, a], [a, "urn:xeip:session:unknown", a]]) {
    const denied = await subscribe(actor, session, selector);
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { error: "forbidden" });
  }
  for (const envelope of [message({ sender: b }), message({ session: elsewhere }),
    message({ session: "urn:xeip:session:unknown" }), message({ recipient: c }), message({ recipient: "urn:xeip:entity:unknown" })]) {
    const denied = await post(a, envelope);
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { error: "forbidden" });
  }
  const target = await subscribe(b);
  assert.equal(target.status, 200);
  const sent = message();
  assert.deepEqual(await (await post(a, sent)).json(), { accepted: true, delivered: 1 });
  const reader = target.body.getReader();
  const parser = new SseParser(), decoder = new TextDecoder();
  try {
    let received;
    while (!received) {
      const next = await reader.read();
      if (next.done) throw new Error("authorized stream ended early");
      for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) {
        if (frame.event === "xeip.message") received = JSON.parse(frame.data);
      }
    }
    assert.deepEqual(received, sent);
  } finally { await reader.cancel(); }
});

test("revocation closes active streams, denies reconnects, and permits only the rotated credential", { timeout: 5000 }, async t => {
  const { policy, credentials, subscribe, post } = await setup(t);
  const stream = await subscribe(b);
  assert.equal(stream.status, 200);
  policy.revokeCredential(b);
  await streamEnded(stream);
  assert.equal((await subscribe(b)).status, 401);
  assert.equal((await post(b, message({ sender: b, recipient: a }))).status, 401);
  assert.deepEqual(await (await post(a, message())).json(), { accepted: true, delivered: 0 });
  const replacement = secret();
  policy.rotateCredential(b, replacement);
  assert.equal((await subscribe(b)).status, 401); // Original token remains revoked.
  credentials.set(b, replacement);
  assert.equal((await subscribe(b)).status, 200);
  assert.deepEqual(await (await post(a, message())).json(), { accepted: true, delivered: 1 });
});

test("a failing owner observer cannot prevent the relay's revocation cleanup", { timeout: 5000 }, async t => {
  const { policy, subscribe } = await setup(t, admission => {
    admission.onChange(() => { throw new Error("observer failed"); });
  });
  const stream = await subscribe(b);
  assert.equal(stream.status, 200);
  assert.throws(() => policy.revokeCredential(b), error => error instanceof AggregateError &&
    error.errors[0].message === "observer failed");
  await streamEnded(stream);
  assert.equal((await subscribe(b)).status, 401);
});

test("revocation remains attached when a closed native server listens again", { timeout: 5000 }, async t => {
  const { policy, server, subscribe } = await setup(t);
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  await new Promise(resolve => server.listen(port, "127.0.0.1", resolve));
  const stream = await subscribe(b);
  assert.equal(stream.status, 200);
  policy.revokeCredential(b);
  await streamEnded(stream);
  assert.equal((await subscribe(b)).status, 401);
});

test("membership removal closes streams and stops publication and broadcast delivery", { timeout: 5000 }, async t => {
  const { policy, subscribe, post } = await setup(t);
  const stream = await subscribe(b);
  assert.equal(stream.status, 200);
  policy.setMembers(room, [a]);
  await streamEnded(stream);
  assert.equal((await subscribe(b)).status, 403);
  assert.equal((await post(b, message({ sender: b, recipient: a }))).status, 403);
  assert.equal((await post(a, message())).status, 403); // Recipient is no longer admitted.
  assert.deepEqual(await (await post(a, message({ recipient: undefined }))).json(), { accepted: true, delivered: 0 });
  policy.setMembers(room, [a, b]);
  assert.equal((await subscribe(b)).status, 200);
});

for (const change of ["rotation", "membership"]) {
  test("rechecks " + change + " after an in-flight POST body is read", { timeout: 5000 }, async t => {
    const { policy, credentials, server, base } = await setup(t);
    const headersSeen = new Promise(resolve => server.once("request", resolve));
    const body = JSON.stringify(message());
    const completed = new Promise((resolve, reject) => {
      const req = request(base + "/messages", { method: "POST", headers: {
        Authorization: "Bearer " + credentials.get(a), "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body)
      } }, response => { response.resume(); response.once("end", () => resolve(response.statusCode)); });
      req.once("error", reject);
      req.flushHeaders();
      headersSeen.then(() => {
        if (change === "rotation") policy.rotateCredential(a, secret()); else policy.setMembers(room, [b]);
        req.end(body);
      }).catch(reject);
    });
    assert.equal(await completed, change === "rotation" ? 401 : 403);
  });
}

test("limits per-entity open streams and releases slots after revocation", { timeout: 5000 }, async t => {
  const { policy, credentials, subscribe } = await setup(t);
  const streams = [];
  for (let index = 0; index < 4; index++) {
    const response = await subscribe(a); assert.equal(response.status, 200); streams.push(response);
  }
  assert.equal((await subscribe(a)).status, 429);
  policy.rotateCredential(a, secret());
  await Promise.all(streams.map(streamEnded));
  assert.equal((await subscribe(a)).status, 401);
  const replacement = secret(); policy.rotateCredential(a, replacement); credentials.set(a, replacement);
  assert.equal((await subscribe(a)).status, 200);
});

test("bounds aggregate subscriptions across distinct authenticated entities", { timeout: 15000 }, async t => {
  const credentials = Array.from({ length: 65 }, (_, index) => ({ entity: a + index, token: secret() }));
  const policy = new LocalAdmission({ credentials, sessions: [{ xeip: "0.1", id: room, mode: "group",
    members: credentials.map(value => value.entity), createdAt: "2026-10-09T00:00:00Z" }] });
  const server = createRelay({ admission: policy });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const streams = [];
  t.after(async () => {
    await Promise.allSettled(streams.map(value => value.body.cancel()));
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  });
  const connect = credential => fetch("http://127.0.0.1:" + server.address().port + "/events?session=" +
    encodeURIComponent(room) + "&entity=" + encodeURIComponent(credential.entity),
    { headers: { Authorization: "Bearer " + credential.token } });
  for (let index = 0; index < 256; index++) {
    const response = await connect(credentials[Math.floor(index / 4)]);
    streams.push(response); assert.equal(response.status, 200);
  }
  const denied = await connect(credentials[64]);
  assert.equal(denied.status, 429); await denied.body.cancel();
  policy.revokeCredential(credentials[0].entity);
  await Promise.all(streams.slice(0, 4).map(streamEnded));
  const permitted = await connect(credentials[64]);
  streams.push(permitted); assert.equal(permitted.status, 200);
});
