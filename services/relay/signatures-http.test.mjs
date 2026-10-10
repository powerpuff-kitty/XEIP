import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import { LOCAL_SIGNED_ENVELOPES_PROFILE } from "./relay-core.mjs";
import { LocalAdmission } from "./admission.mjs";
import { encodeKeyId, entityUrn } from "../../tools/derive-keyid.mjs";
import { signEnvelope, ed25519PrivateKeyFromSeed } from "../../tools/signed-envelope.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "./websocket.mjs";

const TOKEN = "signatures-test-shared-token-000";
// Standard Ed25519 keypair for seed 000102…1f; the public key and derived
// key-id are pinned by the signed-envelope conformance vectors.
const SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PUBLIC_KEY_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const KID = encodeKeyId(Buffer.from(PUBLIC_KEY_HEX, "hex"));
const SIGNER = entityUrn(KID);
const OTHER = "urn:xeip:entity:recipient-01";
const SESSION = "urn:xeip:session:signatures";
const privateKey = ed25519PrivateKeyFromSeed(Buffer.from(SEED_HEX, "hex"));

const envelope = (sender = SIGNER, recipient = OTHER) => ({
  xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender, recipient, session: SESSION, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello" }
});
const signed = (value = envelope()) => signEnvelope(value, { privateKey, kid: KID });

async function setup(t, { admission = false, signatures } = {}) {
  const credentials = new Map([SIGNER, OTHER].map(entity => [entity, randomBytes(32).toString("base64url")]));
  const options = admission
    ? { admission: new LocalAdmission({
        credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
        sessions: [{ xeip: "0.1", id: SESSION, mode: "group", members: [SIGNER, OTHER], createdAt: "2026-10-09T00:00:00Z" }]
      }) }
    : { token: TOKEN };
  if (signatures !== undefined) options.signatures = signatures;
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
  const auth = actor => ({ Authorization: "Bearer " + (admission ? credentials.get(actor) : TOKEN) });
  const post = (value, actor) => fetch(base + "/messages", { method: "POST",
    headers: { ...auth(actor), "Content-Type": "application/json" },
    body: JSON.stringify(value), signal: AbortSignal.timeout(5000) });
  const health = async () => (await fetch(base + "/health")).json();
  const subscribe = async (element, actor = element) => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", SESSION); url.searchParams.set("entity", element);
    const response = await fetch(url, { headers: auth(actor), signal: abort.signal });
    const stream = { response, abort, frames: [] };
    if (response.status !== 200) { abort.abort(); return stream; }
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
  return { server, base, post, health, subscribe };
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

test("advertises the signed-envelope profile and rejects invalid configuration", async t => {
  for (const signatures of [null, false, 1, "on", [], { extra: true }, { v: "0.1" }]) {
    assert.throws(() => createRelay({ token: TOKEN, signatures }), /signatures/);
  }
  const { health } = await setup(t, { signatures: {} });
  assert.equal((await health()).signatureProfile, LOCAL_SIGNED_ENVELOPES_PROFILE);
});

test("accepts a validly signed envelope and rejects a tampered body over HTTP", async t => {
  const { post, subscribe } = await setup(t, { signatures: {} });
  const target = await subscribe(OTHER);
  assert.equal(target.response.status, 200);
  const good = signed();
  const accepted = await post(good);
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), { accepted: true, delivered: 1 });
  await waitFor(() => target.frames.some(frame => frame.event === "xeip.message"), "signed delivery");
  assert.deepEqual(JSON.parse(target.frames.find(frame => frame.event === "xeip.message").data), good);

  const tampered = signed();
  tampered.body.data = "tampered";
  const rejected = await post(tampered);
  assert.equal(rejected.status, 422);
  assert.deepEqual(await rejected.json(), { error: "invalid signature" });
  await target.close();
});

test("maps a spoofed sender to 403 and a missing or invalid signature to 422 over HTTP", async t => {
  const { post } = await setup(t, { signatures: {} });
  const spoofed = signed(envelope(OTHER, SIGNER));
  assert.equal((await post(spoofed)).status, 403);
  assert.deepEqual(await (await post(spoofed)).json(), { error: "forbidden" });

  const missing = envelope();
  assert.equal((await post(missing)).status, 422);
  const malformed = signed();
  malformed.extensions["xeip.sig"].sig = "!!!";
  assert.equal((await post(malformed)).status, 422);
  assert.deepEqual(await (await post(malformed)).json(), { error: "invalid signature" });
  const unsupported = signed();
  unsupported.extensions["xeip.sig"].alg = "none";
  assert.equal((await post(unsupported)).status, 422);
});

test("leaves unsigned envelopes untouched when the profile is disabled", async t => {
  const { post, health } = await setup(t, {});
  assert.equal((await health()).signatureProfile, undefined);
  assert.deepEqual(await (await post(envelope())).json(), { accepted: true, delivered: 0 });
});

test("applies the signature and admission checks together", async t => {
  const { post } = await setup(t, { admission: true, signatures: {} });
  assert.deepEqual(await (await post(signed(), SIGNER)).json(), { accepted: true, delivered: 0 });
  // A signature that verifies against the wrong sender is still forbidden.
  assert.equal((await post(signed(envelope(SIGNER, OTHER)), OTHER)).status, 403);
  // A spoofed sender fails sender binding before admission authorization.
  assert.equal((await post(signed(envelope(OTHER, SIGNER)), SIGNER)).status, 403);
  // An unsigned envelope is unacceptable even for an authorized principal.
  const unsigned = await post(envelope(SIGNER, OTHER), SIGNER);
  assert.equal(unsigned.status, 422);
  assert.deepEqual(await unsigned.json(), { error: "invalid signature" });
});

test("enforces the same checks over WebSocket send", async t => {
  const { base, subscribe } = await setup(t, { signatures: {} });
  const target = await subscribe(OTHER);
  const client = await openWebSocket(base, { token: TOKEN });
  const kind = type => client.messages.find(value => value.type === type);

  client.send({ type: "send", message: signed() });
  await waitFor(() => kind("accepted"), "signed send accepted");
  assert.equal(kind("accepted").delivered, 1);

  const tampered = signed();
  tampered.body.data = "tampered";
  client.send({ type: "send", message: tampered });
  await waitFor(() => client.messages.filter(value => value.type === "error").length >= 1, "tampered send rejected");
  let error = client.messages.filter(value => value.type === "error")[0];
  assert.equal(error.status, 422);
  assert.equal(error.error, "invalid signature");

  client.send({ type: "send", message: signed(envelope(OTHER, SIGNER)) });
  await waitFor(() => client.messages.filter(value => value.type === "error").length >= 2, "spoofed send rejected");
  error = client.messages.filter(value => value.type === "error")[1];
  assert.equal(error.status, 403);
  assert.equal(error.error, "forbidden");

  client.send({ type: "send", message: envelope() });
  await waitFor(() => client.messages.filter(value => value.type === "error").length >= 3, "missing signature rejected");
  error = client.messages.filter(value => value.type === "error")[2];
  assert.equal(error.status, 422);
  assert.equal(error.error, "invalid signature");

  client.close();
  await target.close();
});
