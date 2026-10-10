// End-to-end conformance for the TypeScript SDK's portable signed-envelope
// implementation (sdks/typescript/src/identity.ts, imported through the built
// sdks/typescript/dist/index.js) against the relay's opt-in `signatures`
// enforcement. It proves the SDK signs, the relay verifies, and both transports
// (HTTP/SSE and WebSocket) agree on accept/reject statuses. Run the TS build
// first (`npm run build:ts`); like the other conformance tests this file only
// consumes the built SDK and never builds Rust.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "../services/relay/server.mjs";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "../services/relay/websocket.mjs";
import {
  XeipHttpSseClient, signEnvelope, verifySignedEnvelope,
  ed25519PrivateKeyFromSeed, encodeKeyId, entityUrn
} from "../sdks/typescript/dist/index.js";

// The standard Ed25519 keypair pinned by the signed-envelope conformance
// vectors: seed 000102…1f, public key 03a1…31b8, hence a fixed entity URN.
const SEED = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const PUBLIC_KEY = Buffer.from("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", "hex");
const KID = encodeKeyId(PUBLIC_KEY);
const SIGNER = entityUrn(KID);
const RECIPIENT = "urn:xeip:entity:recipient-01";
const SESSION = "urn:xeip:session:signed-conformance";
const TOKEN = randomBytes(24).toString("hex");

let privateKey;
before(async () => { privateKey = await ed25519PrivateKeyFromSeed(SEED); });

const envelope = (sender = SIGNER, recipient = RECIPIENT) => ({
  xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender, recipient, session: SESSION, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello signed world" }
});
const signed = (value = envelope()) => signEnvelope(value, { privateKey, kid: KID });

// Upgraded sockets are not covered by closeAllConnections(), so track them to
// guarantee server.close() can finish on every path.
async function listen(t, server) {
  const sockets = new Set();
  server.on("upgrade", (_req, socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    const onError = reject;
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => { server.off("error", onError); resolve(); });
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return server.address().port;
}

async function waitFor(predicate, label) {
  const deadline = Date.now() + 4000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(label ?? "condition not met");
    await delay(10);
  }
}

// A minimal masked-frame Node WebSocket client; server replies are unmasked.
class TestSocket {
  constructor(socket) {
    this.socket = socket;
    this.messages = [];
    this.parser = new FrameParser({ maxFrame: 128 * 1024, maxMessage: 128 * 1024, expectMask: false });
    // Cleanup destroys the socket from under the client; a late reset is expected.
    socket.on("error", () => {});
    socket.on("data", chunk => {
      for (const event of this.parser.push(chunk)) {
        if (event.type === "message") this.messages.push(JSON.parse(event.text));
        else if (event.type === "ping") this.socket.write(encodeFrame(OPCODES.pong, event.payload, true, randomBytes(4)));
      }
    });
  }
  send(value) { if (!this.socket.destroyed) this.socket.write(encodeFrame(OPCODES.text, Buffer.from(JSON.stringify(value)), true, randomBytes(4))); }
  close() {
    if (!this.socket.destroyed) this.socket.write(encodeFrame(OPCODES.close, Buffer.alloc(0), true, randomBytes(4)));
    this.socket.end();
  }
}

function openWebSocket(base, { token } = {}) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const url = new URL(base);
    const req = request({ host: url.hostname, port: url.port, path: "/ws",
      headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key, ...(token ? { Authorization: "Bearer " + token } : {}) } });
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

test("TypeScript SDK signatures interoperate with the relay over HTTP", { timeout: 15000 }, async t => {
  const port = await listen(t, createRelay({ token: TOKEN, signatures: {} }));
  const base = "http://127.0.0.1:" + port;
  const post = value => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(value), signal: AbortSignal.timeout(5000) });

  // The SDK's own verifier agrees with the relay on the accepted envelope.
  const good = await signed();
  assert.deepEqual(await verifySignedEnvelope(good), { valid: true });

  const accepted = await post(good);
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), { accepted: true, delivered: 0 });

  // The SDK client proves the same envelope round-trips through its send path.
  const client = new XeipHttpSseClient({ baseUrl: base, token: TOKEN });
  assert.deepEqual(await client.send(good), { accepted: true, delivered: 0 });

  // A body changed after signing fails the detached-signature check.
  const tampered = { ...good, body: { ...good.body, data: "tampered" } };
  const tamperedResponse = await post(tampered);
  assert.equal(tamperedResponse.status, 422);
  assert.deepEqual(await tamperedResponse.json(), { error: "invalid signature" });
  await assert.rejects(client.send(tampered), /HTTP 422/);

  // A valid signature over an envelope that claims a different sender fails
  // the key-id-to-sender binding before authorization.
  const spoofed = await signed(envelope(RECIPIENT, SIGNER));
  const spoofedResponse = await post(spoofed);
  assert.equal(spoofedResponse.status, 403);
  assert.deepEqual(await spoofedResponse.json(), { error: "forbidden" });
  await assert.rejects(client.send(spoofed), /HTTP 403/);

  // With the profile enabled an unsigned envelope is never acceptable.
  const unsigned = envelope();
  const unsignedResponse = await post(unsigned);
  assert.equal(unsignedResponse.status, 422);
  assert.deepEqual(await unsignedResponse.json(), { error: "invalid signature" });
  await assert.rejects(client.send(unsigned), /HTTP 422/);
});

test("TypeScript SDK signatures interoperate with the relay over WebSocket", { timeout: 15000 }, async t => {
  const port = await listen(t, createRelay({ token: TOKEN, signatures: {} }));
  const client = await openWebSocket("http://127.0.0.1:" + port, { token: TOKEN });
  t.after(() => client.close());
  const errors = () => client.messages.filter(value => value.type === "error");

  client.send({ type: "send", message: await signed() });
  await waitFor(() => client.messages.some(value => value.type === "accepted"), "signed send accepted");
  assert.equal(client.messages.find(value => value.type === "accepted").delivered, 0);

  const tampered = await signed();
  tampered.body.data = "tampered";
  client.send({ type: "send", message: tampered });
  await waitFor(() => errors().length >= 1, "tampered send rejected");
  assert.deepEqual(errors()[0], { type: "error", status: 422, error: "invalid signature" });

  client.send({ type: "send", message: await signed(envelope(RECIPIENT, SIGNER)) });
  await waitFor(() => errors().length >= 2, "spoofed send rejected");
  assert.deepEqual(errors()[1], { type: "error", status: 403, error: "forbidden" });

  client.send({ type: "send", message: envelope() });
  await waitFor(() => errors().length >= 3, "unsigned send rejected");
  assert.deepEqual(errors()[2], { type: "error", status: 422, error: "invalid signature" });
});
