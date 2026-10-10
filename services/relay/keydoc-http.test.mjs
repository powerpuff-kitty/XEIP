import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import {
  LOCAL_SIGNED_ENVELOPES_PROFILE,
  LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE
} from "./relay-core.mjs";
import { encodeKeyId, entityUrn } from "../../tools/derive-keyid.mjs";
import { signEnvelope, ed25519PrivateKeyFromSeed } from "../../tools/signed-envelope.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "./websocket.mjs";

const TOKEN = "keydoc-test-shared-token-000";

// Deterministic RFC 8032 seeds shared with the committed key-document vectors:
// A is the entity genesis root, B a rotated root and C an endorsed device.
const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SEED_B = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const SEED_C = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

const publicKeyOf = seed => createPublicKey(ed25519PrivateKeyFromSeed(Buffer.from(seed, "hex")))
  .export({ format: "der", type: "spki" }).subarray(-32);

const privateKeyA = ed25519PrivateKeyFromSeed(Buffer.from(SEED_A, "hex"));
const privateKeyB = ed25519PrivateKeyFromSeed(Buffer.from(SEED_B, "hex"));
const privateKeyC = ed25519PrivateKeyFromSeed(Buffer.from(SEED_C, "hex"));
const KID_A = encodeKeyId(publicKeyOf(SEED_A));
const KID_B = encodeKeyId(publicKeyOf(SEED_B));
const KID_C = encodeKeyId(publicKeyOf(SEED_C));
const ENTITY_A = entityUrn(KID_A);
const ENTITY_B = entityUrn(KID_B);
const ENTITY_C = entityUrn(KID_C);

const chainVectors = JSON.parse(readFileSync(
  new URL("../../conformance/fixtures/identity-keydoc/keydoc-chain.vectors.json", import.meta.url), "utf8"));
const genesis = chainVectors.documents["genesis.gen1"];
const rotation = chainVectors.documents["rotation.gen2"];
const badSignature = chainVectors.documents["bad-signature.gen2"];
const ANCHOR_A = { genesisKid: KID_A };

const RECIPIENT = "urn:xeip:entity:recipient-01";
const SESSION = "urn:xeip:session:keydoc";
const envelope = (sender, recipient = RECIPIENT) => ({
  xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender, recipient, session: SESSION, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello" }
});
const signedWith = (privateKey, kid, sender) =>
  signEnvelope(envelope(sender), { privateKey, kid });

async function setup(t, { signatures, keyDocuments } = {}) {
  const options = { token: TOKEN };
  if (signatures !== undefined) options.signatures = signatures;
  if (keyDocuments !== undefined) options.keyDocuments = keyDocuments;
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
  const auth = { Authorization: "Bearer " + TOKEN };
  const post = value => fetch(base + "/messages", { method: "POST",
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify(value), signal: AbortSignal.timeout(5000) });
  const health = async () => (await fetch(base + "/health")).json();
  const subscribe = async (element = RECIPIENT) => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", SESSION); url.searchParams.set("entity", element);
    const response = await fetch(url, { headers: auth, signal: abort.signal });
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

test("requires signatures and rejects invalid or untrusted documents at construction", () => {
  // The trusted documents are a tightening of signed-envelope enforcement.
  assert.throws(() => createRelay({ token: TOKEN, keyDocuments: [{ document: genesis, anchor: ANCHOR_A }] }),
    /keyDocuments requires signatures/);
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [] }), /non-empty/);
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: genesis, extra: 1 }] }),
    /unknown keyDocuments entry field/);

  // A self-certifying document with no anchor must fail closed: trust is not
  // "which key the id means" but an out-of-band anchor.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: genesis }] }),
    /no anchor/);
  // The pinned anchor must match the chain's genesis key-id.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: genesis, anchor: { genesisKid: KID_B } }] }),
    /untrusted anchor/);
  // A bad signature and a broken chain are both rejected.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: badSignature, anchor: ANCHOR_A }] }),
    /signature mismatch/);
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: rotation, anchor: ANCHOR_A }] }),
    /chain gap/);
});

test("accepts a trust-anchored kid and rejects an unknown self-certifying kid over HTTP", async t => {
  const { post, health, subscribe } = await setup(t, {
    signatures: {}, keyDocuments: [{ document: genesis, anchor: ANCHOR_A }]
  });
  const advertised = await health();
  assert.equal(advertised.signatureProfile, LOCAL_SIGNED_ENVELOPES_PROFILE);
  assert.equal(advertised.keyDocumentProfile, LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE);
  assert.deepEqual(advertised.keyDocuments, { entities: 1 });
  // Health must not leak per-entity key material.
  assert.ok(!JSON.stringify(advertised).includes(KID_A), "health must not expose key ids");

  const target = await subscribe();
  const good = signedWith(privateKeyA, KID_A, ENTITY_A);
  const accepted = await post(good);
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), { accepted: true, delivered: 1 });
  await waitFor(() => target.frames.some(frame => frame.event === "xeip.message"), "trusted delivery");

  // A valid, self-certifying key that no trusted chain endorses is forbidden.
  const unknown = signedWith(privateKeyB, KID_B, ENTITY_B);
  const rejected = await post(unknown);
  assert.equal(rejected.status, 403);
  assert.deepEqual(await rejected.json(), { error: "forbidden" });

  // The signature gate still runs first: a tampered trusted envelope is 422.
  const tampered = signedWith(privateKeyA, KID_A, ENTITY_A);
  tampered.body.data = "tampered";
  assert.equal((await post(tampered)).status, 422);
  await target.close();
});

test("resolves current rotated roots and endorsed devices through a supplied chain", async t => {
  const { post } = await setup(t, {
    signatures: {},
    keyDocuments: [{ document: genesis, anchor: ANCHOR_A }, { document: rotation }]
  });
  // The successor root (KID_B) is current only after the rotation generation.
  assert.equal((await post(signedWith(privateKeyB, KID_B, ENTITY_B))).status, 202);
  // The endorsed device (KID_C) is current in both generations.
  assert.equal((await post(signedWith(privateKeyC, KID_C, ENTITY_C))).status, 202);
});

test("leaves behavior unchanged when keyDocuments is not configured", async t => {
  const { post, health } = await setup(t, { signatures: {} });
  assert.equal((await health()).keyDocumentProfile, undefined);
  // A self-certifying key with no trusted document is still accepted, exactly
  // as before the feature was added.
  assert.deepEqual(await (await post(signedWith(privateKeyB, KID_B, ENTITY_B))).json(),
    { accepted: true, delivered: 0 });

  const plain = await setup(t, {});
  assert.equal((await plain.health()).signatureProfile, undefined);
  assert.deepEqual(await (await plain.post(envelope(RECIPIENT))).json(),
    { accepted: true, delivered: 0 });
});

test("enforces trusted-key resolution over WebSocket send", async t => {
  const { base, subscribe } = await setup(t, {
    signatures: {}, keyDocuments: [{ document: genesis, anchor: ANCHOR_A }]
  });
  const target = await subscribe();
  const client = await openWebSocket(base, { token: TOKEN });
  const errors = () => client.messages.filter(value => value.type === "error");

  client.send({ type: "send", message: signedWith(privateKeyA, KID_A, ENTITY_A) });
  await waitFor(() => client.messages.some(value => value.type === "accepted"), "trusted send accepted");
  assert.equal(client.messages.find(value => value.type === "accepted").delivered, 1);

  client.send({ type: "send", message: signedWith(privateKeyB, KID_B, ENTITY_B) });
  await waitFor(() => errors().length >= 1, "unknown send rejected");
  assert.deepEqual(errors()[0], { type: "error", status: 403, error: "forbidden" });

  client.close();
  await target.close();
});
