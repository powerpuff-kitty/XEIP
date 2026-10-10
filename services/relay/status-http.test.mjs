import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "./server.mjs";
import {
  LOCAL_SIGNED_ENVELOPES_PROFILE,
  LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE,
  LOCAL_STATUS_DOCUMENTS_PROFILE
} from "./relay-core.mjs";
import { encodeKeyId, entityUrn } from "../../tools/derive-keyid.mjs";
import { signEnvelope, ed25519PrivateKeyFromSeed } from "../../tools/signed-envelope.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "./websocket.mjs";

const TOKEN = "status-test-shared-token-000";

// Deterministic RFC 8032 seeds shared with the committed key-document and
// status vectors: A is the entity genesis root, C an endorsed device.
const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SEED_C = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

const publicKeyOf = seed => createPublicKey(ed25519PrivateKeyFromSeed(Buffer.from(seed, "hex")))
  .export({ format: "der", type: "spki" }).subarray(-32);

const privateKeyA = ed25519PrivateKeyFromSeed(Buffer.from(SEED_A, "hex"));
const privateKeyC = ed25519PrivateKeyFromSeed(Buffer.from(SEED_C, "hex"));
const KID_A = encodeKeyId(publicKeyOf(SEED_A));
const KID_C = encodeKeyId(publicKeyOf(SEED_C));
const ENTITY_A = entityUrn(KID_A);
const ENTITY_C = entityUrn(KID_C);

// The committed status vectors carry a verified genesis key document (root A,
// device C) and the signed status documents used below.
const statusVectors = JSON.parse(readFileSync(
  new URL("../../conformance/fixtures/identity-status/status.vectors.json", import.meta.url), "utf8"));
const trusted = statusVectors.trusted["keydoc.entity"];
const status = name => statusVectors.statuses[name];
const ANCHOR_A = { genesisKid: KID_A };

const RECIPIENT = "urn:xeip:entity:recipient-01";
const SESSION = "urn:xeip:session:status";
const envelope = (sender, recipient = RECIPIENT) => ({
  xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message",
  sender, recipient, session: SESSION, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "hello" }
});
const signedWith = (privateKey, kid, sender) => signEnvelope(envelope(sender), { privateKey, kid });

async function setup(t, { signatures, keyDocuments, statusDocuments } = {}) {
  const options = { token: TOKEN };
  if (signatures !== undefined) options.signatures = signatures;
  if (keyDocuments !== undefined) options.keyDocuments = keyDocuments;
  if (statusDocuments !== undefined) options.statusDocuments = statusDocuments;
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

test("requires keyDocuments and rejects invalid, rollback or non-root status documents", () => {
  // A status document is meaningless without the trusted key document that
  // supplies the roots that must sign it.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, statusDocuments: [{ document: status("status.revoke.1") }] }),
    /statusDocuments requires keyDocuments/);
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: trusted, anchor: ANCHOR_A }], statusDocuments: [] }),
    /non-empty/);
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments: [{ document: trusted, anchor: ANCHOR_A }],
    statusDocuments: [{ document: status("status.revoke.1"), extra: 1 }] }), /unknown statusDocuments entry field/);

  const keyDocuments = [{ document: trusted, anchor: ANCHOR_A }];
  // A device-signed status is not root-signed: unknown signer at construction.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments,
    statusDocuments: [{ document: status("status.nonroot") }] }), /unknown signer/);
  // A serial that does not advance is a rollback at construction.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments,
    statusDocuments: [{ document: status("status.revoke.2") }, { document: status("status.revoke.1") }] }),
    /serial rollback/);
  // A status older than the supplied maximum age is stale at construction.
  assert.throws(() => createRelay({ token: TOKEN, signatures: {}, keyDocuments,
    statusDocuments: [{ document: status("status.stale"), now: "2027-01-01T00:00:00Z", maxAgeSeconds: 1 }] }),
    /stale status/);
});

test("accepts a non-revoked kid and rejects a revoked kid over HTTP", async t => {
  const { post, health, subscribe } = await setup(t, {
    signatures: {},
    keyDocuments: [{ document: trusted, anchor: ANCHOR_A }],
    statusDocuments: [{ document: status("status.revoke.1") }]
  });
  const advertised = await health();
  assert.equal(advertised.signatureProfile, LOCAL_SIGNED_ENVELOPES_PROFILE);
  assert.equal(advertised.keyDocumentProfile, LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE);
  assert.equal(advertised.statusProfile, LOCAL_STATUS_DOCUMENTS_PROFILE);
  assert.deepEqual(advertised.keyDocuments, { entities: 1 });
  assert.deepEqual(advertised.statusDocuments, { entities: 1 });
  // Health must not leak per-entity key or revocation material.
  assert.ok(!JSON.stringify(advertised).includes(KID_A), "health must not expose key ids");
  assert.ok(!JSON.stringify(advertised).includes(KID_C), "health must not expose revoked key ids");

  const target = await subscribe();
  // The root key is current and not revoked: accepted.
  const root = signedWith(privateKeyA, KID_A, ENTITY_A);
  const accepted = await post(root);
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), { accepted: true, delivered: 1 });
  await waitFor(() => target.frames.some(frame => frame.event === "xeip.message"), "non-revoked delivery");

  // The endorsed device is a current trusted key, but the status revokes it.
  const revoked = await post(signedWith(privateKeyC, KID_C, ENTITY_C));
  assert.equal(revoked.status, 403);
  assert.deepEqual(await revoked.json(), { error: "forbidden" });
  await target.close();
});

test("leaves behavior unchanged when statusDocuments is not configured", async t => {
  // With trusted keys but no status, the current device is still accepted.
  const { post } = await setup(t, {
    signatures: {}, keyDocuments: [{ document: trusted, anchor: ANCHOR_A }]
  });
  assert.deepEqual(await (await post(signedWith(privateKeyC, KID_C, ENTITY_C))).json(),
    { accepted: true, delivered: 0 });

  // With no profiles at all, a self-certifying key routes exactly as before.
  const plain = await setup(t, {});
  assert.equal((await plain.health()).statusProfile, undefined);
  assert.equal((await plain.health()).keyDocumentProfile, undefined);
  assert.deepEqual(await (await plain.post(envelope(RECIPIENT))).json(),
    { accepted: true, delivered: 0 });
});

test("enforces status revocation over WebSocket send", async t => {
  const { base, subscribe } = await setup(t, {
    signatures: {},
    keyDocuments: [{ document: trusted, anchor: ANCHOR_A }],
    statusDocuments: [{ document: status("status.revoke.1") }]
  });
  const target = await subscribe();
  const client = await openWebSocket(base, { token: TOKEN });
  const errors = () => client.messages.filter(value => value.type === "error");

  client.send({ type: "send", message: signedWith(privateKeyA, KID_A, ENTITY_A) });
  await waitFor(() => client.messages.some(value => value.type === "accepted"), "non-revoked send accepted");
  assert.equal(client.messages.find(value => value.type === "accepted").delivered, 1);

  client.send({ type: "send", message: signedWith(privateKeyC, KID_C, ENTITY_C) });
  await waitFor(() => errors().length >= 1, "revoked send rejected");
  assert.deepEqual(errors()[0], { type: "error", status: 403, error: "forbidden" });

  client.close();
  await target.close();
});
