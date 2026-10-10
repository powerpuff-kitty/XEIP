/**
 * Simulated opt-in trusted-key-document resolution for the local relay. No AI
 * model, device action or persistence. The key pairs are the public
 * deterministic demo seeds shared with the signed-envelope and key-document
 * conformance vectors. The trusted chain is built in-process and never leaves
 * the relay.
 */
import assert from "node:assert/strict";
import { createPublicKey, randomUUID } from "node:crypto";
import { createRelay } from "../../services/relay/server.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { encodeKeyId, entityUrn } from "../../tools/derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed, signEnvelope } from "../../tools/signed-envelope.mjs";
import {
  KEYDOC_VERSION,
  keyDocumentChainDigest,
  signKeyDocument
} from "../../tools/key-document.mjs";
import { STATUS_VERSION, signStatusDocument } from "../../tools/identity-status.mjs";
import {
  LOCAL_SIGNED_ENVELOPES_PROFILE,
  LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE,
  LOCAL_STATUS_DOCUMENTS_PROFILE
} from "../../services/relay/relay-core.mjs";

const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SEED_B = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const SEED_C = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const privateKeyA = ed25519PrivateKeyFromSeed(Buffer.from(SEED_A, "hex"));
const privateKeyB = ed25519PrivateKeyFromSeed(Buffer.from(SEED_B, "hex"));
const privateKeyC = ed25519PrivateKeyFromSeed(Buffer.from(SEED_C, "hex"));
const kidOf = privateKey => encodeKeyId(
  createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32));
const kidA = kidOf(privateKeyA);
const kidB = kidOf(privateKeyB);
const kidC = kidOf(privateKeyC);
const entityA = entityUrn(kidA);
const entityB = entityUrn(kidB);
const entityC = entityUrn(kidC);
const recipient = "urn:xeip:entity:recipient-01";
const session = "urn:xeip:session:keydoc-demo";
const token = "keydoc-demo-shared-token-00000";

const genesis = signKeyDocument({
  xeip: KEYDOC_VERSION,
  entity: entityA,
  genesis: kidA,
  generation: 1,
  issuedAt: "2026-10-10T00:00:00Z",
  roots: [kidA],
  devices: [kidC]
}, { privateKey: privateKeyA, kid: kidA });
const anchor = { genesisKid: kidA, genesisDigest: keyDocumentChainDigest(genesis) };
// A signed status document (revocation list) for the entity, root-signed and
// revoking the endorsed device key. Serial is monotonic.
const revokeDevice = signStatusDocument({
  xeip: STATUS_VERSION,
  entity: entityA,
  serial: 1,
  issuedAt: "2026-10-10T00:00:00Z",
  revoked: [{ kid: kidC, generation: 1 }]
}, { privateKey: privateKeyA, kid: kidA });

const envelope = (sender, to = recipient) => ({
  xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender, recipient: to,
  session, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "hello" }
});
const sign = (privateKey, kid, sender) => signEnvelope(envelope(sender), { privateKey, kid });

async function startRelay(options) {
  const server = createRelay(options);
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const base = "http://127.0.0.1:" + server.address().port;
  const auth = { Authorization: "Bearer " + token };
  const streams = [];
  const subscribe = async entity => {
    const abort = new AbortController();
    const url = new URL(base + "/events");
    url.searchParams.set("session", session); url.searchParams.set("entity", entity);
    const response = await fetch(url, { headers: auth, signal: abort.signal });
    assert.equal(response.status, 200);
    const stream = { received: [], abort };
    streams.push(stream);
    stream.worker = (async () => {
      const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
      try {
        while (true) {
          const { done, value } = await reader.read(); if (done) break;
          for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
            if (frame.event === "xeip.message") stream.received.push(JSON.parse(frame.data));
          }
        }
      } catch { /* aborted */ }
      finally { await reader.cancel().catch(() => {}); }
    })();
    stream.worker.catch(() => {});
    return stream;
  };
  const post = value => fetch(base + "/messages", { method: "POST",
    headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify(value), signal: AbortSignal.timeout(4000) });
  const health = async () => (await fetch(base + "/health")).json();
  return { server, streams, subscribe, post, health };
}

async function stop(instance) {
  for (const stream of instance.streams) stream.abort.abort();
  await Promise.allSettled(instance.streams.map(stream => stream.worker));
  instance.server.closeAllConnections();
  await new Promise(resolve => instance.server.close(resolve));
}

async function waitFor(predicate) {
  const deadline = Date.now() + 4000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for keydoc demo");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

// Fail closed: a self-certifying document with the wrong anchor is rejected
// before any relay exists.
assert.throws(
  () => createRelay({ token, signatures: {}, keyDocuments: [{ document: genesis, anchor: { genesisKid: kidB } }] }),
  /untrusted anchor/
);

// Opt-in trusted-key resolution: a valid signature over an unknown key is not enough.
const enforced = await startRelay({ token, signatures: {}, keyDocuments: [{ document: genesis, anchor }] });
try {
  const advertised = await enforced.health();
  assert.equal(advertised.signatureProfile, LOCAL_SIGNED_ENVELOPES_PROFILE);
  assert.equal(advertised.keyDocumentProfile, LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE);
  assert.deepEqual(advertised.keyDocuments, { entities: 1 });
  assert.ok(!JSON.stringify(advertised).includes(kidA), "health must not expose key ids");

  const target = await enforced.subscribe(recipient);
  const good = sign(privateKeyA, kidA, entityA);
  const accepted = await enforced.post(good);
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), { accepted: true, delivered: 1 });
  await waitFor(() => target.received.some(message => message.id === good.id));

  const unknown = await enforced.post(sign(privateKeyB, kidB, entityB));
  assert.equal(unknown.status, 403);
  assert.deepEqual(await unknown.json(), { error: "forbidden" });
} finally {
  await stop(enforced);
}

// Fail closed: a status document needs the trusted key document whose roots
// must sign it.
assert.throws(
  () => createRelay({ token, signatures: {}, statusDocuments: [{ document: revokeDevice }] }),
  /statusDocuments requires keyDocuments/
);

// Opt-in status/revocation: a current trusted key that the accepted status
// revokes is denied even though its signature and key-document resolution pass.
const revoked = await startRelay({
  token, signatures: {},
  keyDocuments: [{ document: genesis, anchor }],
  statusDocuments: [{ document: revokeDevice }]
});
try {
  const advertised = await revoked.health();
  assert.equal(advertised.statusProfile, LOCAL_STATUS_DOCUMENTS_PROFILE);
  assert.deepEqual(advertised.statusDocuments, { entities: 1 });
  assert.ok(!JSON.stringify(advertised).includes(kidC), "health must not expose revoked key ids");

  const accepted = await revoked.post(sign(privateKeyA, kidA, entityA));
  assert.equal(accepted.status, 202);

  const denied = await revoked.post(sign(privateKeyC, kidC, entityC));
  assert.equal(denied.status, 403);
  assert.deepEqual(await denied.json(), { error: "forbidden" });
} finally {
  await stop(revoked);
}

// Default behavior is unchanged: without keyDocuments a self-certifying key routes.
const disabled = await startRelay({ token, signatures: {} });
try {
  assert.equal((await disabled.health()).keyDocumentProfile, undefined);
  assert.equal((await disabled.health()).statusProfile, undefined);
  assert.deepEqual(await (await disabled.post(sign(privateKeyB, kidB, entityB))).json(),
    { accepted: true, delivered: 0 });
} finally {
  await stop(disabled);
}

console.log("PASS local trusted key documents + status: bad anchor fails closed, trusted kid accepted, unknown kid 403 forbidden, status-revoked device 403 forbidden, health advertises profiles without key/status material, self-certifying key accepted when disabled");
