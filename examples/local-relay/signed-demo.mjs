/**
 * Simulated opt-in detached-signature enforcement for the local relay. No AI
 * model, device action or persistence. The Ed25519 key pair is the public
 * deterministic demo seed from the signed-envelope conformance vectors.
 */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRelay } from "../../services/relay/server.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { encodeKeyId, entityUrn } from "../../tools/derive-keyid.mjs";
import { signEnvelope, ed25519PrivateKeyFromSeed } from "../../tools/signed-envelope.mjs";
import { LOCAL_SIGNED_ENVELOPES_PROFILE } from "../../services/relay/relay-core.mjs";

const SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PUBLIC_KEY_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const privateKey = ed25519PrivateKeyFromSeed(Buffer.from(SEED_HEX, "hex"));
const kid = encodeKeyId(Buffer.from(PUBLIC_KEY_HEX, "hex"));
const sender = entityUrn(kid);
const recipient = "urn:xeip:entity:recipient-01";
const session = "urn:xeip:session:signed-demo";
const token = "signed-demo-shared-token-000000";

const envelope = (from = sender, to = recipient) => ({
  xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender: from, recipient: to,
  session, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "hello" }
});
const sign = (value = envelope()) => signEnvelope(value, { privateKey, kid });

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
    if (Date.now() >= deadline) throw new Error("timed out waiting for signed demo");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

// Opt-in signature enforcement: every accepted envelope must verify and bind to sender.
const enforced = await startRelay({ token, signatures: {} });
try {
  assert.equal((await enforced.health()).signatureProfile, LOCAL_SIGNED_ENVELOPES_PROFILE);
  const target = await enforced.subscribe(recipient);
  const good = sign();
  const accepted = await enforced.post(good);
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), { accepted: true, delivered: 1 });
  await waitFor(() => target.received.some(message => message.id === good.id));

  const tampered = sign();
  tampered.body.data = "tampered";
  const mismatch = await enforced.post(tampered);
  assert.equal(mismatch.status, 422);
  assert.deepEqual(await mismatch.json(), { error: "invalid signature" });

  const spoofed = await enforced.post(sign(envelope(recipient, sender)));
  assert.equal(spoofed.status, 403);
  assert.deepEqual(await spoofed.json(), { error: "forbidden" });

  assert.equal((await enforced.post(envelope())).status, 422);
} finally {
  await stop(enforced);
}

// Default behavior is unchanged: without the profile an unsigned envelope routes.
const disabled = await startRelay({ token });
try {
  assert.equal((await disabled.health()).signatureProfile, undefined);
  assert.deepEqual(await (await disabled.post(envelope())).json(), { accepted: true, delivered: 0 });
} finally {
  await stop(disabled);
}

console.log("PASS local signed envelopes: health profile, valid signed accepted, tampered/missing 422 invalid signature, spoofed 403 forbidden, unsigned accepted when disabled");
