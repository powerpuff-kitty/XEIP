import test from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "../../services/relay/server.mjs";
import { XeipHttpSseClient, makeMessage, DeliveryGapError } from "./dist/index.js";

test("SDK resumes through a real relay, surfaces eviction and checkpoints received sequences", async t => {
  const token = "sdk-delivery-test-token-long-enough";
  const server = createRelay({ token, delivery: { maxPerSession: 1 } });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const client = new XeipHttpSseClient({ baseUrl: "http://127.0.0.1:" + server.address().port, token });
  const session = "urn:xeip:session:sdk", sender = "urn:xeip:entity:sender", recipient = "urn:xeip:entity:recipient";
  const message = data => makeMessage({ kind: "message", sender, recipient, session, body: { contentType: "text/plain", data } });
  await client.send(message("evicted"));
  const retained = message("retained");
  await client.send(retained);
  const signal = AbortSignal.timeout(5000);
  const first = client.deliveryEvents(session, recipient, signal, 0);
  assert.deepEqual((await first.next()).value, { type: "gap", session, from: 2 });
  assert.deepEqual((await first.next()).value, { type: "message", message: retained, seq: 2 });
  await first.return();
  const fresh = message("after disconnect");
  await client.send(fresh);
  const resumed = client.deliveryEvents(session, recipient, signal, 2);
  assert.deepEqual((await resumed.next()).value, { type: "message", message: fresh, seq: 3 });
  await resumed.return();
  await assert.rejects(client.events(session, recipient, signal, 0).next(), DeliveryGapError);
});
