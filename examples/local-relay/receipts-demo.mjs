/** Simulated local recipient acknowledgment; no AI model, device action or persistence. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { createRelay } from "../../services/relay/server.mjs";
import { LocalAdmission } from "../../services/relay/admission.mjs";

const human = "urn:xeip:entity:human";
const agent = "urn:xeip:entity:agent";
const session = "urn:xeip:session:receipts-demo";
// Ephemeral credentials are generated locally and never printed.
const credentials = new Map([human, agent].map(entity => [entity, randomBytes(32).toString("base64url")]));
const admission = new LocalAdmission({
  credentials: [...credentials].map(([entity, token]) => ({ entity, token })),
  sessions: [{ xeip: "0.1", id: session, mode: "group", members: [human, agent], createdAt: new Date().toISOString() }]
});
const server = createRelay({ admission, delivery: {}, receipts: {} });
await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
const base = "http://127.0.0.1:" + server.address().port;
const auth = entity => ({ Authorization: "Bearer " + credentials.get(entity) });

try {
  const envelope = { xeip: "0.1", id: "urn:uuid:" + randomUUID(), kind: "message", sender: human, recipient: agent,
    session, timestamp: new Date().toISOString(), body: { contentType: "text/plain", data: "report status" } };
  const accepted = await fetch(base + "/messages", { method: "POST",
    headers: { ...auth(human), "Content-Type": "application/json" }, body: JSON.stringify(envelope), signal: AbortSignal.timeout(4000) });
  assert.equal(accepted.status, 202);
  const { seq } = await accepted.json();
  assert.equal(seq, 1);

  const receipt = (actor, document) => fetch(base + "/receipts", { method: "POST",
    headers: { ...auth(actor), "Content-Type": "application/json" }, body: JSON.stringify(document), signal: AbortSignal.timeout(4000) });

  const first = await receipt(agent, { session, seq });
  assert.equal(first.status, 202);
  assert.deepEqual(await first.json(), { acknowledged: true, session, seq, duplicate: false });

  const repeat = await receipt(agent, { session, seq, status: "received" });
  assert.equal(repeat.status, 202);
  assert.deepEqual(await repeat.json(), { acknowledged: true, session, seq, duplicate: true });

  // The sender is a session member but not the recipient, so it is ineligible.
  const ineligible = await receipt(human, { session, seq });
  assert.equal(ineligible.status, 403); await ineligible.body.cancel();

  const unknown = await receipt(agent, { session, seq: 999 });
  assert.equal(unknown.status, 404); await unknown.body.cancel();

  console.log("PASS local receipts: recipient ack, idempotent duplicate, ineligible-principal 403 and unknown-target 404");
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
