import test from "node:test";
import assert from "node:assert/strict";
import { XeipHttpSseClient, assertEnvelope, assertEntity, makeMessage } from "./dist/index.js";
import { readFileSync } from "node:fs";

function fixture(name) {
  return JSON.parse(readFileSync(new URL("../../conformance/fixtures/" + name, import.meta.url), "utf8"));
}

test("valid golden fixtures and rejects bad versions", () => {
  assertEnvelope(fixture("message.valid.json"));
  assertEntity(fixture("entity.valid.json"));
  assert.throws(() => assertEnvelope(fixture("message.invalid-version.json")), /version/);
});

test("builds an envelope with a unique ID and UTC timestamp", () => {
  const msg = makeMessage({
    kind: "message",
    sender: "urn:xeip:entity:human-01",
    recipient: "urn:xeip:entity:agent-01",
    session: "urn:xeip:session:demo",
    body: { contentType: "text/plain", data: "hi" }
  });
  assert.equal(msg.xeip, "0.1");
  assert.match(msg.id, /^urn:uuid:/);
  assert.match(msg.timestamp, /Z$/);
});

test("SSE async iterator parses only XEIP messages", async () => {
  const envelope = fixture("message.valid.json");
  const output = ': connected\n\nevent: xeip.message\ndata: ' + JSON.stringify(envelope) + '\n\n';
  const fakeFetch = async () => new Response(output, { status: 200, headers: { "content-type": "text/event-stream" } });
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost:8787", token: "development-only", fetchImpl: fakeFetch });
  const got = [];
  for await (const message of client.events("urn:xeip:session:demo", "urn:xeip:entity:agent-01")) got.push(message);
  assert.equal(got.length, 1);
  assert.equal(got[0].id, envelope.id);
});

test("rejects unsupported URI and extra envelope fields", () => {
  const bad = fixture("message.valid.json");
  bad.sender = "not-a-uri";
  assert.throws(() => assertEnvelope(bad), /sender/);
  bad.sender = "urn:xeip:entity:human-01";
  bad.unexpected = true;
  assert.throws(() => assertEnvelope(bad), /unexpected/);
});
