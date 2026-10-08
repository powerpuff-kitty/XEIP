import test from "node:test";
import assert from "node:assert/strict";
import { XeipHttpSseClient, assertEnvelope, assertEntity, makeMessage } from "./dist/index.js";
import { readFileSync } from "node:fs";
import * as sdk from "./dist/index.js";

function fixture(name) {
  return JSON.parse(readFileSync(new URL("../../conformance/fixtures/" + name, import.meta.url), "utf8"));
}

for (const delivered of [-1, 0.5, 9007199254740992]) {
  test("send rejects impossible stream-write count " + delivered, async () => {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered }), {
        status: 202, headers: { "Content-Type": "application/json" }
      })
    });
    await assert.rejects(client.send(fixture("message.valid.json")), /invalid relay response/);
  });
}

test("send requires HTTP 202 rather than any successful status", async () => {
  let cancelled = false;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify({ accepted: true, delivered: 1 }))); },
      cancel() { cancelled = true; }
    }), { status: 200 })
  });
  await assert.rejects(client.send(fixture("message.valid.json")), /HTTP 200/);
  assert.equal(cancelled, true);
});

test("send accepts zero active stream writes without claiming recipient delivery", async () => {
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered: 0 }), { status: 202 })
  });
  assert.deepEqual(await client.send(fixture("message.valid.json")), { accepted: true, delivered: 0 });
});

for (const [duplicate, delivered] of [[false, 1], [true, 0]]) {
  test("send preserves the optional duplicate flag " + duplicate, async () => {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered, duplicate }), { status: 202 }) });
    assert.deepEqual(await client.send(fixture("message.valid.json")), { accepted: true, delivered, duplicate });
  });
}
for (const duplicate of [null, "true", 1]) {
  test("send rejects malformed duplicate flag " + JSON.stringify(duplicate), async () => {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered: 0, duplicate }), { status: 202 }) });
    await assert.rejects(client.send(fixture("message.valid.json")), /invalid relay response/);
  });
}
test("send rejects a duplicate acceptance claiming new stream writes", async () => {
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered: 1, duplicate: true }), { status: 202 }) });
  await assert.rejects(client.send(fixture("message.valid.json")), /invalid relay response/);
});

test("events requires HTTP 200 and cancels an unexpected successful response", async () => {
  let cancelled = false;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode("event: xeip.message\ndata: " + JSON.stringify(fixture("message.valid.json")) + "\n\n")); },
      cancel() { cancelled = true; }
    }), { status: 201, headers: { "Content-Type": "text/event-stream" } })
  });
  const iterator = client.events("urn:xeip:session:demo", "urn:xeip:entity:human-01");
  try { await assert.rejects(iterator.next(), /HTTP 201/); }
  finally { await iterator.return(); }
  assert.equal(cancelled, true);
});

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

const vectors = JSON.parse(readFileSync(new URL("../../conformance/vectors.json", import.meta.url)));
for (const vector of vectors) {
  test("conformance: " + vector.name, () => {
    const value = { ...fixture(vector.schema + ".valid.json"), ...vector.patch };
    for (const field of vector.remove ?? []) delete value[field];
    const validate = {
      message: sdk.assertEnvelope,
      entity: sdk.assertEntity,
      session: sdk.assertSession,
      capability: sdk.assertCapability
    }[vector.schema];
    assert.equal(typeof validate, "function", "missing " + vector.schema + " validator");
    if (vector.valid) assert.doesNotThrow(() => validate(value));
    else assert.throws(() => validate(value), TypeError);
  });
}

function streamingClient(chunks, contentType = "text/event-stream") {
  return new XeipHttpSseClient({
    baseUrl: "http://localhost:8787", token: "development-only",
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      }
    }), { headers: { "content-type": contentType } })
  });
}
const encode = text => new TextEncoder().encode(text);
for (const ending of ["\n", "\r\n", "\r"]) {
  test("SSE handles byte fragmentation with " + JSON.stringify(ending), async () => {
    const message = fixture("message.valid.json");
    message.body.data = "hello 🐱";
    const frame = "event: xeip.message" + ending + "data: " + JSON.stringify(message) + ending + ending;
    const bytes = encode(frame);
    const client = streamingClient(Array.from(bytes, byte => Uint8Array.of(byte)));
    const received = [];
    for await (const msg of client.events("urn:xeip:session:test", "urn:xeip:entity:test")) received.push(msg);
    assert.deepEqual(received, [message]);
  });
}
test("SSE rejects an oversized incomplete frame", async () => {
  const client = streamingClient([encode("data: " + "x".repeat(140_000))]);
  await assert.rejects(async () => {
    for await (const msg of client.events("urn:xeip:session:test", "urn:xeip:entity:test")) void msg;
  }, /limit|large/i);
});
test("SSE bounds individual frames rather than entire network chunks", async () => {
  const message = fixture("message.valid.json");
  const frame = "event: xeip.message\ndata: " + JSON.stringify(message) + "\n\n";
  const client = streamingClient([encode(frame.repeat(500))]);
  let count = 0;
  for await (const msg of client.events("urn:xeip:session:test", "urn:xeip:entity:test")) count++;
  assert.equal(count, 500);
});
test("SSE rejects a successful response with the wrong media type", async () => {
  const client = streamingClient([encode("{}")], "application/json");
  await assert.rejects(async () => {
    for await (const msg of client.events("urn:xeip:session:test", "urn:xeip:entity:test")) void msg;
  }, /event-stream|content.type/i);
});
test("envelopes reject data that cannot be represented as JSON", () => {
  for (const data of [undefined, NaN, Infinity, 1n, () => {}, { nested: undefined }]) {
    assert.throws(() => assertEnvelope({ ...fixture("message.valid.json"), body: { contentType: "application/json", data } }), TypeError);
  }
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => assertEnvelope({ ...fixture("message.valid.json"), body: { contentType: "application/json", data: cyclic } }), TypeError);
});

test("SSE joins multiline data into a JSON envelope", async () => {
  const message = fixture("message.valid.json");
  const frame = "event: xeip.message\n" + JSON.stringify(message, null, 2).split("\n").map(line => "data: " + line).join("\n") + "\n\n";
  const received = [];
  for await (const msg of streamingClient([encode(frame)]).events("urn:xeip:session:test", "urn:xeip:entity:test")) received.push(msg);
  assert.deepEqual(received, [message]);
});

function openStreamClient(status, frame = "") {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { if (frame) controller.enqueue(encode(frame)); },
    cancel() { cancelled = true; }
  });
  const client = new XeipHttpSseClient({
    baseUrl: "http://localhost", token: "development-only",
    fetchImpl: async () => new Response(body, { status, headers: { "content-type": "text/event-stream" } })
  });
  return { client, wasCancelled: () => cancelled };
}
test("SSE cancels the body of a rejected HTTP response", async () => {
  const stream = openStreamClient(500);
  await assert.rejects(async () => {
    for await (const msg of stream.client.events("urn:xeip:session:test", "urn:xeip:entity:test")) void msg;
  }, /HTTP 500/);
  assert.equal(stream.wasCancelled(), true);
});
test("ending SSE iteration cancels the underlying subscription", async () => {
  const frame = "event: xeip.message\ndata: " + JSON.stringify(fixture("message.valid.json")) + "\n\n";
  const stream = openStreamClient(200, frame);
  for await (const msg of stream.client.events("urn:xeip:session:test", "urn:xeip:entity:test")) break;
  assert.equal(stream.wasCancelled(), true);
});
test("invalid SSE envelopes cancel the underlying subscription", async () => {
  const frame = "event: xeip.message\ndata: " + JSON.stringify(fixture("message.invalid-version.json")) + "\n\n";
  const stream = openStreamClient(200, frame);
  await assert.rejects(async () => {
    for await (const msg of stream.client.events("urn:xeip:session:test", "urn:xeip:entity:test")) void msg;
  }, /version/);
  assert.equal(stream.wasCancelled(), true);
});
