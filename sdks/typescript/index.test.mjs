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

test("send surfaces the relay 422 error body", async () => {
  for (const error of ["unsupported version", "malformed xeip version"]) {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify({ error }), {
        status: 422, headers: { "Content-Type": "application/json" }
      })
    });
    await assert.rejects(client.send(fixture("message.valid.json")), new RegExp(error));
  }
});

test("send falls back to the status when a 422 body is not JSON", async () => {
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response("not json", { status: 422 })
  });
  await assert.rejects(client.send(fixture("message.valid.json")), /HTTP 422/);
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

test("send preserves the optional delivery sequence and rejects malformed values", async () => {
  const accepted = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered: 1, seq: 7 }), { status: 202 }) });
  assert.deepEqual(await accepted.send(fixture("message.valid.json")), { accepted: true, delivered: 1, seq: 7 });
  for (const seq of [-1, 1.5, "1", null]) {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify({ accepted: true, delivered: 0, seq }), { status: 202 }) });
    await assert.rejects(client.send(fixture("message.valid.json")), /invalid relay response/);
  }
});

test("acknowledge posts a receipt and parses the acceptance", async () => {
  let seen = null;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async (url, options) => {
      seen = { url: String(url), options };
      return new Response(JSON.stringify({ acknowledged: true, session: "urn:xeip:session:demo", seq: 42, duplicate: false }), {
        status: 202, headers: { "Content-Type": "application/json" }
      });
    }
  });
  const acceptance = await client.acknowledge("urn:xeip:session:demo",
    { seq: 42, id: "urn:xeip:message:x", status: "received" });
  assert.deepEqual(acceptance, { acknowledged: true, session: "urn:xeip:session:demo", seq: 42, duplicate: false });
  assert.equal(seen.url, "http://localhost/receipts");
  assert.equal(seen.options.method, "POST");
  assert.equal(seen.options.headers["Authorization"], "Bearer demo-token");
  assert.equal(seen.options.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(seen.options.body),
    { session: "urn:xeip:session:demo", seq: 42, id: "urn:xeip:message:x", status: "received" });
});

test("acknowledge omits absent selectors from the request body", async () => {
  let body = null;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return new Response(JSON.stringify({ acknowledged: true, session: "urn:xeip:session:demo", seq: 7, duplicate: false }), { status: 202 });
    }
  });
  await client.acknowledge("urn:xeip:session:demo", { id: "urn:xeip:message:x" });
  assert.deepEqual(body, { session: "urn:xeip:session:demo", id: "urn:xeip:message:x" });
});

test("acknowledge preserves a duplicate acknowledgment", async () => {
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(JSON.stringify({ acknowledged: true, session: "urn:xeip:session:demo", seq: 42, duplicate: true }), { status: 202 }) });
  assert.deepEqual(await client.acknowledge("urn:xeip:session:demo", { seq: 42 }),
    { acknowledged: true, session: "urn:xeip:session:demo", seq: 42, duplicate: true });
});

test("acknowledge rejects a target without a selector before fetch", async () => {
  let called = false;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => { called = true; return new Response("{}", { status: 202 }); } });
  await assert.rejects(client.acknowledge("urn:xeip:session:demo", {}), /seq or id/);
  assert.equal(called, false);
});

test("acknowledge rejects malformed selectors before fetch", async () => {
  for (const [target, pattern] of [
    [{ seq: -1 }, /seq/],
    [{ seq: 1.5 }, /seq/],
    [{ seq: "1" }, /seq/],
    [{ seq: null }, /seq/],
    [{ id: "not-a-uri" }, /id/],
    [{ seq: 1, status: "completed" }, /status/],
    [{ seq: 1, unknown: true }, /unexpected/]
  ]) {
    let called = false;
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => { called = true; return new Response("{}", { status: 202 }); } });
    await assert.rejects(client.acknowledge("urn:xeip:session:demo", target), pattern);
    assert.equal(called, false, JSON.stringify(target));
  }
});

test("acknowledge rejects a response that does not match the request", async () => {
  for (const body of [
    { acknowledged: true, session: "urn:xeip:session:other", seq: 42, duplicate: false },
    { acknowledged: true, session: "urn:xeip:session:demo", seq: 41, duplicate: false }
  ]) {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify(body), { status: 202 }) });
    await assert.rejects(client.acknowledge("urn:xeip:session:demo", { seq: 42 }), /invalid relay response/);
  }
});

test("acknowledge rejects a non-JSON 202 body as an invalid relay response", async () => {
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response("not json", { status: 202 }) });
  await assert.rejects(client.acknowledge("urn:xeip:session:demo", { seq: 1 }), /invalid relay response/);
});

test("acknowledge rejects a non-202 response and cancels the body", async () => {
  let cancelled = false;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode("{}")); },
      cancel() { cancelled = true; }
    }), { status: 404 })
  });
  await assert.rejects(client.acknowledge("urn:xeip:session:demo", { seq: 42 }), /HTTP 404/);
  assert.equal(cancelled, true);
});

test("acknowledge rejects a malformed acceptance", async () => {
  for (const body of [
    { session: "urn:xeip:session:demo", seq: 42, duplicate: false },
    { acknowledged: true, session: "urn:xeip:session:demo", seq: 42, duplicate: "false" },
    { acknowledged: true, session: "urn:xeip:session:demo", seq: 1.5, duplicate: false },
    { acknowledged: true, session: "urn:xeip:session:demo", seq: -1, duplicate: false },
    { acknowledged: true, session: 7, seq: 42, duplicate: false },
    { acknowledged: true, session: "urn:xeip:session:demo", seq: 42, duplicate: null }
  ]) {
    const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
      fetchImpl: async () => new Response(JSON.stringify(body), { status: 202 }) });
    await assert.rejects(client.acknowledge("urn:xeip:session:demo", { seq: 42 }), /invalid relay response/);
  }
});

test("events sends a Last-Event-ID resume cursor and rejects an invalid one before fetch", async () => {
  let seen = null;
  const client = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async (_url, options) => { seen = options.headers; return new Response("", { status: 200, headers: { "content-type": "text/event-stream" } }); } });
  for await (const _message of client.events("urn:xeip:session:demo", "urn:xeip:entity:human-01", undefined, 4)) void _message;
  assert.equal(seen["Last-Event-ID"], "4");

  let called = false;
  const invalid = new XeipHttpSseClient({ baseUrl: "http://localhost", token: "demo-token",
    fetchImpl: async () => { called = true; return new Response("", { status: 200 }); } });
  const iterator = invalid.events("urn:xeip:session:demo", "urn:xeip:entity:human-01", undefined, -1);
  await assert.rejects(iterator.next(), /after/);
  assert.equal(called, false);
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
  assertEnvelope(fixture("extensions/message.valid.json"));
  assertEntity(fixture("entity.valid.json"));
  assert.throws(() => assertEnvelope(fixture("message.invalid-version.json")), /version/);
  assert.throws(() => assertEnvelope(fixture("message.invalid-malformed-version.json")), /malformed/);
  assert.throws(() => assertEnvelope(fixture("message.invalid-unknown-field.json")), /unexpected/);
});

test("message schema xeip const matches the first supported version", () => {
  const schema = JSON.parse(readFileSync(new URL("../../schemas/message.schema.json", import.meta.url)));
  assert.equal(schema.properties.xeip.const, sdk.XEIP_SUPPORTED_VERSIONS[0]);
  assert.equal(sdk.XEIP_VERSION, sdk.XEIP_SUPPORTED_VERSIONS[0]);
});

test("advertises supported versions and distinguishes unsupported from malformed xeip", () => {
  assert.deepEqual(sdk.XEIP_SUPPORTED_VERSIONS, ["0.1"]);
  assert.ok(sdk.XEIP_SUPPORTED_VERSIONS.includes("0.1"));
  for (const xeip of ["9.9", "0.2", "1.0"]) {
    assert.throws(() => assertEnvelope({ ...fixture("message.valid.json"), xeip }), /unsupported version/, xeip);
  }
  for (const xeip of ["", "0", "0.1.0", "v0.1", "0.1 ", 1, null, true]) {
    assert.throws(() => assertEnvelope({ ...fixture("message.valid.json"), xeip }),
      error => error instanceof TypeError && !/unsupported version/.test(error.message), JSON.stringify(xeip));
  }
  const missing = { ...fixture("message.valid.json") };
  delete missing.xeip;
  assert.throws(() => assertEnvelope(missing), error => !/unsupported version/.test(error.message));
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
