/**
 * Deterministic property/fuzz-style tests for the security hardening work on
 * the XEIP development relay (issue #6: negative tests and fuzzing).
 *
 * Everything here is seeded with a constant xorshift32 PRNG so that runs are
 * reproducible, bounded and dependency-free.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "./server.mjs";
import { SseParser } from "../../sdks/typescript/src/sse.js";
import { CLOSE, FrameParser, OPCODES, WebSocketError, encodeFrame } from "./websocket.mjs";

const TOKEN = "test-token-very-long-and-secret";
const SEED = 0x1a2b3c4d;
const MAX_BODY = 64 * 1024;
const MAX_FRAME = 128 * 1024;

// A fixed, valid envelope so generated bodies never depend on the clock or UUIDs.
const VALID_ENVELOPE = {
  xeip: "0.1",
  id: "urn:uuid:00000000-0000-4000-8000-000000000000",
  kind: "message",
  sender: "urn:xeip:entity:human",
  recipient: "urn:xeip:entity:agent",
  session: "urn:xeip:session:test",
  timestamp: "2026-10-09T00:00:00Z",
  body: { contentType: "text/plain", data: "hello" }
};

/** Deterministic xorshift32; returns uint32 values. */
function xorshift32(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    return state;
  };
}

const randomInt = (rng, max) => rng() % max;

function randomBytesWith(rng, length) {
  const out = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i++) out[i] = rng() & 0xff;
  return out;
}

async function withRelay(run) {
  const server = createRelay({ token: TOKEN });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  try {
    await run(base);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

// Rotates through the hostile body shapes named in issue #6. Every shape is
// guaranteed to be invalid (or oversized) so the response status stays bounded.
function hostileBody(rng, validJson) {
  switch (randomInt(rng, 5)) {
    case 0: // arbitrary bytes, frequently invalid UTF-8
      return randomBytesWith(rng, randomInt(rng, 256));
    case 1: { // truncated JSON
      const cut = 1 + randomInt(rng, validJson.length - 1);
      return Buffer.from(validJson.slice(0, cut));
    }
    case 2: { // deeply nested arrays, above and below the 64-container limit
      const depth = randomInt(rng, 2) === 0 ? 1 + randomInt(rng, 80) : 100 + randomInt(rng, 9900);
      return Buffer.from("{\"xeip\":\"0.1\",\"data\":" + "[".repeat(depth) + "0" + "]".repeat(depth) + "}");
    }
    case 3: // duplicate keys where the last value is invalid
      return Buffer.from(validJson.replace(/\}$/, ",\"xeip\":\"9.9\"}"));
    default: // oversized body, rejected via Content-Length before buffering
      return randomBytesWith(rng, MAX_BODY + 1 + randomInt(rng, 4096));
  }
}

test("random-byte POST bodies stay in the bounded status set and the relay stays up", { timeout: 20000 }, async () => {
  await withRelay(async base => {
    const rng = xorshift32(SEED);
    const validJson = JSON.stringify(VALID_ENVELOPE);
    const allowed = new Set([400, 413, 422]);
    for (let i = 0; i < 150; i++) {
      const response = await fetch(base + "/messages", {
        method: "POST",
        headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
        body: hostileBody(rng, validJson)
      });
      await response.arrayBuffer();
      assert.ok(allowed.has(response.status), "unexpected status " + response.status + " for body case " + i);

      const health = await fetch(base + "/health");
      await health.arrayBuffer();
      assert.equal(health.status, 200, "relay unavailable after body case " + i);
    }
    const accepted = await fetch(base + "/messages", {
      method: "POST",
      headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
      body: validJson
    });
    await accepted.arrayBuffer();
    assert.equal(accepted.status, 202, "relay must still accept a genuine message after fuzzing");
  });
});

test("SseParser recovers every valid frame across arbitrary chunk boundaries", { timeout: 5000 }, () => {
  const stream =
    "\uFEFF" +
    "data: hello\n\n" +
    "event: xeip.message\nid: 7\ndata: {\"a\":1}\n\n" +
    ": comment only\n\n" +
    "data: line one\ndata: line two\n\n" +
    "event: custom\ndata: value\r\n\r\n" +
    "data: spaced: value\n\n";
  const expected = [
    { event: "message", data: "hello" },
    { event: "xeip.message", data: "{\"a\":1}", id: "7" },
    { event: "message", data: "line one\nline two" },
    { event: "custom", data: "value" },
    { event: "message", data: "spaced: value" }
  ];

  const rng = xorshift32(SEED ^ 0x11111111);
  for (let run = 0; run < 40; run++) {
    const parser = new SseParser();
    const frames = [];
    for (let at = 0; at < stream.length;) {
      const size = 1 + randomInt(rng, 8);
      frames.push(...parser.push(stream.slice(at, at + size)));
      at += size;
    }
    assert.deepEqual(frames, expected, "random chunking run " + run);
  }

  const perCharacter = new SseParser();
  const frames = [];
  for (const character of stream) frames.push(...perCharacter.push(character));
  assert.deepEqual(frames, expected, "single-code-unit chunking");
});

test("SseParser never hangs and only ever rejects oversized frames with RangeError", { timeout: 5000 }, () => {
  const rng = xorshift32(SEED ^ 0x22222222);
  for (let i = 0; i < 200; i++) {
    const text = randomBytesWith(rng, randomInt(rng, 4096)).toString("latin1");
    const parser = new SseParser();
    let frames;
    try {
      frames = parser.push(text);
    } catch (error) {
      assert.ok(error instanceof RangeError, "unexpected error: " + error);
      continue;
    }
    assert.ok(Array.isArray(frames));
  }
  // Deterministically exercise the unfinished-frame bound.
  const parser = new SseParser();
  assert.throws(() => parser.push("a".repeat(128 * 1024 + 1)), RangeError);
});

test("FrameParser survives truncated, corrupted, unmasked and oversized client frames", { timeout: 5000 }, () => {
  const rng = xorshift32(SEED ^ 0x33333333);
  const codes = new Set(Object.values(CLOSE));
  const baseFrames = [
    encodeFrame(OPCODES.text, Buffer.from(JSON.stringify({ type: "subscribe", session: "urn:xeip:session:test", entity: "urn:xeip:entity:b" })), true, randomBytesWith(rng, 4)),
    encodeFrame(OPCODES.text, Buffer.from("ping"), true, randomBytesWith(rng, 4)),
    encodeFrame(OPCODES.ping, Buffer.from("hb"), true, randomBytesWith(rng, 4)),
    encodeFrame(OPCODES.close, Buffer.from([0x03, 0xe8]), true, randomBytesWith(rng, 4)),
    encodeFrame(OPCODES.binary, Buffer.from([1, 2, 3]), true, randomBytesWith(rng, 4)),
    encodeFrame(OPCODES.text, Buffer.from("ab"), false, randomBytesWith(rng, 4)),
    encodeFrame(OPCODES.continuation, Buffer.from("cd"), true, randomBytesWith(rng, 4))
  ];

  for (let i = 0; i < 500; i++) {
    const base = baseFrames[randomInt(rng, baseFrames.length)];
    const mutated = Buffer.from(base);
    let chunk;
    if (randomInt(rng, 3) === 0) {
      chunk = mutated.subarray(0, randomInt(rng, mutated.length + 1)); // truncation
    } else if (randomInt(rng, 2) === 0) {
      const flips = 1 + randomInt(rng, 4); // bit flips
      for (let flip = 0; flip < flips; flip++) mutated[randomInt(rng, mutated.length)] ^= 1 << randomInt(rng, 8);
      chunk = mutated;
    } else {
      const cut = randomInt(rng, mutated.length + 1); // truncation plus an unrelated tail
      chunk = Buffer.concat([mutated.subarray(0, cut), baseFrames[randomInt(rng, baseFrames.length)]]);
    }

    const parser = new FrameParser({ maxFrame: MAX_FRAME, maxMessage: MAX_FRAME, expectMask: true });
    let events;
    try {
      events = parser.push(chunk);
    } catch (error) {
      assert.ok(error instanceof WebSocketError, "non-WebSocketError thrown: " + error);
      assert.ok(codes.has(error.code), "undocumented close code: " + error.code);
      continue;
    }
    assert.ok(Array.isArray(events));
    for (const event of events) {
      if (event.type === "close") assert.equal(typeof event.code, "number");
    }
  }

  // Unmasked client frame is a protocol error.
  const unmasked = new FrameParser({ maxFrame: MAX_FRAME, maxMessage: MAX_FRAME, expectMask: true });
  assert.throws(
    () => unmasked.push(encodeFrame(OPCODES.text, Buffer.from("x"))),
    error => error instanceof WebSocketError && error.code === CLOSE.protocol
  );

  // An oversized frame header is rejected as too big before any payload allocation.
  const oversized = Buffer.alloc(14);
  oversized[0] = 0x80 | OPCODES.text;
  oversized[1] = 0x80 | 127;
  oversized.writeBigUInt64BE(BigInt(MAX_FRAME + 1), 2);
  const parser = new FrameParser({ maxFrame: MAX_FRAME, maxMessage: MAX_FRAME, expectMask: true });
  assert.throws(
    () => parser.push(oversized),
    error => error instanceof WebSocketError && error.code === CLOSE.tooBig
  );
});
