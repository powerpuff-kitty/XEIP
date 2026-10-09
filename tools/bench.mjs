// tools/bench.mjs
//
// Micro- and transport-level benchmarks for the XEIP reference implementations.
// Development-only, like everything else in this repo: run with `npm run bench`.
// It starts and stops its own loopback relay and cleans up temp files.
import { performance } from "node:perf_hooks";
import { cpus, tmpdir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { request } from "node:http";
import { createRelay } from "../services/relay/server.mjs";
import { ReplayWindow } from "../services/relay/replay.mjs";
import { DeliveryLog } from "../services/relay/delivery.mjs";
import { ReceiptLedger } from "../services/relay/receipts.mjs";
import { LimitPolicy } from "../services/relay/limits.mjs";
import { DurableStore } from "../services/relay/durable.mjs";
import { FrameParser, OPCODES, encodeFrame, websocketAccept } from "../services/relay/websocket.mjs";
import { validateEnvelope } from "../sdks/typescript/src/validation.js";
import { SseParser } from "../sdks/typescript/src/sse.js";
import { encodeKeyId } from "./derive-keyid.mjs";

const TOKEN = "benchmark-shared-token-0123456789";
const session = "urn:xeip:session:bench";
const sender = "urn:xeip:entity:sender";
const recipient = "urn:xeip:entity:recipient";
const envelope = (extra = {}) => ({ xeip: "0.1", id: "urn:uuid:" + randomBytes(16).toString("hex"),
  kind: "message", sender, recipient, session, timestamp: new Date().toISOString(),
  body: { contentType: "text/plain", data: "benchmark payload" }, ...extra });

const results = [];
function record(group, name, ops, seconds, detail = "") {
  const perOpMs = (seconds * 1000) / ops;
  results.push({ group, name, opsPerSec: ops / seconds, perOpMs, detail });
}
async function timeAsync(name, iterations, fn, detail) {
  const start = performance.now();
  await fn();
  record("transport", name, iterations, (performance.now() - start) / 1000, detail);
}
function timeSync(group, name, iterations, fn, detail = "") {
  // Warm up, then measure.
  for (let i = 0; i < Math.min(iterations, 1000); i++) fn(i);
  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn(i);
  record(group, name, iterations, (performance.now() - start) / 1000, detail);
}
function seed(bytes) { return randomBytes(bytes); }

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve("http://127.0.0.1:" + server.address().port));
  });
}
async function close(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

// --- micro benchmarks -----------------------------------------------------
function micro() {
  const fixture = envelope();
  timeSync("encoding", "validateEnvelope (envelope)", 200000, () => validateEnvelope(fixture));

  const frame = "event: xeip.message\ndata: " + JSON.stringify(fixture) + "\n\n";
  timeSync("parsing", "SseParser.push (~120 B frame)", 200000, () => { new SseParser().push(frame); });

  const key = seed(32);
  timeSync("encoding", "encodeKeyId (ed25519 key-id)", 300000, () => encodeKeyId(key));

  const replay = new ReplayWindow({ windowMs: 3600000, maxEntries: 4096 });
  timeSync("policy", "ReplayWindow.accept", 200000, i => replay.accept(envelope({ id: "urn:uuid:" + i.toString(16).padStart(32, "0") })));

  const delivery = new DeliveryLog({ maxPerSession: 4096, maxSessions: 1024 });
  timeSync("policy", "DeliveryLog.append", 200000, i => delivery.append(session, envelope({ id: "urn:uuid:" + i.toString(16).padStart(32, "0") })));

  const receipts = new ReceiptLedger({ windowMs: 3600000, maxPerSession: 4096, maxPerPrincipal: 8192 });
  const principal = { entity: recipient };
  timeSync("policy", "ReceiptLedger.record", 200000, i => receipts.record(principal, session, i, "urn:uuid:" + i.toString(16).padStart(32, "0")));

  const limits = new LimitPolicy({ requestsPerSecond: 100000, burst: 100000, keyBy: "peer" });
  timeSync("policy", "LimitPolicy.take", 500000, () => limits.take("127.0.0.1"));

  const clientFrames = encodeFrame(OPCODES.text, Buffer.from(JSON.stringify(fixture)), true, seed(4));
  timeSync("parsing", "FrameParser.push (masked text)", 200000, () => { new FrameParser({ maxFrame: 128 * 1024, maxMessage: 128 * 1024 }).push(clientFrames); });
}

// --- transport benchmarks -------------------------------------------------
async function httpThroughput(base, count) {
  const body = JSON.stringify(envelope());
  const post = () => fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" }, body });
  const start = performance.now();
  for (let i = 0; i < count; i++) { const res = await post(); await res.arrayBuffer(); }
  record("transport", "HTTP POST /messages (sequential)", count, (performance.now() - start) / 1000);

  const concurrency = 32;
  const concurrent = performance.now();
  let sent = 0;
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (sent < count) { sent++; const res = await post(); await res.arrayBuffer(); }
  }));
  record("transport", "HTTP POST /messages (32 concurrent)", count, (performance.now() - concurrent) / 1000);
}

async function sseFanout(base, subscribers, count) {
  const controllers = [];
  const readers = [];
  for (let i = 0; i < subscribers; i++) {
    const controller = new AbortController();
    controllers.push(controller);
    const url = new URL(base + "/events");
    url.searchParams.set("session", session);
    url.searchParams.set("entity", i % 2 ? recipient : sender);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + TOKEN }, signal: controller.signal });
    readers.push({ response, controller });
  }
  // Warm up the subscriptions so all are registered before posting.
  await new Promise(resolve => setTimeout(resolve, 100));
  const received = new Array(subscribers).fill(0);
  const deadline = performance.now() + 20000;
  const workers = readers.map(async ({ response }, index) => {
    const reader = response.body.getReader(); const decoder = new TextDecoder(); const parser = new SseParser();
    try {
      while (received[index] < count && performance.now() < deadline) {
        const next = await reader.read(); if (next.done) break;
        for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) if (frame.event === "xeip.message") received[index]++;
      }
    } catch { /* aborted */ } finally { await reader.cancel().catch(() => {}); }
  });
  const body = JSON.stringify(envelope({ recipient: undefined }));
  const start = performance.now();
  for (let i = 0; i < count; i++) { const res = await fetch(base + "/messages", { method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" }, body }); await res.arrayBuffer(); }
  const postSeconds = (performance.now() - start) / 1000;
  await Promise.all(workers);
  record("transport", `SSE fanout (${subscribers} subscribers)`, count, (performance.now() - start) / 1000,
    `${count * subscribers} frames total; post-only ${(count / postSeconds).toFixed(0)} msg/s`);
  for (const controller of controllers) controller.abort();
}

function openWs(base, token) {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const url = new URL(base);
    const req = request({ host: url.hostname, port: url.port, path: "/ws",
      headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key, Authorization: "Bearer " + token } });
    req.once("upgrade", (response, socket, head) => {
      if (response.headers["sec-websocket-accept"] !== websocketAccept(key)) { socket.destroy(); return reject(new Error("bad accept")); }
      const parser = new FrameParser({ maxFrame: 128 * 1024, maxMessage: 128 * 1024, expectMask: false });
      const messages = [];
      socket.on("data", chunk => { for (const event of parser.push(chunk)) {
        if (event.type === "message") messages.push(event);
        else if (event.type === "ping") socket.write(encodeFrame(OPCODES.pong, event.payload, true, seed(4)));
      } });
      if (head.length) socket.unshift(head);
      resolve({ socket, messages, send: value => socket.write(encodeFrame(OPCODES.text, Buffer.from(JSON.stringify(value)), true, seed(4))) });
    });
    req.once("response", response => { response.resume(); reject(new Error("HTTP " + response.statusCode)); });
    req.once("error", reject); req.end();
  });
}

async function wsThroughput(base, count) {
  const client = await openWs(base, TOKEN);
  const body = envelope();
  const start = performance.now();
  for (let i = 0; i < count; i++) client.send({ type: "send", message: body });
  const deadline = performance.now() + 20000;
  const acceptedCount = () => client.messages.filter(m => JSON.parse(m.text).type === "accepted").length;
  while (acceptedCount() < count && performance.now() < deadline) await new Promise(r => setTimeout(r, 5));
  record("transport", "WebSocket send + accept (1 client)", count, (performance.now() - start) / 1000, `${acceptedCount()} accepted`);
  client.socket.destroy();
}

async function durableBench() {
  for (const fsync of ["never", "always"]) {
    const dir = mkdtempSync(join(tmpdir(), "xeip-bench-"));
    try {
      const store = new DurableStore({ dir, backend: "segments", fsync, retentionMs: 3600000, maxEntriesPerSession: 1000000, maxSessions: 1024, maxBytes: 268435456 });
      const count = fsync === "always" ? 300 : 5000;
      const msg = envelope();
      const start = performance.now();
      for (let i = 0; i < count; i++) store.append(session, { ...msg, id: "urn:uuid:" + i.toString(16).padStart(32, "0") });
      record("storage", `DurableStore.append (fsync=${fsync})`, count, (performance.now() - start) / 1000);
      store.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}

async function main() {
  console.log(`Node ${process.version} | ${cpus()[0]?.model ?? "unknown CPU"} (${cpus().length} cores)`);
  console.log("Warming up and measuring...\n");
  micro();

  const server = createRelay({ token: TOKEN });
  const base = await listen(server);
  try {
    console.error("[bench] http..."); await httpThroughput(base, 1000);
    console.error("[bench] sse..."); await sseFanout(base, 25, 200);
    console.error("[bench] ws..."); await wsThroughput(base, 1000);
  } finally { await close(server); }

  console.error("[bench] durable...");
  await durableBench();

  const groups = [...new Set(results.map(r => r.group))];
  for (const group of groups) {
    console.log(`== ${group} ==`);
    for (const r of results.filter(x => x.group === group)) {
      const rate = r.opsPerSec >= 1000 ? (r.opsPerSec / 1000).toFixed(1) + "k" : r.opsPerSec.toFixed(0);
      console.log(`  ${r.name.padEnd(42)} ${rate.padStart(9)} ops/s  ${r.perOpMs.toFixed(3).padStart(9)} ms/op  ${r.detail}`);
    }
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
