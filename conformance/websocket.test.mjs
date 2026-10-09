// Real cross-language WebSocket checks for the reference Rust client. The Node
// relay and the Rust peer exchange the same public envelopes as HTTP/SSE, and
// authentication/authorization stays independent of the transport.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { createRelay } from "../services/relay/server.mjs";
import { LocalAdmission } from "../services/relay/admission.mjs";
import { SseParser } from "../sdks/typescript/src/sse.js";
import { XeipHttpSseClient } from "../sdks/typescript/dist/index.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const token = randomBytes(24).toString("hex");
const fixture = JSON.parse(readFileSync(new URL("fixtures/message.valid.json", import.meta.url), "utf8"));
const human = fixture.sender;    // urn:xeip:entity:human-01 (TypeScript side)
const agent = fixture.recipient; // urn:xeip:entity:agent-01 (Rust side)
let executable;

before(async () => {
  const run = promisify(execFile);
  const bigBuffer = { maxBuffer: 16 * 1024 * 1024 };
  await run("cargo", ["build", "--example", "websocket_peer", "--locked", "--quiet"], { cwd: root, timeout: 120000, ...bigBuffer });
  const { stdout } = await run("cargo", ["metadata", "--no-deps", "--format-version", "1", "--locked"], { cwd: root, ...bigBuffer });
  executable = join(JSON.parse(stdout).target_directory, "debug", "examples", "websocket_peer" + (process.platform === "win32" ? ".exe" : ""));
});

async function listen(t, server) {
  // Upgraded sockets are not covered by closeAllConnections(); track them so
  // server.close() can finish on every path.
  const sockets = new Set();
  server.on("upgrade", (_req, socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    const onError = reject;
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => { server.off("error", onError); resolve(); });
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return server.address().port;
}

// Updates the Rust peer from CLI flags, or from XEIP_* variables in env-only mode.
function wsPeer(t, port, options = {}) {
  const env = { ...process.env };
  const args = [];
  const assign = (flag, key, value) => {
    if (options.envOnly) env[key] = String(value);
    else args.push(flag, String(value));
  };
  assign("--host", "XEIP_HOST", options.host ?? "127.0.0.1");
  assign("--port", "XEIP_PORT", port);
  assign("--path", "XEIP_PATH", options.path ?? "/ws");
  assign("--token", "XEIP_DEV_TOKEN", options.token ?? token);
  assign("--session", "XEIP_SESSION", options.session ?? fixture.session);
  assign("--entity", "XEIP_ENTITY", options.entity ?? agent);
  if (options.after !== undefined) assign("--after", "XEIP_AFTER", options.after);
  assign("--mode", "XEIP_MODE", options.mode ?? "listen");
  if (options.file !== undefined) assign("--file", "XEIP_FILE", options.file);

  const child = spawn(executable, args, { cwd: root, env, stdio: ["pipe", "pipe", "pipe"] });
  // Decode streams as UTF-8 so a read boundary inside a multi-byte codepoint
  // cannot corrupt a JSON control line.
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  const events = [];
  const waiters = [];
  let stdout = "", stderr = "", exited = null;
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const wake = () => {
    // Re-queue any waiter whose condition is still unmet so an unrelated event
    // cannot permanently drop it.
    const pending = waiters.splice(0);
    for (const attempt of pending) if (!attempt()) waiters.push(attempt);
  };
  child.stdout.on("data", chunk => {
    stdout += chunk;
    let newline;
    while ((newline = stdout.indexOf("\n")) >= 0) {
      const line = stdout.slice(0, newline).trim();
      stdout = stdout.slice(newline + 1);
      if (!line) continue;
      let event;
      try { event = JSON.parse(line); } catch { event = { type: "raw", line }; }
      events.push(event);
      if (event.type === "ready") resolveReady(event);
      wake();
    }
  });
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-8192); });
  const done = new Promise(resolve => {
    child.once("error", error => {
      rejectReady(error);
      resolve({ code: null, signal: null, error: String(error) });
    });
    child.once("close", (code, signal) => {
      exited = { code, signal };
      rejectReady(new Error("Rust WebSocket peer exited before readiness: " + stderr));
      wake();
      resolve({ code, signal, error: stderr });
    });
  });
  ready.catch(() => {});
  const watchdog = setTimeout(() => {
    rejectReady(new Error("Rust WebSocket peer readiness timed out: " + stderr));
    child.kill();
  }, 10000);
  ready.then(() => clearTimeout(watchdog), () => clearTimeout(watchdog));
  t.after(async () => {
    clearTimeout(watchdog);
    if (child.exitCode === null && child.signalCode === null) child.kill();
    const kill9 = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }, 2000);
    kill9.unref();
    child.stdin.destroy();
    // Bound teardown so a wedged peer cannot hang the test runner.
    await Promise.race([done, delay(6000)]);
    clearTimeout(kill9);
  });
  const waitFor = (predicate, label, timeout = 5000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(label ?? "condition not met")), timeout);
    const attempt = () => {
      const value = predicate();
      if (value) { clearTimeout(timer); resolve(value); return true; }
      if (exited) {
        clearTimeout(timer);
        reject(new Error((label ?? "condition not met") + " (peer exited " + exited.code + "): " + stderr));
        return true;
      }
      return false;
    };
    if (attempt()) return;
    waiters.push(attempt);
  });
  return {
    child,
    ready,
    done,
    events,
    waitFor,
    send: envelope => child.stdin.write(JSON.stringify(envelope) + "\n"),
    endStdin: () => child.stdin.end()
  };
}

// Reads only `xeip.message` frames, mirroring services/relay/websocket.test.mjs.
async function subscribeSse(base, credentials, actor, session = fixture.session) {
  const controller = new AbortController();
  const received = [];
  const url = new URL(base + "/events");
  url.searchParams.set("session", session);
  url.searchParams.set("entity", actor);
  const response = await fetch(url, { headers: { Authorization: "Bearer " + credentials }, signal: controller.signal });
  assert.equal(response.status, 200);
  const worker = (async () => {
    const reader = response.body.getReader(), decoder = new TextDecoder(), parser = new SseParser();
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        for (const frame of parser.push(decoder.decode(next.value, { stream: true }))) {
          if (frame.event === "xeip.message") received.push(JSON.parse(frame.data));
        }
      }
    } catch { /* aborted */ }
  })();
  worker.catch(() => {});
  return { received, close: async () => { controller.abort(); await worker.catch(() => {}); } };
}

async function waitForLength(list, length, label) {
  const deadline = Date.now() + 5000;
  while (list.length < length) {
    if (Date.now() >= deadline) throw new Error(label);
    await delay(10);
  }
  return list[length - 1];
}

test("Rust WebSocket subscriber receives a TypeScript HTTP envelope", { timeout: 20000 }, async t => {
  const port = await listen(t, createRelay({ token }));
  const rust = wsPeer(t, port, { entity: agent, mode: "listen" });
  await rust.ready;
  const client = new XeipHttpSseClient({ baseUrl: "http://127.0.0.1:" + port, token });
  assert.deepEqual(await client.send(fixture), { accepted: true, delivered: 1 });
  const delivered = await rust.waitFor(() => rust.events.find(event => event.type === "message"), "Rust WebSocket delivery");
  assert.deepEqual(delivered.message, fixture);
});

test("TypeScript SSE subscriber receives a Rust WebSocket envelope with nested Unicode payload", { timeout: 20000 }, async t => {
  const port = await listen(t, createRelay({ token }));
  const sse = await subscribeSse("http://127.0.0.1:" + port, token, human);
  t.after(() => sse.close());
  const rust = wsPeer(t, port, { entity: agent, mode: "stdin" });
  await rust.ready;
  const message = { ...fixture, id: "urn:xeip:message:unicode-command", kind: "command",
    sender: agent, recipient: human,
    body: { contentType: "application/json", data: { text: "Hello 🐈\nBonjour", nested: [null, true, 42, { key: "é" }] } },
    extensions: { "example.org/trace": { labels: ["camera", "🐈"] } } };
  rust.send(message);
  const accepted = await rust.waitFor(() => rust.events.find(event => event.type === "accepted"), "Rust send acceptance");
  assert.deepEqual(accepted, { type: "accepted", delivered: 1 });
  rust.endStdin();
  assert.deepEqual(await waitForLength(sse.received, 1, "SSE delivery timed out"), message);
  assert.equal((await rust.done).code, 0);
});

test("Rust WebSocket peer honors XEIP_* environment configuration", { timeout: 20000 }, async t => {
  const port = await listen(t, createRelay({ token }));
  const rust = wsPeer(t, port, { entity: agent, mode: "listen", envOnly: true });
  await rust.ready;
  const client = new XeipHttpSseClient({ baseUrl: "http://127.0.0.1:" + port, token });
  assert.deepEqual(await client.send(fixture), { accepted: true, delivered: 1 });
  const delivered = await rust.waitFor(() => rust.events.find(event => event.type === "message"), "env-configured delivery");
  assert.deepEqual(delivered.message, fixture);
});

test("Rust WebSocket subscriber uses an admission credential bound to its entity", { timeout: 20000 }, async t => {
  const humanToken = randomBytes(32).toString("base64url");
  const agentToken = randomBytes(32).toString("base64url");
  const admission = new LocalAdmission({
    credentials: [{ entity: human, token: humanToken }, { entity: agent, token: agentToken }],
    sessions: [{ xeip: "0.1", id: fixture.session, mode: "direct",
      members: [human, agent], createdAt: fixture.timestamp }]
  });
  const port = await listen(t, createRelay({ admission }));
  const rust = wsPeer(t, port, { token: agentToken, entity: agent, mode: "listen" });
  await rust.ready;
  const client = new XeipHttpSseClient({ baseUrl: "http://127.0.0.1:" + port, token: humanToken });
  assert.deepEqual(await client.send(fixture), { accepted: true, delivered: 1 });
  const delivered = await rust.waitFor(() => rust.events.find(event => event.type === "message"), "admission delivery");
  assert.deepEqual(delivered.message, fixture);

  // A valid credential cannot subscribe as the other entity.
  const spoof = wsPeer(t, port, { token: humanToken, entity: agent, mode: "listen" });
  await assert.rejects(spoof.ready, /before readiness/);
  const spoofResult = await spoof.done;
  assert.equal(spoofResult.code, 1);
  assert.match(spoofResult.error, /403|forbidden/i);
});

test("Rust WebSocket peer rejects unauthenticated and wrong-token upgrades", { timeout: 15000 }, async t => {
  const port = await listen(t, createRelay({ token }));
  for (const [name, peerToken] of [["unauthenticated", ""], ["wrong token", "wrong-token-with-enough-length"]]) {
    await t.test(name, async t => {
      const rust = wsPeer(t, port, { token: peerToken, entity: agent, mode: "listen" });
      await assert.rejects(rust.ready, /before readiness/);
      const result = await rust.done;
      assert.equal(result.code, 1);
      assert.match(result.error, /401/);
    });
  }
});

test("Rust WebSocket subscriber resumes with after and reports a gap on eviction", { timeout: 20000 }, async t => {
  const port = await listen(t, createRelay({ token, delivery: { maxPerSession: 1 } }));
  const client = new XeipHttpSseClient({ baseUrl: "http://127.0.0.1:" + port, token });
  const first = await client.send(fixture);
  const second = await client.send({ ...fixture, id: fixture.id + "-second" });
  assert.equal(first.seq, 1);
  assert.equal(second.seq, 2);

  const rust = wsPeer(t, port, { entity: agent, mode: "listen", after: 0 });
  await rust.ready;
  const gap = await rust.waitFor(() => rust.events.find(event => event.type === "gap"), "gap control");
  assert.deepEqual(gap, { type: "gap", session: fixture.session, from: 2 });
  const replayed = await rust.waitFor(() => rust.events.find(event => event.type === "message"), "replayed message");
  assert.equal(replayed.seq, 2);
  assert.deepEqual(replayed.message, { ...fixture, id: fixture.id + "-second" });
});

test("Rust WebSocket peer rejects a misrouted upgrade path", { timeout: 15000 }, async t => {
  const port = await listen(t, createRelay({ token }));
  const rust = wsPeer(t, port, { entity: agent, mode: "listen", path: "/nope" });
  await assert.rejects(rust.ready, /before readiness/);
  const result = await rust.done;
  assert.equal(result.code, 1);
  assert.match(result.error, /404/);
});
