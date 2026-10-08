// Real cross-language transport checks, separate from the dependency-free Node tests.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { createRelay } from "../services/relay/server.mjs";
import { LocalAdmission } from "../services/relay/admission.mjs";
import { XeipHttpSseClient } from "../sdks/typescript/dist/index.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const token = randomBytes(24).toString("hex");
const fixture = JSON.parse(readFileSync(new URL("fixtures/message.valid.json", import.meta.url), "utf8"));
let executable;
before(async () => {
  const run = promisify(execFile);
  await run("cargo", ["build", "--locked", "-p", "xeip-core", "--example", "local_relay_peer"], { cwd: root, timeout: 120000 });
  const { stdout } = await run("cargo", ["metadata", "--no-deps", "--format-version", "1", "--locked"], { cwd: root });
  executable = join(JSON.parse(stdout).target_directory, "debug", "examples", "local_relay_peer" + (process.platform === "win32" ? ".exe" : ""));
});

async function listen(t, server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return server.address().port;
}

function peer(t, port, peerToken = token) {
  const child = spawn(executable, [], {
    cwd: root, env: { ...process.env, XEIP_PORT: String(port), XEIP_DEV_TOKEN: peerToken },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "", error = "";
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  child.stdout.on("data", chunk => {
    output += chunk;
    if (output.includes('\n')) {
      try {
        if (JSON.parse(output.split('\n')[0]).type === "ready") resolveReady();
      } catch (cause) { rejectReady(cause); }
    }
  });
  child.stderr.on("data", chunk => { error = (error + chunk).slice(-8192); });
  const done = new Promise((resolve, reject) => {
    child.once("error", cause => { rejectReady(cause); reject(cause); });
    child.once("close", (code, signal) => {
      rejectReady(new Error("Rust peer exited before readiness: " + error));
      resolve({ code, signal, error });
    });
  });
  const watchdog = setTimeout(() => {
    rejectReady(new Error("Rust peer readiness timed out"));
    child.kill();
  }, 10000);
  ready.then(() => clearTimeout(watchdog), () => clearTimeout(watchdog));
  t.after(async () => { clearTimeout(watchdog); child.kill(); await done; });
  return { ready, done };
}

for (const mode of ["shared", "admission", "replay"]) {
test("TypeScript and Rust exchange public envelopes in both directions (" + mode + ")", { timeout: 20000 }, async t => {
  const humanToken = mode === "shared" ? token : randomBytes(32).toString("base64url");
  const agentToken = mode === "shared" ? token : randomBytes(32).toString("base64url");
  const options = mode === "shared" ? { token } : { admission: new LocalAdmission({
    credentials: [{ entity: fixture.sender, token: humanToken }, { entity: fixture.recipient, token: agentToken }],
    sessions: [{ xeip: "0.1", id: fixture.session, mode: "direct",
      members: [fixture.sender, fixture.recipient], createdAt: fixture.timestamp }]
  }) };
  if (mode === "replay") options.replay = {};
  const port = await listen(t, createRelay(options));
  // Observe HTTP subscription readiness without sending a probe message.
  let resolveSubscribed;
  const subscribed = new Promise(resolve => { resolveSubscribed = resolve; });
  const client = new XeipHttpSseClient({ baseUrl: "http://127.0.0.1:" + port, token: humanToken,
    fetchImpl: async (...args) => {
      const response = await fetch(...args);
      if (new URL(args[0]).pathname === "/events") resolveSubscribed();
      return response;
    }
  });
  const abort = new AbortController();
  const replies = client.events(fixture.session, fixture.sender, abort.signal);
  let pending = replies.next();
  pending.catch(() => {}); // Cleanup may abort a pending read after an earlier failure.
  t.after(async () => { abort.abort(); await pending.catch(() => {}); await replies.return(); });
  await subscribed;
  const rust = peer(t, port, agentToken);
  await rust.ready;
  if (mode !== "shared") {
    await assert.rejects(client.send({ ...fixture, sender: fixture.recipient }), /403/);
    await assert.rejects(client.send({ ...fixture, session: "urn:xeip:session:forbidden" }), /403/);
  }
  const messages = [fixture, { ...fixture,
    id: "urn:xeip:message:unicode-command", kind: "command",
    body: { contentType: "application/json", data: { text: "Hello 🐈\nBonjour", nested: [null, true, 42, { key: "é" }] } },
    extensions: { "example.org/trace": { labels: ["camera", "🐈"] } }
  }];
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i];
    assert.deepEqual(await client.send(message), { accepted: true, delivered: 1,
      ...(mode === "replay" ? { duplicate: false } : {}) });
    const reply = await Promise.race([pending, rust.done.then(result => {
      throw new Error("Rust peer exited during exchange: " + result.error);
    })]);
    assert.equal(reply.done, false);
    assert.deepEqual(reply.value, { ...message,
      id: message.id + "-reply", sender: message.recipient, recipient: message.sender, replyTo: message.id
    });
    if (mode === "replay") {
      assert.deepEqual(await client.send(message), { accepted: true, delivered: 0, duplicate: true });
      await assert.rejects(client.send({ ...message, body: { ...message.body, data: "changed retry" } }), /409/);
    }
    if (i + 1 < messages.length) { pending = replies.next(); pending.catch(() => {}); }
  }
  await replies.return();
});
}

test("Rust peer rejects unauthorized subscriptions before readiness", { timeout: 15000 }, async t => {
  const port = await listen(t, createRelay({ token }));
  const rust = peer(t, port, "wrong-token-with-enough-length");
  await assert.rejects(rust.ready, /before readiness/);
  assert.equal((await rust.done).code, 1);
});

test("Rust peer cannot select another entity using a valid admission credential", { timeout: 15000 }, async t => {
  const humanToken = randomBytes(32).toString("base64url");
  const admission = new LocalAdmission({ credentials: [
    { entity: fixture.sender, token: humanToken },
    { entity: fixture.recipient, token: randomBytes(32).toString("base64url") }
  ], sessions: [{ xeip: "0.1", id: fixture.session, mode: "direct",
    members: [fixture.sender, fixture.recipient], createdAt: fixture.timestamp }] });
  const port = await listen(t, createRelay({ admission }));
  const rust = peer(t, port, humanToken);
  await assert.rejects(rust.ready, /before readiness/);
  const result = await rust.done;
  assert.equal(result.code, 1);
  assert.match(result.error, /403/);
});

test("Rust peer rejects non-SSE HTTP responses before readiness", { timeout: 15000 }, async t => {
  const port = await listen(t, createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("{}");
  }));
  const rust = peer(t, port);
  await assert.rejects(rust.ready, /before readiness/);
  const result = await rust.done;
  assert.equal(result.code, 1);
  assert.match(result.error, /text\/event-stream/);
});

test("Rust peer rejects invalid and misrouted incoming envelopes", { timeout: 15000 }, async t => {
  for (const [name, patch] of [["unsupported version", { xeip: "0.2" }],
    ["different session", { session: "urn:xeip:session:other" }]]) {
    await t.test(name, async t => {
      let posts = 0;
      const port = await listen(t, createServer((req, res) => {
        if (req.method === "POST") posts++;
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.end("event: xeip.message\ndata: " + JSON.stringify({ ...fixture, ...patch }) + "\n\n");
      }));
      const rust = peer(t, port);
      await rust.ready;
      assert.equal((await rust.done).code, 1);
      assert.equal(posts, 0);
    });
  }
});

test("Rust peer checks HTTP acceptance status and bounded response shape", { timeout: 15000 }, async t => {
  for (const [name, status, response] of [
    ["wrong HTTP status", 200, { accepted: true, delivered: 1 }],
    ["not accepted", 202, { accepted: false, delivered: 1 }],
    ["no subscriber write", 202, { accepted: true, delivered: 0 }],
    ["negative write count", 202, { accepted: true, delivered: -1 }],
    ["string write count", 202, { accepted: true, delivered: "1" }],
    ["unsafe integer write count", 202, { accepted: true, delivered: 9007199254740992 }],
    ["null duplicate flag", 202, { accepted: true, delivered: 1, duplicate: null }],
    ["string duplicate flag", 202, { accepted: true, delivered: 1, duplicate: "false" }],
    ["duplicate claiming stream writes", 202, { accepted: true, delivered: 1, duplicate: true }],
    ["oversized response", 202, { accepted: true, delivered: 1, padding: "x".repeat(4096) }],
  ]) {
    await t.test(name, async t => {
      let posted;
      const port = await listen(t, createServer(async (req, res) => {
        if (req.method === "GET") {
          res.writeHead(200, { "Content-Type": "text/event-stream" });
          res.write("event: xeip.message\ndata: " + JSON.stringify(fixture) + "\n\n");
        } else {
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          posted = { authorization: req.headers.authorization, body: JSON.parse(Buffer.concat(chunks)) };
          res.writeHead(status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(response));
        }
      }));
      const rust = peer(t, port);
      await rust.ready;
      const result = await rust.done;
      assert.equal(result.code, 1);
      assert.equal(posted.authorization, "Bearer " + token);
      assert.deepEqual(posted.body, { ...fixture, id: fixture.id + "-reply",
        sender: fixture.recipient, recipient: fixture.sender, replyTo: fixture.id });
      if (name === "oversized response") assert.match(result.error, /oversized/);
    });
  }
});

test("Rust peer does not follow subscription redirects", { timeout: 15000 }, async t => {
  const paths = [];
  const port = await listen(t, createServer((req, res) => {
    paths.push(new URL(req.url, "http://localhost").pathname);
    res.writeHead(302, { Location: "/trap" });
    res.end();
  }));
  const rust = peer(t, port);
  await assert.rejects(rust.ready, /before readiness/);
  assert.equal((await rust.done).code, 1);
  assert.deepEqual(paths, ["/events"]);
});
