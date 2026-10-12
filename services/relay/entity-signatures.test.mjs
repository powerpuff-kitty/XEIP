import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { randomBytes } from "node:crypto";
import {
  FrameParser,
  OPCODES,
  encodeFrame,
  websocketAccept,
} from "./websocket.mjs";
import { createRelay } from "./server.mjs";
import { LocalAdmission } from "./admission.mjs";
import { signStatusDocument } from "../../tools/identity-status.mjs";
const f = JSON.parse(
  fs.readFileSync(
    new URL(
      "../../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
const options = f.vectors[0].options,
  token = "e".repeat(43);
function config(t) {
  const dir = fs.mkdtempSync(join(tmpdir(), "xeip-entity-relay-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const entity = f.envelope.sender,
    session = f.envelope.session;
  return {
    admission: new LocalAdmission({
      credentials: [{ entity, token, kid: f.kid }],
      sessions: [
        {
          xeip: "0.1",
          id: session,
          mode: "group",
          members: [entity],
          createdAt: f.envelope.timestamp,
        },
      ],
    }),
    entitySignatures: {
      trustDir: join(dir, "trust"),
      maxAgeSeconds: 60,
      knownExtensions: ["app.action"],
    },
    keyDocuments: options.keyDocuments.map((document) => ({
      document,
      anchor: options.anchor,
    })),
    statusDocuments: [{ document: options.statusDocument }],
  };
}
async function start(configuration) {
  const server = createRelay(configuration);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}
async function close(server) {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
async function openSocket(server) {
  const key = randomBytes(16).toString("base64");
  return await new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port: server.address().port,
      path: "/ws",
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
        Authorization: "Bearer " + token,
      },
    });
    req.once("error", reject);
    req.once("response", (r) => {
      r.resume();
      reject(new Error("upgrade rejected"));
    });
    req.once("upgrade", (response, socket, head) => {
      assert.equal(
        response.headers["sec-websocket-accept"],
        websocketAccept(key),
      );
      if (head.length) socket.unshift(head);
      resolve(socket);
    });
    req.end();
  });
}
async function post(server, message, credential = token) {
  const r = await fetch(
    "http://127.0.0.1:" + server.address().port + "/messages",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + credential,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(5000),
    },
  );
  const body = await r.json();
  return { status: r.status, body };
}
test("entity profile accepts parent/device messages and refuses tampering, downgrade and stale trust", async (t) => {
  let now = options.nowSeconds * 1000;
  t.mock.method(Date, "now", () => now);
  const server = await start(config(t));
  t.after(() => close(server));
  assert.equal((await post(server, f.signed)).status, 202);
  const changed = structuredClone(f.signed);
  changed.extensions["app.action"].approved = false;
  assert.equal((await post(server, changed)).status, 422);
  assert.equal(
    (
      await post(
        server,
        f.vectors.find((v) => v.name === "legacy downgrade").envelope,
      )
    ).status,
    422,
  );
  now += 61000;
  assert.equal((await post(server, f.signed)).status, 403);
  const health = await (
    await fetch("http://127.0.0.1:" + server.address().port + "/health")
  ).json();
  assert.equal(health.signatureProfile, "xeip.entity-signed-envelopes/0.2");
  assert.equal(JSON.stringify(health).includes(f.kid), false);
});
test("entity profile rejects ambiguous configuration and requires local admission and checkpoint storage", (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t);
  assert.throws(() => createRelay({ ...c, signatures: {} }), /choose/);
  const { admission, ...rest } = c;
  assert.throws(() => createRelay({ ...rest, token }), /admission/);
  assert.throws(
    () => createRelay({ ...c, entitySignatures: { maxAgeSeconds: 60 } }),
    /trustDir/,
  );
});
test("relay restart refuses old status and releases the checkpoint after close or later initialization failure", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t);
  let server = await start(c);
  await close(server);
  const newer = signStatusDocument(
    { ...options.statusDocument, serial: 2, signatures: [] },
    {
      privateKey: Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
      kid: options.keyDocuments[0].genesis,
    },
  );
  server = await start({ ...c, statusDocuments: [{ document: newer }] });
  await close(server);
  assert.throws(() => createRelay(c), /rollback/);
  assert.equal(fs.existsSync(join(c.entitySignatures.trustDir, "LOCK")), false);
  server = await start({ ...c, statusDocuments: [{ document: newer }] });
  await close(server);
});

test("WebSocket applies the entity profile without falling back to legacy signatures", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const server = await start(config(t));
  t.after(() => close(server));
  const socket = await openSocket(server);
  const parser = new FrameParser({
    maxFrame: 128 * 1024,
    maxMessage: 128 * 1024,
    expectMask: false,
  });
  const queue = [];
  let pending;
  socket.on("data", (chunk) => {
    for (const event of parser.push(chunk)) {
      if (event.type === "message") {
        const value = JSON.parse(event.text);
        if (pending) {
          pending(value);
          pending = null;
        } else queue.push(value);
      }
    }
  });
  const next = () =>
    queue.length
      ? Promise.resolve(queue.shift())
      : new Promise((resolve, reject) => {
          const timer = setTimeout(
            () => reject(new Error("WebSocket response timeout")),
            5000,
          );
          pending = (value) => {
            clearTimeout(timer);
            resolve(value);
          };
        });
  const send = (message) =>
    socket.write(
      encodeFrame(
        OPCODES.text,
        Buffer.from(JSON.stringify({ type: "send", message })),
        true,
        randomBytes(4),
      ),
    );
  try {
    send(f.signed);
    assert.equal((await next()).type, "accepted");
    send(f.vectors.find((v) => v.name === "legacy downgrade").envelope);
    assert.equal((await next()).status, 422);
  } finally {
    socket.destroy();
  }
});

test("later relay policy failure releases the entity checkpoint lock", (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t);
  assert.throws(
    () => createRelay({ ...c, limits: { unknown: true } }),
    /invalid/,
  );
  assert.equal(fs.existsSync(join(c.entitySignatures.trustDir, "LOCK")), false);
});

test("restart requires a newer key chain to extend the previously accepted document", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const { signKeyDocument, keyDocumentChainDigest } = await import(
    "../../tools/key-document.mjs"
  );
  const c = config(t),
    genesis = options.keyDocuments[0];
  const signer = {
    privateKey: Buffer.from(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "hex",
    ),
    kid: genesis.genesis,
  };
  const next = (previous, devices) =>
    signKeyDocument(
      {
        ...previous,
        generation: previous.generation + 1,
        previous: keyDocumentChainDigest(previous),
        devices,
        signatures: [],
      },
      signer,
    );
  const accepted = next(genesis, []);
  const provision = (documents, serial) => ({
    ...c,
    keyDocuments: documents.map((document) => ({
      document,
      anchor: options.anchor,
    })),
    statusDocuments: [
      {
        document: signStatusDocument(
          { ...options.statusDocument, serial, signatures: [] },
          signer,
        ),
      },
    ],
  });
  const server = await start(provision([genesis, accepted], 2));
  await close(server);
  const divergent = next(genesis, genesis.devices);
  assert.throws(
    () =>
      createRelay(
        provision([genesis, divergent, next(divergent, genesis.devices)], 3),
      ),
    /fork|continuity/,
  );
  assert.equal(fs.existsSync(join(c.entitySignatures.trustDir, "LOCK")), false);
  const newer = await start(
    provision([genesis, accepted, next(accepted, [])], 3),
  );
  await close(newer);
});

test("entity mode rejects a different signing key", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t);
  const server = await start(c);
  t.after(() => close(server));
  const { signEntityEnvelope } = await import(
    "../../packages/identity/entity-envelope.mjs"
  );
  const rootSigned = signEntityEnvelope(f.envelope, {
    privateKey: Buffer.from(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "hex",
    ),
    kid: options.keyDocuments[0].genesis,
    criticalExtensions: ["app.action"],
  });
  assert.equal((await post(server, rootSigned)).status, 403);
});

test("live revocation closes SSE and denies reconnect and send", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t),
    server = await start(c);
  const abort = new AbortController();
  t.after(async () => {
    abort.abort();
    await close(server);
  });
  const url =
    "http://127.0.0.1:" +
    server.address().port +
    "/events?session=" +
    encodeURIComponent(f.envelope.session) +
    "&entity=" +
    encodeURIComponent(f.envelope.sender);
  const response = await fetch(url, {
    headers: { Authorization: "Bearer " + token },
    signal: abort.signal,
  });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  await reader.read();
  const ended = reader.read().then(
    (result) => result.done,
    () => true,
  );
  const revoked = signStatusDocument(
    {
      ...options.statusDocument,
      serial: 2,
      revoked: [{ kid: f.kid, generation: 1 }],
      signatures: [],
    },
    {
      privateKey: Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
      kid: options.keyDocuments[0].genesis,
    },
  );
  server.updateEntityTrust({
    keyDocuments: c.keyDocuments,
    statusDocuments: [{ document: revoked }],
  });
  const timer = setTimeout(() => abort.abort(), 3000);
  try {
    assert.equal(await ended, true);
    assert.equal(abort.signal.aborted, false);
  } finally {
    clearTimeout(timer);
  }
  const denied = await fetch(url, {
    headers: { Authorization: "Bearer " + token },
  });
  assert.equal(denied.status, 403);
  await denied.arrayBuffer();
  assert.equal((await post(server, f.signed)).status, 403);
});

test("entity mode rejects credentials without a key binding", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t);
  c.admission = new LocalAdmission({
    credentials: [{ entity: f.envelope.sender, token }],
    sessions: [],
  });
  const server = await start(c);
  t.after(() => close(server));
  assert.equal((await post(server, f.signed)).status, 403);
  await assert.rejects(openSocket(server), /upgrade rejected/);
});

test("expired trust closes an idle WebSocket without a subscription", async (t) => {
  let now = options.nowSeconds * 1000;
  t.mock.method(Date, "now", () => now);
  const server = await start(config(t));
  const socket = await openSocket(server);
  t.after(async () => {
    socket.destroy();
    await close(server);
  });
  const parser = new FrameParser({
    maxFrame: 128 * 1024,
    maxMessage: 128 * 1024,
    expectMask: false,
  });
  const closed = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("idle connection not revoked")),
      3500,
    );
    socket.on("data", (chunk) => {
      for (const event of parser.push(chunk))
        if (event.type === "close") {
          clearTimeout(timer);
          resolve(event.code);
        }
    });
  });
  now += 61000;
  assert.equal(await closed, 1008);
  await assert.rejects(openSocket(server), /upgrade rejected/);
});

test("expired trust closes an idle SSE stream and blocks retained history", async (t) => {
  let now = options.nowSeconds * 1000;
  t.mock.method(Date, "now", () => now);
  const server = await start({ ...config(t), delivery: {} });
  const abort = new AbortController();
  t.after(async () => {
    abort.abort();
    await close(server);
  });
  assert.equal((await post(server, f.signed)).status, 202);
  const url =
    "http://127.0.0.1:" +
    server.address().port +
    "/events?session=" +
    encodeURIComponent(f.envelope.session) +
    "&entity=" +
    encodeURIComponent(f.envelope.sender);
  const response = await fetch(url, {
    headers: { Authorization: "Bearer " + token },
    signal: abort.signal,
  });
  const reader = response.body.getReader();
  await reader.read();
  now += 61000;
  const timer = setTimeout(() => abort.abort(), 3500);
  try {
    assert.equal(
      await reader.read().then(
        (result) => result.done,
        () => true,
      ),
      true,
    );
    assert.equal(abort.signal.aborted, false);
  } finally {
    clearTimeout(timer);
  }
  const denied = await fetch(url + "&after=0", {
    headers: { Authorization: "Bearer " + token },
  });
  assert.equal(denied.status, 403);
  await denied.arrayBuffer();
});

function refreshedStatus(
  serial,
  revoked = [],
  issuedAt = options.statusDocument.issuedAt,
) {
  return signStatusDocument(
    { ...options.statusDocument, serial, revoked, issuedAt, signatures: [] },
    {
      privateKey: Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
      kid: options.keyDocuments[0].genesis,
    },
  );
}
async function pausedPost(server, path, document, changeTrust) {
  const body = JSON.stringify(document);
  return await new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port: server.address().port,
      path,
      method: "POST",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json",
        Expect: "100-continue",
        "Content-Length": Buffer.byteLength(body),
      },
    });
    req.on("error", reject);
    req.setTimeout(5000, () => req.destroy(new Error("paused POST timed out")));
    req.on("response", (response) => {
      let text = "";
      response.on("data", (data) => {
        text += data;
      });
      response.on("end", () =>
        resolve({ status: response.statusCode, body: JSON.parse(text) }),
      );
    });
    req.on("continue", () => {
      req.write(body.slice(0, 4));
      try {
        changeTrust();
        req.end(body.slice(4));
      } catch (error) {
        req.destroy(error);
      }
    });
    req.flushHeaders();
  });
}
for (const target of ["messages", "receipts"])
  for (const transition of ["revocation", "expiry", "storage failure"]) {
    test(
      target + " rechecks trust after body read during " + transition,
      async (t) => {
        let now = options.nowSeconds * 1000;
        t.mock.method(Date, "now", () => now);
        const c = config(t),
          server = await start({ ...c, delivery: {}, receipts: {} });
        t.after(() => close(server));
        const initial = await post(server, f.signed);
        assert.equal(initial.status, 202);
        const seq = initial.body.seq;
        const { signEntityEnvelope } = await import(
          "../../packages/identity/entity-envelope.mjs"
        );
        const message = signEntityEnvelope(
          { ...f.envelope, id: "urn:test:after-trust-change" },
          {
            privateKey: Buffer.from(f.seed, "hex"),
            kid: f.kid,
            criticalExtensions: ["app.action"],
          },
        );
        const document =
          target === "messages"
            ? message
            : { session: f.envelope.session, seq };
        const denied = await pausedPost(server, "/" + target, document, () => {
          if (transition === "expiry") now += 61000;
          else if (transition === "revocation")
            server.updateEntityTrust({
              keyDocuments: c.keyDocuments,
              statusDocuments: [
                {
                  document: refreshedStatus(2, [{ kid: f.kid, generation: 1 }]),
                },
              ],
            });
          else {
            fs.mkdirSync(join(c.entitySignatures.trustDir, "trust.json.tmp"));
            assert.throws(() =>
              server.updateEntityTrust({
                keyDocuments: c.keyDocuments,
                statusDocuments: [{ document: refreshedStatus(2) }],
              }),
            );
          }
        });
        assert.equal(denied.status, 403);
        if (transition !== "storage failure") {
          server.updateEntityTrust({
            keyDocuments: c.keyDocuments,
            statusDocuments: [
              {
                document: refreshedStatus(
                  3,
                  [],
                  new Date(now).toISOString().replace(".000Z", "Z"),
                ),
              },
            ],
          });
          if (target === "messages")
            assert.equal((await post(server, message)).body.seq, seq + 1);
          else {
            const accepted = await pausedPost(
              server,
              "/receipts",
              document,
              () => {},
            );
            assert.equal(accepted.status, 202);
            assert.equal(accepted.body.duplicate, false);
          }
        }
      },
    );
  }

function socketEvents(socket, t) {
  const parser = new FrameParser({
    maxFrame: 128 * 1024,
    maxMessage: 128 * 1024,
    expectMask: false,
  });
  const queue = [];
  let pending;
  socket.on("data", (chunk) => {
    for (const event of parser.push(chunk)) {
      if (pending) {
        const resolve = pending;
        pending = undefined;
        resolve(event);
      } else queue.push(event);
    }
  });
  return () =>
    queue.length
      ? Promise.resolve(queue.shift())
      : new Promise((resolve, reject) => {
          const timer = setTimeout(
            () => reject(new Error("socket event timeout")),
            3000,
          );
          t.after(() => clearTimeout(timer));
          pending = (event) => {
            clearTimeout(timer);
            resolve(event);
          };
        });
}
test("invalid refresh preserves SSE and WebSockets; failed persistence closes them", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const c = config(t),
    server = await start(c),
    abort = new AbortController();
  const subscribed = await openSocket(server),
    idle = await openSocket(server);
  t.after(async () => {
    subscribed.destroy();
    idle.destroy();
    abort.abort();
    await close(server);
  });
  const nextSubscribed = socketEvents(subscribed, t),
    nextIdle = socketEvents(idle, t);
  subscribed.write(
    encodeFrame(
      OPCODES.text,
      Buffer.from(
        JSON.stringify({
          type: "subscribe",
          session: f.envelope.session,
          entity: f.envelope.sender,
        }),
      ),
      true,
      randomBytes(4),
    ),
  );
  assert.equal(JSON.parse((await nextSubscribed()).text).type, "subscribed");
  const url =
    "http://127.0.0.1:" +
    server.address().port +
    "/events?session=" +
    encodeURIComponent(f.envelope.session) +
    "&entity=" +
    encodeURIComponent(f.envelope.sender);
  const response = await fetch(url, {
    headers: { Authorization: "Bearer " + token },
    signal: abort.signal,
  });
  const reader = response.body.getReader();
  await reader.read();
  const invalid = refreshedStatus(2);
  invalid.signatures[0].sig = "A".repeat(86);
  assert.throws(
    () =>
      server.updateEntityTrust({
        keyDocuments: c.keyDocuments,
        statusDocuments: [{ document: invalid }],
      }),
    /trust/,
  );
  assert.equal((await post(server, f.signed)).status, 202);
  assert.equal(JSON.parse((await nextSubscribed()).text).type, "message");
  assert.match(
    new TextDecoder().decode((await reader.read()).value),
    /xeip.message/,
  );
  const ended = reader.read().then(
    (result) => result.done,
    () => true,
  );
  fs.mkdirSync(join(c.entitySignatures.trustDir, "trust.json.tmp"));
  assert.throws(() =>
    server.updateEntityTrust({
      keyDocuments: c.keyDocuments,
      statusDocuments: [{ document: refreshedStatus(2) }],
    }),
  );
  assert.equal((await nextSubscribed()).code, 1008);
  assert.equal((await nextIdle()).code, 1008);
  assert.equal(await ended, true);
  await assert.rejects(openSocket(server), /upgrade rejected/);
  const health = await (
    await fetch("http://127.0.0.1:" + server.address().port + "/health")
  ).json();
  assert.equal(health.entityTrust.state, "failed");
  assert.equal(health.status, "degraded");
});

test("removing a device closes its connection and explicit credential rotation enables an endorsed replacement", async (t) => {
  t.mock.method(Date, "now", () => options.nowSeconds * 1000);
  const { signKeyDocument, keyDocumentChainDigest } = await import(
    "../../tools/key-document.mjs"
  );
  const { signEntityEnvelope } = await import(
    "../../packages/identity/entity-envelope.mjs"
  );
  const c = config(t),
    server = await start(c),
    socket = await openSocket(server);
  t.after(async () => {
    socket.destroy();
    await close(server);
  });
  const next = socketEvents(socket, t),
    genesis = options.keyDocuments[0];
  const signer = {
    privateKey: Buffer.from(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "hex",
    ),
    kid: genesis.genesis,
  };
  const removed = signKeyDocument(
    {
      ...genesis,
      generation: 2,
      previous: keyDocumentChainDigest(genesis),
      devices: [],
      signatures: [],
    },
    signer,
  );
  server.updateEntityTrust({
    keyDocuments: [...c.keyDocuments, { document: removed }],
    statusDocuments: [{ document: refreshedStatus(2) }],
  });
  assert.equal((await next()).code, 1008);
  assert.equal((await post(server, f.signed)).status, 403);
  const replacementToken = "r".repeat(43);
  c.admission.rotateCredential(f.envelope.sender, replacementToken, {
    kid: genesis.genesis,
  });
  const signed = signEntityEnvelope(f.envelope, {
    ...signer,
    criticalExtensions: ["app.action"],
  });
  assert.equal((await post(server, signed)).status, 401);
  assert.equal((await post(server, f.signed, replacementToken)).status, 403);
  assert.equal((await post(server, signed, replacementToken)).status, 202);
});
