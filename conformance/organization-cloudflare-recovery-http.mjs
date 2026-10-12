import {
  WireDeadline,
  readJson,
} from "../services/organization/cloudflare/recovery-wire.mjs";
import { test, before, after } from "node:test";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { createRecoveryClient } from "../services/organization/cloudflare/recovery-client.mjs";
import { createRecoveryHandler } from "../services/organization/cloudflare/recovery-http.mjs";
import {
  genesis,
  recoveryOptions,
  sealEntry,
} from "../services/organization/cloudflare/recovery-record.mjs";
const config = {
  url: "https://journal.example/v1/recovery",
  token: "a1".repeat(32),
  options: {
    organization: "recovery-http",
    stream: "56f243dc-5048-4d1d-8a63-b753ed79844c",
    timeoutMs: 5000,
  },
};
const deadlineConfig = {
  ...config,
  options: { ...config.options, timeoutMs: 100 },
};
const o = recoveryOptions(config.options);
const head = {
  organization: o.organization,
  stream: o.stream,
  sequence: 0,
  checksum: genesis(o),
};
const value = (extra = {}) => ({
  expected: head,
  id: randomUUID(),
  bytes: 1,
  payloadDigest: createHash("sha256").update("a").digest("hex"),
  chunks: ["YQ=="],
  ...extra,
});
const receipt = (v) =>
  sealEntry({
    schema: "xeip.recovery-entry/1",
    organization: o.organization,
    stream: o.stream,
    sequence: v.expected.sequence + 1,
    id: v.id,
    previous: v.expected.checksum,
    bytes: v.bytes,
    payloadDigest: v.payloadDigest,
    parts: v.chunks.length,
    totalBytes: v.bytes,
  });
const response = (v, init = {}) =>
  new Response(JSON.stringify(v), {
    headers: { "content-type": "application/json" },
    ...init,
  });
const envelope = (operation = "head", args = {}) => ({
  schema: "xeip.recovery-http/1",
  organization: o.organization,
  stream: o.stream,
  operation,
  args,
});
const request = (body = envelope(), init = {}) =>
  new Request(config.url, {
    method: "POST",
    headers: {
      authorization: "Bearer " + config.token,
      "content-type": "application/json",
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
    ...init,
  });
test("recovery HTTPS authenticates exact scoped append/read with manual redirects and no cache", async () => {
  let seen, stored;
  const handler = createRecoveryHandler({
    ...config,
    journal: {
      head: () => head,
      append: async (v) => (stored = receipt(v)),
      entry: () => stored,
      part: () => ({ entry: stored, part: 0, data: "YQ==" }),
    },
  });
  const client = createRecoveryClient(config, async (url, init) => {
    seen = { url, ...init };
    return handler(new Request(url, init));
  });
  assert.deepEqual(await client.head(), head);
  const v = value(),
    result = await client.append(v);
  assert.deepEqual(result, receipt(v));
  assert.deepEqual(await client.entry(1), result);
  assert.deepEqual(await client.part(1, 0), {
    entry: result,
    part: 0,
    data: "YQ==",
  });
  assert.equal(seen.url, config.url);
  assert.equal(seen.redirect, "manual");
  assert.equal(seen.cache, "no-store");
  assert.equal(seen.credentials, "omit");
  assert.equal(seen.headers.authorization, "Bearer " + config.token);
});
test("recovery accepts decoded chunked responses while rejecting ambiguous or unsupported framing", async () => {
  for (const coding of ["chunked", "Chunked"]) {
    const client = createRecoveryClient(config, async () =>
      response(head, {
        headers: {
          "content-type": "application/json",
          "transfer-encoding": coding,
        },
      }),
    );
    assert.deepEqual(await client.head(), head);
  }
  for (const headers of [
    {
      "transfer-encoding": "chunked",
      "content-length": String(JSON.stringify(head).length),
    },
    { "transfer-encoding": "gzip, chunked" },
    { "transfer-encoding": "chunked, chunked" },
    { "transfer-encoding": "identity" },
  ]) {
    const client = createRecoveryClient(config, async () =>
      response(head, {
        headers: { "content-type": "application/json", ...headers },
      }),
    );
    await assert.rejects(client.head(), (e) => e.name === "StoreUnavailable");
  }
});
const journal = (extra = {}) => ({
  head: () => head,
  entry: () => {
    throw Error("secret");
  },
  part: () => {
    throw Error("secret");
  },
  append: async (v) => receipt(v),
  ...extra,
});
const unavailable = (error) =>
  error.name === "StoreUnavailable" &&
  error.message === "action store unavailable";
test("recovery transport configuration rejects unsafe endpoints, secret formats and accessors", () => {
  for (const c of [
    null,
    {},
    { ...config, extra: 1 },
    ...[
      "http://journal.example/x",
      "https://a:b@journal.example/x",
      "https://journal.example/x?",
      "https://journal.example/x#",
      "https://JOURNAL.example/x",
    ].map((url) => ({ ...config, url })),
    ...["a", "A".repeat(64), "z".repeat(64), "a".repeat(63)].map((token) => ({
      ...config,
      token,
    })),
    { ...config, options: { ...o, timeoutMs: 99 } },
  ])
    assert.throws(() => createRecoveryClient(c));
  let reads = 0;
  assert.throws(() =>
    createRecoveryClient({
      ...config,
      get token() {
        reads++;
        return config.token;
      },
    }),
  );
  assert.equal(reads, 0);
});
test("recovery authorization happens before body reads and journal access", async () => {
  let reads = 0,
    calls = 0;
  const h = createRecoveryHandler({
    ...config,
    journal: journal({
      head: () => {
        calls++;
        return head;
      },
    }),
  });
  for (const authorization of [
    "",
    "Bearer " + "b".repeat(64),
    "Basic " + config.token,
  ]) {
    const r = new Request(config.url, {
      method: "POST",
      headers: { authorization },
      body: new ReadableStream(
        {
          pull() {
            reads++;
          },
        },
        { highWaterMark: 0 },
      ),
      duplex: "half",
    });
    assert.equal((await h(r)).status, 401);
  }
  assert.equal(reads, 0);
  assert.equal(calls, 0);
});
test("recovery handler rejects other origins, browser credentials and management commands without mutation", async () => {
  let calls = 0;
  const h = createRecoveryHandler({
    ...config,
    journal: journal({
      head: () => {
        calls++;
        return head;
      },
    }),
  });
  for (const headers of [
    { origin: "https://browser.example" },
    { cookie: "secret" },
    { host: "other.example" },
  ]) {
    assert.equal(
      (
        await h(
          request(envelope(), {
            headers: {
              authorization: "Bearer " + config.token,
              "content-type": "application/json",
              ...headers,
            },
          }),
        )
      ).status,
      400,
    );
  }
  for (const operation of [
    "initialize",
    "open",
    "close",
    "sql",
    "reset",
    "delete",
  ])
    assert.equal((await h(request(envelope(operation)))).status, 400);
  for (const v of [
    { ...envelope(), stream: randomUUID() },
    { ...envelope(), organization: "wrong" },
    { ...envelope(), extra: true },
    envelope("head", { extra: 1 }),
    envelope("entry", { sequence: 0 }),
    envelope("part", { sequence: 1, part: 64 }),
  ])
    assert.equal((await h(request(v))).status, 400);
  assert.equal(calls, 0);
});
for (const [label, body, headers] of [
  [
    "duplicate keys",
    '{"schema":"xeip.recovery-http/1","schema":"xeip.recovery-http/1"}',
  ],
  ["BOM", "\ufeff{}"],
  ["invalid UTF8", new Uint8Array([0xff])],
  ["deep nesting", "[".repeat(17) + "0" + "]".repeat(17)],
  [
    "declared oversized",
    "{}",
    { "content-length": String(24 * 1024 * 1024 + 1) },
  ],
  ["length mismatch", "{}", { "content-length": "1" }],
  ["ambiguous length", "{}", { "content-length": "02" }],
  ["encoding", "{}", { "content-encoding": "gzip" }],
  ["media type", "{}", { "content-type": "text/plain" }],
  ["transfer encoding", "{}", { "transfer-encoding": "chunked" }],
])
  test("recovery handler rejects " + label, async () => {
    let calls = 0;
    const h = createRecoveryHandler({
      ...config,
      journal: journal({
        head: () => {
          calls++;
          return head;
        },
      }),
    });
    const r = new Request(config.url, {
      method: "POST",
      body,
      headers: {
        authorization: "Bearer " + config.token,
        "content-type": "application/json",
        ...headers,
      },
    });
    const res = await h(r);
    assert.equal(res.status, 400);
    assert.equal(calls, 0);
    assert.deepEqual(await res.json(), { error: "invalid_request" });
    assert.equal(res.headers.get("cache-control"), "no-store");
  });
test("recovery clients reject failure statuses, redirects and malformed success without retries", async () => {
  for (const [body, init] of [
    [head, { status: 302, headers: { location: "https://evil.example" } }],
    ...[201, 206, 400, 401, 409, 429, 503].map((status) => [head, { status }]),
    [head, { headers: { "content-type": "text/plain" } }],
    [
      head,
      {
        headers: {
          "content-type": "application/json",
          "content-encoding": "gzip",
        },
      },
    ],
    [
      head,
      {
        headers: { "content-type": "application/json", "content-length": "1" },
      },
    ],
    [{ ...head, checksum: "0".repeat(64) }, {}],
    [{ ...head, stream: randomUUID() }, {}],
    [{ ...head, extra: 1 }, {}],
  ]) {
    let calls = 0;
    const c = createRecoveryClient(config, async () => {
      calls++;
      return response(body, init);
    });
    await assert.rejects(c.head(), unavailable);
    assert.equal(calls, 1);
  }
});
test("recovery client binds entry cursor and append receipt to exact request", async () => {
  const v = value(),
    e = receipt(v);
  for (const change of [
    { sequence: 2 },
    { id: randomUUID() },
    { previous: "0".repeat(64) },
    { payloadDigest: "0".repeat(64) },
    { bytes: 2, totalBytes: 2 },
  ]) {
    const { checksum, ...rest } = e;
    const c = createRecoveryClient(config, async () =>
      response(sealEntry({ ...rest, ...change })),
    );
    await assert.rejects(c.append(v), unavailable);
  }
  await assert.rejects(
    createRecoveryClient(config, async () => response(e)).entry(2),
    unavailable,
  );
  for (const p of [
    { entry: e, part: 1, data: "YQ==" },
    { entry: e, part: 0, data: "YR==" },
  ])
    await assert.rejects(
      createRecoveryClient(config, async () => response(p)).part(1, 0),
      unavailable,
    );
});
test("recovery server never acknowledges invalid journal returns or leaks thrown errors", async () => {
  for (const fn of [
    () => {
      throw TypeError(config.token);
    },
    () => ({ ...head, checksum: "0".repeat(64) }),
  ]) {
    const h = createRecoveryHandler({
      ...config,
      journal: journal({ head: fn }),
    });
    const r = await h(request());
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: "unavailable" });
  }
});
test("recovery client timeout does not retry a hung fetch and cancels late responses", async () => {
  let resolve,
    calls = 0,
    canceled = false;
  const c = createRecoveryClient(deadlineConfig, () => {
    calls++;
    return new Promise((r) => {
      resolve = r;
    });
  });
  await assert.rejects(c.head(), unavailable);
  await assert.rejects(c.head(), unavailable);
  assert.equal(calls, 1);
  resolve(
    new Response(
      new ReadableStream({
        cancel() {
          canceled = true;
        },
      }),
    ),
  );
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(canceled, true);
});
test("recovery body timeout and aborted requests cannot invoke a late journal operation", async () => {
  let calls = 0;
  const h = createRecoveryHandler({
    ...deadlineConfig,
    journal: journal({
      head: () => {
        calls++;
        return head;
      },
    }),
  });
  for (const abort of [false, true]) {
    let canceled = false;
    const controller = new AbortController();
    const r = new Request(config.url, {
      method: "POST",
      headers: {
        authorization: "Bearer " + config.token,
        "content-type": "application/json",
      },
      body: new ReadableStream({
        cancel() {
          canceled = true;
        },
      }),
      signal: controller.signal,
      duplex: "half",
    });
    if (abort) controller.abort();
    assert.equal((await h(r)).status, 503);
    assert.equal(canceled, true);
  }
  assert.equal(calls, 0);
});
test("recovery operation timeout holds admission until late completion without a late acknowledgement", async () => {
  let resolve,
    calls = 0;
  const h = createRecoveryHandler({
    ...deadlineConfig,
    journal: journal({
      head: () => {
        calls++;
        return new Promise((r) => {
          resolve = r;
        });
      },
    }),
  });
  const r = await h(request());
  assert.equal(r.status, 503);
  assert.equal((await h(request())).status, 429);
  assert.equal(calls, 1);
  resolve(head);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal((await h(request(envelope("initialize")))).status, 400);
});
let runtime;
before(async () => {
  runtime = await harness({
    entryPoint: new URL(
      "./organization-cloudflare-recovery-http-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "RecoveryHttpClientFixture",
    durableObjects: {
      JOURNAL: { className: "RecoveryHttpJournalFixture", useSQLite: true },
      ACTION: { className: "RecoveryHttpActionFixture", useSQLite: true },
    },
  });
});
after(async () => {
  await runtime?.close();
});
const nativeOptions = { ...o, timeoutMs: 10000 };
async function setupNative(options = nativeOptions, binding = "LIFECYCLE") {
  const f = await runtime.fixture(undefined, binding),
    j = await runtime.fixture(f.name, "JOURNAL");
  assert.equal(
    (await j.send({ operation: "initialize", options })).status,
    200,
  );
  assert.equal(
    (await j.send({ operation: "configureHttp", options })).status,
    200,
  );
  assert.equal(
    (
      await f.send({
        operation: "configure",
        name: f.name,
        options,
        initialize: true,
      })
    ).status,
    200,
  );
  return { f, j, options };
}
test("native authenticated recovery persists multipart data and reopens after runtime restart", async () => {
  let { f, j } = await setupNative();
  const first = await f.send({ operation: "append", bytes: 700000 });
  assert.equal(first.status, 200);
  assert.equal(first.body.parts, 3);
  await runtime.restart();
  f = await runtime.fixture(f.name);
  j = await runtime.fixture(j.name, "JOURNAL");
  assert.equal(
    (await j.send({ operation: "open", options: nativeOptions })).status,
    200,
  );
  await j.send({ operation: "configureHttp", options: nativeOptions });
  await f.send({
    operation: "configure",
    name: f.name,
    options: nativeOptions,
  });
  assert.deepEqual(
    (await f.send({ operation: "entry", sequence: 1 })).body,
    first.body,
  );
  const data = [];
  for (let part = 0; part < 3; part++)
    data.push(
      Buffer.from(
        (await f.send({ operation: "part", sequence: 1, part })).body.data,
        "base64",
      ),
    );
  assert.equal(Buffer.concat(data).length, 700000);
  assert.equal(
    createHash("sha256").update(Buffer.concat(data)).digest("hex"),
    first.body.payloadDigest,
  );
});
test("native authenticated recovery transports the full16 MiB journal bound", async () => {
  const { f } = await setupNative();
  const r = await f.send({ operation: "append", bytes: 16777216 });
  assert.equal(r.status, 200);
  assert.equal(r.body.parts, 64);
  assert.equal(r.body.bytes, 16777216);
  assert.deepEqual(
    (await f.send({ operation: "entry", sequence: 1 })).body,
    r.body,
  );
  assert.equal(
    Buffer.from(
      (await f.send({ operation: "part", sequence: 1, part: 63 })).body.data,
      "base64",
    ).length,
    262144,
  );
});
test("native recovery transport waits for journal sync before issuing a receipt", async () => {
  const { f, j } = await setupNative();
  await j.send({ operation: "controls", control: { holdSync: 2 } });
  let completed = false;
  const pending = f.send({ operation: "append" }).then((r) => {
    completed = true;
    return r;
  });
  try {
    for (let i = 0; i < 200; i++) {
      if (
        (await j.send({ operation: "controls", control: {} })).body.syncs === 2
      )
        break;
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.equal(
      (await j.send({ operation: "controls", control: {} })).body.syncs,
      2,
    );
    assert.equal(completed, false);
    assert.equal((await f.send({ operation: "head" })).status, 503);
  } finally {
    await j.send({ operation: "controls", control: { holdSync: 0 } });
  }
  assert.equal((await pending).status, 200);
});
test("native action receipts use HTTP recovery and reconcile a lost response without replay", async () => {
  const options = { ...nativeOptions, organization: "fixture-organization" },
    { f, j } = await setupNative(options, "ACTION");
  await f.send({ operation: "lostReceipt", value: true });
  const proposal = {
    operation: "propose",
    principal: "agent",
    request: {
      id: "one",
      session: "operations",
      target: "internal",
      tool: "lookup",
      arguments: { query: "fixture" },
      expiresAt: Math.floor(Date.now() / 1000) + 240,
    },
  };
  assert.equal((await f.send(proposal)).body.error, "StoreUnavailable");
  assert.equal((await j.send({ operation: "head" })).body.sequence, 1);
  await f.send({ operation: "lostReceipt", value: false });
  assert.equal(
    (await f.send({ operation: "configure", name: f.name, options })).status,
    200,
  );
  const accepted = await f.send(proposal);
  assert.equal(accepted.status, 200);
  assert.equal((await j.send({ operation: "head" })).body.sequence, 1);
  const p = accepted.body.proposal,
    target = { session: p.action.session, id: p.action.id, digest: p.digest };
  assert.equal(
    (
      await f.send({
        operation: "decide",
        principal: "human",
        decision: "approve",
        ...target,
      })
    ).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "execute", principal: "agent", ...target }))
      .status,
    200,
  );
  assert.equal((await j.send({ operation: "head" })).body.sequence, 4);
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
  assert.equal(
    (await f.send({ operation: "configure", name: f.name, options })).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "execute", principal: "agent", ...target })).body
      .error,
    "StoreConflict",
  );
  assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
});
test("native wrong recovery credentials cannot read or append the journal", async () => {
  const { f, j } = await setupNative();
  await f.send({
    operation: "configure",
    name: f.name,
    options: nativeOptions,
    token: "b2".repeat(32),
  });
  assert.equal((await f.send({ operation: "append" })).status, 503);
  assert.equal((await j.send({ operation: "head" })).body.sequence, 0);
});
test("recovery stream bounds apply without content length and cancel readers", async () => {
  let calls = 0,
    canceled = false;
  const h = createRecoveryHandler({
    ...config,
    journal: journal({
      head: () => {
        calls++;
        return head;
      },
    }),
  });
  const body = new ReadableStream({
    start(c) {
      c.enqueue(new Uint8Array(24 * 1024 * 1024 + 1));
    },
    cancel() {
      canceled = true;
    },
  });
  const r = await h(
    new Request(config.url, {
      method: "POST",
      headers: {
        authorization: "Bearer " + config.token,
        "content-type": "application/json",
      },
      body,
      duplex: "half",
    }),
  );
  assert.equal(r.status, 400);
  assert.equal(canceled, true);
  assert.equal(calls, 0);
  canceled = false;
  const c = createRecoveryClient(
    config,
    async () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(new Uint8Array(384 * 1024 + 1));
          },
          cancel() {
            canceled = true;
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  await assert.rejects(c.head(), unavailable);
  assert.equal(canceled, true);
});
test("recovery response body deadlines cancel readers and reject late bytes", async () => {
  let canceled = false;
  const c = createRecoveryClient(
    deadlineConfig,
    async () =>
      new Response(
        new ReadableStream({
          cancel() {
            canceled = true;
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  await assert.rejects(c.head(), unavailable);
  assert.equal(canceled, true);
});
test("recovery client rejects changed response URL or followed redirects", async () => {
  for (const extra of [
    { url: "https://evil.example/" },
    { redirected: true },
  ]) {
    const r = response(head);
    Object.defineProperties(
      r,
      Object.fromEntries(
        Object.entries(extra).map(([k, v]) => [k, { value: v }]),
      ),
    );
    await assert.rejects(
      createRecoveryClient(config, async () => r).head(),
      unavailable,
    );
  }
});
test("recovery synchronous work cannot acknowledge after its elapsed deadline", async () => {
  const h = createRecoveryHandler({
    ...deadlineConfig,
    journal: journal({
      head: () => {
        const until = performance.now() + 120;
        while (performance.now() < until) {}
        return head;
      },
    }),
  });
  assert.equal((await h(request())).status, 503);
});

// Review regressions use a real elapsed deadline and full-size payload validation.
{
  const config = {
    url: "https://journal.example/v1/recovery",
    token: "a1".repeat(32),
    options: {
      organization: "recovery-http",
      stream: "56f243dc-5048-4d1d-8a63-b753ed79844c",
      timeoutMs: 4000,
    },
  };
  const o = recoveryOptions(config.options),
    head = {
      organization: o.organization,
      stream: o.stream,
      sequence: 0,
      checksum: genesis(o),
    };
  const data = Buffer.alloc(16777216, 97),
    chunk = Buffer.alloc(262144, 97).toString("base64");
  const v = {
    expected: head,
    id: randomUUID(),
    bytes: data.length,
    payloadDigest: createHash("sha256").update(data).digest("hex"),
    chunks: Array(64).fill(chunk),
  };
  const entry = sealEntry({
    schema: "xeip.recovery-entry/1",
    organization: o.organization,
    stream: o.stream,
    sequence: 1,
    id: v.id,
    previous: head.checksum,
    payloadDigest: v.payloadDigest,
    bytes: v.bytes,
    parts: 64,
    totalBytes: v.bytes,
  });
  for (const side of ["client", "handler"])
    test(
      "recovery " +
        side +
        " rejects an append that crosses its deadline during receipt validation",
      async () => {
        let scope;
        const original = WireDeadline.prototype.wait;
        // Observe the real deadline; do not change the clock, timers, validation or result.
        WireDeadline.prototype.wait = function (...args) {
          scope = this;
          return original.apply(this, args);
        };
        const late = () => {
          while (performance.now() < scope.expires - 20) {}
          return entry;
        };
        try {
          if (side === "client") {
            const client = createRecoveryClient(config, async () =>
              Response.json(late()),
            );
            await assert.rejects(
              client.append(v),
              (e) => e.name === "StoreUnavailable",
            );
          } else {
            const handler = createRecoveryHandler({
              ...config,
              journal: {
                head: () => head,
                entry: () => entry,
                part: () => null,
                append: async () => late(),
              },
            });
            const r = await handler(
              new Request(config.url, {
                method: "POST",
                headers: {
                  authorization: "Bearer " + config.token,
                  "content-type": "application/json",
                },
                body: JSON.stringify({
                  schema: "xeip.recovery-http/1",
                  organization: o.organization,
                  stream: o.stream,
                  operation: "append",
                  args: v,
                }),
              }),
            );
            assert.equal(r.status, 503);
          }
        } finally {
          WireDeadline.prototype.wait = original;
        }
      },
    );
  test("malformed recovery endpoint configuration cannot expose its input", () => {
    try {
      createRecoveryClient({ ...config, url: "secret endpoint with password" });
      assert.fail("must reject");
    } catch (error) {
      assert.equal(error.message, "invalid recovery transport configuration");
      assert.equal(Object.hasOwn(error, "input"), false);
      assert.equal(Object.hasOwn(error, "cause"), false);
    }
  });
}

// Model the documented deployed-Worker clock behavior, retaining real timers.
for (const side of ["client", "handler"])
  test(
    "recovery " +
      side +
      " honors deadline when CPU clock readings remain frozen until I/O",
    async () => {
      const cfg = {
        url: "https://journal.example/v1/recovery",
        token: "a1".repeat(32),
        options: {
          organization: "clock",
          stream: "56f243dc-5048-4d1d-8a63-b753ed79844c",
          timeoutMs: 100,
        },
      };
      const opts = recoveryOptions(cfg.options),
        head = {
          organization: opts.organization,
          stream: opts.stream,
          sequence: 0,
          checksum: genesis(opts),
        };
      const descriptor = Object.getOwnPropertyDescriptor(performance, "now");
      Object.defineProperty(performance, "now", {
        configurable: true,
        value: () => 0,
      });
      const cpu = () => {
        const until = process.hrtime.bigint() + 150000000n;
        while (process.hrtime.bigint() < until) {}
        return head;
      };
      try {
        if (side === "client")
          await assert.rejects(
            createRecoveryClient(cfg, async () => Response.json(cpu())).head(),
            (e) => e.name === "StoreUnavailable",
          );
        else {
          const h = createRecoveryHandler({
            ...cfg,
            journal: {
              head: cpu,
              entry: () => null,
              part: () => null,
              append: async () => null,
            },
          });
          const r = await h(
            new Request(cfg.url, {
              method: "POST",
              headers: {
                authorization: "Bearer " + cfg.token,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                schema: "xeip.recovery-http/1",
                organization: opts.organization,
                stream: opts.stream,
                operation: "head",
                args: {},
              }),
            }),
          );
          assert.equal(r.status, 503);
        }
      } finally {
        if (descriptor) Object.defineProperty(performance, "now", descriptor);
        else delete performance.now;
      }
    },
  );

// A depth check must ignore JSON string contents without ignoring real nesting.
test("recovery JSON depth accepts quoted syntax and rejects actual level17", async () => {
  const text =
    '\\"{}[]' +
    String.fromCharCode(92).repeat(5) +
    '"[{}]' +
    String.fromCharCode(92) +
    "u005b";
  const valid = "[".repeat(16) + JSON.stringify(text) + "]".repeat(16);
  const parsed = await readJson(
    new Response(valid, { headers: { "content-type": "application/json" } }),
    10000,
    new WireDeadline(),
  );
  let leaf = parsed;
  for (let i = 0; i < 16; i++) {
    assert.equal(leaf.length, 1);
    leaf = leaf[0];
  }
  assert.equal(leaf, text);
  for (const raw of [
    "[".repeat(17) + "0" + "]".repeat(17),
    "[".repeat(16) + '{"key":"value"}' + "]".repeat(16),
    '{"k":1,"\\u006b":2}',
    '"bad' + String.fromCharCode(92) + 'q"',
    '"unterminated' + String.fromCharCode(92),
    '"' + String.fromCharCode(1) + '"',
    '"' + String.fromCharCode(92) + 'ud800"',
  ])
    await assert.rejects(
      readJson(
        new Response(raw, { headers: { "content-type": "application/json" } }),
        10000,
        new WireDeadline(),
      ),
      TypeError,
    );
});

test("configured native HTTP journal reopens existing history after object recreation", async () => {
  const { f, j } = await setupNative();
  const first = await f.send({ operation: "append", bytes: 32 });
  assert.equal(first.status, 200);
  await runtime.restart();
  const reopened = await runtime.fixture(j.name, "JOURNAL");
  const forwarded = await reopened.send({
    operation: "forwardHttp",
    request: {
      url: config.url,
      method: "POST",
      headers: {
        authorization: "Bearer " + config.token,
        "content-type": "application/json",
      },
      body: JSON.stringify(envelope("head")),
    },
  });
  assert.equal(forwarded.status, 200);
  assert.equal(forwarded.body.status, 200);
  assert.equal(JSON.parse(forwarded.body.body).sequence, 1);
  assert.equal(JSON.parse(forwarded.body.body).checksum, first.body.checksum);
});
