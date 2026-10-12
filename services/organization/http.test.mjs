import test from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { request as secureRequest } from "node:https";
import { readFileSync } from "node:fs";
import { createOrganizationServer } from "./http.mjs";
import { OperationError } from "./controller.mjs";

async function setup(t, options = {}) {
  const calls = [],
    state = { ready: true, failure: null };
  const controller = {
    handle: async (...args) => {
      calls.push(args);
      if (state.failure) throw state.failure;
      return { state: "pending" };
    },
  };
  const server = createOrganizationServer({
    controller,
    origin: "https://xeip.test",
    allowInsecureLoopback: true,
    ready: async () => state.ready,
    ...options,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const send = (
    body = "{}",
    headers = {},
    path = "/v1/actions",
    method = "POST",
  ) =>
    new Promise((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port: server.address().port,
          path,
          method,
          headers: {
            Host: "xeip.test",
            "Content-Type": "application/json",
            Authorization: "Bearer fixture",
            ...headers,
          },
        },
        (res) => {
          let text = "";
          res.on("data", (part) => (text += part));
          res.on("end", () =>
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: JSON.parse(text),
            }),
          );
        },
      );
      req.on("error", reject);
      req.end(body);
    });
  return { server, send, state, calls };
}
test("HTTP boundary requires explicit TLS or literal-loopback test mode", () => {
  assert.throws(
    () =>
      createOrganizationServer({
        controller: { handle: async () => ({}) },
        origin: "https://xeip.test",
        ready: async () => true,
      }),
    TypeError,
  );
});
test("console routes are opt-in, method restricted, and retain Host/Origin checks", async (t) => {
  const disabled = await setup(t);
  assert.equal(
    (await disabled.send("", {}, "/console/config", "GET")).status,
    404,
  );
  const f = await setup(t, {
    console: {
      asset: (path) =>
        path === "/console/config"
          ? {
              type: "application/json",
              body: Buffer.from('{"public":true}'),
              headers: { "Content-Security-Policy": "default-src 'none'" },
            }
          : undefined,
      profile: async () => ({ subject: "human" }),
    },
  });
  assert.deepEqual((await f.send("", {}, "/console/config", "GET")).body, {
    public: true,
  });
  assert.equal(
    (
      await f.send(
        "",
        { Origin: "https://evil.test" },
        "/console/config",
        "GET",
      )
    ).status,
    403,
  );
  assert.equal((await f.send("", {}, "/console/config", "POST")).status, 405);
  assert.equal(
    (await f.send("", {}, "/console/../configuration.mjs", "GET")).status,
    404,
  );
  assert.deepEqual((await f.send("", {}, "/v1/console/profile", "GET")).body, {
    subject: "human",
  });
  assert.equal(f.calls.length, 0);
});
test("timed-out profile retains its work slot until authentication actually settles", async (t) => {
  let finish;
  const f = await setup(t, {
    maxConcurrent: 1,
    operationTimeoutMs: 100,
    console: {
      asset: () => undefined,
      profile: () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    },
  });
  assert.equal(
    (await f.send("", {}, "/v1/console/profile", "GET")).status,
    504,
  );
  assert.equal((await f.send()).status, 429);
  finish({ subject: "human" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal((await f.send()).status, 200);
});
test("HTTP observations include only bounded operation/outcome fields and machine duration", async (t) => {
  const observations = [];
  const f = await setup(t, { onRequest: (value) => observations.push(value) });
  const body = JSON.stringify({
    body: { data: { operation: "execute", arguments: { password: "secret" } } },
  });
  await f.send(body, { Authorization: "Bearer private" });
  assert.equal(observations.length, 1);
  assert.equal(observations[0].operation, "execute");
  assert.equal(observations[0].route, "actions");
  assert.equal(observations[0].status, 200);
  assert.equal(observations[0].state, "pending");
  assert.equal(observations[0].elapsedMs >= 0, true);
  assert.equal(JSON.stringify(observations).includes("secret"), false);
  assert.equal(JSON.stringify(observations).includes("private"), false);
});
test("bounded JSON requests reach the controller and health distinguishes readiness", async (t) => {
  const f = await setup(t);
  const response = await f.send('{"hello":"world"}');
  assert.equal(response.status, 200);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(f.calls[0][0], "Bearer fixture");
  assert.equal(f.calls[0][1], '{"hello":"world"}');
  assert.ok(f.calls[0][2].signal instanceof AbortSignal);
  assert.equal((await f.send("", {}, "/live", "GET")).status, 200);
  f.state.ready = false;
  assert.equal((await f.send("", {}, "/ready", "GET")).status, 503);
  assert.equal((await f.send("", {}, "/live", "GET")).status, 200);
});
for (const [name, body, headers, path, method, status] of [
  ["host", "{}", { Host: "attacker.test" }, "/v1/actions", "POST", 403],
  [
    "origin",
    "{}",
    { Origin: "https://attacker.test" },
    "/v1/actions",
    "POST",
    403,
  ],
  [
    "content type",
    "{}",
    { "Content-Type": "text/plain" },
    "/v1/actions",
    "POST",
    415,
  ],
  [
    "compressed body",
    "{}",
    { "Content-Encoding": "gzip" },
    "/v1/actions",
    "POST",
    415,
  ],
  ["oversized body", "x".repeat(98305), {}, "/v1/actions", "POST", 413],
  ["invalid UTF-8", Buffer.from([0xc3, 0x28]), {}, "/v1/actions", "POST", 400],
  ["query selectors", "{}", {}, "/v1/actions?token=ignored", "POST", 404],
  ["wrong method", "", {}, "/v1/actions", "GET", 405],
])
  test("rejects " + name + " before controller work", async (t) => {
    const f = await setup(t);
    assert.equal((await f.send(body, headers, path, method)).status, status);
    assert.equal(f.calls.length, 0);
  });
test("maps safe errors without returning credential details", async (t) => {
  const f = await setup(t);
  for (const status of [400, 401, 403, 409, 503]) {
    f.state.failure = new OperationError(status, "safe_error");
    const response = await f.send();
    assert.equal(response.status, status);
    assert.deepEqual(response.body, { error: "safe_error" });
  }
  f.state.failure = new Error("private token detail");
  const response = await f.send();
  assert.equal(response.status, 503);
  assert.equal(JSON.stringify(response.body).includes("private"), false);
});
test("limits concurrent work and cancels requests that exceed the operation deadline", async (t) => {
  let entered, release;
  const inside = new Promise((resolve) => (entered = resolve)),
    held = new Promise((resolve) => (release = resolve));
  let signal;
  const f = await setup(t, {
    maxConcurrent: 1,
    operationTimeoutMs: 100,
    controller: {
      handle: async (_header, _body, options) => {
        signal = options.signal;
        entered();
        await held;
        return { state: "pending" };
      },
    },
  });
  const first = f.send();
  await inside;
  assert.equal((await f.send()).status, 429);
  assert.equal((await first).status, 504);
  assert.equal(signal.aborted, true);
  assert.equal(
    (await f.send()).status,
    429,
    "timed-out work keeps its concurrency slot until it settles",
  );
  release();
});
test("slow request bodies time out and cannot later invoke the controller", async (t) => {
  const f = await setup(t, { bodyTimeoutMs: 100 });
  const response = await new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: f.server.address().port,
        path: "/v1/actions",
        method: "POST",
        headers: {
          Host: "xeip.test",
          "Content-Type": "application/json",
          "Content-Length": "20",
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      },
    );
    req.on("error", reject);
    req.write("{");
  });
  assert.equal(response, 408);
  assert.equal(f.calls.length, 0);
});
test("timed-out readiness retains its slot while liveness stays available", async (t) => {
  let release;
  const held = new Promise((resolve) => (release = resolve));
  const f = await setup(t, {
    maxConcurrent: 1,
    readinessTimeoutMs: 100,
    ready: () => held,
  });
  assert.equal((await f.send("", {}, "/ready", "GET")).status, 503);
  assert.equal((await f.send("", {}, "/live", "GET")).status, 200);
  assert.equal((await f.send("", {}, "/ready", "GET")).status, 429);
  release(true);
});
test("a disconnected body read cannot crash the server or invoke the controller", async (t) => {
  const f = await setup(t);
  await new Promise((resolve) => {
    const req = request({
      host: "127.0.0.1",
      port: f.server.address().port,
      path: "/v1/actions",
      method: "POST",
      headers: {
        Host: "xeip.test",
        "Content-Type": "application/json",
        "Content-Length": "20",
      },
    });
    req.on("error", () => {});
    req.on("close", resolve);
    req.write("{");
    // Let the server receive a partial request before the peer disconnects.
    setTimeout(() => req.destroy(), 30);
  });
  assert.equal((await f.send("", {}, "/live", "GET")).status, 200);
  assert.equal(f.calls.length, 0);
});
test("real TLS verifies the configured certificate and rejects an untrusted client connection", async (t) => {
  const tls = {
    key: readFileSync(new URL("./test-fixtures/tls/key.pem", import.meta.url)),
    cert: readFileSync(
      new URL("./test-fixtures/tls/cert.pem", import.meta.url),
    ),
  };
  const f = await setup(t, { tls, allowInsecureLoopback: false });
  const get = (ca) =>
    new Promise((resolve, reject) => {
      const req = secureRequest(
        {
          host: "127.0.0.1",
          port: f.server.address().port,
          path: "/live",
          headers: { Host: "xeip.test" },
          ca,
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode));
        },
      );
      req.on("error", reject);
      req.end();
    });
  await assert.rejects(
    get(undefined),
    (e) => e.code === "DEPTH_ZERO_SELF_SIGNED_CERT",
  );
  assert.equal(await get(tls.cert), 200);
});
