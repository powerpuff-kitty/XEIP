import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { request, Server } from "node:https";
import { supervise } from "./main.mjs";
import { serveOrganization } from "./runtime.mjs";

const tls = {
  cert: readFileSync(new URL("./test-fixtures/tls/cert.pem", import.meta.url)),
  key: readFileSync(new URL("./test-fixtures/tls/key.pem", import.meta.url)),
};
function dependencies() {
  const state = { healthy: true, closed: false, trustClosed: false };
  return {
    state,
    controller: {
      handle: async () => ({ state: "succeeded", result: { ok: true } }),
    },
    authentication: { ready: async () => state.healthy },
    trust: {
      status: () => ({ state: state.healthy ? "ready" : "stale" }),
      updateAsync: async () => {},
      close: () => {
        state.trustClosed = true;
      },
    },
    checkDatabase: async () => {},
    closeDatabase: async () => {
      state.closed = true;
    },
    provisioning: () => ({}),
  };
}
const configuration = {
  origin: "https://xeip.test",
  tls,
  bind: { host: "127.0.0.1", port: 0 },
  shutdownMs: 1000,
};
const send = (runtime, path, body) =>
  new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: runtime.address().port,
        servername: "xeip.test",
        ca: tls.cert,
        path,
        method: body ? "POST" : "GET",
        headers: { Host: "xeip.test", "Content-Type": "application/json" },
      },
      (res) => {
        let text = "";
        res.on("data", (chunk) => (text += chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: JSON.parse(text) }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
test("runtime listens with verified TLS after dependency checks and exposes independent health", async (t) => {
  const deps = dependencies();
  const runtime = await serveOrganization(configuration, deps);
  t.after(() => runtime.stop());
  assert.equal((await send(runtime, "/ready")).status, 200);
  assert.equal(
    (await send(runtime, "/v1/actions", "{}")).body.state,
    "succeeded",
  );
  deps.state.healthy = false;
  assert.equal((await send(runtime, "/ready")).status, 503);
  assert.equal((await send(runtime, "/live")).status, 200);
  assert.deepEqual(await runtime.stop(), { forced: false });
  assert.equal(deps.state.closed, true);
  assert.equal(deps.state.trustClosed, true);
});
test("runtime startup failure closes resources without exposing a listener", async () => {
  const deps = dependencies();
  deps.state.healthy = false;
  await assert.rejects(serveOrganization(configuration, deps), {
    message: "organization startup unavailable",
  });
  assert.equal(deps.state.closed, true);
  assert.equal(deps.state.trustClosed, true);
});
test("listener bind failure cleans up already verified dependencies with a redacted error", async (t) => {
  const first = await serveOrganization(configuration, dependencies());
  t.after(() => first.stop());
  const deps = dependencies();
  await assert.rejects(
    serveOrganization(
      {
        ...configuration,
        bind: { host: "127.0.0.1", port: first.address().port },
      },
      deps,
    ),
    { message: "organization startup unavailable" },
  );
  assert.equal(deps.state.closed, true);
});

for (const uncooperative of [false, true]) {
  test(`fatal listener error requires supervised nonzero exit (pending worker=${uncooperative})`, async (t) => {
    let listener;
    const listen = Server.prototype.listen;
    t.mock.method(Server.prototype, "listen", function (...args) {
      listener = this;
      return listen.apply(this, args);
    });
    const deps = dependencies();
    let entered;
    const started = new Promise((resolve) => {
      entered = resolve;
    });
    let finish;
    if (uncooperative)
      deps.controller.handle = () => {
        entered();
        return new Promise((resolve) => {
          finish = resolve;
        });
      };
    const runtime = await serveOrganization(
      { ...configuration, shutdownMs: 150 },
      deps,
    );
    t.after(async () => {
      finish?.({});
      await runtime.stop();
    });
    const events = [];
    let exited;
    const exit = new Promise((resolve) => {
      exited = resolve;
    });
    supervise(
      runtime,
      (event) => events.push(event),
      (code) => exited(code),
    );
    const request = uncooperative
      ? send(runtime, "/v1/actions", "{}").catch(() => {})
      : undefined;
    if (uncooperative) await started;
    listener.emit("error", new Error("sensitive listener detail"));
    listener.emit("error", new Error("duplicate failure"));
    const code = await Promise.race([
      exit,
      new Promise((resolve) => setTimeout(() => resolve("missing exit"), 1500)),
    ]);
    assert.equal(code, 1);
    assert.equal(deps.state.closed, !uncooperative);
    assert.equal(
      events.filter((event) => event === "listener_failed").length,
      1,
    );
    assert.equal(
      events.includes(uncooperative ? "shutdown_forced" : "shutdown_complete"),
      true,
    );
    assert.equal(JSON.stringify(events).includes("sensitive"), false);
    finish?.({});
    await request;
  });
}

test("supervisor reports lease loss separately and exits nonzero after drain", async () => {
  const events = [];
  let exited;
  const exit = new Promise((r) => {
    exited = r;
  });
  supervise(
    {
      failed: Promise.resolve("control_lease_lost"),
      stop: async () => ({ forced: false }),
    },
    (e) => events.push(e),
    exited,
  );
  assert.equal(await exit, 1);
  assert.deepEqual(events, [
    "control_lease_lost",
    "draining",
    "shutdown_complete",
  ]);
});
