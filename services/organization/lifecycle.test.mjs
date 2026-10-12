import test from "node:test";
import assert from "node:assert/strict";
import { RuntimeLifecycle } from "./lifecycle.mjs";

const gate = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function setup(overrides = {}) {
  const state = {
    trust: "ready",
    provider: true,
    database: true,
    closed: false,
    listenerClosed: false,
    forceClosed: false,
    updates: 0,
  };
  const lifecycle = new RuntimeLifecycle({
    controller: { handle: async () => ({ state: "pending" }) },
    trust: {
      status: () => ({ state: state.trust }),
      updateAsync: async () => {
        state.updates++;
      },
      close: () => {},
    },
    authentication: { ready: async () => state.provider },
    checkDatabase: async () => {
      if (!state.database) throw new Error("db credential private");
    },
    closeDatabase: async () => {
      state.closed = true;
    },
    closeListeners: async () => {
      state.listenerClosed = true;
    },
    forceCloseListeners: () => {
      state.forceClosed = true;
    },
    provisioning: () => ({ keyDocuments: [], statusDocuments: [] }),
    shutdownMs: 150,
    ...overrides,
  });
  return { lifecycle, state };
}

test("startup fails closed and liveness is not used as dependency readiness", async () => {
  for (const dependency of ["trust", "provider", "database"]) {
    const { lifecycle, state } = setup();
    state[dependency] = dependency === "trust" ? "stale" : false;
    await assert.rejects(lifecycle.start(), {
      message: "organization startup unavailable",
    });
    await assert.rejects(
      lifecycle.handle("Bearer private", "{}", {
        signal: new AbortController().signal,
      }),
      { status: 503 },
    );
    assert.equal(await lifecycle.ready(), false);
  }
});
test("readiness coalesces concurrent dependency probes and notices stale trust immediately", async () => {
  let probes = 0;
  const { lifecycle, state } = setup({
    checkDatabase: async () => {
      probes++;
    },
  });
  await lifecycle.start();
  assert.deepEqual(
    await Promise.all(Array.from({ length: 20 }, () => lifecycle.ready())),
    Array(20).fill(true),
  );
  assert.equal(probes, 1);
  state.trust = "stale";
  assert.equal(await lifecycle.ready(), false);
  await lifecycle.stop();
});
test("drain rejects new work and keeps the pool open until accepted completion is recorded", async () => {
  const entered = gate(),
    finish = gate();
  const { lifecycle, state } = setup({
    controller: {
      handle: async () => {
        entered.resolve();
        await finish.promise;
        assert.equal(state.closed, false);
        return { state: "succeeded" };
      },
    },
  });
  await lifecycle.start();
  const action = lifecycle.handle("Bearer secret", "{}", {
    signal: new AbortController().signal,
  });
  await entered.promise;
  const stopping = lifecycle.stop();
  assert.equal(await lifecycle.ready(), false);
  await assert.rejects(
    lifecycle.handle("Bearer secret", "{}", {
      signal: new AbortController().signal,
    }),
    { status: 503 },
  );
  assert.equal(state.closed, false);
  finish.resolve();
  assert.deepEqual(await action, { state: "succeeded" });
  assert.deepEqual(await stopping, { forced: false });
  assert.equal(state.closed, true);
  assert.equal(state.listenerClosed, true);
});
test("drain deadline cancels work, gives it time to record a result and never starts new work", async () => {
  const entered = gate();
  let attempted = 0;
  const { lifecycle, state } = setup({
    controller: {
      handle: async (_a, _b, { signal }) => {
        entered.resolve();
        await new Promise((resolve) =>
          signal.addEventListener("abort", resolve, { once: true }),
        );
        assert.equal(state.closed, false);
        if (!signal.aborted) attempted++;
        return { state: "failed" };
      },
    },
  });
  await lifecycle.start();
  const action = lifecycle.handle("Bearer secret", "{}", {
    signal: new AbortController().signal,
  });
  await entered.promise;
  assert.deepEqual(await lifecycle.stop(), { forced: false });
  await action;
  assert.equal(attempted, 0);
  assert.equal(state.closed, true);
  assert.equal(state.forceClosed, true);
});
test("uncooperative workers produce a bounded forced-exit result without closing their pool early", async () => {
  const entered = gate(),
    finish = gate();
  const { lifecycle, state } = setup({
    controller: {
      handle: async () => {
        entered.resolve();
        await finish.promise;
        return {};
      },
    },
  });
  await lifecycle.start();
  const action = lifecycle.handle("Bearer secret", "{}", {
    signal: new AbortController().signal,
  });
  await entered.promise;
  assert.deepEqual(await lifecycle.stop(), { forced: true });
  assert.equal(state.closed, false);
  assert.equal(state.forceClosed, true);
  finish.resolve();
  await action;
});
test("failed trust reload retains readiness when the verified trust implementation retains its prior policy", async () => {
  let invalid = false;
  const { lifecycle, state } = setup({
    provisioning: () => {
      if (invalid) throw new Error("sensitive file path");
      return {};
    },
  });
  await lifecycle.start();
  assert.equal(await lifecycle.reloadTrust(), true);
  assert.equal(state.updates, 1);
  invalid = true;
  assert.equal(await lifecycle.reloadTrust(), false);
  assert.equal(state.updates, 1);
  assert.equal(await lifecycle.ready(), true);
  state.trust = "failed";
  assert.equal(await lifecycle.ready(), false);
  await lifecycle.stop();
  assert.equal(await lifecycle.reloadTrust(), false);
});
test("auxiliary profile work drains with controller work and rejects new work during stop", async () => {
  const { lifecycle, state } = setup();
  await lifecycle.start();
  const finish = gate();
  const work = lifecycle.run(
    async () => {
      await finish.promise;
      return "profile";
    },
    { signal: new AbortController().signal },
  );
  assert.equal(lifecycle.status().active, 1);
  const stopping = lifecycle.stop();
  await assert.rejects(
    lifecycle.run(async () => null, { signal: new AbortController().signal }),
  );
  assert.equal(state.closed, false);
  finish.resolve();
  assert.equal(await work, "profile");
  assert.deepEqual(await stopping, { forced: false });
  assert.equal(state.closed, true);
});

test("trust reload waits for commit and participates in bounded drain cancellation", async () => {
  const entered = gate();
  let aborted = false,
    closed = false,
    settled = false;
  const { lifecycle, state } = setup({
    trust: {
      status: () => ({ state: "ready" }),
      updateAsync: async (_value, { signal }) => {
        entered.resolve();
        await new Promise((_resolve, reject) => {
          signal.addEventListener(
            "abort",
            () => {
              aborted = true;
              reject(new Error("cancelled"));
            },
            { once: true },
          );
        });
      },
      close: () => {
        closed = true;
      },
    },
  });
  await lifecycle.start();
  const reloading = Promise.resolve(lifecycle.reloadTrust()).then((result) => {
    settled = true;
    return result;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    settled,
    false,
    "reload must not report success before the async commit",
  );
  await entered.promise;
  assert.equal(await lifecycle.ready(), true);
  const stopping = lifecycle.stop();
  assert.equal(state.closed, false);
  assert.equal(await reloading, false);
  assert.deepEqual(await stopping, { forced: false });
  assert.equal(aborted, true);
  assert.equal(closed, true);
  assert.equal(await lifecycle.reloadTrust(), false);
});
