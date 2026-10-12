import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createServer } from "node:net";
import pg from "pg";
import { openControlLease, openControlMaintenance } from "./control-lease.mjs";
const config = { connectionTimeoutMillis: 3000, query_timeout: 3000 };
test("cancellation during a real PostgreSQL handshake settles opening", async () => {
  const abort = new AbortController();
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.resume();
    // Deliberately never send a PostgreSQL authentication response.
    abort.abort();
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  let deadline;
  try {
    const result = await Promise.race([
      openControlLease(
        {
          host: "127.0.0.1",
          port: server.address().port,
          user: "synthetic",
          database: "synthetic",
          password: "synthetic",
          ssl: false,
          connectionTimeoutMillis: 100,
          query_timeout: 100,
        },
        { signal: abort.signal },
      ).then(
        async (lease) => {
          await lease.close();
          return "unexpected activation";
        },
        (error) => error.message,
      ),
      new Promise((resolve) => {
        deadline = setTimeout(() => resolve("opening remained pending"), 1500);
      }),
    ]);
    assert.equal(abort.signal.aborted, true);
    assert.equal(result, "organization control lease unavailable");
  } finally {
    clearTimeout(deadline);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
});
const gate = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function fixture(t) {
  const state = {
    held: true,
    queries: [],
    ended: 0,
    connected: 0,
    heartbeatFailure: false,
    wait: undefined,
    enter: undefined,
  };
  const client = Object.assign(new EventEmitter(), {
    connect: async () => {
      state.connected++;
    },
    query: async (sql) => {
      state.queries.push(sql);
      if (sql.includes("pg_try_advisory_lock")) {
        state.enter?.resolve();
        await state.wait?.promise;
        return { rows: [{ held: state.held }] };
      }
      if (state.heartbeatFailure) throw new Error("private connection details");
      return { rows: [{ alive: 1 }] };
    },
    end: async () => {
      state.ended++;
      client.emit("end");
    },
  });
  t.mock.method(pg, "Client", function (options) {
    state.configuration = options;
    return client;
  });
  return { client, state };
}
test("lease refuses contention and closes its dedicated connection", async (t) => {
  const f = fixture(t);
  f.state.held = false;
  await assert.rejects(
    openControlLease(config),
    (e) => e.message === "organization control lease unavailable",
  );
  assert.equal(f.state.ended, 1);
});
test("lease is active only until close, without borrowing any pool slot", async (t) => {
  const f = fixture(t),
    lease = await openControlLease(config);
  assert.equal(lease.signal.aborted, false);
  lease.assertActive();
  await lease.close();
  await lease.close();
  assert.equal(lease.signal.aborted, true);
  assert.throws(() => lease.assertActive());
  assert.equal(f.state.connected, 1);
  assert.equal(f.state.ended, 1);
});
for (const event of ["error", "end"])
  test(`observed ${event} immediately invalidates lease`, async (t) => {
    const f = fixture(t),
      lease = await openControlLease(config);
    f.client.emit(event, new Error("private connection details"));
    assert.equal(lease.signal.aborted, true);
    assert.throws(
      () => lease.assertActive(),
      (e) => e.message === "organization control lease unavailable",
    );
    await lease.close();
    assert.equal(f.state.ended, 1);
  });
test("failed heartbeat invalidates authority and closes connection", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(t),
    lease = await openControlLease(config);
  f.state.heartbeatFailure = true;
  const lost = new Promise((r) =>
    lease.signal.addEventListener("abort", r, { once: true }),
  );
  t.mock.timers.tick(1000);
  await lost;
  await lease.close();
  assert.equal(f.state.ended, 1);
});
test("cancellation during lock acquisition cannot activate a late successful lock", async (t) => {
  const f = fixture(t),
    abort = new AbortController();
  f.state.wait = gate();
  f.state.enter = gate();
  const pending = openControlLease(config, { signal: abort.signal });
  const denied = assert.rejects(
    pending,
    (e) => e.message === "organization control lease unavailable",
  );
  await Promise.race([f.state.enter.promise, pending]);
  abort.abort();
  await denied;
  f.state.wait.resolve();
  assert.equal(f.state.ended, 1);
});
test("pre-cancelled or unbounded leases never connect", async (t) => {
  const f = fixture(t),
    abort = new AbortController();
  abort.abort();
  await assert.rejects(openControlLease(config, { signal: abort.signal }));
  for (const bad of [
    {},
    { connectionTimeoutMillis: 0, query_timeout: 3000 },
    { connectionTimeoutMillis: 3000, query_timeout: Infinity },
  ])
    await assert.rejects(openControlLease(bad));
  assert.equal(f.state.connected, 0);
});

test("normal close does not report unexpected loss", async (t) => {
  fixture(t);
  const lease = await openControlLease(config);
  let failed = false;
  void lease.failed.then(() => {
    failed = true;
  });
  await lease.close();
  await Promise.resolve();
  assert.equal(failed, false);
});
test("stalled close reports unavailable within a bounded deadline", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(t),
    lease = await openControlLease(config);
  f.client.end = () => new Promise(() => {});
  const closed = lease.close();
  const denied = assert.rejects(
    closed,
    (e) => e.message === "organization control lease unavailable",
  );
  assert.equal(lease.signal.aborted, true);
  t.mock.timers.tick(3000);
  await denied;
});

test("dedicated connection preserves non-enumerable pool credentials", async (t) => {
  const f = fixture(t),
    options = { ...config };
  Object.defineProperty(options, "password", {
    value: "synthetic-lease-password",
    enumerable: false,
  });
  const lease = await openControlLease(options);
  try {
    assert.equal(
      f.state.configuration.password === "synthetic-lease-password",
      true,
    );
  } finally {
    await lease.close();
  }
});

test("owner transactions retain one session and refuse concurrent or released handles", async (t) => {
  const f = fixture(t);
  const owner = await openControlMaintenance(config);
  try {
    const first = await owner.pool.connect();
    const listener = () => {};
    assert.equal(first.on("notice", listener), first);
    first.removeListener("notice", listener);
    await first.query("SELECT first");
    await assert.rejects(owner.pool.connect());
    first.release();
    assert.equal(f.state.ended, 0);
    owner.assertActive();
    const second = await owner.pool.connect();
    assert.throws(() => first.query("SELECT stale"));
    assert.throws(() => first.release());
    await assert.rejects(owner.pool.connect());
    await second.query("SELECT second");
    second.release();
    assert.equal(f.state.connected, 1);
    assert.deepEqual(f.state.queries.slice(1), [
      "SELECT first",
      "SELECT second",
    ]);
  } finally {
    await owner.close();
  }
  assert.equal(f.state.ended, 1);
});

test("broken owner transaction closes ownership and cannot acquire a replacement backend", async (t) => {
  const f = fixture(t);
  const owner = await openControlMaintenance(config);
  const client = await owner.pool.connect();
  client.release(true);
  assert.equal(owner.signal.aborted, true);
  await assert.rejects(owner.pool.connect());
  assert.throws(() => client.query("COMMIT"));
  await owner.close();
  assert.equal(f.state.connected, 1);
  assert.equal(f.state.ended, 1);
});

test("owner heartbeat does not interleave with a borrowed transaction", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(t);
  const owner = await openControlMaintenance(config);
  const client = await owner.pool.connect();
  t.mock.timers.tick(1000);
  assert.equal(f.state.queries.length, 1);
  client.release();
  t.mock.timers.tick(1000);
  await Promise.resolve();
  assert.equal(f.state.queries.at(-1), "SELECT 1 AS alive");
  await owner.close();
});
