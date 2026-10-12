import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { ControlStore, controlEventDigest } from "./control-store.mjs";
import { StoreConflict, StoreUnavailable } from "./errors.mjs";
import { publicAuthority } from "./control-state.mjs";
import {
  enroll,
  configuration,
  provisioning,
  acceptedAt,
} from "./test-fixtures/control.mjs";
const prepared = enroll();
const digest = controlEventDigest(1, "0".repeat(64), prepared.digest);
const head = { revision: 1, digest };
const input = (serial = 1) => ({
  authority: publicAuthority(configuration()),
  provisioning: provisioning(serial),
  acceptedAt: acceptedAt + serial,
});

// Protocol fault injection only: actual SQL semantics live in organization-control.
function fixture({ empty = false, fault, corrupt } = {}) {
  const queries = [];
  let destroyed,
    releases = 0;
  const client = Object.assign(new EventEmitter(), {
    async query(sql) {
      queries.push(sql);
      if (sql === "COMMIT") {
        if (fault === "notice")
          client.emit("notice", { message: "sensitive notice" });
        if (fault === "lost") throw Error("sensitive disconnected commit");
      }
      if (sql.includes("pg_logical_emit_message") && fault === "marker")
        throw Error("sensitive WAL failure");
      if (sql.includes("FROM xeip_org.control_head"))
        return { rows: empty ? [] : [{ revision: "1", digest, ...corrupt }] };
      if (sql.includes("state_canonical"))
        return {
          rows: [
            {
              revision: "1",
              previous_digest: "0".repeat(64),
              state_canonical: prepared.canonical,
              state_digest: prepared.digest,
              digest,
            },
          ],
        };
      return { rows: [] };
    },
    release(value) {
      destroyed = value;
      releases++;
    },
  });
  const pool = {
    options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
    connect: async () => client,
  };
  return {
    store: new ControlStore(pool),
    client,
    queries,
    result: () => ({
      destroyed,
      releases,
      listeners: client.listenerCount("notice"),
    }),
  };
}
const operations = {
  inspect: (store) => store.inspect(),
  enroll: (store) => store.enroll({ ...input(), retainedRecords: {} }),
  open: (store) => store.open(input()),
  publishTrust: (store) => store.publishTrust(head, input(2)),
  changeAuthority: (store) => store.changeAuthority(head, input(2)),
};
test("owner inspection returns explicit empty state without enrolling", async () => {
  const f = fixture({ empty: true });
  assert.equal(await f.store.inspect(), null);
  assert.equal(
    f.queries.some((sql) => sql.startsWith("INSERT")),
    false,
  );
  assert.equal(f.queries.at(-1), "COMMIT");
});
for (const [name, invoke] of Object.entries(operations)) {
  for (const fault of ["notice", "lost", "marker"])
    test(`${name} refuses ${fault} durability failure and destroys connection`, async () => {
      const f = fixture({ empty: name === "enroll", fault });
      await assert.rejects(
        invoke(f.store),
        (error) =>
          error instanceof StoreUnavailable &&
          !error.stack.includes("sensitive"),
      );
      assert.deepEqual(f.result(), {
        destroyed: true,
        releases: 1,
        listeners: 0,
      });
      assert.ok(
        f.queries.some((sql) => sql.includes("pg_logical_emit_message")),
      );
      assert.equal(f.queries.includes("COMMIT"), fault !== "marker");
    });
  test(`${name} acknowledges only after WAL marker and commit`, async () => {
    const f = fixture({ empty: name === "enroll" });
    const current = await invoke(f.store);
    assert.ok(Object.isFrozen(current));
    assert.ok(Object.isFrozen(current.snapshot.state));
    assert.match(f.queries.at(-2), /pg_logical_emit_message/);
    assert.equal(f.queries.at(-1), "COMMIT");
    assert.deepEqual(f.result(), {
      destroyed: false,
      releases: 1,
      listeners: 0,
    });
  });
}
test("head revisions cannot be coerced or rounded", async () => {
  for (const revision of ["0", "01", "1.0", "9007199254740992", 1, null]) {
    const f = fixture({ corrupt: { revision } });
    await assert.rejects(f.store.open(input()), StoreUnavailable);
    assert.equal(f.queries.includes("COMMIT"), false);
  }
  for (const revision of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1", null]) {
    assert.throws(
      () => controlEventDigest(revision, digest, digest),
      StoreUnavailable,
    );
    const f = fixture();
    await assert.rejects(
      f.store.publishTrust({ revision, digest }, input(2)),
      StoreConflict,
    );
    assert.equal(f.queries.length, 0);
  }
  assert.match(
    controlEventDigest(Number.MAX_SAFE_INTEGER, digest, digest),
    /^[a-f0-9]{64}$/,
  );
});
test("publication does not invoke input accessors", async () => {
  const f = fixture();
  let invoked = false;
  const malicious = { ...input(2) };
  Object.defineProperty(malicious, "provisioning", {
    enumerable: true,
    get() {
      invoked = true;
      throw Error("sensitive");
    },
  });
  await assert.rejects(f.store.publishTrust(head, malicious), StoreUnavailable);
  await assert.rejects(
    f.store.enroll({
      ...input(),
      retainedRecords: {},
      get extra() {
        invoked = true;
      },
    }),
    StoreUnavailable,
  );
  assert.equal(invoked, false);
  assert.equal(f.queries.length, 0);
});
for (const name of ["open", "publishTrust"])
  test(`${name} yields while validating signed control state`, async () => {
    const f = fixture();
    let ticks = 0;
    const interval = setInterval(() => ticks++, 1);
    try {
      await operations[name](f.store);
      assert.ok(ticks > 0, "signature validation must allow timer progress");
    } finally {
      clearInterval(interval);
    }
  });
test("cancellation during control verification prevents writes and acknowledgement", async () => {
  const f = fixture(),
    controller = new AbortController();
  const pending = f.store.publishTrust(head, input(2), {
    signal: controller.signal,
  });
  const rejected = assert.rejects(pending, StoreUnavailable);
  setTimeout(() => controller.abort(), 0);
  await rejected;
  assert.equal(
    f.queries.some((sql) => sql.startsWith("INSERT")),
    false,
  );
  assert.equal(f.queries.includes("COMMIT"), false);
});
test("control validation deadline terminates before any enrollment transaction", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture({ empty: true });
  const pending = f.store.enroll({ ...input(), retainedRecords: {} });
  const rejected = assert.rejects(pending, StoreUnavailable);
  t.mock.timers.tick(8000);
  await rejected;
  assert.equal(f.queries.length, 0);
});

for (const fault of ["notice", "lost", "marker"])
  test(`dispatch head validation refuses uncertain ${fault} durability`, async () => {
    const f = fixture({ fault });
    await assert.rejects(f.store.checkCurrent(head), StoreUnavailable);
    assert.equal(f.result().destroyed, true);
  });
test("dispatch head validation refuses a newer durable revision", async () => {
  const f = fixture({ corrupt: { revision: "2" } });
  await assert.rejects(f.store.checkCurrent(head), StoreConflict);
  assert.equal(f.queries.includes("COMMIT"), false);
});
