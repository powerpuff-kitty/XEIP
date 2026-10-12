import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { EventEmitter } from "node:events";
import {
  parseControlArguments,
  maintainControl,
} from "./control-maintenance.mjs";
import { configuration } from "./test-fixtures/control.mjs";
const hash = "a".repeat(64);
test("owner commands require explicit empty or exact-head intent", () => {
  assert.deepEqual(
    parseControlArguments(["inspect", "--owner-config", "/owner"]),
    { operation: "inspect", ownerPath: "/owner" },
  );
  assert.deepEqual(
    parseControlArguments([
      "enroll",
      "--owner-config",
      "/owner",
      "--runtime-config",
      "/runtime",
      "--expect-empty",
    ]),
    { operation: "enroll", ownerPath: "/owner", runtimePath: "/runtime" },
  );
  assert.deepEqual(
    parseControlArguments([
      "change",
      "--owner-config",
      "/owner",
      "--runtime-config",
      "/runtime",
      "--expected-revision",
      "12",
      "--expected-digest",
      hash,
    ]),
    {
      operation: "change",
      ownerPath: "/owner",
      runtimePath: "/runtime",
      expected: { revision: 12, digest: hash },
    },
  );
  for (const args of [
    [],
    ["unknown"],
    ["inspect", "--owner-config", "/owner", "--owner-config", "/second"],
    ["enroll", "--owner-config", "/owner", "--runtime-config", "/runtime"],
    ...["0", "01", "1.0", "9007199254740992"].map((r) => [
      "change",
      "--owner-config",
      "/owner",
      "--runtime-config",
      "/runtime",
      "--expected-revision",
      r,
      "--expected-digest",
      hash,
    ]),
    [
      "change",
      "--owner-config",
      "/owner",
      "--runtime-config",
      "/runtime",
      "--expected-revision",
      "1",
      "--expected-digest",
      "private-value",
    ],
  ]) {
    assert.throws(
      () => parseControlArguments(args),
      (e) => e.message === "control_maintenance_failed",
    );
  }
});
test("different database, expired provisioning and cancelled commands refuse before connecting", async (t) => {
  let connected = 0;
  t.mock.method(pg, "Client", function () {
    connected++;
    throw new Error("should not connect");
  });
  const owner = {
    host: "db.test",
    port: 5432,
    database: "xeip",
    user: "owner",
    connectionTimeoutMillis: 3000,
    query_timeout: 3000,
  };
  const config = configuration();
  config.database = { ...owner, user: "runtime", host: "other.test" };
  await assert.rejects(
    maintainControl(owner, { operation: "enroll", configuration: config }),
  );
  config.database.host = owner.host;
  // This fixed historical fixture is deliberately stale at the current clock.
  await assert.rejects(
    maintainControl(owner, { operation: "enroll", configuration: config }),
  );
  const abort = new AbortController();
  abort.abort();
  await assert.rejects(
    maintainControl(owner, { operation: "inspect" }, { signal: abort.signal }),
  );
  assert.equal(connected, 0);
});
test("cancellation during final owner close cannot report command success", async (t) => {
  let entered, finish;
  const closing = new Promise((resolve) => {
    entered = resolve;
  });
  const gate = new Promise((resolve) => {
    finish = resolve;
  });
  const client = Object.assign(new EventEmitter(), {
    connect: async () => {},
    query: async (sql) => ({
      rows: sql.includes("pg_try_advisory_lock") ? [{ held: true }] : [],
    }),
    end: async () => {
      entered();
      await gate;
    },
  });
  t.mock.method(pg, "Client", function () {
    return client;
  });
  const abort = new AbortController();
  const pending = maintainControl(
    { connectionTimeoutMillis: 3000, query_timeout: 3000 },
    { operation: "inspect" },
    { signal: abort.signal },
  );
  const denied = assert.rejects(
    pending,
    (e) => e.message === "control_maintenance_failed",
  );
  await closing;
  abort.abort();
  finish();
  await denied;
});
