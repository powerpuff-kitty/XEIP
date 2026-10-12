import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
let runtime;
before(async () => {
  runtime = await harness({
    entryPoint: new URL(
      "./organization-cloudflare-recovery-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "RecoveryFixture",
  });
});
after(async () => {
  await runtime?.close();
});
const options = (extra = {}) => ({
  organization: "recovery-fixture",
  stream: "56f243dc-5048-4d1d-8a63-b753ed79844c",
  ...extra,
});
const initialize = (f, extra = {}) =>
  f.send({ operation: "initialize", options: options(extra) });
const reopen = (f, extra = {}) =>
  f.send({ operation: "open", options: options(extra) });
const append = (f, extra = {}) => f.send({ operation: "append", ...extra });
const head = async (f) => (await f.send({ operation: "head" })).body;
test("recovery journal requires explicit isolated initialization and exact scope on reopen", async () => {
  const f = await runtime.fixture();
  assert.equal((await reopen(f)).body.error, "StoreUnavailable");
  assert.deepEqual(
    (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
  const first = await initialize(f);
  assert.equal(first.status, 200);
  assert.equal(first.body.sequence, 0);
  assert.equal((await initialize(f)).body.error, "StoreConflict");
  assert.equal(
    (await reopen(f, { organization: "wrong" })).body.error,
    "StoreUnavailable",
  );
  assert.equal(
    (await reopen(f, { stream: randomUUID() })).body.error,
    "StoreUnavailable",
  );
  assert.deepEqual((await reopen(f)).body, first.body);
});
test("recovery journal durably orders payloads and reconstructs bounded parts after restart", async () => {
  let f = await runtime.fixture();
  await initialize(f);
  const previous = await head(f),
    id = randomUUID();
  const first = await append(f, { id, bytes: 700000 });
  assert.equal(first.status, 200);
  assert.equal(first.body.sequence, 1);
  assert.equal(first.body.previous, previous.checksum);
  assert.equal(first.body.parts, 3);
  const next = await append(f);
  assert.equal(next.body.sequence, 2);
  assert.equal(next.body.previous, first.body.checksum);
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal((await reopen(f)).body.sequence, 2);
  const data = [];
  for (let part = 0; part < first.body.parts; part++) {
    const result = await f.send({ operation: "part", sequence: 1, part });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.entry, first.body);
    data.push(Buffer.from(result.body.data, "base64"));
  }
  assert.equal(Buffer.concat(data).length, 700000);
  assert.equal(
    createHash("sha256").update(Buffer.concat(data)).digest("hex"),
    first.body.payloadDigest,
  );
});
const control = (f, control) => f.send({ operation: "controls", control });
const health = async (f) =>
  (await f.send({ operation: "healthy" })).body.healthy;
const rawValue = (expected, extra = {}) => ({
  expected,
  id: randomUUID(),
  bytes: 1,
  payloadDigest: createHash("sha256").update("a").digest("hex"),
  chunks: ["YQ=="],
  ...extra,
});
test("recovery exact-tail retries bind scope, predecessor and bytes; old retries conflict", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const expected = await head(f),
    id = randomUUID();
  const receipt = await append(f, { expected, id });
  assert.equal(receipt.status, 200);
  assert.deepEqual((await append(f, { expected, id })).body, receipt.body);
  for (const extra of [
    { expected: { ...expected, organization: "other" } },
    { expected: { ...expected, stream: randomUUID() } },
    { expected: { ...expected, checksum: "0".repeat(64) } },
    { fill: 98 },
    { bytes: 17 },
  ])
    assert.notEqual((await append(f, { expected, id, ...extra })).status, 200);
  assert.equal(await health(f), true);
  assert.equal((await append(f, { expected })).status, 409);
  await append(f);
  assert.equal((await append(f, { expected, id })).status, 409);
  assert.equal(await health(f), true);
});
test("recovery caps persist, preserve healthy state on exhaustion and bind reopen", async () => {
  for (const caps of [{ maxEntries: 1 }, { maxBytes: 16 }]) {
    const f = await runtime.fixture();
    await initialize(f, caps);
    assert.equal((await append(f)).status, 200);
    assert.equal((await append(f)).status, 409);
    assert.equal(await health(f), true);
    assert.equal((await reopen(f)).status, 503);
    assert.equal((await reopen(f, caps)).status, 200);
  }
});
test("recovery malformed payloads and cursors cannot change storage or poison state", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const expected = await head(f),
    valid = rawValue(expected);
  for (const extra of [
    { extra: 1 },
    { bytes: 0 },
    { bytes: 16777217 },
    { bytes: 1.1 },
    { id: "invalid" },
    { payloadDigest: "0".repeat(64) },
    { chunks: [] },
    { chunks: ["YR=="] },
    { chunks: ["YQ==", "YQ=="] },
    { chunks: ["é"] },
    { expected: { ...expected, sequence: -1 } },
  ])
    assert.equal(
      (await append(f, { value: { ...valid, ...extra } })).status,
      400,
    );
  assert.deepEqual(await head(f), expected);
  await append(f);
  for (const sequence of [0, -1, 2, 1.5])
    assert.equal((await f.send({ operation: "entry", sequence })).status, 400);
  for (const part of [-1, 1, 0.5])
    assert.equal(
      (await f.send({ operation: "part", sequence: 1, part })).status,
      400,
    );
  assert.equal(await health(f), true);
});
test("recovery never opens or initializes over the source namespace", async () => {
  const f = await runtime.fixture();
  await f.sql("CREATE TABLE xeip_metadata(singleton INTEGER PRIMARY KEY)");
  assert.equal((await initialize(f)).status, 409);
  assert.equal((await reopen(f)).status, 503);
  assert.deepEqual(
    (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [{ name: "xeip_metadata" }],
  );
});
test("recovery acknowledgment waits for sync and blocks overlapping writes and reads", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const expected = await head(f);
  await control(f, { holdSync: 2 });
  let finished = false;
  const pending = append(f, { expected }).then((x) => {
    finished = true;
    return x;
  });
  try {
    for (let i = 0; i < 100; i++) {
      if ((await control(f, {})).body.syncs === 2) break;
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.equal((await control(f, {})).body.syncs, 2);
    assert.equal(finished, false);
    assert.equal((await f.send({ operation: "head" })).status, 503);
    assert.equal((await append(f, { expected })).status, 409);
    assert.equal(
      (await f.send({ operation: "entry", sequence: 1 })).status,
      503,
    );
  } finally {
    await control(f, { holdSync: 0 });
  }
  assert.equal((await pending).status, 200);
  assert.equal((await head(f)).sequence, 1);
});
test("recovery failed or timed-out sync quarantines an uncertain committed tail until fresh open", async () => {
  for (const mode of ["failure", "timeout", "close"]) {
    const f = await runtime.fixture();
    await initialize(f, { timeoutMs: 100 });
    const expected = await head(f),
      id = randomUUID();
    await control(f, mode === "failure" ? { failSync: 2 } : { holdSync: 2 });
    const pending = append(f, { expected, id });
    if (mode === "close") {
      for (let i = 0; i < 100; i++) {
        if ((await control(f, {})).body.syncs === 2) break;
        await new Promise((r) => setTimeout(r, 5));
      }
      await f.send({ operation: "close" });
      await control(f, { holdSync: 0 });
    }
    assert.equal((await pending).status, 503);
    await control(f, { holdSync: 0, failSync: 0 });
    assert.equal(await health(f), false);
    assert.equal((await f.send({ operation: "head" })).status, 503);
    assert.equal((await reopen(f)).body.sequence, 1);
    assert.equal((await append(f, { expected, id })).status, 200);
  }
});
test("recovery transaction rollback and ambiguous commit require fresh reconciliation", async () => {
  for (const mode of ["before", "after", "chunk"]) {
    const f = await runtime.fixture();
    await initialize(f);
    await control(
      f,
      mode === "chunk"
        ? { afterQuery: "INSERT INTO xeip_recovery_chunks" }
        : { transaction: mode },
    );
    assert.equal((await append(f, { bytes: 700000 })).status, 503);
    assert.equal(await health(f), false);
    await control(f, { afterQuery: null, transaction: null });
    assert.equal((await reopen(f)).body.sequence, mode === "after" ? 1 : 0);
    assert.equal(
      (await f.sql("SELECT COUNT(*) AS n FROM xeip_recovery_chunks")).body
        .rows[0].n,
      mode === "after" ? 3 : 0,
    );
  }
});
test("recovery initialization rolls back DDL faults and recovers uncertain initial sync", async () => {
  const f = await runtime.fixture();
  await control(f, { afterQuery: "\nCREATE TABLE xeip_recovery_meta" });
  assert.equal((await initialize(f)).status, 503);
  assert.deepEqual(
    (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows,
    [],
  );
  await control(f, { afterQuery: null, failSync: 1 });
  assert.equal((await initialize(f)).status, 503);
  await control(f, { failSync: 0 });
  assert.equal((await reopen(f)).body.sequence, 0);
});
test("recovery SQL forbids update, delete, primary and alternate-key replacement", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await append(f);
  await append(f);
  for (const table of ["meta", "entries", "chunks"]) {
    assert.equal(
      (await f.sql(`DELETE FROM xeip_recovery_${table}`)).status,
      503,
    );
    const column =
      table === "meta"
        ? "canonical"
        : table === "entries"
          ? "checksum"
          : "data";
    assert.equal(
      (await f.sql(`UPDATE xeip_recovery_${table} SET ${column}=${column}`))
        .status,
      503,
    );
    assert.equal(
      (
        await f.sql(
          `INSERT OR REPLACE INTO xeip_recovery_${table} SELECT * FROM xeip_recovery_${table} LIMIT 1`,
        )
      ).status,
      503,
    );
  }
  const row = (
      await f.sql("SELECT * FROM xeip_recovery_entries WHERE sequence=1")
    ).body.rows[0],
    prev = await head(f);
  const canonical = JSON.stringify({
    ...JSON.parse(row.canonical),
    sequence: 3,
    previous: prev.checksum,
    totalBytes: 48,
  });
  assert.equal(
    (
      await f.sql(
        "INSERT OR REPLACE INTO xeip_recovery_entries(sequence,id,previous,bytes,parts,total_bytes,checksum,canonical) VALUES(?,?,?,?,?,?,?,?)",
        3,
        row.id,
        prev.checksum,
        16,
        1,
        48,
        row.checksum,
        canonical,
      )
    ).status,
    503,
  );
  assert.equal((await reopen(f)).body.sequence, 2);
});
test("recovery full open detects missing, extra, orphan and corrupted parts with restored catalog", async () => {
  for (const mode of ["missing", "extra", "orphan", "bytes"]) {
    const f = await runtime.fixture();
    await initialize(f);
    await append(f, { bytes: 300000 });
    const triggers = (
      await f.sql(
        "SELECT sql,name FROM sqlite_master WHERE type='trigger' AND tbl_name='xeip_recovery_chunks'",
      )
    ).body.rows;
    for (const t of triggers) await f.sql(`DROP TRIGGER ${t.name}`);
    if (mode === "missing")
      assert.equal(
        (await f.sql("DELETE FROM xeip_recovery_chunks WHERE part=1")).status,
        200,
      );
    if (mode === "extra")
      assert.equal(
        (await f.sql("INSERT INTO xeip_recovery_chunks VALUES(1,2,'YQ==')"))
          .status,
        200,
      );
    if (mode === "orphan")
      assert.equal(
        (await f.sql("INSERT INTO xeip_recovery_chunks VALUES(2,0,'YQ==')"))
          .status,
        503,
      );
    if (mode === "bytes")
      assert.equal(
        (
          await f.sql(
            "UPDATE xeip_recovery_chunks SET data='YQ==' WHERE part=0",
          )
        ).status,
        200,
      );
    for (const t of triggers) await f.sql(t.sql);
    assert.equal((await reopen(f)).status, mode === "orphan" ? 200 : 503, mode);
  }
});
test("recovery catalog changes quarantine live instances", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await append(f);
  await f.sql("DROP TRIGGER xeip_recovery_entries_delete");
  assert.equal((await f.send({ operation: "head" })).status, 503);
  assert.equal((await reopen(f)).status, 503);
});
test("recovery crosses reconciliation page boundaries without skipping entries", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  for (let i = 0; i < 130; i++)
    assert.equal((await append(f, { bytes: 1 })).status, 200);
  assert.equal((await reopen(f)).body.sequence, 130);
  assert.equal(
    (await f.send({ operation: "entry", sequence: 129 })).body.totalBytes,
    129,
  );
});
test("recovery accepts maximum 16 MiB payload with provider-safe rows", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  const receipt = await append(f, { bytes: 16777216 });
  assert.equal(receipt.status, 200);
  assert.equal(receipt.body.parts, 64);
  assert.ok(
    (
      await f.sql(
        "SELECT MAX(length(CAST(data AS BLOB))) AS n FROM xeip_recovery_chunks",
      )
    ).body.rows[0].n <= 349528,
  );
  assert.equal((await reopen(f)).body.sequence, 1);
  assert.equal((await append(f, { bytes: 16777217 })).status, 400);
});
test("recovery byte validation rejects getters and mutated input without invoking code", async () => {
  const { validateAppend, recoveryOptions } = await import(
    "../services/organization/cloudflare/recovery-record.mjs"
  );
  const o = recoveryOptions(options()),
    expected = {
      organization: o.organization,
      stream: o.stream,
      sequence: 0,
      checksum: "0".repeat(64),
    };
  let called = false;
  const accessor = { ...rawValue(expected) };
  Object.defineProperty(accessor, "chunks", {
    get() {
      called = true;
      return ["YQ=="];
    },
    enumerable: true,
  });
  assert.throws(() => validateAppend(accessor, o), TypeError);
  assert.equal(called, false);
  const chunks = ["YQ=="];
  Object.defineProperty(chunks, 0, {
    get() {
      called = true;
      return "YQ==";
    },
  });
  assert.throws(
    () => validateAppend(rawValue(expected, { chunks }), o),
    TypeError,
  );
  assert.equal(called, false);
  const input = rawValue(expected),
    copy = validateAppend(input, o);
  input.chunks[0] = "Yg==";
  input.expected.sequence = 1;
  assert.equal(copy.chunks[0], "YQ==");
  assert.equal(copy.expected.sequence, 0);
  for (const extra of [
    { maxEntries: 0 },
    { maxBytes: 1073741825 },
    { timeoutMs: 99 },
    { extra: 1 },
  ])
    assert.throws(() => recoveryOptions(options(extra)), TypeError);
});
test("recovery selected reads and reopen reject a self-consistent historical rewrite that breaks its successor", async () => {
  const { sealEntry, canonicalize } = await import(
    "../services/organization/cloudflare/recovery-record.mjs"
  );
  const f = await runtime.fixture();
  await initialize(f);
  await append(f);
  await append(f);
  const row = (
    await f.sql("SELECT * FROM xeip_recovery_entries WHERE sequence=1")
  ).body.rows[0];
  const { checksum, ...old } = JSON.parse(row.canonical),
    entry = sealEntry({ ...old, id: randomUUID() });
  const trigger = (
    await f.sql(
      "SELECT sql FROM sqlite_master WHERE name='xeip_recovery_entries_update'",
    )
  ).body.rows[0].sql;
  assert.equal(
    (await f.sql("DROP TRIGGER xeip_recovery_entries_update")).status,
    200,
  );
  assert.equal(
    (
      await f.sql(
        "UPDATE xeip_recovery_entries SET id=?,checksum=?,canonical=? WHERE sequence=1",
        entry.id,
        entry.checksum,
        canonicalize(entry),
      )
    ).status,
    200,
  );
  assert.equal((await f.sql(trigger)).status, 200);
  assert.equal((await f.send({ operation: "entry", sequence: 1 })).status, 503);
  assert.equal((await reopen(f)).status, 503);
});
test("recovery consistent rollback of the entire journal needs an independent witness", async () => {
  const f = await runtime.fixture();
  await initialize(f);
  await append(f);
  await append(f);
  const witnessed = await head(f);
  const triggers = (
    await f.sql(
      "SELECT sql,name FROM sqlite_master WHERE type='trigger' AND name IN ('xeip_recovery_entries_delete','xeip_recovery_chunks_delete')",
    )
  ).body.rows;
  for (const t of triggers)
    assert.equal((await f.sql(`DROP TRIGGER ${t.name}`)).status, 200);
  assert.equal(
    (await f.sql("DELETE FROM xeip_recovery_chunks WHERE sequence=2")).status,
    200,
  );
  assert.equal(
    (await f.sql("DELETE FROM xeip_recovery_entries WHERE sequence=2")).status,
    200,
  );
  for (const t of triggers) assert.equal((await f.sql(t.sql)).status, 200);
  assert.equal((await f.send({ operation: "head" })).status, 503);
  const fresh = await reopen(f);
  assert.equal(fresh.status, 200);
  assert.equal(fresh.body.sequence, 1);
  assert.notDeepEqual(fresh.body, witnessed);
});
