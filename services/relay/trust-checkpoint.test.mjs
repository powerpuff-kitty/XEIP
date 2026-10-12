import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { syncBuiltinESMExports } from "node:module";
import { TrustCheckpoint } from "./trust-checkpoint.mjs";
const entity = "urn:test:entity";
const record = {
  anchor: "a".repeat(64),
  generation: 1,
  keyDigest: "b".repeat(64),
  serial: 1,
  statusDigest: "c".repeat(64),
};
function directory(t) {
  const dir = fs.mkdtempSync(join(tmpdir(), "xeip-trust-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return join(dir, "state");
}
const state = (patch = {}) => ({ [entity]: { ...record, ...patch } });
test("checkpoints reject restart rollback, same-counter forks and anchor replacement", (t) => {
  const dir = directory(t);
  new TrustCheckpoint(dir, state()).close();
  new TrustCheckpoint(
    dir,
    state({
      generation: 2,
      keyDigest: "d".repeat(64),
      serial: 2,
      statusDigest: "e".repeat(64),
    }),
    { [entity]: { 1: record.keyDigest, 2: "d".repeat(64) } },
  ).close();
  for (const next of [
    state(),
    state({
      generation: 2,
      keyDigest: "f".repeat(64),
      serial: 2,
      statusDigest: "e".repeat(64),
    }),
    state({ generation: 2, keyDigest: "d".repeat(64), serial: 2 }),
    state({
      anchor: "f".repeat(64),
      generation: 2,
      keyDigest: "d".repeat(64),
      serial: 2,
      statusDigest: "e".repeat(64),
    }),
  ]) {
    assert.throws(() => new TrustCheckpoint(dir, next), /rollback|fork|anchor/);
    assert.equal(fs.existsSync(join(dir, "LOCK")), false);
  }
});
test("omitting an entity preserves its high-water checkpoint", (t) => {
  const dir = directory(t);
  new TrustCheckpoint(dir, state({ serial: 2 })).close();
  new TrustCheckpoint(dir, {}).close();
  assert.throws(() => new TrustCheckpoint(dir, state()), /rollback/);
});
test("missing or corrupt checkpoint never silently initializes an existing directory", (t) => {
  const dir = directory(t);
  fs.mkdirSync(dir);
  assert.throws(() => new TrustCheckpoint(dir, state()), /checkpoint/);
  fs.writeFileSync(join(dir, "trust.json"), "{bad");
  assert.throws(() => new TrustCheckpoint(dir, state()), /checkpoint/);
});
test("exclusive checkpoint ownership ends at close", (t) => {
  const dir = directory(t),
    store = new TrustCheckpoint(dir, state());
  t.after(() => store.close());
  assert.throws(() => new TrustCheckpoint(dir, state()), /locked/);
  store.close();
  new TrustCheckpoint(dir, state()).close();
});
test("failed checkpoint replacement preserves prior state and releases ownership", (t) => {
  const dir = directory(t);
  new TrustCheckpoint(dir, state()).close();
  const before = fs.readFileSync(join(dir, "trust.json"), "utf8");
  fs.mkdirSync(join(dir, "trust.json.tmp"));
  assert.throws(() => new TrustCheckpoint(dir, state({ serial: 2 })));
  assert.equal(fs.existsSync(join(dir, "LOCK")), false);
  assert.equal(fs.readFileSync(join(dir, "trust.json"), "utf8"), before);
  fs.rmSync(join(dir, "trust.json.tmp"), { recursive: true });
  new TrustCheckpoint(dir, state()).close();
});
test("directory sync failure refuses checkpoint activation", (t) => {
  const dir = directory(t),
    original = fs.fsyncSync;
  const mocked = t.mock.method(fs, "fsyncSync", (fd) => {
    if (fs.fstatSync(fd).isDirectory())
      throw Object.assign(new Error("sync failed"), { code: "EIO" });
    return original(fd);
  });
  syncBuiltinESMExports();
  try {
    assert.throws(() => new TrustCheckpoint(dir, state()), /sync failed/);
    assert.equal(fs.existsSync(join(dir, "LOCK")), false);
  } finally {
    mocked.mock.restore();
    syncBuiltinESMExports();
  }
});

test("live checkpoint updates preserve ownership, reject rollback and survive reopen", (t) => {
  const dir = directory(t),
    store = new TrustCheckpoint(dir, state());
  t.after(() => store.close());
  store.update(state({ serial: 2, statusDigest: "d".repeat(64) }));
  assert.throws(() => new TrustCheckpoint(dir, state()), /locked/);
  assert.throws(() => store.update(state()), /rollback/);
  assert.equal(store.healthy, true);
  store.close();
  assert.throws(() => store.update(state()), /closed/);
  assert.throws(() => new TrustCheckpoint(dir, state()), /rollback/);
  new TrustCheckpoint(
    dir,
    state({ serial: 2, statusDigest: "d".repeat(64) }),
  ).close();
});

test("failed live persistence poisons the checkpoint while retaining its lock", (t) => {
  const dir = directory(t),
    store = new TrustCheckpoint(dir, state());
  t.after(() => store.close());
  fs.mkdirSync(join(dir, "trust.json.tmp"));
  assert.throws(() =>
    store.update(state({ serial: 2, statusDigest: "d".repeat(64) })),
  );
  assert.equal(store.healthy, false);
  assert.throws(() => new TrustCheckpoint(dir, state()), /locked/);
  fs.rmSync(join(dir, "trust.json.tmp"), { recursive: true });
  assert.throws(() => store.update(state()), /reopen/);
  store.close();
  new TrustCheckpoint(dir, state()).close();
});
