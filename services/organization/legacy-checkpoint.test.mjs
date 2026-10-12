import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
  chmodSync,
  symlinkSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openLegacyCheckpoint } from "./legacy-checkpoint.mjs";
import { enroll } from "./test-fixtures/control.mjs";
function fixture(t, existing = true) {
  const parent = mkdtempSync(join(tmpdir(), "xeip-legacy-import-"));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const directory = join(parent, "trust");
  if (existing) mkdirSync(directory, { mode: 0o700 });
  return {
    parent,
    directory,
    file: join(directory, "trust.json"),
    lock: join(directory, "LOCK"),
  };
}
test("legacy import retains every record, excludes another opener and never rewrites checkpoint", (t) => {
  const f = fixture(t);
  const records = enroll().state.records;
  const bytes = JSON.stringify({ version: 1, entities: records });
  writeFileSync(f.file, bytes, { mode: 0o600 });
  const opened = openLegacyCheckpoint(f.directory);
  try {
    assert.deepEqual(opened.records, records);
    assert.equal(Object.isFrozen(opened.records), true);
    assert.throws(() => openLegacyCheckpoint(f.directory));
    opened.assertOwned();
    assert.equal(readFileSync(f.file, "utf8"), bytes);
  } finally {
    opened.close();
  }
  opened.close();
  assert.throws(() => opened.assertOwned());
  assert.equal(existsSync(f.lock), false);
  assert.equal(readFileSync(f.file, "utf8"), bytes);
});
test("absent legacy directory is reserved as empty without inventing checkpoint history", (t) => {
  const f = fixture(t, false);
  const opened = openLegacyCheckpoint(f.directory);
  assert.equal(Object.keys(opened.records).length, 0);
  assert.equal(existsSync(f.lock), true);
  assert.equal(existsSync(f.file), false);
  opened.close();
  assert.equal(existsSync(f.directory), false);
});
for (const kind of [
  "missing",
  "malformed",
  "duplicate",
  "oversized",
  "wrong-shape",
  "invalid-record",
  "symlink",
  "writable",
])
  test(`existing ${kind} history refuses instead of becoming empty`, (t) => {
    const f = fixture(t);
    let data = JSON.stringify({ version: 1, entities: {} });
    if (kind === "malformed") data = "{";
    if (kind === "duplicate") data = '{"version":1,"version":1,"entities":{}}';
    if (kind === "oversized") data = " ".repeat(8 * 1024 * 1024 + 1);
    if (kind === "wrong-shape") data = '{"version":2,"entities":{}}';
    if (kind === "invalid-record") data = '{"version":1,"entities":{"bad":{}}}';
    if (kind !== "missing") writeFileSync(f.file, data, { mode: 0o600 });
    if (kind === "symlink") {
      unlinkSync(f.file);
      symlinkSync(join(f.parent, "elsewhere"), f.file);
    }
    if (kind === "writable") chmodSync(f.file, 0o666);
    assert.throws(() => openLegacyCheckpoint(f.directory));
    assert.equal(existsSync(f.lock), false);
    assert.equal(existsSync(f.directory), true);
  });
test("preexisting legacy lock is never removed", (t) => {
  const f = fixture(t);
  writeFileSync(f.lock, "another-owner", { mode: 0o600 });
  assert.throws(() => openLegacyCheckpoint(f.directory));
  assert.equal(readFileSync(f.lock, "utf8"), "another-owner");
});
test("replacement lock invalidates import and is not removed during close", (t) => {
  const f = fixture(t);
  writeFileSync(f.file, '{"version":1,"entities":{}}', { mode: 0o600 });
  const opened = openLegacyCheckpoint(f.directory);
  unlinkSync(f.lock);
  writeFileSync(f.lock, "replacement", { mode: 0o600 });
  assert.throws(() => opened.assertOwned());
  assert.throws(() => opened.close());
  assert.equal(readFileSync(f.lock, "utf8"), "replacement");
});
test("unsafe or symlink checkpoint directory is refused", (t) => {
  const f = fixture(t);
  chmodSync(f.directory, 0o777);
  assert.throws(() => openLegacyCheckpoint(f.directory));
  chmodSync(f.directory, 0o700);
  const alias = join(f.parent, "alias");
  symlinkSync(f.directory, alias);
  assert.throws(() => openLegacyCheckpoint(alias));
});
