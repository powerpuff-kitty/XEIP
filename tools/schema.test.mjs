import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

test("fixture CLI rejects schema-invalid positive fixtures", () => {
  const directory = mkdtempSync(join(tmpdir(), "xeip-fixtures-"));
  try {
    cpSync(new URL("../conformance/fixtures", import.meta.url), directory, { recursive: true });
    const messagePath = join(directory, "message.valid.json");
    const value = JSON.parse(readFileSync(messagePath));
    value.timestamp = "2026-02-30T12:00:00Z";
    writeFileSync(messagePath, JSON.stringify(value));
    const result = spawnSync(process.execPath, [
      new URL("./validate-fixtures.mjs", import.meta.url).pathname, "--fixtures-dir", directory
    ], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /message.valid.json|timestamp/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("fixture CLI rejects a negative fixture that conforms to its schema", () => {
  const directory = mkdtempSync(join(tmpdir(), "xeip-fixtures-"));
  try {
    cpSync(new URL("../conformance/fixtures", import.meta.url), directory, { recursive: true });
    const value = JSON.parse(readFileSync(join(directory, "message.valid.json")));
    // Keep the old checker's version assertion satisfied while introducing a different false negative.
    writeFileSync(join(directory, "message.invalid-calendar.json"), JSON.stringify(value));
    const result = spawnSync(process.execPath, [
      new URL("./validate-fixtures.mjs", import.meta.url).pathname, "--fixtures-dir", directory
    ], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /message.invalid-calendar.json/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
