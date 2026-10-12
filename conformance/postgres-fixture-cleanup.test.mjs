// Process-level failure-path checks. The private Docker shim never calls Docker.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";

const fixture = new URL("./postgres.mjs", import.meta.url).href;
for (const mode of [
  "created",
  "absent",
  "foreign",
  "inspect-failed",
  "remove-failed",
]) {
  test(`PostgreSQL create failure cleanup: ${mode}`, { timeout: 10000 }, () => {
    const directory = fs.mkdtempSync(
      join(tmpdir(), "xeip-fixture-cleanup-test-"),
    );
    const stateFile = join(directory, "state.json");
    let state;
    try {
      fs.writeFileSync(
        join(directory, "docker"),
        `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
const mode = process.env.XEIP_TEST_CREATE_MODE;
const stateFile = process.env.XEIP_TEST_CREATE_STATE;
const save = state => fs.writeFileSync(stateFile, JSON.stringify(state), {mode:0o600});
if (args[0] === 'image' && args[1] === 'inspect') process.exit(0);
if (args[0] === 'create') {
  const name = args[args.indexOf('--name') + 1];
  const labelIndex = args.indexOf('--label');
  const label = labelIndex < 0 ? '' : args[labelIndex + 1];
  const mount = args[args.indexOf('--mount') + 1];
  const passwordFile = /src=([^,]+)/.exec(mount)[1];
  save({name,label,passwordFile,secret:fs.readFileSync(passwordFile,'utf8'),removed:false});
  process.stderr.write('synthetic create response failure');
  process.exit(77);
}
const state = JSON.parse(fs.readFileSync(stateFile,'utf8'));
if (args[0] === 'inspect') {
  if (mode === 'absent') {
    process.stderr.write('Error: No such object: ' + state.name + '\\n'); process.exit(1);
  }
  if (mode === 'inspect-failed') {
    process.stderr.write('Cannot connect to Docker daemon\\n'); process.exit(1);
  }
  process.stdout.write(mode === 'foreign' ? 'another-owner\\n' : state.name + '\\n');
  process.exit(0);
}
if (args[0] === 'rm') {
  if (args.at(-1) !== state.name || !args.includes('-v')) process.exit(89);
  state.removeAttempted = true; save(state);
  if (mode === 'remove-failed') {
    process.stderr.write('synthetic container removal failure'); process.exit(78);
  }
  state.removed = true; save(state); process.exit(0);
}
process.exit(90);
`,
        { mode: 0o700 },
      );
      const child = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `
import { withPostgres } from ${JSON.stringify(fixture)};
try { await withPostgres(() => {}, {baselineChecks:false}); process.exitCode = 2; }
catch (error) { process.stdout.write(JSON.stringify({message:error.message})); process.exitCode = 1; }
`,
        ],
        {
          env: {
            ...process.env,
            PATH: directory + ":" + process.env.PATH,
            XEIP_TEST_CREATE_MODE: mode,
            XEIP_TEST_CREATE_STATE: stateFile,
          },
          encoding: "utf8",
          timeout: 8000,
        },
      );
      assert.equal(child.status, 1, "fixture must reject the ambiguous create");
      state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      assert.match(
        state.label,
        /^xeip\.postgres-fixture=xeip-postgres-fixture-/,
      );
      assert.equal(state.label, "xeip.postgres-fixture=" + state.name);
      assert.equal(state.removed, mode === "created");
      assert.equal(
        !!state.removeAttempted,
        mode === "created" || mode === "remove-failed",
      );
      assert.equal(
        fs.existsSync(state.passwordFile),
        mode === "foreign" ||
          mode === "inspect-failed" ||
          mode === "remove-failed",
      );
      const message = JSON.parse(child.stdout).message;
      if (
        mode === "foreign" ||
        mode === "inspect-failed" ||
        mode === "remove-failed"
      )
        assert.match(message, /cleanup failed/);
      else assert.doesNotMatch(message, /cleanup failed/);
      assert.ok(!child.stdout.includes(state.secret));
      assert.ok(!child.stderr.includes(state.secret));
    } finally {
      if (!state && fs.existsSync(stateFile))
        state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      if (state?.passwordFile) {
        assert.match(basename(dirname(state.passwordFile)), /^xeip-postgres-/);
        fs.rmSync(dirname(state.passwordFile), {
          recursive: true,
          force: true,
        });
      }
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
}
