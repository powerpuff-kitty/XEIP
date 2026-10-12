import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
test("launcher rejects missing/unknown commands with redacted nonzero exit", async () => {
  for (const args of [
    [],
    ["serve", "--config", "/missing/sensitive-config"],
    ["publish"],
    ["check", "--config", "/missing/sensitive-config"],
  ]) {
    await assert.rejects(
      exec(process.execPath, ["services/organization/main.mjs", ...args], {
        timeout: 30000,
      }),
      (error) => {
        assert.equal(error.code, 1);
        assert.equal(error.stderr.includes("sensitive-config"), false);
        assert.equal(error.stderr.includes("Error:"), false);
        assert.equal(error.stderr.includes("startup_failed"), true);
        return true;
      },
    );
  }
});
test("maintenance requires explicit protected owner configuration and a runtime role", async () => {
  await assert.rejects(
    exec(
      process.execPath,
      [
        "services/organization/maintenance.mjs",
        "--config",
        "/missing/private-owner",
        "--runtime-role",
        "pg_owner",
      ],
      { timeout: 30000 },
    ),
    (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stderr, '{"event":"maintenance_failed"}\n');
      return true;
    },
  );
});
test("control commands redact invalid arguments and protected-file failures", async () => {
  for (const args of [
    [],
    ["inspect", "--owner-config", "/missing/private-owner"],
    [
      "enroll",
      "--owner-config",
      "/missing/private-owner",
      "--runtime-config",
      "/private-runtime",
      "--expect-empty",
    ],
    [
      "change",
      "--owner-config",
      "/private-owner",
      "--runtime-config",
      "/private-runtime",
      "--expected-revision",
      "1",
      "--expected-digest",
      "sensitive-input",
    ],
  ]) {
    await assert.rejects(
      exec(
        process.execPath,
        ["services/organization/control-maintenance.mjs", ...args],
        { timeout: 30000 },
      ),
      (error) => {
        assert.equal(error.code, 1);
        assert.equal(error.stdout, "");
        assert.equal(error.stderr, '{"event":"control_maintenance_failed"}\n');
        return true;
      },
    );
  }
});
