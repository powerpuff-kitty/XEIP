import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
const moduleUrl = new URL("./fixture-cleanup.mjs", import.meta.url).href;
for (const signal of ["SIGINT", "SIGTERM"]) {
  test(
    `${signal} drains nested fixture cleanup even after failure and repeated signal`,
    { timeout: 10000 },
    async () => {
      const child = spawn(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `
      import { registerFixtureCleanup } from ${JSON.stringify(moduleUrl)};
      registerFixtureCleanup(() => process.stdout.write("outer\\n"));
      const remove = registerFixtureCleanup(() => process.stdout.write("removed\\n"));
      remove();
      registerFixtureCleanup(() => { throw Error("private fixture secret"); });
      registerFixtureCleanup(async () => {
        process.kill(process.pid, ${JSON.stringify(signal)});
        await new Promise(resolve => setTimeout(resolve, 20));
        process.stdout.write("inner\\n");
      });
      process.stdout.write("ready\\n");
      setInterval(() => {}, 1000);
    `,
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let output = "",
        errors = "",
        sent = false;
      const watchdog = setTimeout(() => child.kill("SIGKILL"), 8000);
      child.stdout.on("data", (data) => {
        output += data;
        if (!sent && output.includes("ready\n")) {
          sent = true;
          child.kill(signal);
        }
      });
      child.stderr.on("data", (data) => {
        errors += data;
      });
      try {
        const result = await new Promise((resolve, reject) => {
          child.once("error", reject);
          child.once("close", (code, signal) => resolve({ code, signal }));
        });
        assert.deepEqual(result, { code: 1, signal: null });
        assert.equal(output, "ready\ninner\nouter\n");
        assert.equal(
          errors,
          "Owned fixture cleanup failed; inspect remaining xeip fixture resources.\n",
        );
      } finally {
        clearTimeout(watchdog);
        child.kill("SIGKILL");
      }
    },
  );
}
test("unregistering the last fixture removes only coordinator signal listeners", async () => {
  const { registerFixtureCleanup } = await import("./fixture-cleanup.mjs");
  const original = [
    process.listenerCount("SIGINT"),
    process.listenerCount("SIGTERM"),
  ];
  const remove = registerFixtureCleanup(() =>
    assert.fail("unregistered cleanup"),
  );
  assert.equal(process.listenerCount("SIGINT"), original[0] + 1);
  assert.equal(process.listenerCount("SIGTERM"), original[1] + 1);
  remove();
  remove();
  assert.deepEqual(
    [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")],
    original,
  );
});
