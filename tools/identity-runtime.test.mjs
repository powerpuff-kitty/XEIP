import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

// A runtime import of a CLI would force command wrappers into deployed artifacts.
test("production entrypoints resolve without command-line modules", async () => {
  const result = await build({
    absWorkingDir: fileURLToPath(new URL("../", import.meta.url)),
    entryPoints: [
      "services/relay/server.mjs",
      "services/organization/main.mjs",
      "services/organization/maintenance.mjs",
    ],
    bundle: true,
    platform: "node",
    format: "esm",
    packages: "external",
    outdir: "unused",
    write: false,
    metafile: true,
    logLevel: "silent",
  });
  assert.deepEqual(
    Object.keys(result.metafile.inputs).filter((path) =>
      path.startsWith("tools/"),
    ),
    [],
  );
});
