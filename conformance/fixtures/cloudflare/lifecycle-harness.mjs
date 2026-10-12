/** TEST ONLY: local workerd with private fixture controls. */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
export async function harness({
  entryPoint = new URL(
    "../../organization-cloudflare-lifecycle-worker.mjs",
    import.meta.url,
  ).pathname,
  className = "LifecycleFixture",
  outboundService,
  durableObjects = {},
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "xeip-lifecycle-")),
    scriptPath = join(directory, "worker.mjs");
  let mf,
    sequence = 0;
  const start = async () => {
    mf = new Miniflare({
      host: "127.0.0.1",
      port: 0,
      modules: true,
      modulesRoot: directory,
      scriptPath,
      compatibilityDate: "2026-07-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: {
        ...durableObjects,
        LIFECYCLE: { className, useSQLite: true },
      },
      durableObjectsPersist: join(directory, "storage"),
      ...(outboundService ? { outboundService } : {}),
    });
    await mf.ready;
  };
  try {
    await build({
      entryPoints: [entryPoint],
      outfile: scriptPath,
      bundle: true,
      format: "esm",
      platform: "neutral",
      conditions: ["browser"],
      external: ["cloudflare:workers", "node:*"],
      logLevel: "silent",
    });
    await start();
  } catch (error) {
    await mf?.dispose();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
  return {
    async fixture(name = "case-" + ++sequence, binding = "LIFECYCLE") {
      const namespace = await mf.getDurableObjectNamespace(binding),
        stub = namespace.get(namespace.idFromName(name));
      const send = async (input) => {
        const response = await stub.fetch("https://fixture.invalid/", {
          method: "POST",
          body: JSON.stringify(input),
        });
        return { status: response.status, body: await response.json() };
      };
      return {
        name,
        send,
        sql: (query, ...bindings) =>
          send({ operation: "sql", query, bindings }),
      };
    },
    async restart() {
      await mf.dispose();
      await start();
    },
    async close() {
      await mf?.dispose();
      await rm(directory, { recursive: true, force: true });
    },
  };
}
