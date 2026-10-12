/** Offline artifact builder. It never loads credentials or invokes deployment. */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { build } from "esbuild";
import { parseProfile } from "./profile.mjs";
const root = fileURLToPath(new URL("../../../", import.meta.url));
/** @param {{profile:string,name:string,outdir:string}} options */
export async function buildPackage({ profile, name, outdir }) {
  const configuration = parseProfile(profile);
  if (
    typeof name !== "string" ||
    !/^[a-z][a-z0-9-]{0,62}$/.test(name) ||
    (configuration.trustFeed && name.length > 55)
  )
    throw new TypeError("invalid Worker name");
  const result = await build({
    absWorkingDir: root,
    entryPoints: ["services/organization/cloudflare/worker.mjs"],
    bundle: true,
    write: false,
    metafile: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    conditions: ["browser"],
    external: ["cloudflare:workers", "node:*"],
    logLevel: "silent",
  });
  const lock = JSON.parse(
    await readFile(join(root, "package-lock.json"), "utf8"),
  );
  const packages = new Map();
  for (const input of Object.keys(result.metafile.inputs)) {
    const at = input.lastIndexOf("node_modules/");
    if (at < 0) continue;
    const suffix = input.slice(at + "node_modules/".length).split("/");
    const name = suffix[0].startsWith("@")
      ? suffix.slice(0, 2).join("/")
      : suffix[0];
    const key = input.slice(0, at) + "node_modules/" + name;
    const dependency = lock.packages[key];
    if (!dependency?.version || !dependency?.integrity)
      throw new Error("missing package provenance");
    packages.set(key, {
      name,
      version: dependency.version,
      integrity: dependency.integrity,
    });
  }
  const config = {
    name,
    main: "worker.mjs",
    compatibility_date: "2026-07-30",
    compatibility_flags: ["nodejs_compat"],
    no_bundle: true,
    workers_dev: false,
    preview_urls: false,
    routes: [],
    triggers: { crons: [] },
    durable_objects: {
      bindings: [{ name: "ORGANIZATION", class_name: "OrganizationObject" }],
    },
    migrations: [{ tag: "v1", new_sqlite_classes: ["OrganizationObject"] }],
    vars: { XEIP_PROFILE: JSON.stringify(configuration) },
    observability: {
      enabled: true,
      logs: { enabled: true, invocation_logs: false },
    },
  };
  const files = new Map([
    ["worker.mjs", result.outputFiles[0].contents],
    ["wrangler.json", Buffer.from(JSON.stringify(config, null, 2) + "\n")],
  ]);
  if (configuration.trustFeed) {
    const scheduler = {
      name: name + "-refresh",
      main: "scheduler.mjs",
      compatibility_date: config.compatibility_date,
      no_bundle: true,
      workers_dev: false,
      preview_urls: false,
      routes: [],
      triggers: { crons: ["* * * * *"] },
      services: [
        {
          binding: "REFRESH",
          service: name,
          entrypoint: "RefreshEntrypoint",
          props: { purpose: "trust-refresh" },
        },
      ],
      observability: config.observability,
    };
    files.set(
      "scheduler.mjs",
      await readFile(
        join(root, "services/organization/cloudflare/scheduler.mjs"),
      ),
    );
    files.set(
      "scheduler.wrangler.json",
      Buffer.from(JSON.stringify(scheduler, null, 2) + "\n"),
    );
  }
  const manifest = {
    schema: 1,
    experimental: true,
    compatibilityDate: config.compatibility_date,
    files: [...files].map(([path, data]) => ({
      path,
      bytes: data.length,
      sha256: createHash("sha256").update(data).digest("hex"),
    })),
    packages: [...packages.values()].sort((a, b) =>
      a.name.localeCompare(b.name),
    ),
    tooling: {
      esbuild: lock.packages["node_modules/esbuild"].version,
      wrangler: lock.packages["node_modules/wrangler"].version,
    },
  };
  const destination = resolve(outdir);
  await mkdir(destination, { recursive: false, mode: 0o700 });
  for (const [path, data] of files)
    await writeFile(join(destination, path), data, { flag: "wx", mode: 0o600 });
  await writeFile(
    join(destination, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
    { flag: "wx", mode: 0o600 },
  );
  return manifest;
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [profilePath, name, outdir, ...extra] = process.argv.slice(2);
    if (!profilePath || !name || !outdir || extra.length)
      throw new Error("usage");
    const profile = await readFile(profilePath, "utf8");
    const manifest = await buildPackage({ profile, name, outdir });
    console.log(
      JSON.stringify({ artifact: resolve(outdir), files: manifest.files }),
    );
  } catch {
    console.error(
      "Cloudflare package failed. Usage: node build.mjs PUBLIC_PROFILE.json WORKER_NAME NEW_OUTPUT_DIRECTORY",
    );
    process.exitCode = 1;
  }
}
