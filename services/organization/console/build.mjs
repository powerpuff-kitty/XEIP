/** Fixed-name, local-only console bundle; no source maps or remote dependencies. */
import { build } from "esbuild";
import { readFile, mkdir, writeFile, copyFile } from "node:fs/promises";
import { createHash } from "node:crypto";
const root = new URL("../../../", import.meta.url),
  output = new URL("dist/console/", root);
await mkdir(output, { recursive: true });
await build({
  entryPoints: [new URL("app.mjs", import.meta.url).pathname],
  outfile: new URL("app.js", output).pathname,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  sourcemap: false,
  legalComments: "inline",
  logLevel: "warning",
});
for (const name of ["index.html", "app.css"])
  await copyFile(new URL(name, import.meta.url), new URL(name, output));
const dependency = JSON.parse(
  await readFile(
    new URL("node_modules/keycloak-js/package.json", root),
    "utf8",
  ),
);
const license = await readFile(
  new URL("node_modules/keycloak-js/LICENSE.txt", root),
  "utf8",
);
await writeFile(
  new URL("THIRD_PARTY_LICENSES.txt", output),
  `keycloak-js ${dependency.version}\n${license}`,
);
const files = {};
for (const name of [
  "index.html",
  "app.js",
  "app.css",
  "THIRD_PARTY_LICENSES.txt",
])
  files[name] = createHash("sha256")
    .update(await readFile(new URL(name, output)))
    .digest("hex");
await writeFile(
  new URL("manifest.json", output),
  JSON.stringify(
    {
      schema: "xeip.console/1",
      dependencies: [
        {
          name: dependency.name,
          version: dependency.version,
          license: dependency.license,
        },
      ],
      files,
    },
    null,
    2,
  ) + "\n",
);
console.log(
  "Built console assets with pinned Keycloak adapter and license inventory.",
);
