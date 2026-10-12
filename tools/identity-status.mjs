// Compatibility entrypoint: shared implementation lives in packages/identity.
export * from "../packages/identity/identity-status.mjs";
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { verifyStatusDocument } from "../packages/identity/identity-status.mjs";

function printUsage() {
  return "usage:\n  node tools/identity-status.mjs verify <status.json> <trusted-keydoc.json>\n";
}

function main(argv) {
  const [command, statusPath, trustedPath] = argv;
  if (command === "verify" && statusPath !== undefined && trustedPath !== undefined) {
    try {
      const trusted = JSON.parse(readFileSync(trustedPath, "utf8"));
      const result = verifyStatusDocument(readFileSync(statusPath, "utf8"), trusted);
      process.stdout.write(JSON.stringify(result) + "\n");
      if (!result.valid) process.exitCode = 1;
    } catch (error) {
      process.stderr.write(`error: ${error.message}\n`);
      process.exitCode = 1;
    }
    return;
  }
  process.stderr.write(printUsage());
  process.exitCode = 1;
}

// Run only when invoked directly, so importing the module in tests is silent.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
