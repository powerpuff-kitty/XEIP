// Compatibility entrypoint: shared implementation lives in packages/identity.
export * from "../packages/identity/key-document.mjs";
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { verifyKeyDocument } from "../packages/identity/key-document.mjs";

function printUsage() {
  return "usage:\n  node tools/key-document.mjs verify <file.json>\n";
}

function main(argv) {
  const [command, argument] = argv;
  if (command === "verify" && argument !== undefined) {
    try {
      const result = verifyKeyDocument(readFileSync(argument, "utf8"));
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
