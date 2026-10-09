// tools/check-js.mjs
// Syntax-checks every tracked JavaScript file with `node --check`. The relay and
// tools are plain ESM and are not covered by the TypeScript typecheck, so this
// is the minimal static gate for them. Run with `npm run check:js`.
import { execFileSync } from "node:child_process";

const files = execFileSync("git", ["ls-files", "*.mjs", "*.js"], { encoding: "utf8" })
  .trim().split("\n").filter(Boolean);

let failed = 0;
for (const file of files) {
  try {
    execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
  } catch (error) {
    failed += 1;
    process.stderr.write(`syntax error in ${file}\n${error.stderr?.toString() ?? error.message}\n`);
  }
}
if (failed > 0) {
  process.stderr.write(`${failed} of ${files.length} JS files failed node --check\n`);
  process.exitCode = 1;
} else {
  console.log(`node --check: ${files.length} JS files OK`);
}
