import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const loader = String.raw`
  function check(resolved) {
    if (/^node:fs(?:\/promises)?$/.test(resolved.url) ||
        /\/services\/organization\/(store|schema|database|mcp)\.mjs$/.test(resolved.url) ||
        /\/node_modules\/(pg|@modelcontextprotocol)\//.test(resolved.url)) {
      throw new Error('orchestration requires concrete adapter: ' + resolved.url);
    }
    return resolved;
  }
  export function resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    return resolved.then ? resolved.then(check) : check(resolved);
  }
`;

// A concrete adapter import would otherwise read migration files or load an
// unused network client before an injected adapter can be supplied.
for (const [module, exported] of [
  ["controller.mjs", "OrganizationController"],
  ["execution.mjs", "createActionExecutor"],
]) {
  test(`${module} loads with storage and connector implementations unavailable`, async () => {
    const script = String.raw`
      import * as moduleHooks from 'node:module';
      import assert from 'node:assert/strict';
      const loader = ${JSON.stringify("data:text/javascript," + encodeURIComponent(loader))};
      if (typeof moduleHooks.registerHooks === 'function')
        moduleHooks.registerHooks(await import(loader));
      else
        moduleHooks.register(loader, import.meta.url);
      const module = await import(${JSON.stringify(new URL(module, import.meta.url).href)});
      assert.equal(typeof module[${JSON.stringify(exported)}], 'function');
    `;
    const result = await run(
      process.execPath,
      ["--input-type=module", "--eval", script],
      { timeout: 15000, maxBuffer: 65536 },
    );
    assert.equal(result.stderr, "");
  });
}
