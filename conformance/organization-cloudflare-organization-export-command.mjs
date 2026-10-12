import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { spawnSync } from "node:child_process";
import { organizationBundleFixture as fixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { OrganizationExports } from "../services/organization/cloudflare/organization-export.mjs";
import { parseOwnerCommand } from "../services/organization/cloudflare/profile.mjs";
import { validateOwnerReceipt } from "../services/organization/cloudflare/owner.mjs";
import { verifyOrganizationBundle } from "../services/organization/cloudflare/organization-bundle.mjs";
const load = () =>
  import("../services/organization/cloudflare/organization-export-command.mjs");
const operator = "fixture:operator";
async function setup(t, options = {}) {
  const source = fixture({ revisions: 257, attempts: 33, ...options });
  const directory = await fs.mkdtemp(join(tmpdir(), "xeip-export-command-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const state = { closes: 0, mutate: null, commands: [], error: null };
  const exports = new OrganizationExports({
    organization: source.organization,
    capture: async () => ({
      checkpoint: source.checkpoint,
      assertUsable() {},
      close() {
        state.closes++;
      },
      readPage: (request) =>
        source.readPage(source.checkpoint.manifest, request),
    }),
  });
  t.after(() => exports.close());
  const send = async (raw, exportContext) => {
    const command = parseOwnerCommand(raw);
    state.commands.push(command.operation);
    if (state.error) await state.error(command);
    let field, value;
    if (command.operation === "organizationExportBegin") {
      field = "export";
      value = await exports.begin(operator);
    } else if (command.operation === "organizationExportPart") {
      field = "part";
      value = exports.part(
        operator,
        command.exportId,
        command.component,
        command.index,
      );
    } else if (command.operation === "organizationExportPage") {
      field = "page";
      value = await exports.page(operator, command.exportId, {
        section: command.section,
        cursor: command.cursor,
      });
    } else {
      field = "closed";
      exports.end(operator, command.exportId);
      value = { exportId: command.exportId };
    }
    const receipt = JSON.parse(
      JSON.stringify({
        ok: true,
        operator,
        requestId: command.requestId,
        operation: command.operation,
        [field]: value,
      }),
    );
    state.mutate?.(receipt, command);
    return validateOwnerReceipt(JSON.stringify(receipt), {
      ...command,
      operator,
      exportContext,
    });
  };
  return {
    source,
    state,
    directory: join(directory, "bundle"),
    session: { send },
  };
}

test("owner bundle collector persists complete protected files and confirms source cleanup", async (t) => {
  const h = await setup(t),
    { collectOwnerOrganizationBundle } = await load();
  const result = await collectOwnerOrganizationBundle({
    directory: h.directory,
    organization: h.source.organization,
    session: h.session,
  });
  const verified = await verifyOrganizationBundle(h.directory, {
    organization: h.source.organization,
    expectedDigest: h.source.checkpoint.manifest.digest,
  });
  assert.equal(result.bundle.checksum, verified.checksum);
  assert.equal(result.sourceClosed, true);
  assert.equal(h.state.closes, 1);
  assert.equal((await fs.stat(h.directory)).mode & 0o777, 0o700);
  for (const name of await fs.readdir(h.directory))
    assert.equal((await fs.stat(join(h.directory, name))).mode & 0o777, 0o600);
  const before = await fs.readFile(join(h.directory, "manifest.json"), "utf8");
  await assert.rejects(
    collectOwnerOrganizationBundle({
      directory: h.directory,
      organization: h.source.organization,
      session: h.session,
    }),
    /^Error: organization export failed$/,
  );
  assert.equal(
    await fs.readFile(join(h.directory, "manifest.json"), "utf8"),
    before,
  );
  assert.equal(h.state.closes, 2);
});

for (const fault of [
  "component-hash",
  "noncanonical",
  "malformed-utf8",
  "history",
  "foreign-description",
])
  test(`owner bundle collector refuses ${fault} without sealing or leaking response data`, async (t) => {
    const h = await setup(t),
      { collectOwnerOrganizationBundle } = await load();
    h.state.mutate = (receipt, command) => {
      if (
        fault === "foreign-description" &&
        command.operation === "organizationExportBegin"
      )
        receipt.export.manifest.organization = "foreign";
      if (
        ["noncanonical", "malformed-utf8"].includes(fault) &&
        command.operation === "organizationExportBegin"
      ) {
        const bytes = Buffer.from(
          canonicalize(h.source.checkpoint.trust) + "\n",
        );
        if (fault === "noncanonical") bytes[bytes.length - 1] = 32;
        else bytes[10] = 255;
        receipt.export.components.trust.sha256 = createHash("sha256")
          .update(bytes)
          .digest("hex");
      }
      if (
        command.operation === "organizationExportPart" &&
        command.component === "trust"
      ) {
        const bytes = Buffer.from(receipt.part.data, "base64");
        if (fault === "component-hash") bytes[10] ^= 1;
        if (fault === "noncanonical") bytes[bytes.length - 1] = 32;
        if (fault === "malformed-utf8") bytes[10] = 255;
        receipt.part.data = bytes.toString("base64");
      }
      if (
        fault === "history" &&
        command.operation === "organizationExportPage" &&
        command.section === "authority"
      )
        receipt.page.page.records[0].checksum = "0".repeat(64);
    };
    await assert.rejects(
      collectOwnerOrganizationBundle({
        directory: h.directory,
        organization: h.source.organization,
        session: h.session,
      }),
      /^Error: organization export failed$/,
    );
    await assert.rejects(fs.stat(join(h.directory, "manifest.json")), {
      code: "ENOENT",
    });
    if (fault !== "foreign-description") assert.equal(h.state.closes, 1);
  });

test("owner bundle collector reports unconfirmed cleanup without discarding a verified bundle", async (t) => {
  const h = await setup(t),
    { collectOwnerOrganizationBundle } = await load();
  h.state.error = async (command) => {
    if (command.operation === "organizationExportClose")
      throw Error("must-not-leak");
  };
  const result = await collectOwnerOrganizationBundle({
    directory: h.directory,
    organization: h.source.organization,
    session: h.session,
  });
  assert.equal(result.sourceClosed, false);
  assert.equal(
    (
      await verifyOrganizationBundle(h.directory, {
        organization: h.source.organization,
      })
    ).checksum,
    result.bundle.checksum,
  );
  assert.equal(JSON.stringify(result).includes("must-not-leak"), false);
});

test("owner bundle collector stops after an overdue component response and never resumes a partial collection", async (t) => {
  const h = await setup(t),
    { collectOwnerOrganizationBundle } = await load();
  // Advance the timer only after the component is actually in flight. Source
  // preparation time on a contended host must not choose the fault location.
  let clock = 0;
  t.mock.method(performance, "now", () => clock);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pump = setInterval(() => t.mock.timers.tick(0), 1);
  let entered;
  const inFlight = new Promise((resolve) => {
    entered = resolve;
  });
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const send = h.session.send;
  h.session.send = async (...args) => {
    const result = await send(...args);
    if (JSON.parse(args[0]).operation === "organizationExportPart") {
      entered();
      await held;
    }
    return result;
  };
  try {
    const collecting = collectOwnerOrganizationBundle({
      directory: h.directory,
      organization: h.source.organization,
      session: h.session,
      timeoutMs: 100,
    });
    await Promise.race([
      inFlight,
      collecting.then(() => {
        throw Error("unexpected completion");
      }),
    ]);
    clock = 100;
    t.mock.timers.tick(100);
    await assert.rejects(collecting, /^Error: organization export failed$/);
  } finally {
    release();
    clearInterval(pump);
    t.mock.timers.reset();
    t.mock.restoreAll();
  }
  await new Promise((done) => setImmediate(done));
  await assert.rejects(fs.stat(join(h.directory, "manifest.json")), {
    code: "ENOENT",
  });
  assert.equal(
    h.state.commands.filter((op) => op === "organizationExportPart").length,
    1,
  );
  assert.equal(h.state.closes, 1);
});

for (const cleanup of ["clean", "reject", "hang"]) {
  test(`organization export CLI preserves verified backup with ${cleanup} transport cleanup`, async (t) => {
    const directory = await fs.mkdtemp(join(tmpdir(), "xeip-export-cli-"));
    t.after(() => fs.rm(directory, { recursive: true, force: true }));
    const loader = join(directory, "loader.mjs"),
      configPath = join(directory, "operator.json"),
      target = join(directory, "bundle");
    const configuration = {
      name: "xeip-operator",
      compatibility_date: "2026-07-30",
      services: [
        {
          binding: "OWNER",
          service: "xeip-fixture",
          entrypoint: "OwnerEntrypoint",
          remote: false,
          props: { operator },
        },
      ],
    };
    await fs.writeFile(configPath, JSON.stringify(configuration));
    const sourceModule = new URL(
      "./fixtures/cloudflare/organization-bundle-harness.mjs",
      import.meta.url,
    ).href;
    const exportsModule = new URL(
      "../services/organization/cloudflare/organization-export.mjs",
      import.meta.url,
    ).href;
    const mock = `import {organizationBundleFixture} from ${JSON.stringify(sourceModule)};
import {OrganizationExports} from ${JSON.stringify(exportsModule)};
import {writeFile} from 'node:fs/promises';
export async function getPlatformProxy(options){
 await writeFile(${JSON.stringify(join(directory, "session-path"))}, options.configPath);
 const source=organizationBundleFixture();
 const manager=new OrganizationExports({organization:source.organization,capture:async()=>({checkpoint:source.checkpoint,assertUsable(){},close(){},readPage:request=>source.readPage(source.checkpoint.manifest,request)})});
 return {dispose:async()=>{manager.close(); ${cleanup === "reject" ? "throw Error('must-not-leak');" : cleanup === "hang" ? "await new Promise(()=>{});" : ""}},env:{OWNER:{manage:async raw=>{
  const c=JSON.parse(raw),operator=${JSON.stringify(operator)}; let field,value;
  if(c.operation==='organizationExportBegin'){field='export';value=await manager.begin(operator);}
  else if(c.operation==='organizationExportPart'){field='part';value=manager.part(operator,c.exportId,c.component,c.index);}
  else if(c.operation==='organizationExportPage'){field='page';value=await manager.page(operator,c.exportId,{section:c.section,cursor:c.cursor});}
  else if(c.operation==='organizationExportClose'){field='closed';manager.end(operator,c.exportId);value={exportId:c.exportId};}
  else throw Error('must-not-leak');
  return JSON.stringify({ok:true,operator,operation:c.operation,requestId:c.requestId,[field]:value});
 }}}};
}`;
    await fs.writeFile(
      loader,
      `export async function resolve(s,c,next){if(s==='wrangler')return {url:${JSON.stringify("data:text/javascript," + encodeURIComponent(mock))},shortCircuit:true};return next(s,c)}`,
    );
    const commandPath = new URL(
      "../services/organization/cloudflare/organization-export-command.mjs",
      import.meta.url,
    ).pathname;
    const child = spawnSync(
      process.execPath,
      [
        "--loader",
        loader,
        commandPath,
        "collect",
        configPath,
        "bundle-fixture",
        target,
        "--local",
      ],
      { encoding: "utf8", timeout: 30000 },
    );
    assert.equal(child.status, 0, child.stderr);
    await assert.rejects(
      fs.stat(await fs.readFile(join(directory, "session-path"), "utf8")),
      { code: "ENOENT" },
    );
    const output = JSON.parse(child.stdout);
    assert.deepEqual(Object.keys(output).sort(), [
      "actions",
      "bundleChecksum",
      "checkpointDigest",
      "cut",
      "organization",
      "sourceClosed",
      "transportClosed",
    ]);
    assert.equal(output.organization, "bundle-fixture");
    assert.equal(output.sourceClosed, true);
    assert.equal(output.transportClosed, cleanup === "clean");
    assert.equal(output.actions, 2);
    assert.equal(child.stdout.includes('"private"'), false);
    const checked = spawnSync(
      process.execPath,
      [
        commandPath,
        "verify",
        target,
        "bundle-fixture",
        output.checkpointDigest,
      ],
      { encoding: "utf8", timeout: 30000 },
    );
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(
      JSON.parse(checked.stdout).bundleChecksum,
      output.bundleChecksum,
    );
    for (const args of [
      ["collect", configPath, "foreign", join(directory, "foreign"), "--local"],
      [
        "collect",
        configPath,
        "bundle-fixture",
        join(directory, "wrong-mode"),
        "--remote",
      ],
      ["collect", configPath, "bundle-fixture", join(directory, "no-mode")],
      ["verify", target, "foreign"],
      ["verify", target, "bundle-fixture", "0".repeat(64)],
    ]) {
      const failed = spawnSync(
        process.execPath,
        ["--loader", loader, commandPath, ...args],
        { encoding: "utf8", timeout: 30000 },
      );
      assert.equal(failed.status, 1);
      assert.equal(failed.stdout, "");
      assert.ok(failed.stderr.includes("Organization export failed."));
      assert.equal(failed.stderr.includes("must-not-leak"), false);
    }
    await assert.rejects(fs.stat(join(directory, "wrong-mode")), {
      code: "ENOENT",
    });
    const singleCommand = join(directory, "command.json");
    await fs.writeFile(
      singleCommand,
      JSON.stringify({
        operation: "organizationExportBegin",
        requestId: "34345d17-153a-4214-823a-5c93f2f2f2d7",
      }),
    );
    const generic = spawnSync(
      process.execPath,
      [
        "--loader",
        loader,
        new URL(
          "../services/organization/cloudflare/owner.mjs",
          import.meta.url,
        ).pathname,
        configPath,
        singleCommand,
        "--local",
      ],
      { encoding: "utf8", timeout: 30000 },
    );
    assert.equal(generic.status, 1);
    assert.equal(generic.stdout, "");
  });
}
