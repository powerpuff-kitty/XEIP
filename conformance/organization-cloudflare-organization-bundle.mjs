import { organizationBundleFixture as fixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
const load = () =>
  import("../services/organization/cloudflare/organization-bundle.mjs");
const zero = "0".repeat(64),
  organization = "bundle-fixture";
async function directory(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "xeip-organization-bundle-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return join(root, "bundle");
}

test("organization bundle verifies complete action and multi-page control histories offline", async (t) => {
  const source = fixture({ revisions: 257, attempts: 33 }),
    target = await directory(t),
    { collectOrganizationBundle, verifyOrganizationBundle } = await load();
  const result = await collectOrganizationBundle({
    directory: target,
    ...source,
  });
  const verified = await verifyOrganizationBundle(target, {
    organization,
    expectedDigest: source.checkpoint.manifest.digest,
  });
  assert.equal(canonicalize(verified), canonicalize(result));
  assert.equal(result.checkpoint.digest, source.checkpoint.manifest.digest);
  assert.equal((await fs.stat(target)).mode & 0o777, 0o700);
  for (const name of await fs.readdir(target))
    assert.equal((await fs.stat(join(target, name))).mode & 0o777, 0o600);
  await assert.rejects(
    collectOrganizationBundle({ directory: target, ...source }),
    /collection failed/,
  );
  await assert.rejects(
    verifyOrganizationBundle(target, { organization: "foreign" }),
    /invalid organization bundle/,
  );
  await assert.rejects(
    verifyOrganizationBundle(target, { organization, expectedDigest: zero }),
    /invalid organization bundle/,
  );
});
test("organization bundle includes empty action and administrative histories", async (t) => {
  const source = fixture({ actions: 0 }),
    target = await directory(t),
    { collectOrganizationBundle, verifyOrganizationBundle } = await load();
  await collectOrganizationBundle({ directory: target, ...source });
  assert.equal(
    (await verifyOrganizationBundle(target, { organization })).checkpoint
      .actions.cut,
    0,
  );
});

for (const fault of [
  "section",
  "checkpoint",
  "early-actions",
  "authority-gap",
  "admin-fork",
])
  test(`organization bundle refuses ${fault} pages before sealing`, async (t) => {
    const source = fixture({ attempts: 17 }),
      target = await directory(t),
      { collectOrganizationBundle } = await load();
    await assert.rejects(
      collectOrganizationBundle({
        directory: target,
        ...source,
        readPage: async (manifest, options) => {
          const value = structuredClone(
            await source.readPage(manifest, options),
          );
          if (fault === "section") value.section = "other";
          if (fault === "checkpoint") value.checkpointDigest = zero;
          if (fault === "early-actions" && options.section === "actions")
            value.page = { cut: 2, after: 0, next: 0, record: null };
          if (fault === "authority-gap" && options.section === "authority")
            value.page.records = [];
          if (fault === "admin-fork" && options.section === "administration")
            value.page.records[0].previous = "a".repeat(64);
          return value;
        },
      }),
      /collection failed/,
    );
    await assert.rejects(fs.stat(join(target, "manifest.json")), {
      code: "ENOENT",
    });
  });

for (const fault of [
  "missing",
  "extra",
  "noncanonical",
  "bom",
  "symlink",
  "permissions",
  "component",
  "page",
])
  test(`organization bundle offline verification refuses ${fault} files`, async (t) => {
    const source = fixture(),
      target = await directory(t),
      { collectOrganizationBundle, verifyOrganizationBundle } = await load();
    await collectOrganizationBundle({ directory: target, ...source });
    const file = join(target, "actions-000001.json");
    if (fault === "missing") await fs.unlink(file);
    if (fault === "extra")
      await fs.writeFile(join(target, "extra.json"), "{}\n", { mode: 0o600 });
    if (fault === "noncanonical") await fs.appendFile(file, " ");
    if (fault === "bom")
      await fs.writeFile(file, "\ufeff" + (await fs.readFile(file, "utf8")));
    if (fault === "symlink") {
      await fs.unlink(file);
      await fs.symlink("actions-000002.json", file);
    }
    if (fault === "permissions") await fs.chmod(file, 0o644);
    if (fault === "component") {
      const p = join(target, "trust.json"),
        v = JSON.parse(await fs.readFile(p, "utf8"));
      v.organization = "foreign";
      await fs.writeFile(p, canonicalize(v) + "\n");
    }
    if (fault === "page")
      await fs.copyFile(join(target, "actions-000002.json"), file);
    await assert.rejects(
      verifyOrganizationBundle(target, { organization }),
      /invalid organization bundle/,
    );
  });

for (const fault of ["write", "sync", "reader"])
  test(`organization bundle ${fault} failures cannot return a seal`, async (t) => {
    const source = fixture(),
      target = await directory(t),
      { collectOrganizationBundle } = await load();
    const io = {
      ...fs,
      open: async (path, ...args) => {
        const handle = await fs.open(path, ...args);
        if (String(path).endsWith("lifecycle.json")) {
          if (fault === "write")
            handle.writeFile = async () => {
              throw Error("private failure");
            };
          if (fault === "sync")
            handle.sync = async () => {
              throw Error("private failure");
            };
        }
        return handle;
      },
    };
    await assert.rejects(
      collectOrganizationBundle({
        directory: target,
        ...source,
        io,
        readPage:
          fault === "reader"
            ? async () => {
                throw Error("private credential");
              }
            : source.readPage,
      }),
      (e) => e.message === "organization bundle collection failed",
    );
    await assert.rejects(fs.stat(join(target, "manifest.json")), {
      code: "ENOENT",
    });
  });

test("organization bundle timeout cannot resume collection when a reader settles late", async (t) => {
  const source = fixture(),
    target = await directory(t),
    { collectOrganizationBundle } = await load();
  let resolve;
  const held = new Promise((r) => {
    resolve = r;
  });
  const pending = collectOrganizationBundle({
    directory: target,
    ...source,
    timeoutMs: 100,
    readPage: () => held,
  });
  await assert.rejects(pending, /collection failed/);
  resolve(
    await source.readPage(source.checkpoint.manifest, {
      section: "actions",
      cursor: 0,
    }),
  );
  await new Promise((r) => setTimeout(r, 30));
  await assert.rejects(fs.stat(join(target, "manifest.json")), {
    code: "ENOENT",
  });
});

test("organization bundle rejects a synchronous reader crossing the elapsed deadline", async (t) => {
  const source = fixture(),
    target = await directory(t),
    { collectOrganizationBundle } = await load();
  await assert.rejects(
    collectOrganizationBundle({
      directory: target,
      ...source,
      timeoutMs: 100,
      readPage: async (...args) => {
        const end = performance.now() + 150;
        while (performance.now() < end) {}
        return source.readPage(...args);
      },
    }),
    /collection failed/,
  );
  await assert.rejects(fs.stat(join(target, "manifest.json")), {
    code: "ENOENT",
  });
});

test("organization bundle preserves valid trust records beyond the generic JSON node budget", async (t) => {
  const records = Object.fromEntries(
    Array.from({ length: 3000 }, (_, i) => [
      "retained:" + i,
      {
        anchor: zero,
        generation: 1,
        keyDigest: zero,
        serial: 0,
        statusDigest: zero,
      },
    ]),
  );
  const source = fixture({ records }),
    target = await directory(t),
    { collectOrganizationBundle, verifyOrganizationBundle } = await load();
  await collectOrganizationBundle({ directory: target, ...source });
  assert.equal(
    (await verifyOrganizationBundle(target, { organization })).checkpoint
      .digest,
    source.checkpoint.manifest.digest,
  );
  assert.equal(
    Object.keys(
      JSON.parse(await fs.readFile(join(target, "trust.json"), "utf8")).records,
    ).length,
    3000,
  );
});

test("organization bundle rejects foreign capture before creating a destination", async (t) => {
  const source = fixture(),
    target = await directory(t),
    { collectOrganizationBundle } = await load();
  await assert.rejects(
    collectOrganizationBundle({
      directory: target,
      ...source,
      organization: "foreign",
    }),
    /collection failed/,
  );
  await assert.rejects(fs.stat(target), { code: "ENOENT" });
});

test("organization bundle rejects an audit sequence gap even when every record and the snapshot digest agree", async (t) => {
  const source = fixture({ firstSequence: 2 }),
    target = await directory(t),
    { collectOrganizationBundle } = await load();
  await assert.rejects(
    collectOrganizationBundle({ directory: target, ...source }),
    /collection failed/,
  );
  await assert.rejects(fs.stat(join(target, "manifest.json")), {
    code: "ENOENT",
  });
});

test("organization bundle refuses success after final seal synchronization fails", async (t) => {
  const source = fixture(),
    target = await directory(t),
    { collectOrganizationBundle, verifyOrganizationBundle } = await load();
  const io = {
    ...fs,
    open: async (path, ...args) => {
      const handle = await fs.open(path, ...args);
      if (String(path).endsWith("manifest.json"))
        handle.sync = async () => {
          throw Error("uncertain final sync");
        };
      return handle;
    },
  };
  await assert.rejects(
    collectOrganizationBundle({ directory: target, ...source, io }),
    /collection failed/,
  );
  // Visible bytes after uncertain durability do not certify historical fsync.
  assert.equal(
    (await verifyOrganizationBundle(target, { organization })).checkpoint
      .digest,
    source.checkpoint.manifest.digest,
  );
});
