import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { auditChecksum } from "../services/organization/cloudflare/admin-audit.mjs";
import {
  collectArchive,
  verifyArchive,
} from "../services/organization/cloudflare/archive.mjs";
const source = {
  name: "xeip-archive",
  compatibility_date: "2026-07-30",
  services: [
    {
      binding: "OWNER",
      service: "xeip-staging",
      entrypoint: "OwnerEntrypoint",
      remote: false,
      props: { operator: "operations:archive" },
    },
  ],
};
const zero = "0".repeat(64);
const state = { state: "initialized", trustRevision: 1, authorityRevision: 0 };
function records(count = 40) {
  const rows = [];
  let previous = zero,
    start;
  for (let i = 1; i <= count; i++) {
    if (i % 2)
      start = {
        operator: "fixture:owner",
        requestId: randomUUID(),
        operation: "refreshTrust",
        commandDigest: "a".repeat(64),
        attemptId: randomUUID(),
        outcome: "started",
        occurredAt: 1000 + i,
        before: state,
      };
    const event =
      i % 2
        ? start
        : {
            ...start,
            outcome: "completed",
            occurredAt: 1000 + i,
            after: state,
          };
    const checksum = auditChecksum(i, previous, canonicalize(event));
    rows.push({ sequence: i, event, previous, checksum });
    previous = checksum;
  }
  return rows;
}
function page(rows, after, limit) {
  const values = rows.slice(after, after + limit);
  return {
    records: values,
    next: after + values.length,
    headSequence: rows.length,
    headChecksum: rows.at(-1)?.checksum ?? zero,
  };
}
async function setup(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "xeip-archive-test-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}
const reader =
  (rows) =>
  async ({ after, limit }) =>
    page(rows, after, limit);
test("archive seals a complete fixed cut, preserves unknown attempts and verifies offline", async (t) => {
  const root = await setup(t),
    rows = records(41),
    directory = join(root, "archive");
  const manifest = await collectArchive({
    directory,
    source,
    readPage: reader(rows),
  });
  assert.equal(manifest.records, 41);
  assert.equal(manifest.pages, 3);
  assert.equal(manifest.headChecksum, rows.at(-1).checksum);
  assert.equal(
    canonicalize(await verifyArchive(directory)),
    canonicalize(manifest),
  );
  assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
  for (const name of await fs.readdir(directory))
    assert.equal((await fs.stat(join(directory, name))).mode & 0o777, 0o600);
  await assert.rejects(
    collectArchive({ directory, source, readPage: reader(rows) }),
  );
});
test("archive stops at the first head while source grows", async (t) => {
  const root = await setup(t),
    rows = records(40),
    extra = records(44); // first40 remain identical; append a new valid started event.
  let previous = rows.at(-1).checksum;
  for (const row of extra.slice(40)) {
    row.previous = previous;
    row.checksum = auditChecksum(
      row.sequence,
      previous,
      canonicalize(row.event),
    );
    rows.push(row);
    previous = row.checksum;
  }
  let calls = 0;
  const manifest = await collectArchive({
    directory: join(root, "archive"),
    source,
    readPage: async ({ after, limit }) =>
      page(calls++ ? rows : rows.slice(0, 40), after, limit),
  });
  assert.equal(manifest.records, 40);
  assert.equal(calls, 3);
});
for (const mode of ["link", "time", "terminal", "duplicate terminal", "head"])
  test(
    "archive rejects cross-page " + mode + " inconsistency without a seal",
    async (t) => {
      const root = await setup(t),
        rows = records(40),
        directory = join(root, "bad");
      if (mode === "link") rows[16].previous = "b".repeat(64);
      if (mode === "time") rows[16].event.occurredAt = 1;
      if (mode === "terminal") rows[17].event.commandDigest = "c".repeat(64);
      if (mode === "duplicate terminal")
        rows[18].event = { ...rows[17].event, occurredAt: 1019 };
      if (mode !== "head")
        for (let i = 16; i < rows.length; i++) {
          if (i > 16) rows[i].previous = rows[i - 1].checksum;
          rows[i].checksum = auditChecksum(
            i + 1,
            rows[i].previous,
            canonicalize(rows[i].event),
          );
        }
      await assert.rejects(
        collectArchive({
          directory,
          source,
          readPage: async ({ after, limit }) => {
            const p = page(rows, after, limit);
            if (mode === "head" && after) p.headChecksum = "d".repeat(64);
            return p;
          },
        }),
      );
      await assert.rejects(fs.stat(join(directory, "manifest.json")));
    },
  );
test("prior complete archive pins source, high-water mark and historical hash", async (t) => {
  const root = await setup(t),
    rows = records(40),
    previous = join(root, "previous");
  await collectArchive({
    directory: previous,
    source,
    readPage: reader(rows.slice(0, 16)),
  });
  const good = await collectArchive({
    directory: join(root, "next"),
    source,
    previous,
    readPage: reader(rows),
  });
  assert.equal(good.previous.headSequence, 16);
  assert.equal(good.previous.headChecksum, rows[15].checksum);
  for (const [name, candidate, s] of [
    ["rollback", rows.slice(0, 10), source],
    ["fork", records(40), source],
    ["source", rows, { ...source, name: "xeip-different" }],
  ])
    await assert.rejects(
      collectArchive({
        directory: join(root, name),
        source: s,
        previous,
        readPage: reader(candidate),
      }),
    );
});
for (const mode of ["truncated", "extra", "permissive", "symlink", "manifest"])
  test("offline verifier rejects " + mode + " archive", async (t) => {
    const root = await setup(t),
      directory = join(root, "archive");
    await collectArchive({ directory, source, readPage: reader(records()) });
    if (mode === "truncated")
      await fs.truncate(join(directory, "000001.json"), 10);
    if (mode === "extra") await fs.writeFile(join(directory, "extra"), "x");
    if (mode === "permissive")
      await fs.chmod(join(directory, "000001.json"), 0o644);
    if (mode === "symlink") {
      await fs.rename(join(directory, "000001.json"), join(root, "page"));
      await fs.symlink(join(root, "page"), join(directory, "000001.json"));
    }
    if (mode === "manifest") {
      const path = join(directory, "manifest.json");
      const m = JSON.parse(await fs.readFile(path, "utf8"));
      m.records--;
      await fs.writeFile(path, canonicalize(m) + "\n");
    }
    await assert.rejects(verifyArchive(directory));
  });
for (const phase of ["page-write", "page-sync", "seal-sync", "directory-sync"])
  test(
    "failure during " +
      phase +
      " never reports archive success or overwrites prior files",
    async (t) => {
      const root = await setup(t),
        directory = join(root, "archive");
      let failed = false;
      const io = {
        ...fs,
        open: async (path, flags, ...rest) => {
          const h = await fs.open(path, flags, ...rest);
          if (String(flags).includes("x")) {
            const write = h.writeFile.bind(h),
              sync = h.sync.bind(h);
            h.writeFile = async (...args) => {
              if (
                phase === "page-write" &&
                String(path).endsWith("000001.json")
              ) {
                failed = true;
                throw Error("secret-internal-error");
              }
              return write(...args);
            };
            h.sync = async () => {
              if (
                (phase === "page-sync" &&
                  String(path).endsWith("000001.json")) ||
                (phase === "seal-sync" &&
                  String(path).endsWith("manifest.json"))
              ) {
                failed = true;
                throw Error("secret-internal-error");
              }
              return sync();
            };
          } else if (phase === "directory-sync" && path === directory) {
            h.sync = async () => {
              failed = true;
              throw Error("secret-internal-error");
            };
          }
          return h;
        },
      };
      await assert.rejects(
        collectArchive({ directory, source, readPage: reader(records()), io }),
        { message: "archive collection failed" },
      );
      assert.equal(failed, true);
      if (phase !== "seal-sync")
        await assert.rejects(fs.stat(join(directory, "manifest.json")));
    },
  );
test("empty archive is valid and RPC failure is redacted", async (t) => {
  const root = await setup(t);
  const result = await collectArchive({
    directory: join(root, "empty"),
    source,
    readPage: reader([]),
  });
  assert.equal(result.records, 0);
  assert.equal(result.headChecksum, zero);
  await assert.rejects(
    collectArchive({
      directory: join(root, "bad"),
      source,
      readPage: async () => {
        throw Error("sensitive endpoint");
      },
    }),
    { message: "archive collection failed" },
  );
});

test("RPC deadline leaves an unsealed directory and cannot commit a late response", async (t) => {
  const root = await setup(t),
    directory = join(root, "late");
  let release;
  await assert.rejects(
    collectArchive({
      directory,
      source,
      timeoutMs: 100,
      readPage: () => new Promise((r) => (release = r)),
    }),
    { message: "archive collection failed" },
  );
  release(page(records(), 0, 16));
  await new Promise((r) => setTimeout(r, 10));
  await assert.rejects(fs.stat(join(directory, "manifest.json")));
  assert.deepEqual(await fs.readdir(directory), []);
});
test("offline verifier refuses a FIFO manifest without waiting for a writer", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const root = await setup(t),
    directory = join(root, "fifo");
  await fs.mkdir(directory, { mode: 0o700 });
  assert.equal(
    spawnSync("mkfifo", [join(directory, "manifest.json")]).status,
    0,
  );
  const moduleUrl = new URL(
    "../services/organization/cloudflare/archive.mjs",
    import.meta.url,
  ).href;
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `import {verifyArchive} from ${JSON.stringify(moduleUrl)};try{await verifyArchive(${JSON.stringify(directory)});process.exit(1);}catch{process.exit(0);}`,
    ],
    { timeout: 5000 },
  );
  assert.equal(
    result.status,
    0,
    "verifier must reject without blocking on FIFO",
  );
});

import { harness } from "./fixtures/cloudflare/worker-harness.mjs";
import {
  identity,
  configuration,
  provisioning,
} from "./fixtures/cloudflare/authority-harness.mjs";
import { validateOwnerReceipt } from "../services/organization/cloudflare/owner.mjs";
test("native private export collects multiple pages without writing source and verifies after restart", async (t) => {
  const root = await setup(t),
    actors = [identity("agent"), identity("human")];
  const profile = {
    organization: "archive-fixture",
    origin: "https://xeip.example",
    gateway: actors[0].entity,
    trust: { maxAgeSeconds: 300 },
    targets: [
      {
        id: "internal",
        revision: "1",
        recipient: actors[0].entity,
        tools: ["lookup"],
        endpoint: "https://mcp.example/mcp",
        resourceMetadataUrl: "https://mcp.example/resource",
        issuer: "https://mcp.example",
        tokenEndpoint: "https://mcp.example/token",
        clientId: "xeip",
        scope: "tools:lookup",
      },
    ],
  };
  const h = await harness({
    XEIP_PROFILE: JSON.stringify(profile),
    XEIP_CREDENTIALS: JSON.stringify({
      introspectionClientSecret: "fixture-secret",
      targets: { internal: "fixture-secret" },
    }),
  });
  t.after(() => h.close());
  const config = configuration(
    {
      config: {
        issuer: "https://id.example/realms/xeip",
        audience: "xeip-api",
        clientIds: ["xeip-agent", "xeip-console"],
        introspectionClientId: "xeip-introspection",
      },
    },
    actors,
  );
  delete config.authentication.allowInsecureLoopback;
  const send = async (operation, extra = {}) => {
    const command = { operation, requestId: randomUUID(), ...extra };
    const r = await h.send({ raw: JSON.stringify(command) });
    return validateOwnerReceipt(JSON.stringify(r.body), {
      ...command,
      operator: "fixture:operator",
    });
  };
  assert.equal((await send("initialize", { configuration: config })).ok, true);
  for (let i = 0; i < 10; i++)
    assert.equal(
      (
        await send("refreshTrust", {
          provisioning: provisioning(actors, i + 1),
          expectedRevision: i,
        })
      ).ok,
      true,
    );
  const before = (await send("auditExport")).audit;
  const directory = join(root, "native");
  let calls = 0;
  const manifest = await collectArchive({
    directory,
    source: {
      ...source,
      services: [
        { ...source.services[0], props: { operator: "fixture:operator" } },
      ],
    },
    readPage: async (options) => {
      calls++;
      const result = await send("auditExport", options);
      assert.equal(result.ok, true);
      return result.audit;
    },
  });
  assert.equal(calls, 2);
  assert.equal(manifest.records, 22);
  assert.equal(manifest.headChecksum, before.headChecksum);
  assert.equal(
    (await send("auditExport")).audit.headSequence,
    before.headSequence,
  );
  await h.restart();
  assert.equal(
    (await verifyArchive(directory)).manifestChecksum,
    manifest.manifestChecksum,
  );
  assert.equal(
    (
      await h.send({
        kind: "default-rpc",
        raw: JSON.stringify({
          operation: "auditExport",
          requestId: randomUUID(),
        }),
      })
    ).status,
    502,
  );
});
test("CLI verification reports only bounded metadata and errors reveal no artifact payload", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const root = await setup(t),
    directory = join(root, "archive");
  const manifest = await collectArchive({
    directory,
    source,
    readPage: reader(records()),
  });
  const cli = new URL(
    "../services/organization/cloudflare/archive.mjs",
    import.meta.url,
  ).pathname;
  const result = spawnSync(process.execPath, [cli, "verify", directory], {
    encoding: "utf8",
    timeout: 10000,
  });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.manifestChecksum, manifest.manifestChecksum);
  assert.equal(output.records, 40);
  assert.ok(!result.stdout.includes("fixture:owner"));
  await fs.writeFile(join(directory, "manifest.json"), "sentinel-secret", {
    mode: 0o600,
  });
  const bad = spawnSync(process.execPath, [cli, "verify", directory], {
    encoding: "utf8",
    timeout: 10000,
  });
  assert.equal(bad.status, 1);
  assert.equal(bad.stdout, "");
  assert.ok(!bad.stderr.includes("sentinel-secret"));
});
test("failure flushing the final directory is reported as uncertain even with a structurally valid seal", async (t) => {
  const root = await setup(t),
    directory = join(root, "archive");
  let syncs = 0;
  const io = {
    ...fs,
    open: async (path, ...args) => {
      const h = await fs.open(path, ...args);
      if (path === directory) {
        const sync = h.sync.bind(h);
        h.sync = async () => {
          if (++syncs === 2) throw Error("injected final directory failure");
          return sync();
        };
      }
      return h;
    },
  };
  await assert.rejects(
    collectArchive({ directory, source, readPage: reader(records()), io }),
    { message: "archive collection failed" },
  );
  assert.equal((await verifyArchive(directory)).records, 40);
});

test("a terminal record can reference a start on a previous archive page", async (t) => {
  const root = await setup(t),
    rows = records(40);
  const [startA, endA, startB, endB] = rows
    .slice(14, 18)
    .map((r) => structuredClone(r.event));
  for (const [offset, event] of [startA, startB, endB, endA].entries())
    rows[14 + offset].event = { ...event, occurredAt: 1015 + offset };
  for (let i = 14; i < rows.length; i++) {
    rows[i].previous = rows[i - 1].checksum;
    rows[i].checksum = auditChecksum(
      i + 1,
      rows[i].previous,
      canonicalize(rows[i].event),
    );
  }
  const directory = join(root, "cross-page");
  const m = await collectArchive({ directory, source, readPage: reader(rows) });
  assert.equal(
    (await verifyArchive(directory)).manifestChecksum,
    m.manifestChecksum,
  );
});

for (const name of ["000001.json", "manifest.json"])
  test(
    "offline verifier rejects a prepended UTF-8 BOM in " + name,
    async (t) => {
      const root = await setup(t),
        directory = join(root, "archive");
      await collectArchive({ directory, source, readPage: reader(records()) });
      const path = join(directory, name);
      await fs.writeFile(
        path,
        Buffer.concat([
          Buffer.from([0xef, 0xbb, 0xbf]),
          await fs.readFile(path),
        ]),
      );
      await assert.rejects(verifyArchive(directory), {
        message: "invalid archive",
      });
    },
  );

for (const mode of ["rollback", "fork"]) {
  function observedPage(rows, after, limit) {
    const p = page(
      rows.slice(
        0,
        after === 0 ? 40 : mode === "rollback" && after === 32 ? 42 : 44,
      ),
      after,
      limit,
    );
    if (mode === "fork" && after === 32) p.headChecksum = "d".repeat(64);
    return p;
  }
  test(
    "collector rejects observed " + mode + " above the fixed cut",
    async (t) => {
      const directory = join(await setup(t), "archive"),
        rows = records(44);
      await assert.rejects(
        collectArchive({
          directory,
          source,
          readPage: async ({ after, limit }) =>
            observedPage(rows, after, limit),
        }),
        { message: "archive collection failed" },
      );
      await assert.rejects(fs.stat(join(directory, "manifest.json")));
    },
  );
  test(
    "offline verifier rejects observed " +
      mode +
      " above the fixed cut despite a matching seal",
    async (t) => {
      const directory = join(await setup(t), "archive"),
        rows = records(44);
      const manifest = await collectArchive({
        directory,
        source,
        readPage: reader(rows.slice(0, 40)),
      });
      const hash = (value) => createHash("sha256").update(value).digest("hex");
      const files = createHash("sha256").update("XEIP archive pages v1\n");
      for (let i = 0; i < 3; i++) {
        const name = String(i + 1).padStart(6, "0") + ".json";
        const raw =
          canonicalize(observedPage(rows, i * 16, i === 2 ? 8 : 16)) + "\n";
        await fs.writeFile(join(directory, name), raw);
        files.update(canonicalize([name, hash(raw)]));
      }
      const { manifestChecksum, ...data } = manifest;
      data.filesChecksum = files.digest("hex");
      await fs.writeFile(
        join(directory, "manifest.json"),
        canonicalize({
          ...data,
          manifestChecksum: hash(
            "XEIP owner archive v1\n" + canonicalize(data),
          ),
        }) + "\n",
      );
      await assert.rejects(verifyArchive(directory), {
        message: "invalid archive",
      });
    },
  );
}
