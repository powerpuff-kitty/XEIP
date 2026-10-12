import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import {
  collectActionArchive,
  verifyActionArchive,
} from "../services/organization/cloudflare/action-archive.mjs";
import {
  actionSnapshotHasher,
  projectAction,
} from "../services/organization/cloudflare/action-export.mjs";
const entity =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const source = {
  name: "xeip-archive",
  compatibility_date: "2026-07-30",
  services: [
    {
      binding: "OWNER",
      service: "xeip-staging",
      entrypoint: "OwnerEntrypoint",
      remote: false,
      props: { operator: "operator:archive" },
    },
  ],
};
function records(count = 3) {
  return Array.from({ length: count }, (_, i) => {
    const actor = { subject: "agent", entity, kid: entity.slice(16) },
      action = {
        id: "request-" + i,
        session: "session",
        actor,
        expiresAt: 1000,
        arguments: { secret: "private argument " + i },
      };
    const canonical = canonicalize(action),
      digest = createHash("sha256")
        .update("XEIP organization action v1\n" + canonical)
        .digest("hex");
    return {
      row: {
        session_id: action.session,
        request_id: action.id,
        digest,
        canonical,
        expires_at: 1000,
        state: "pending",
        version: 0,
        approver: null,
        approval_expires_at: null,
        claim_id: null,
        result_canonical: null,
      },
      history: [
        {
          sequence: i + 1,
          session_id: action.session,
          request_id: action.id,
          digest,
          event: "proposed",
          actor: canonicalize(actor),
          occurred_at: 900,
        },
      ],
    };
  });
}
function snapshot(records, cut = records.at(-1)?.history.at(-1).sequence ?? 0) {
  const items = records
    .filter((r) => r.history[0].sequence <= cut)
    .map((r) => projectAction(r.row, r.history, cut));
  const header = {
      schema: "xeip.action-snapshot/1",
      organization: "fixture",
      cut,
      actions: items.length,
    },
    h = actionSnapshotHasher(header);
  for (const r of items) h.update(canonicalize(r) + "\n");
  return { ...header, digest: h.digest("hex") };
}
const reader = (records) => ({
  capture: async (cut) => snapshot(records, cut),
  readPage: async ({ cut, after }) => {
    const record = records.find(
      (r) => r.history[0].sequence > after && r.history[0].sequence <= cut,
    );
    return {
      cut,
      after,
      next: record?.history[0].sequence ?? after,
      record: record ? projectAction(record.row, record.history, cut) : null,
    };
  },
});
async function setup(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "xeip-action-archive-test-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}
test("action archive captures complete private records, verifies offline and refuses overwrite", async (t) => {
  const directory = join(await setup(t), "archive"),
    rows = records();
  const manifest = await collectActionArchive({
    directory,
    source,
    ...reader(rows),
  });
  assert.equal(
    canonicalize(await verifyActionArchive(directory)),
    canonicalize(manifest),
  );
  assert.equal(manifest.snapshot.actions, 3);
  for (const name of await fs.readdir(directory))
    assert.equal((await fs.stat(join(directory, name))).mode & 0o777, 0o600);
  assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
  await assert.rejects(
    collectActionArchive({ directory, source, ...reader(rows) }),
  );
});
test("empty action archive verifies without inventing record pages", async (t) => {
  const directory = join(await setup(t), "archive");
  const m = await collectActionArchive({ directory, source, ...reader([]) });
  assert.equal(m.pages, 0);
  assert.deepEqual(await fs.readdir(directory), ["manifest.json"]);
  assert.equal((await verifyActionArchive(directory)).snapshot.cut, 0);
});
test("action archive pins the initial cut while later proposals arrive", async (t) => {
  const rows = records(3),
    r = reader(rows),
    directory = join(await setup(t), "archive");
  let changed = false;
  const m = await collectActionArchive({
    directory,
    source,
    capture: r.capture,
    readPage: async (options) => {
      if (!changed) {
        changed = true;
        rows.push(records(4)[3]);
      }
      return r.readPage(options);
    },
  });
  assert.equal(m.snapshot.actions, 3);
  assert.equal((await verifyActionArchive(directory)).pages, 3);
});
test("prior action archive binds source, history and independently verifiable continuity", async (t) => {
  const root = await setup(t),
    rows = records(4),
    previous = join(root, "prior");
  const p = await collectActionArchive({
    directory: previous,
    source,
    ...reader(rows.slice(0, 2)),
  });
  const m = await collectActionArchive({
    directory: join(root, "next"),
    source,
    previous,
    ...reader(rows),
  });
  assert.equal(m.previous.manifestChecksum, p.manifestChecksum);
  await verifyActionArchive(join(root, "next"));
  for (const [name, s, values] of [
    ["source", { ...source, name: "xeip-changed" }, rows],
    ["rollback", source, rows.slice(0, 1)],
  ])
    await assert.rejects(
      collectActionArchive({
        directory: join(root, name),
        source: s,
        previous,
        ...reader(values),
      }),
    );
  const fork = records(4);
  fork[0].row.canonical = fork[0].row.canonical.replace(
    "private argument 0",
    "forked argument 0",
  );
  fork[0].row.digest = createHash("sha256")
    .update("XEIP organization action v1\n" + fork[0].row.canonical)
    .digest("hex");
  fork[0].history[0].digest = fork[0].row.digest;
  const r = reader(fork);
  await assert.rejects(
    collectActionArchive({
      directory: join(root, "fork"),
      source,
      previous,
      ...r,
      capture: async (cut) =>
        cut === p.snapshot.cut ? p.snapshot : r.capture(cut),
    }),
    { message: "action archive collection failed" },
  );
  await assert.rejects(fs.stat(join(root, "fork", "manifest.json")));
});
for (const mode of ["missing", "extra", "duplicate", "digest", "early-end"])
  test(
    "action collector rejects " + mode + " source records without sealing",
    async (t) => {
      const directory = join(await setup(t), "archive"),
        rows = records(),
        r = reader(rows);
      let calls = 0;
      await assert.rejects(
        collectActionArchive({
          directory,
          source,
          capture: r.capture,
          readPage: async (options) => {
            const p = await r.readPage(options);
            calls++;
            if (mode === "missing" && calls === 1)
              return { cut: options.cut, after: 0, next: 2, record: rows[1] };
            if (mode === "duplicate" && calls === 2)
              return { ...p, next: 1, record: rows[0] };
            if (mode === "early-end" && calls === 2)
              return { ...p, next: options.after, record: null };
            if (mode === "extra" && p.record === null)
              return { ...p, next: 4, record: records(4)[3] };
            if (mode === "digest" && calls === 1) {
              p.record.row.canonical = p.record.row.canonical.replace(
                "private argument 0",
                "changed argument 0",
              );
              p.record.row.digest = createHash("sha256")
                .update(
                  "XEIP organization action v1\n" + p.record.row.canonical,
                )
                .digest("hex");
              p.record.history[0].digest = p.record.row.digest;
            }
            return p;
          },
        }),
        { message: "action archive collection failed" },
      );
      await assert.rejects(fs.stat(join(directory, "manifest.json")));
    },
  );
for (const mode of [
  "page-bom",
  "manifest-bom",
  "missing",
  "extra",
  "permissive",
  "symlink",
  "truncated",
])
  test("offline action verifier rejects " + mode, async (t) => {
    const root = await setup(t),
      directory = join(root, "archive");
    await collectActionArchive({ directory, source, ...reader(records()) });
    const path = join(
      directory,
      mode === "manifest-bom" ? "manifest.json" : "000001.json",
    );
    if (mode.endsWith("bom"))
      await fs.writeFile(
        path,
        Buffer.concat([Buffer.from([239, 187, 191]), await fs.readFile(path)]),
      );
    if (mode === "missing") await fs.unlink(path);
    if (mode === "extra")
      await fs.writeFile(join(directory, "unexpected"), "x");
    if (mode === "permissive") await fs.chmod(path, 0o644);
    if (mode === "symlink") {
      await fs.rename(path, join(root, "original"));
      await fs.symlink(join(root, "original"), path);
    }
    if (mode === "truncated") await fs.truncate(path, 4);
    await assert.rejects(verifyActionArchive(directory), {
      message: "invalid action archive",
    });
  });
for (const phase of [
  "page-write",
  "page-sync",
  "seal-sync",
  "directory-sync",
  "final-directory-sync",
])
  test(
    "action archive " + phase + " failure is redacted and never acknowledged",
    async (t) => {
      const directory = join(await setup(t), "archive");
      let failed = false,
        dirSyncs = 0;
      const io = {
        ...fs,
        open: async (path, flags, ...rest) => {
          const h = await fs.open(path, flags, ...rest),
            write = h.writeFile.bind(h),
            sync = h.sync.bind(h);
          h.writeFile = async (...args) => {
            if (
              phase === "page-write" &&
              String(path).endsWith("000001.json")
            ) {
              failed = true;
              throw Error("private-fs-error");
            }
            return write(...args);
          };
          h.sync = async () => {
            if (path === directory) dirSyncs++;
            if (
              (phase === "page-sync" && String(path).endsWith("000001.json")) ||
              (phase === "seal-sync" &&
                String(path).endsWith("manifest.json")) ||
              (phase === "directory-sync" && path === directory) ||
              (phase === "final-directory-sync" &&
                path === directory &&
                dirSyncs === 2)
            ) {
              failed = true;
              throw Error("private-fs-error");
            }
            return sync();
          };
          return h;
        },
      };
      await assert.rejects(
        collectActionArchive({ directory, source, ...reader(records()), io }),
        { message: "action archive collection failed" },
      );
      assert.equal(failed, true);
      if (phase === "final-directory-sync")
        await verifyActionArchive(directory);
      else if (phase !== "seal-sync")
        await assert.rejects(fs.stat(join(directory, "manifest.json")));
    },
  );
test("action archive RPC deadline cannot seal a late response and preserves fixed errors", async (t) => {
  const directory = join(await setup(t), "archive"),
    r = reader(records());
  let release;
  await assert.rejects(
    collectActionArchive({
      directory,
      source,
      capture: r.capture,
      readPage: () =>
        new Promise((resolve) => {
          release = resolve;
        }),
      timeoutMs: 100,
    }),
    { message: "action archive collection failed" },
  );
  release(await r.readPage({ cut: 3, after: 0 }));
  await new Promise((resolve) => setTimeout(resolve, 25));
  await assert.rejects(fs.stat(join(directory, "manifest.json")));
});
test("action archive CLI emits only bounded metadata and generic failures", async (t) => {
  const { execFileSync } = await import("node:child_process"),
    directory = join(await setup(t), "archive");
  await collectActionArchive({ directory, source, ...reader(records()) });
  const cli = "services/organization/cloudflare/action-archive.mjs";
  const output = execFileSync(process.execPath, [cli, "verify", directory], {
    encoding: "utf8",
  });
  assert.equal(JSON.parse(output).ok, true);
  assert.ok(!output.includes("private argument"));
  assert.ok(output.length < 1024);
  assert.throws(
    () =>
      execFileSync(
        process.execPath,
        [cli, "verify", join(directory, "missing")],
        { encoding: "utf8", stdio: "pipe" },
      ),
    (e) =>
      e.status === 1 &&
      !e.stderr.includes("private argument") &&
      e.stdout === "",
  );
});
