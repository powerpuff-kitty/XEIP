import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, createHash } from "node:crypto";
import {
  canonicalize,
  recoveryOptions,
  genesis,
  sealEntry,
  PART_BYTES,
} from "../services/organization/cloudflare/recovery-record.mjs";
const mod = () =>
  import("../services/organization/cloudflare/recovery-archive.mjs");
const options = recoveryOptions({
  organization: "archive-org",
  stream: randomUUID(),
});
const source = { url: "https://journal.example/v1/recovery", options };
const hash = (b) => createHash("sha256").update(b).digest("hex");
function fixture(payloads = [], idFor = () => randomUUID()) {
  const entries = [],
    calls = [];
  let head = {
      organization: options.organization,
      stream: options.stream,
      sequence: 0,
      checksum: genesis(options),
    },
    total = 0;
  const add = (value) => {
    const data = Buffer.from(value),
      chunks = [];
    for (let i = 0; i < data.length; i += PART_BYTES)
      chunks.push(data.subarray(i, i + PART_BYTES).toString("base64"));
    const entry = sealEntry({
      schema: "xeip.recovery-entry/1",
      organization: options.organization,
      stream: options.stream,
      sequence: head.sequence + 1,
      id: idFor(hash(data)),
      previous: head.checksum,
      payloadDigest: hash(data),
      bytes: data.length,
      parts: chunks.length,
      totalBytes: total + data.length,
    });
    total = entry.totalBytes;
    head = { ...head, sequence: entry.sequence, checksum: entry.checksum };
    entries.push({ entry, chunks });
    return entry;
  };
  payloads.forEach(add);
  const client = {
    head: async () => {
      calls.push("head");
      return { ...head };
    },
    entry: async (n) => {
      calls.push("entry");
      return structuredClone(entries[n - 1].entry);
    },
    part: async (n, p) => {
      calls.push("part");
      return {
        entry: structuredClone(entries[n - 1].entry),
        part: p,
        data: entries[n - 1].chunks[p],
      };
    },
    append: () => {
      throw Error("must never append");
    },
  };
  return { client, entries, calls, add };
}
async function location(t) {
  const path = await fs.mkdtemp(join(tmpdir(), "xeip-recovery-archive-test-"));
  t.after(() => fs.rm(path, { recursive: true, force: true }));
  return path;
}
for (const payloads of [[], ["one", "two"], [Buffer.alloc(PART_BYTES + 17, 7)]])
  test(`recovery bundle roundtrip (${payloads.length} entries, ${payloads[0]?.length ?? 0} bytes)`, async (t) => {
    const { collectRecoveryArchive, verifyRecoveryArchive } = await mod(),
      base = await location(t),
      f = fixture(payloads);
    const directory = join(base, "bundle"),
      m = await collectRecoveryArchive({ directory, source, client: f.client });
    assert.equal(m.head.sequence, payloads.length);
    assert.equal(
      m.totalBytes,
      payloads.reduce((n, p) => n + Buffer.byteLength(p), 0),
    );
    assert.equal(
      canonicalize(await verifyRecoveryArchive(directory)),
      canonicalize(m),
    );
    assert.ok(!JSON.stringify(m).includes("timeoutMs"));
    assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
    for (const name of await fs.readdir(directory))
      assert.equal((await fs.stat(join(directory, name))).mode & 0o777, 0o600);
  });
test("fixed captured head stays complete while the journal advances", async (t) => {
  const { collectRecoveryArchive, verifyRecoveryArchive } = await mod(),
    base = await location(t),
    f = fixture(["first"]);
  let initial = true;
  const client = {
    ...f.client,
    head: async () => {
      const h = await f.client.head();
      if (initial) {
        initial = false;
        f.add("later");
      }
      return h;
    },
  };
  const m = await collectRecoveryArchive({
    directory: join(base, "bundle"),
    source,
    client,
  });
  assert.equal(m.head.sequence, 1);
  assert.equal(
    (await verifyRecoveryArchive(join(base, "bundle"))).head.sequence,
    1,
  );
});
test("collection verifies complete payload digest, not just individual base64 parts", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    base = await location(t),
    f = fixture([Buffer.alloc(PART_BYTES + 17, 7)]);
  f.entries[0].chunks[1] = Buffer.alloc(17, 8).toString("base64");
  await assert.rejects(
    collectRecoveryArchive({
      directory: join(base, "bundle"),
      source,
      client: f.client,
    }),
    /^Error: recovery archive collection failed$/,
  );
  await assert.rejects(fs.access(join(base, "bundle", "manifest.json")));
});
for (const damage of [
  "wrong-sequence",
  "wrong-part",
  "changed-header",
  "duplicate-id",
  "regressed-head",
])
  test(`collector refuses ${damage} without sealing`, async (t) => {
    const { collectRecoveryArchive } = await mod(),
      base = await location(t),
      f = fixture(["one", "two"]),
      client = { ...f.client };
    if (damage === "wrong-sequence")
      client.entry = async () => f.entries[1].entry;
    if (damage === "wrong-part")
      client.part = async (n, p) => ({
        ...(await f.client.part(n, p)),
        part: p + 1,
      });
    if (damage === "changed-header")
      client.part = async (n, p) => ({
        ...(await f.client.part(n, p)),
        entry: f.entries[1].entry,
      });
    if (damage === "duplicate-id") {
      const { checksum, ...e } = f.entries[1].entry;
      f.entries[1].entry = sealEntry({ ...e, id: f.entries[0].entry.id });
    }
    if (damage === "regressed-head") {
      let calls = 0;
      client.head = async () =>
        ++calls === 1
          ? f.client.head()
          : {
              organization: options.organization,
              stream: options.stream,
              sequence: 0,
              checksum: genesis(options),
            };
    }
    const directory = join(base, "bundle");
    await assert.rejects(collectRecoveryArchive({ directory, source, client }));
    await assert.rejects(fs.access(join(directory, "manifest.json")));
  });
test("prior bundle anchors continuity and rejects rollback or a different prefix", async (t) => {
  const { collectRecoveryArchive, verifyRecoveryArchive } = await mod(),
    base = await location(t),
    f = fixture(["one"]),
    first = join(base, "first"),
    second = join(base, "second");
  await collectRecoveryArchive({ directory: first, source, client: f.client });
  f.add("two");
  await collectRecoveryArchive({
    directory: second,
    source,
    client: f.client,
    previous: first,
  });
  assert.equal(
    (await verifyRecoveryArchive(second, { previous: first })).head.sequence,
    2,
  );
  await assert.rejects(verifyRecoveryArchive(second, { previous: second }));
  await assert.rejects(
    collectRecoveryArchive({
      directory: join(base, "rollback"),
      source,
      client: fixture(["one"]).client,
      previous: second,
    }),
  );
  await assert.rejects(
    collectRecoveryArchive({
      directory: join(base, "fork"),
      source,
      client: fixture(["other", "tail"]).client,
      previous: first,
    }),
  );
  await assert.rejects(
    collectRecoveryArchive({
      directory: join(base, "url"),
      source: { ...source, url: "https://other.example/" },
      client: f.client,
      previous: first,
    }),
  );
});
for (const damage of [
  "missing",
  "extra",
  "symlink",
  "public-file",
  "public-directory",
  "whitespace",
  "duplicate-key",
  "payload",
  "manifest",
  "trailing",
  "oversized",
])
  test(`offline verification rejects ${damage}`, async (t) => {
    const { collectRecoveryArchive, verifyRecoveryArchive } = await mod(),
      base = await location(t),
      directory = join(base, "bundle");
    await collectRecoveryArchive({
      directory,
      source,
      client: fixture(["one"]).client,
    });
    const file = join(directory, "0000001.json");
    if (damage === "missing") await fs.unlink(file);
    if (damage === "extra")
      await fs.writeFile(join(directory, "extra"), "x", { mode: 0o600 });
    if (damage === "symlink") {
      await fs.rename(file, join(base, "data"));
      await fs.symlink(join(base, "data"), file);
    }
    if (damage === "public-file") await fs.chmod(file, 0o644);
    if (damage === "public-directory") await fs.chmod(directory, 0o755);
    if (damage === "whitespace") await fs.appendFile(file, " ");
    if (damage === "duplicate-key")
      await fs.writeFile(file, '{"chunks":[],"chunks":[]}\n');
    if (damage === "payload") {
      const v = JSON.parse(await fs.readFile(file));
      v.chunks[0] = Buffer.from("bad").toString("base64");
      await fs.writeFile(file, canonicalize(v) + "\n");
    }
    if (damage === "manifest")
      await fs.writeFile(join(directory, "manifest.json"), "{}\n");
    if (damage === "trailing") await fs.appendFile(file, "{}");
    if (damage === "oversized") {
      const h = await fs.open(file, "r+");
      await h.truncate(24 * 1024 * 1024 + 1);
      await h.close();
    }
    await assert.rejects(
      verifyRecoveryArchive(directory),
      /^Error: invalid recovery archive$/,
    );
  });
test("existing evidence and symlink destination are never overwritten", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    base = await location(t),
    directory = join(base, "bundle"),
    f = fixture(["one"]);
  await collectRecoveryArchive({ directory, source, client: f.client });
  const before = await fs.readFile(join(directory, "manifest.json"));
  await assert.rejects(
    collectRecoveryArchive({ directory, source, client: f.client }),
  );
  assert.deepEqual(await fs.readFile(join(directory, "manifest.json")), before);
  await fs.symlink(directory, join(base, "link"));
  await assert.rejects(
    collectRecoveryArchive({
      directory: join(base, "link"),
      source,
      client: f.client,
    }),
  );
});
test("a late client response cannot resume writes or seal collection", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    base = await location(t),
    directory = join(base, "bundle"),
    f = fixture(["one"]);
  let release,
    calls = 0;
  const client = {
    ...f.client,
    part: () => {
      calls++;
      return new Promise((r) => {
        release = r;
      });
    },
  };
  await assert.rejects(
    collectRecoveryArchive({ directory, source, client, timeoutMs: 100 }),
  );
  release(await f.client.part(1, 0));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(calls, 1);
  assert.deepEqual(await fs.readdir(directory), []);
});
test("durability failure leaves evidence incomplete and reports only a fixed error", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    base = await location(t),
    directory = join(base, "bundle"),
    f = fixture(["secret payload"]);
  const io = {
    ...fs,
    open: async (path, ...args) => {
      const h = await fs.open(path, ...args);
      if (String(path).endsWith("0000001.json"))
        return {
          writeFile: (...a) => h.writeFile(...a),
          sync: async () => {
            throw Error("sensitive cause");
          },
          close: () => h.close(),
        };
      return h;
    },
  };
  await assert.rejects(
    collectRecoveryArchive({ directory, source, client: f.client, io }),
    /^Error: recovery archive collection failed$/,
  );
  await assert.rejects(fs.access(join(directory, "manifest.json")));
  assert.ok((await fs.stat(join(directory, "0000001.json"))).size > 0);
});
test("maximum 16 MiB payload is reconstructed and verified without widening the cap", async (t) => {
  const { collectRecoveryArchive, verifyRecoveryArchive } = await mod(),
    base = await location(t),
    directory = join(base, "bundle");
  const m = await collectRecoveryArchive({
    directory,
    source,
    client: fixture([Buffer.alloc(16777216, 97)]).client,
  });
  assert.equal(m.totalBytes, 16777216);
  assert.equal(
    (await verifyRecoveryArchive(directory)).manifestChecksum,
    m.manifestChecksum,
  );
});
function actionRecords() {
  const entity =
      "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
    actor = { subject: "agent", entity, kid: entity.slice(16) };
  const action = {
      id: "one",
      session: "operations",
      actor,
      expiresAt: 1000,
      arguments: { secret: "sensitive action argument" },
    },
    canonical = canonicalize(action),
    digest = hash("XEIP organization action v1\n" + canonical);
  const row = {
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
  };
  const event = {
    sequence: 1,
    session_id: action.session,
    request_id: action.id,
    digest,
    event: "proposed",
    actor: canonicalize(actor),
    occurred_at: 900,
  };
  return [
    { row, history: [event] },
    {
      row: { ...row, state: "revoked", version: 1 },
      history: [
        event,
        { ...event, sequence: 2, event: "revoked", occurred_at: 901 },
      ],
    },
  ];
}
test("offline action interpretation requires exact cross-record continuity and deterministic IDs", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    { verifyRecoveryActions } = await import(
      "../services/organization/cloudflare/recovery-action-archive.mjs"
    ),
    { actionRecoveryPayload, actionRecoveryId } = await import(
      "../services/organization/cloudflare/action-recovery.mjs"
    );
  const base = await location(t),
    records = actionRecords(),
    payloads = records.map((r, i) =>
      actionRecoveryPayload(options.organization, i + 1, r),
    );
  const directory = join(base, "good");
  await collectRecoveryArchive({
    directory,
    source,
    client: fixture(payloads, actionRecoveryId).client,
  });
  const summary = await verifyRecoveryActions(directory);
  assert.equal(summary.actions, 1);
  assert.equal(summary.states.revoked, 1);
  assert.equal(summary.consumedClaims, 0);
  assert.ok(!JSON.stringify(summary).includes("sensitive"));
  for (const mode of [
    "changed-history",
    "wrong-id",
    "unknown-type",
    "wrong-organization",
    "wrong-sequence",
  ]) {
    const values = structuredClone(payloads);
    if (mode !== "wrong-id") {
      const p = JSON.parse(values[1]);
      if (mode === "changed-history") p.record.history[0].occurred_at++;
      if (mode === "unknown-type") p.schema = "xeip.unknown/1";
      if (mode === "wrong-organization") p.organization = "other";
      if (mode === "wrong-sequence") p.sequence = 1;
      values[1] = canonicalize(p);
    }
    const path = join(base, mode);
    await collectRecoveryArchive({
      directory: path,
      source,
      client: fixture(
        values,
        mode === "wrong-id" ? () => randomUUID() : actionRecoveryId,
      ).client,
    });
    await assert.rejects(
      verifyRecoveryActions(path),
      /^Error: invalid recovery action history$/,
    );
  }
});
test("private configuration collection uses the real authenticated client and never exports its token", async (t) => {
  const { collectConfiguredRecovery } = await import(
      "../services/organization/cloudflare/recovery-archive-command.mjs"
    ),
    { createRecoveryHandler } = await import(
      "../services/organization/cloudflare/recovery-http.mjs"
    );
  const base = await location(t),
    f = fixture(["secret payload"]),
    token = "ab".repeat(32),
    configPath = join(base, "config.json");
  await fs.writeFile(
    configPath,
    JSON.stringify({ ...source, token }, null, 2),
    { mode: 0o600 },
  );
  const handler = createRecoveryHandler({
    ...source,
    token,
    journal: f.client,
  });
  const m = await collectConfiguredRecovery({
    configPath,
    directory: join(base, "bundle"),
    request: (url, init) => handler(new Request(url, init)),
  });
  assert.equal(m.head.sequence, 1);
  assert.ok(!JSON.stringify(m).includes(token));
  for (const name of await fs.readdir(join(base, "bundle")))
    assert.ok(
      !(await fs.readFile(join(base, "bundle", name), "utf8")).includes(token),
    );
  for (const mode of [
    "public",
    "symlink",
    "oversized",
    "duplicate",
    "wrong-secret",
  ]) {
    const path = join(base, mode);
    if (mode === "symlink") await fs.symlink(configPath, path);
    else
      await fs.writeFile(
        path,
        mode === "oversized"
          ? "x".repeat(8193)
          : mode === "duplicate"
            ? '{"url":"a","url":"b"}'
            : JSON.stringify({
                ...source,
                token: mode === "wrong-secret" ? "aa" : token,
              }),
        { mode: mode === "public" ? 0o644 : 0o600 },
      );
    let called = false;
    await assert.rejects(
      collectConfiguredRecovery({
        configPath: path,
        directory: join(base, "out-" + mode),
        request: async () => {
          called = true;
          throw Error("should not contact");
        },
      }),
      /^Error: recovery archive collection failed$/,
    );
    assert.equal(called, false);
  }
});
test("CLI failure output omits config contents, paths and secrets", async (t) => {
  const { promisify } = await import("node:util"),
    { execFile } = await import("node:child_process"),
    base = await location(t),
    path = join(base, "sensitive-config-name");
  await fs.writeFile(path, '{"token":"secret-value"}', { mode: 0o600 });
  await assert.rejects(
    promisify(execFile)(process.execPath, [
      "services/organization/cloudflare/recovery-archive-command.mjs",
      "collect",
      path,
      join(base, "out"),
    ]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /^Recovery archive failed\. Usage:/);
      assert.ok(!error.stderr.includes(path));
      assert.ok(!error.stderr.includes("secret-value"));
      assert.equal(error.stdout, "");
      return true;
    },
  );
});
test("offline action reconstruction preserves consumed claims and rejects claim erasure or replacement", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    { verifyRecoveryActions } = await import(
      "../services/organization/cloudflare/recovery-action-archive.mjs"
    ),
    { actionRecoveryPayload, actionRecoveryId } = await import(
      "../services/organization/cloudflare/action-recovery.mjs"
    ),
    { identity } = await import("./fixtures/cloudflare/authority-harness.mjs");
  const { subject, entity, kid } = identity("human"),
    who = { subject, entity, kid },
    first = actionRecords()[0],
    event = first.history[0],
    claim = randomUUID();
  const approved = {
    row: {
      ...first.row,
      state: "approved",
      version: 1,
      approver: canonicalize({
        ...who,
        clientId: "console",
        roles: ["approver"],
        expiresAt: 1000,
      }),
      approval_expires_at: 1000,
    },
    history: [
      event,
      { ...event, sequence: 2, event: "approved", actor: canonicalize(who) },
    ],
  };
  const claimed = {
    row: { ...approved.row, state: "executing", version: 2, claim_id: claim },
    history: [...approved.history, { ...event, sequence: 3, event: "claimed" }],
  };
  const completed = {
    row: {
      ...claimed.row,
      state: "succeeded",
      version: 3,
      result_canonical: canonicalize({ ok: true }),
    },
    history: [
      ...claimed.history,
      {
        ...event,
        sequence: 4,
        event: "succeeded",
        actor: canonicalize({ worker: "execution", claimId: claim }),
      },
    ],
  };
  const base = await location(t);
  for (const mode of ["valid", "erase", "replace"]) {
    const records = structuredClone([first, approved, claimed, completed]);
    if (mode === "erase") {
      records[3] = structuredClone(approved);
      records[3].history[1].sequence = 4;
    }
    if (mode === "replace") {
      const id = randomUUID();
      records[3].row.claim_id = id;
      records[3].history[3].actor = canonicalize({
        worker: "execution",
        claimId: id,
      });
    }
    const payloads = records.map((r, i) =>
        actionRecoveryPayload(options.organization, i + 1, r),
      ),
      directory = join(base, mode);
    await collectRecoveryArchive({
      directory,
      source,
      client: fixture(payloads, actionRecoveryId).client,
    });
    if (mode === "valid") {
      const v = await verifyRecoveryActions(directory);
      assert.equal(v.consumedClaims, 1);
      assert.equal(v.states.succeeded, 1);
    } else await assert.rejects(verifyRecoveryActions(directory));
  }
});
test("CLI verifies content and action summaries without printing private payloads", async (t) => {
  const { collectRecoveryArchive } = await mod(),
    { actionRecoveryPayload, actionRecoveryId } = await import(
      "../services/organization/cloudflare/action-recovery.mjs"
    ),
    { promisify } = await import("node:util"),
    { execFile } = await import("node:child_process");
  const base = await location(t),
    directory = join(base, "bundle"),
    payload = actionRecoveryPayload(
      options.organization,
      1,
      actionRecords()[0],
    );
  await collectRecoveryArchive({
    directory,
    source,
    client: fixture([payload], actionRecoveryId).client,
  });
  for (const operation of ["verify", "actions"]) {
    const { stdout, stderr } = await promisify(execFile)(process.execPath, [
      "services/organization/cloudflare/recovery-archive-command.mjs",
      operation,
      directory,
    ]);
    const report = JSON.parse(stdout);
    assert.equal(report.ok, true);
    assert.equal(report.operation, operation);
    assert.equal(report.head.sequence, 1);
    assert.equal(stderr, "");
    assert.ok(!stdout.includes("sensitive"));
    assert.ok(!stdout.includes(source.url));
    if (operation === "actions") {
      assert.equal(report.actions, 1);
      assert.equal(report.states.pending, 1);
    }
  }
});
test("final directory synchronization failure cannot report a successful durable bundle", async (t) => {
  const { collectRecoveryArchive, verifyRecoveryArchive } = await mod(),
    base = await location(t),
    directory = join(base, "bundle");
  let syncs = 0;
  const io = {
    ...fs,
    open: async (path, ...args) => {
      const h = await fs.open(path, ...args);
      if (path === directory)
        return {
          sync: async () => {
            if (++syncs === 2) throw Error("final synchronization failed");
            return h.sync();
          },
          close: () => h.close(),
        };
      return h;
    },
  };
  await assert.rejects(
    collectRecoveryArchive({
      directory,
      source,
      client: fixture(["one"]).client,
      io,
    }),
    /^Error: recovery archive collection failed$/,
  );
  // Content can be consistent despite absence of a successfully acknowledged flush.
  assert.equal((await verifyRecoveryArchive(directory)).head.sequence, 1);
});
