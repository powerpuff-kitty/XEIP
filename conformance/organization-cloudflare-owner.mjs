import { test } from "node:test";
import assert from "node:assert/strict";
import * as ownerClient from "../services/organization/cloudflare/owner.mjs";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { organizationBundleFixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import {
  validateOperatorConfig,
  invokeOwner,
} from "../services/organization/cloudflare/owner.mjs";
const config = () => ({
  name: "xeip-operator",
  compatibility_date: "2026-07-30",
  services: [
    {
      binding: "OWNER",
      service: "xeip-staging",
      entrypoint: "OwnerEntrypoint",
      remote: false,
      props: { operator: "operations:alice" },
    },
  ],
});
test("operator configuration requires an explicit single named binding and matching local/remote mode", () => {
  assert.equal(
    validateOperatorConfig(config(), false).services[0].remote,
    false,
  );
  for (const mutate of [
    (c) => delete c.services[0].remote,
    (c) => (c.services[0].remote = true),
    (c) => (c.services[0].entrypoint = "PublicEntrypoint"),
    (c) => (c.services[0].binding = "OTHER"),
    (c) => (c.services[0].props = {}),
    (c) => (c.durable_objects = { bindings: [] }),
    (c) => c.services.push(c.services[0]),
    (c) => (c.vars = { secret: "leak" }),
  ]) {
    const c = config();
    mutate(c);
    assert.throws(() => validateOperatorConfig(c, false));
  }
  const remote = config();
  remote.services[0].remote = true;
  assert.equal(validateOperatorConfig(remote, true).services[0].remote, true);
  assert.throws(() => validateOperatorConfig(config(), true));
});
test("operator rejects invalid paths/configuration before contacting a binding", async () => {
  await assert.rejects(
    invokeOwner({
      configPath: "/nonexistent/xeip-owner-config.json",
      commandPath: "/nonexistent/command.json",
      remote: false,
    }),
  );
});

const correlation = {
  requestId: "e85f2a25-eaed-4d78-90be-1bc3587a1137",
  operation: "status",
  operator: "operations:alice",
};

function exportFixture({ large = false } = {}) {
  const records = large
    ? Object.fromEntries(
        Array.from({ length: 3000 }, (_, i) => [
          "retained:" + i,
          {
            anchor: "0".repeat(64),
            generation: 1,
            keyDigest: "0".repeat(64),
            serial: 0,
            statusDigest: "0".repeat(64),
          },
        ]),
      )
    : {};
  const source = organizationBundleFixture({ records }),
    buffers = {},
    components = {};
  for (const name of ["lifecycle", "trust", "authority", "administration"]) {
    const bytes = Buffer.from(canonicalize(source.checkpoint[name]) + "\n");
    buffers[name] = bytes;
    components[name] = {
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      parts: Math.ceil(bytes.length / 262144),
    };
  }
  return {
    source,
    buffers,
    description: {
      exportId: randomUUID(),
      manifest: source.checkpoint.manifest,
      components,
    },
  };
}

test("owner export begin receipts bind a complete bounded descriptor inventory to the expected organization", () => {
  const f = exportFixture(),
    expected = {
      ...correlation,
      operation: "organizationExportBegin",
      exportContext: { organization: f.source.organization },
    };
  const receipt = {
    ok: true,
    ...correlation,
    operation: expected.operation,
    export: f.description,
  };
  assert.equal(
    ownerClient.validateOwnerReceipt(JSON.stringify(receipt), expected).export
      .exportId,
    f.description.exportId,
  );
  for (const change of [
    (r) => {
      r.export.exportId = "invalid";
    },
    (r) => {
      delete r.export.components.trust;
    },
    (r) => {
      r.export.components.secret = r.export.components.trust;
    },
    (r) => {
      r.export.components.trust.bytes = 16777218;
    },
    (r) => {
      r.export.components.trust.parts++;
    },
    (r) => {
      r.export.components.trust.sha256 = "x".repeat(64);
    },
    (r) => {
      r.export.manifest.digest = "0".repeat(64);
    },
    (r) => {
      r.operator = "foreign";
    },
    (r) => {
      r.requestId = randomUUID();
    },
    (r) => {
      r.operation = "status";
    },
    (r) => {
      r.export.credential = "must-not-leak";
    },
  ]) {
    const value = structuredClone(receipt);
    change(value);
    assert.throws(
      () => ownerClient.validateOwnerReceipt(JSON.stringify(value), expected),
      /^Error: invalid owner response$/,
    );
  }
  for (const exportContext of [undefined, {}, { organization: "foreign" }])
    assert.throws(
      () =>
        ownerClient.validateOwnerReceipt(JSON.stringify(receipt), {
          ...expected,
          exportContext,
        }),
      /^Error: invalid owner response$/,
    );
});

test("owner export parts enforce exact session, component, index and decoded length with canonical base64", () => {
  const f = exportFixture({ large: true });
  const expected = {
    ...correlation,
    operation: "organizationExportPart",
    exportId: f.description.exportId,
    component: "trust",
    index: 0,
    exportContext: { description: f.description },
  };
  const receipt = {
    ok: true,
    ...correlation,
    operation: expected.operation,
    part: {
      exportId: expected.exportId,
      checkpointDigest: f.description.manifest.digest,
      component: "trust",
      index: 0,
      data: f.buffers.trust.subarray(0, 262144).toString("base64"),
    },
  };
  assert.ok(Buffer.byteLength(JSON.stringify(receipt)) > 65536);
  assert.equal(
    ownerClient.validateOwnerReceipt(JSON.stringify(receipt), expected).part
      .data,
    receipt.part.data,
  );
  for (const change of [
    (r) => {
      r.part.exportId = randomUUID();
    },
    (r) => {
      r.part.component = "authority";
    },
    (r) => {
      r.part.index++;
    },
    (r) => {
      r.part.checkpointDigest = "0".repeat(64);
    },
    (r) => {
      r.part.data += "\n";
    },
    (r) => {
      r.part.data = r.part.data.slice(0, -1);
    },
    (r) => {
      r.part.data = Buffer.alloc(262143).toString("base64");
    },
    (r) => {
      r.part.credential = "must-not-leak";
    },
  ]) {
    const value = structuredClone(receipt);
    change(value);
    assert.throws(
      () => ownerClient.validateOwnerReceipt(JSON.stringify(value), expected),
      /^Error: invalid owner response$/,
    );
  }
  assert.throws(
    () =>
      ownerClient.validateOwnerReceipt(JSON.stringify(receipt), {
        ...expected,
        exportContext: undefined,
      }),
    /^Error: invalid owner response$/,
  );
});

test("owner export history receipts validate the captured checkpoint and cursor before exposing records", async () => {
  const f = exportFixture(),
    options = {
      section: "authority",
      cursor: { after: -1, previousChecksum: "0".repeat(64), limit: 128 },
    };
  const expected = {
    ...correlation,
    operation: "organizationExportPage",
    exportId: f.description.exportId,
    ...options,
    exportContext: { checkpoint: f.source.checkpoint },
  };
  const value = await f.source.readPage(f.source.checkpoint.manifest, options);
  const receipt = {
    ok: true,
    ...correlation,
    operation: expected.operation,
    page: { exportId: expected.exportId, ...value },
  };
  assert.equal(
    ownerClient.validateOwnerReceipt(JSON.stringify(receipt), expected).page
      .page.complete,
    true,
  );
  for (const change of [
    (r) => {
      r.page.exportId = randomUUID();
    },
    (r) => {
      r.page.checkpointDigest = "0".repeat(64);
    },
    (r) => {
      r.page.section = "actions";
    },
    (r) => {
      r.page.page.records[0].checksum = "0".repeat(64);
    },
    (r) => {
      r.page.page.records = [];
    },
    (r) => {
      r.page.page.after = 0;
    },
    (r) => {
      r.page.page.next = 1;
    },
    (r) => {
      r.page.extra = "must-not-leak";
    },
  ]) {
    const changed = structuredClone(receipt);
    change(changed);
    assert.throws(
      () => ownerClient.validateOwnerReceipt(JSON.stringify(changed), expected),
      /^Error: invalid owner response$/,
    );
  }
  assert.throws(
    () =>
      ownerClient.validateOwnerReceipt(JSON.stringify(receipt), {
        ...expected,
        exportContext: undefined,
      }),
    /^Error: invalid owner response$/,
  );
});

test("owner export close receipts acknowledge only the requested session and cannot masquerade as status", () => {
  const expected = {
    ...correlation,
    operation: "organizationExportClose",
    exportId: randomUUID(),
  };
  const value = {
    ok: true,
    ...correlation,
    operation: expected.operation,
    closed: { exportId: expected.exportId },
  };
  assert.equal(
    ownerClient.validateOwnerReceipt(JSON.stringify(value), expected).closed
      .exportId,
    expected.exportId,
  );
  assert.throws(
    () =>
      ownerClient.validateOwnerReceipt(
        JSON.stringify({ ...value, closed: { exportId: randomUUID() } }),
        expected,
      ),
    /^Error: invalid owner response$/,
  );
  assert.throws(
    () =>
      ownerClient.validateOwnerReceipt(
        JSON.stringify({ ...receipt(), operation: expected.operation }),
        expected,
      ),
    /^Error: invalid owner response$/,
  );
});
const receipt = () => ({
  ok: true,
  ...correlation,
  status: {
    state: "initialized",
    trust: { state: "ready", revision: 1, entities: 700 },
    authority: { state: "ready", revision: 0, trust: "ready" },
  },
});
test("operator accepts exact bounded receipts including uninitialized status and correlated failures", () => {
  for (const value of [
    receipt(),
    {
      ...receipt(),
      status: { state: "uninitialized", trust: null, authority: null },
    },
    ...["conflict", "invalid_request", "unavailable"].map((error) => ({
      ok: false,
      ...correlation,
      error,
    })),
    ...["forbidden", "invalid_request", "unavailable"].map((error) => ({
      ok: false,
      error,
    })),
  ]) {
    assert.equal(
      JSON.stringify(
        ownerClient.validateOwnerReceipt(JSON.stringify(value), correlation),
      ),
      JSON.stringify(value),
    );
  }
});
test("operator rejects incomplete, uncorrelated and unexpected receipts without disclosing response content", () => {
  const invalid = [
    null,
    [],
    { ok: true, ...correlation },
    { ...receipt(), unexpectedCredential: "sentinel-secret" },
    { ...receipt(), operator: "wrong:operator" },
    { ok: false, ...correlation, requestId: "wrong", error: "conflict" },
    { ok: false, ...correlation, operation: "initialize", error: "conflict" },
    { ok: false, operator: correlation.operator, error: "unavailable" },
    { ok: false, error: "sentinel-secret" },
    { ok: false, error: "conflict" },
    { ok: false, ...correlation, error: "forbidden" },
    {
      ok: false,
      error: "unavailable",
      unexpectedCredential: "sentinel-secret",
    },
  ];
  for (const mutate of [
    (s) => (s.unexpectedCredential = "sentinel-secret"),
    (s) => (s.state = "sentinel-secret"),
    (s) => (s.trust.entities = -1),
    (s) => (s.trust.entities = Number.MAX_SAFE_INTEGER + 1),
    (s) => (s.trust.revision = 0.5),
    (s) => (s.trust.state = "sentinel-secret"),
    (s) => (s.authority.trust = "sentinel-secret"),
    (s) => (s.authority.revision = -1),
    (s) => (s.authority.unexpectedCredential = "sentinel-secret"),
    (s) => delete s.trust.entities,
  ]) {
    const value = receipt();
    mutate(value.status);
    invalid.push(value);
  }
  for (const value of invalid) {
    assert.throws(
      () =>
        ownerClient.validateOwnerReceipt(JSON.stringify(value), correlation),
      /^Error: invalid owner response$/,
    );
  }
  assert.throws(() =>
    ownerClient.validateOwnerReceipt(" ".repeat(65537), correlation),
  );
});
test("operator CLI exits nonzero without printing unexpected fields from an incompatible binding", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xeip-owner-receipt-"));
  try {
    const loader = join(directory, "loader.mjs"),
      configPath = join(directory, "config.json"),
      commandPath = join(directory, "command.json");
    const response = {
      ok: true,
      ...correlation,
      unexpectedCredential: "sentinel-secret",
    };
    const mock = `export async function getPlatformProxy(){return {env:{OWNER:{async manage(){return ${JSON.stringify(JSON.stringify(response))}}}},async dispose(){}}}`;
    await writeFile(
      loader,
      `export async function resolve(s,c,next){if(s==="wrangler")return {url:${JSON.stringify("data:text/javascript," + encodeURIComponent(mock))},shortCircuit:true};return next(s,c)}`,
    );
    await writeFile(configPath, JSON.stringify(config()));
    await writeFile(
      commandPath,
      JSON.stringify({
        operation: correlation.operation,
        requestId: correlation.requestId,
      }),
    );
    const child = spawnSync(
      process.execPath,
      [
        "--no-warnings",
        "--experimental-loader",
        loader,
        "services/organization/cloudflare/owner.mjs",
        configPath,
        commandPath,
        "--local",
      ],
      { encoding: "utf8", timeout: 10000 },
    );
    assert.equal(child.status, 1);
    assert.equal(child.stdout, "");
    assert.match(child.stderr, /Owner command failed; no automatic retry/);
    assert.doesNotMatch(child.stderr, /sentinel-secret|unexpectedCredential/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reusable owner session validates configuration before opening any connection", async () => {
  assert.equal(typeof ownerClient.withOwnerSession, "function");
  await assert.rejects(
    ownerClient.withOwnerSession(
      { configPath: "/nonexistent/xeip-archive-config.json", remote: false },
      async () => {},
    ),
  );
});
test("operator action receipts require exact snapshot/page shape and requested cut/cursor", async () => {
  const { actionSnapshotHasher } = await import(
    "../services/organization/cloudflare/action-export.mjs"
  );
  const header = {
    schema: "xeip.action-snapshot/1",
    organization: "org",
    cut: 0,
    actions: 0,
  };
  const snapshot = {
    ...header,
    digest: actionSnapshotHasher(header).digest("hex"),
  };
  const base = {
    ok: true,
    ...correlation,
    operation: "actionSnapshot",
    snapshot,
  };
  ownerClient.validateOwnerReceipt(JSON.stringify(base), {
    ...correlation,
    operation: "actionSnapshot",
  });
  assert.throws(() =>
    ownerClient.validateOwnerReceipt(JSON.stringify(base), {
      ...correlation,
      operation: "actionSnapshot",
      cut: 1,
    }),
  );
  for (const value of [
    { ...base, status: {} },
    { ...base, snapshot: { ...snapshot, actions: 1 } },
    { ...base, operation: "status" },
  ])
    assert.throws(() =>
      ownerClient.validateOwnerReceipt(JSON.stringify(value), {
        ...correlation,
        operation: "actionSnapshot",
      }),
    );
  const page = {
    ok: true,
    ...correlation,
    operation: "actionPage",
    page: { cut: 0, after: 0, next: 0, record: null },
  };
  ownerClient.validateOwnerReceipt(JSON.stringify(page), {
    ...correlation,
    operation: "actionPage",
    cut: 0,
    after: 0,
  });
  for (const expected of [
    { cut: 1, after: 0 },
    { cut: 0, after: 1 },
  ])
    assert.throws(() =>
      ownerClient.validateOwnerReceipt(JSON.stringify(page), {
        ...correlation,
        operation: "actionPage",
        ...expected,
      }),
    );
  assert.throws(() =>
    ownerClient.validateOwnerReceipt(JSON.stringify({ ...page, status: {} }), {
      ...correlation,
      operation: "actionPage",
      cut: 0,
      after: 0,
    }),
  );
});
