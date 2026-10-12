/** Local production-Worker RPC cost probe. Synthetic seeding fixture; never deploy. */
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { mkdtemp, lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { collectOwnerOrganizationBundle } from "../services/organization/cloudflare/organization-export-command.mjs";
import { verifyOrganizationBundle } from "../services/organization/cloudflare/organization-bundle.mjs";
import { validateOwnerReceipt } from "../services/organization/cloudflare/owner.mjs";
import { parseOwnerCommand } from "../services/organization/cloudflare/profile.mjs";
import { performance } from "node:perf_hooks";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { auditChecksum } from "../services/organization/cloudflare/admin-record.mjs";
import {
  validateAdminCheckpoint,
  validateAdminHistoryPage,
} from "../services/organization/cloudflare/admin-checkpoint.mjs";
import {
  validateExportDescription,
  validateExportReceipt,
} from "../services/organization/cloudflare/organization-export-wire.mjs";
import { organizationBundleFixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { harness } from "./fixtures/cloudflare/worker-harness.mjs";
const require = createRequire(import.meta.url);
const count = Number(process.argv[2] ?? 1000);
const fullBundle = process.argv[3] === "--full-bundle";
if (
  ![1000, 10000, 100000].includes(count) ||
  process.argv.length > (fullBundle ? 4 : 3)
)
  throw Error(
    "usage: node conformance/organization-cloudflare-worker-export-cost.mjs 1000|10000|100000 [--full-bundle]",
  );
const fixture = organizationBundleFixture({ actions: 0 });
const profile = fixture.checkpoint.lifecycle.runtime;
let outboundCalls = 0,
  runtimeClosed = false;
const runtime = await harness(
  {
    XEIP_PROFILE: JSON.stringify(profile),
    XEIP_CREDENTIALS: JSON.stringify({
      introspectionClientSecret: "synthetic-diagnostic-secret",
      targets: Object.fromEntries(
        profile.targets.map((t) => [t.id, "synthetic-diagnostic-secret"]),
      ),
    }),
  },
  {
    entryPoint: new URL(
      "./organization-cloudflare-export-cost-worker.mjs",
      import.meta.url,
    ).pathname,
    costProbe: true,
    outboundService: async () => {
      outboundCalls++;
      throw Error("diagnostic forbids outbound requests");
    },
  },
);
const environment = {
  coordinator: process.version,
  workerd: require("workerd/package.json").version,
  miniflare: require("miniflare/package.json").version,
  platform: process.platform,
  arch: process.arch,
  sourceRecords: count,
  mode: fullBundle ? "full-bundle" : "sample",
  boundary:
    "local real Worker startup/private owner RPC; eviction enabled; no hosted CPU/heap limit enforcement",
};
async function command(operation, extra = {}) {
  const requestId = randomUUID();
  const r = await runtime.send({
    raw: JSON.stringify({ operation, requestId, ...extra }),
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.ok, true, JSON.stringify(r.body));
  assert.equal(r.body.operation, operation);
  assert.equal(r.body.requestId, requestId);
  assert.equal(r.body.operator, "fixture:operator");
  return r.body;
}
async function probe(value) {
  const r = await runtime.send({ kind: "cost-probe", value });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}
async function measure(stage, fn) {
  const start = performance.now();
  let outcome = "ok";
  try {
    return await fn();
  } catch (error) {
    outcome = error.constructor.name;
    throw error;
  } finally {
    console.log(
      JSON.stringify({
        ...environment,
        stage,
        outcome,
        elapsedMs: performance.now() - start,
      }),
    );
  }
}
async function collectFullBundle(before, expectedHead) {
  const parent = await mkdtemp(join(tmpdir(), "xeip-worker-full-bundle-"));
  const directory = join(parent, "bundle");
  const calls = {};
  let capturedDigest;
  console.log(
    JSON.stringify({ ...environment, stage: "bundle-artifact", directory }),
  );
  const result = await measure("complete-bundle-collection", () =>
    collectOwnerOrganizationBundle({
      directory,
      organization: profile.organization,
      session: {
        async send(raw, exportContext) {
          const request = parseOwnerCommand(raw);
          const response = await runtime.send({ raw });
          assert.equal(response.status, 200, JSON.stringify(response.body));
          const receipt = validateOwnerReceipt(JSON.stringify(response.body), {
            ...request,
            operator: "fixture:operator",
            exportContext,
          });
          const key = request.section ?? request.operation;
          calls[key] = (calls[key] ?? 0) + 1;
          if (request.operation === "organizationExportBegin")
            capturedDigest = receipt.export.manifest.digest;
          if (request.section === "administration" && calls[key] % 1000 === 0)
            console.log(
              JSON.stringify({
                ...environment,
                stage: "collection-progress",
                administrationPages: calls[key],
              }),
            );
          return receipt;
        },
      },
    }),
  );
  assert.equal(result.sourceClosed, true);
  assert.equal(calls.organizationExportBegin, 1);
  assert.equal(calls.organizationExportClose, 1);
  assert.equal(calls.administration, Math.ceil(count / 16));
  assert.equal(result.bundle.checkpoint.digest, capturedDigest);
  const administration = validateAdminCheckpoint(
    JSON.parse(await readFile(join(directory, "administration.json"), "utf8")),
    profile.organization,
  );
  assert.equal(administration.headSequence, count);
  assert.equal(administration.headChecksum, expectedHead);
  const after = await probe({ operation: "state" });
  assert.equal(after.headSequence, count);
  assert.equal(after.headChecksum, expectedHead);
  await runtime.close();
  runtimeClosed = true;
  const verified = await measure("offline-complete-bundle-verification", () =>
    verifyOrganizationBundle(directory, {
      organization: profile.organization,
      expectedDigest: capturedDigest,
    }),
  );
  assert.deepEqual(verified, result.bundle);
  assert.equal((await lstat(parent)).mode & 0o777, 0o700);
  assert.equal((await lstat(directory)).mode & 0o777, 0o700);
  const names = await readdir(directory);
  let bytes = 0;
  for (const name of names) {
    const stat = await lstat(join(directory, name));
    assert.equal(stat.isFile(), true);
    assert.equal(stat.mode & 0o777, 0o600);
    bytes += stat.size;
  }
  console.log(
    JSON.stringify({
      ...environment,
      stage: "verified-complete-bundle",
      outcome: "ok",
      directory,
      files: names.length,
      bytes,
      calls,
      sourceClosed: result.sourceClosed,
      runtimeClosed,
      sameInstance: before.instanceId === after.instanceId,
      checkpointDigest: capturedDigest,
      bundleChecksum: verified.checksum,
      coordinatorMaxRssKiB: process.resourceUsage().maxRSS,
      memoryScope:
        "Node coordinator only; excludes workerd and does not establish peak Worker heap",
    }),
  );
}
try {
  await command("initialize", {
    configuration: fixture.checkpoint.authority.configuration,
  });
  const initial = (await command("auditExport")).audit;
  assert.equal(initial.headSequence, 2);
  assert.equal(initial.records.at(-1).event.outcome, "completed");
  let previous = initial.headChecksum,
    records = [],
    cursorChecksum;
  const baseTime = initial.records.at(-1).event.occurredAt;
  for (let index = 1; index < count / 2; index++) {
    const id = "00000000-0000-4000-8000-" + String(index + 1).padStart(12, "0");
    const common = {
      operator: "fixture:operator",
      requestId: id,
      operation: "refreshTrust",
      commandDigest: "a".repeat(64),
      attemptId: id,
      before: { state: "initialized", trustRevision: 0, authorityRevision: 0 },
    };
    for (const outcome of ["started", "completed"]) {
      const sequence = index * 2 + (outcome === "started" ? 1 : 2);
      const event = {
        ...common,
        outcome,
        occurredAt: baseTime + sequence,
        ...(outcome === "completed"
          ? {
              after: {
                state: "initialized",
                trustRevision: 0,
                authorityRevision: 0,
              },
            }
          : {}),
      };
      const canonical = canonicalize(event),
        checksum = auditChecksum(sequence, previous, canonical);
      records.push({ sequence, event, canonical, previous, checksum });
      previous = checksum;
      if (sequence === count - 16) cursorChecksum = checksum;
    }
    if (records.length === 1000) {
      assert.equal((await probe({ operation: "seed", records })).seeded, 1000);
      records = [];
    }
  }
  if (records.length)
    assert.equal(
      (await probe({ operation: "seed", records })).seeded,
      records.length,
    );
  await runtime.restart();
  const status = await measure("cold-status", () => command("status"));
  assert.equal(status.status.state, "initialized");
  const before = await probe({ operation: "state" });
  assert.equal(before.headSequence, count);
  assert.equal(before.headChecksum, previous);
  if (fullBundle) {
    await collectFullBundle(before, previous);
  } else {
    const begin = await measure("export-begin", () =>
      command("organizationExportBegin"),
    );
    const description = validateExportDescription(
      begin.export,
      profile.organization,
    );
    assert.equal(description.components.administration.parts, 1);
    const partResult = await measure("administration-component", () =>
      command("organizationExportPart", {
        exportId: description.exportId,
        component: "administration",
        index: 0,
      }),
    );
    const part = validateExportReceipt(partResult.part, {
      operation: "organizationExportPart",
      exportId: description.exportId,
      component: "administration",
      index: 0,
      exportContext: { description },
    });
    const bytes = Buffer.from(part.data, "base64");
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      description.components.administration.sha256,
    );
    const administration = validateAdminCheckpoint(
      JSON.parse(bytes.toString("utf8")),
      profile.organization,
    );
    assert.equal(
      administration.digest,
      description.manifest.administrationDigest,
    );
    assert.equal(administration.headSequence, count);
    assert.equal(administration.headChecksum, previous);
    const cursor = {
      after: count - 16,
      previousChecksum: cursorChecksum,
      limit: 16,
    };
    const pageResult = await measure("last-administration-page", () =>
      command("organizationExportPage", {
        exportId: description.exportId,
        section: "administration",
        cursor,
      }),
    );
    assert.equal(pageResult.page.checkpointDigest, description.manifest.digest);
    const page = validateAdminHistoryPage(
      pageResult.page.page,
      administration,
      cursor,
    );
    assert.equal(page.next, count);
    assert.equal(page.complete, true);
    assert.equal(page.records.length, 16);
    assert.equal(page.records.at(-1).checksum, previous);
    const closed = await command("organizationExportClose", {
      exportId: description.exportId,
    });
    validateExportReceipt(closed.closed, {
      operation: "organizationExportClose",
      exportId: description.exportId,
    });
    const after = await probe({ operation: "state" });
    assert.equal(after.headSequence, count);
    assert.equal(after.headChecksum, previous);
    console.log(
      JSON.stringify({
        ...environment,
        stage: "verified-close",
        outcome: "ok",
        sameInstance: before.instanceId === after.instanceId,
      }),
    );
  }
} finally {
  if (!runtimeClosed) await runtime.close();
  assert.equal(outboundCalls, 0);
}
