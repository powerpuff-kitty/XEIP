/** Local workerd cost diagnostic, not hosted capacity or memory acceptance.
 * node conformance/organization-cloudflare-workerd-export-cost.mjs 1000|10000|100000
 * Synthetic data and private test-only controls. Never deploy this fixture.
 */
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { createRequire } from "node:module";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { auditChecksum } from "../services/organization/cloudflare/admin-record.mjs";
import { organizationBundleFixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";

const require = createRequire(import.meta.url);
const count = Number(process.argv[2] ?? 1000);
if (![1000, 10000, 100000].includes(count) || process.argv.length > 3)
  throw new Error(
    "usage: node conformance/organization-cloudflare-workerd-export-cost.mjs 1000|10000|100000",
  );
let networkCalls = 0;
const runtime = await harness({
  outboundService: async () => {
    networkCalls++;
    throw new Error("diagnostic forbids outbound requests");
  },
});
try {
  const f = await runtime.fixture();
  const fixture = organizationBundleFixture({ actions: 0 });
  const settings = {
    ...fixture.checkpoint.lifecycle.runtime,
    introspectionClientSecret: "synthetic-diagnostic-secret",
    targets: fixture.checkpoint.lifecycle.runtime.targets.map((target) => ({
      ...target,
      clientSecret: "synthetic-diagnostic-secret",
    })),
  };
  const environment = {
    coordinator: process.version,
    workerd: require("workerd/package.json").version,
    miniflare: require("miniflare/package.json").version,
    platform: process.platform,
    arch: process.arch,
    sourceRecords: count,
    boundary:
      "local workerd Durable Object SQLite and sync without hosted CPU/heap limit enforcement; parent-observed elapsed time",
  };
  async function send(input) {
    const result = await f.send(input);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    return result.body;
  }
  async function measure(stage, input) {
    await send({
      operation: "controls",
      control: { administrativeRows: 0, authorityRows: 0 },
    });
    const beforeInstance = await send({ operation: "probeInstance" });
    const started = performance.now();
    let outcome = "ok";
    try {
      return await send(input);
    } catch (error) {
      outcome = error.constructor.name;
      throw error;
    } finally {
      const elapsedMs = performance.now() - started;
      const afterInstance = await send({ operation: "probeInstance" });
      const sameInstance =
        beforeInstance.instanceId === afterInstance.instanceId;
      const cost = sameInstance ? await send({ operation: "controls" }) : null;
      console.log(
        JSON.stringify({
          ...environment,
          stage,
          outcome: sameInstance ? outcome : "fixture-instance-changed",
          elapsedMs,
          beforeInstance,
          afterInstance,
          administrativeResultRows: cost?.administrativeRows ?? null,
          authorityResultRows: cost?.authorityRows ?? null,
        }),
      );
      if (!sameInstance)
        throw new Error(
          `fixture instance changed during ${stage}; row measurement unavailable`,
        );
    }
  }
  await send({ operation: "open", configuration: settings });
  await send({
    operation: "initialize",
    configuration: fixture.checkpoint.authority.configuration,
  });
  await send({ operation: "close" });
  let previous = "0".repeat(64),
    records = [];
  // Paired records match the Node SQLite diagnostic's workload shape. All
  // generation and seeding happen before measured capture stages.
  for (let index = 0; index < count / 2; index++) {
    const id = "00000000-0000-4000-8000-" + String(index + 1).padStart(12, "0");
    const common = {
      operator: "fixture:owner",
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
        occurredAt: sequence,
        ...(outcome === "completed"
          ? {
              after: {
                state: "initialized",
                trustRevision: 1,
                authorityRevision: 0,
              },
            }
          : {}),
      };
      const canonical = canonicalize(event),
        checksum = auditChecksum(sequence, previous, canonical);
      records.push({ sequence, event, canonical, previous, checksum });
      previous = checksum;
    }
    if (records.length === 1000) {
      await send({ operation: "seedAdministration", records });
      records = [];
    }
  }
  assert.equal(records.length, 0);
  const reopened = await measure("source-open", {
    operation: "open",
    configuration: settings,
  });
  assert.equal(reopened.state, "initialized");
  const checkpoint = await measure("synchronized-checkpoint", {
    operation: "recoveryCheckpoint",
  });
  assert.equal(checkpoint.administration.headSequence, count);
  assert.equal(checkpoint.administration.headChecksum, previous);
  const description = await measure("export-begin", {
    operation: "exportBegin",
    operator: "fixture:owner",
  });
  assert.equal(description.manifest.digest, checkpoint.manifest.digest);
  const part = await measure("first-component", {
    operation: "exportPart",
    operator: "fixture:owner",
    exportId: description.exportId,
    component: "lifecycle",
    index: 0,
  });
  assert.equal(part.checkpointDigest, checkpoint.manifest.digest);
  assert.ok(Buffer.from(part.data, "base64").length > 0);
  await send({
    operation: "exportClose",
    operator: "fixture:owner",
    exportId: description.exportId,
  });
  await send({ operation: "close" });
} finally {
  await runtime.close();
  assert.equal(networkCalls, 0);
}
