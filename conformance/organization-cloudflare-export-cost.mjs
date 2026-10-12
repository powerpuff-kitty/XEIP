/** Local cost diagnostic, not a workerd benchmark or production acceptance test.
 * Run each size in a fresh process: node --expose-gc conformance/organization-cloudflare-export-cost.mjs 1000|10000|100000
 * Synthetic SQLite history only. No network, credentials, deployment or external effects.
 */
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { performance } from "node:perf_hooks";
import { OrganizationService } from "../services/organization/cloudflare/service.mjs";
import { auditChecksum } from "../services/organization/cloudflare/admin-audit.mjs";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { organizationBundleFixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";

const count = Number(process.argv[2] ?? 1000);
if (![1000, 10000, 100000].includes(count) || process.argv.length > 3)
  throw new Error(
    "usage: node --expose-gc conformance/organization-cloudflare-export-cost.mjs 1000|10000|100000",
  );
let networkCalls = 0;
globalThis.fetch = async () => {
  networkCalls++;
  throw new Error("diagnostic forbids network access");
};
const db = new DatabaseSync(":memory:");
let transactionId = 0;
let queries = 0,
  rows = 0,
  administrativeRows = 0;
const storage = {
  sql: {
    exec(query, ...bindings) {
      queries++;
      if (!bindings.length && !/^\s*(SELECT|PRAGMA)/i.test(query)) {
        db.exec(query);
        return { toArray: () => [] };
      }
      const result = db.prepare(query).all(...bindings);
      rows += result.length;
      if (query.includes("xeip_owner_events"))
        administrativeRows += result.length;
      return { toArray: () => result };
    },
  },
  transactionSync(fn) {
    // The service bootstrap nests schema initialization, as Durable Object
    // transactionSync supports. Savepoints preserve nested rollback semantics.
    const name = "xeip_diagnostic_" + ++transactionId;
    db.exec("SAVEPOINT " + name);
    try {
      const value = fn();
      db.exec("RELEASE " + name);
      return value;
    } catch (error) {
      db.exec("ROLLBACK TO " + name);
      db.exec("RELEASE " + name);
      throw error;
    }
  },
  // No disk sync cost is represented by an in-memory SQLite adapter.
  sync: async () => {},
};
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
  runtime: process.version,
  platform: process.platform,
  arch: process.arch,
  sourceRecords: count,
  boundary:
    "Node SQLite in-memory; excludes disk/network, not workerd or hosted acceptance",
};
async function measure(stage, fn) {
  globalThis.gc?.();
  queries = rows = administrativeRows = 0;
  const memoryBefore = process.memoryUsage(),
    cpuBefore = process.cpuUsage(),
    start = performance.now();
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
        cpuMicroseconds: process.cpuUsage(cpuBefore),
        queries,
        resultRows: rows,
        administrativeResultRows: administrativeRows,
        memoryBefore,
        memoryAfter: process.memoryUsage(),
        processPeakRssKiB: process.resourceUsage().maxRSS,
      }),
    );
  }
}
let service;
try {
  service = await OrganizationService.open(storage, settings);
  await service.initialize(fixture.checkpoint.lifecycle.initialAuthority);
  assert.equal(service.status().state, "initialized");
  service.close();
  assert.equal(
    db.prepare("SELECT count(*) AS n FROM xeip_owner_events").get().n,
    0,
  );
  const insert = db.prepare(
    "INSERT INTO xeip_owner_events(sequence,attempt_id,outcome,canonical,previous,checksum) VALUES(?,?,?,?,?,?)",
  );
  let previous = "0".repeat(64);
  db.exec("BEGIN");
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
      const encoded = canonicalize(event),
        checksum = auditChecksum(sequence, previous, encoded);
      insert.run(sequence, id, outcome, encoded, previous, checksum);
      previous = checksum;
    }
  }
  db.exec("COMMIT");
  service = await measure("source-open", () =>
    OrganizationService.open(storage, settings),
  );
  assert.equal(service.status().state, "initialized");
  const checkpoint = await measure("synchronized-checkpoint", () =>
    service.recoveryCheckpoint(),
  );
  assert.equal(checkpoint.administration.headSequence, count);
  assert.equal(checkpoint.administration.headChecksum, previous);
  const description = await measure("export-begin", () =>
    service.beginRecoveryExport("fixture:owner"),
  );
  assert.equal(description.manifest.digest, checkpoint.manifest.digest);
  const part = await measure("first-component", () =>
    service.recoveryExportPart(
      "fixture:owner",
      description.exportId,
      "lifecycle",
      0,
    ),
  );
  assert.equal(part.checkpointDigest, checkpoint.manifest.digest);
  assert.ok(Buffer.from(part.data, "base64").length > 0);
  service.closeRecoveryExport("fixture:owner", description.exportId);
} finally {
  service?.close();
  db.close();
  assert.equal(networkCalls, 0);
}
