/** Local isolate memory diagnostic with synthetic storage seeding. NEVER DEPLOY. */
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { signStatusDocument } from "../packages/identity/identity-status.mjs";
import { prepareEntityTrust } from "../packages/identity/trust-state.mjs";
import { encodeProvisioning } from "../services/organization/cloudflare/trust-chunks.mjs";
import { performance } from "node:perf_hooks";
import { loadavg } from "node:os";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { validatePublicAuthority } from "../services/organization/cloudflare/authority-checkpoint.mjs";
import {
  trustStateChecksum,
  validateTrustCheckpoint,
} from "../services/organization/cloudflare/trust-checkpoint.mjs";
import { auditChecksum } from "../services/organization/cloudflare/admin-record.mjs";
import {
  validateExportDescription,
  validateExportReceipt,
} from "../services/organization/cloudflare/organization-export-wire.mjs";
import { organizationBundleFixture } from "./fixtures/cloudflare/organization-bundle-harness.mjs";
import { harness } from "./fixtures/cloudflare/worker-harness.mjs";
import { heapInspector } from "./fixtures/cloudflare/heap-inspector.mjs";
const require = createRequire(import.meta.url);
const size = process.argv[2] ?? "small";
const cpuProfile = process.argv[3] === "--cpu-profile";
const heapProfile = process.argv[3] === "--heap-profile";
const profiling = cpuProfile || heapProfile;
const profileKind = heapProfile ? "heap" : "cpu";
if (
  !["small", "large", "signed-large"].includes(size) ||
  process.argv.length > (profiling ? 4 : 3)
)
  throw Error(
    "usage: node conformance/organization-cloudflare-export-memory.mjs small|large|signed-large [--cpu-profile|--heap-profile]",
  );
const signed = size === "signed-large",
  large = size !== "small",
  recordCount = signed ? 4095 : large ? 4096 : 16,
  entityLength = large ? 2048 : 64,
  adminCount = 1000;
const fixture = organizationBundleFixture({ actions: 0 });
const profile = structuredClone(fixture.checkpoint.lifecycle.runtime);
const authority = structuredClone(fixture.checkpoint.authority.configuration);
authority.authentication.bindings = Array.from(
  { length: large ? 450 : 2 },
  (_, i) => ({
    subject: "synthetic-agent-" + i,
    entity: "urn:xeip:entity:" + "e".repeat(large ? 1800 : 64),
    kid: profile.gateway.slice(16),
  }),
);
validatePublicAuthority(authority);
const records = Object.fromEntries(
  Array.from({ length: recordCount }, (_, i) => [
    ("retained:" + String(i).padStart(5, "0") + ":").padEnd(entityLength, "r"),
    {
      anchor: "a".repeat(64),
      generation: 1,
      keyDigest: "b".repeat(64),
      serial: 1,
      statusDigest: "c".repeat(64),
    },
  ]),
);
const trust = structuredClone(fixture.checkpoint.trust);
Object.assign(trust, { records, revision: 1, acceptedAt: 0 });
const hash = (s) => createHash("sha256").update(s).digest("hex");
let recordsDigest;
function sealTrust() {
  recordsDigest = hash(canonicalize(records));
  trust.checksum = trustStateChecksum({
    configuration: canonicalize(trust.configuration),
    provisioning: canonicalize(trust.provisioning),
    revision: trust.revision,
    accepted_at: trust.acceptedAt,
    checkpoints_digest: recordsDigest,
  });
}
if (signed) {
  profile.trust.knownExtensions = ["app.action"];
  trust.configuration.knownExtensions = ["app.action"];
}
function populateSignedTrust() {
  const vectors = JSON.parse(
    readFileSync(
      new URL("./fixtures/entity-envelope/vectors.json", import.meta.url),
      "utf8",
    ),
  );
  const base = vectors.vectors[0].options;
  trust.provisioning = {
    keyDocuments: base.keyDocuments.map((document) => ({
      document: structuredClone(document),
      anchor: structuredClone(base.anchor),
    })),
    statusDocuments: [
      {
        document: signStatusDocument(
          {
            ...base.statusDocument,
            serial: 1,
            revoked: [],
            issuedAt: new Date(trust.acceptedAt * 1000)
              .toISOString()
              .replace(".000Z", "Z"),
            signatures: [],
          },
          {
            // Public conformance seed only; no real identity credentials.
            privateKey: Buffer.from(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
              "hex",
            ),
            kid: base.keyDocuments[0].genesis,
          },
        ),
      },
    ],
  };
  const first = trust.provisioning.keyDocuments[0].document;
  const signature = first.signatures[0];
  first.signatures = Array.from({ length: 47000 }, () => ({ ...signature }));
  const prepared = prepareEntityTrust(
    trust.configuration,
    trust.provisioning.keyDocuments,
    trust.provisioning.statusDocuments,
    trust.acceptedAt,
  );
  assert.equal(Object.keys(prepared.checkpoints).length, 1);
  Object.assign(records, prepared.checkpoints);
  assert.equal(Object.keys(records).length, 4096);
}
sealTrust();
validateTrustCheckpoint(trust, profile.organization);
const environment = {
  size,
  cpuProfile,
  heapProfile,
  coordinator: process.version,
  workerd: require("workerd/package.json").version,
  miniflare: require("miniflare/package.json").version,
  platform: process.platform,
  arch: process.arch,
  rollbackRecords: recordCount,
  rollbackEntityLength: entityLength,
  adminRecords: adminCount,
  authorityBytes: Buffer.byteLength(canonicalize(authority)),
  trustCheckpointBytes: Buffer.byteLength(canonicalize(trust)),
  activeSignedEntities: signed ? 1 : 0,
  signatureCopies: signed ? 47000 : 0,
  scope:
    "local XEIP isolate operation-boundary samples; observer enabled; no forced GC; not peak or hosted enforcement; zero actions",
};
console.log(
  JSON.stringify({
    ...environment,
    stage: "prepared-workload",
    loadAverage: loadavg(),
  }),
);
let outboundCalls = 0,
  inspector;
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
    inspector: true,
    costProbe: true,
    entryPoint: new URL(
      "./organization-cloudflare-export-cost-worker.mjs",
      import.meta.url,
    ).pathname,
    outboundService: async () => {
      outboundCalls++;
      throw Error("diagnostic forbids outbound requests");
    },
  },
);
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
async function sample(stage) {
  console.log(
    JSON.stringify({ ...environment, stage, memory: await inspector.usage() }),
  );
}
async function measure(stage, work) {
  const start = performance.now();
  let outcome = "ok";
  try {
    return await work();
  } catch (e) {
    outcome = e.constructor.name;
    throw e;
  } finally {
    console.log(
      JSON.stringify({
        ...environment,
        stage,
        outcome,
        elapsedMs: performance.now() - start,
        loadAverage: loadavg(),
      }),
    );
  }
}
try {
  await command("initialize", { configuration: authority });
  const initialState = await probe({ operation: "state" });
  assert.ok(Number.isSafeInteger(initialState.trustAcceptedAt));
  trust.acceptedAt = initialState.trustAcceptedAt;
  if (signed) populateSignedTrust();
  sealTrust();
  validateTrustCheckpoint(trust, profile.organization);
  environment.trustCheckpointBytes = Buffer.byteLength(canonicalize(trust));
  if (signed) assert.ok(environment.trustCheckpointBytes > 16000000);
  const encoded = encodeProvisioning(
    canonicalize(trust.provisioning),
    trust.revision,
  );
  environment.provisioningBytes = Buffer.byteLength(
    canonicalize(trust.provisioning),
  );
  environment.provisioningChunks = encoded.chunks.length;
  console.log(
    JSON.stringify({
      ...environment,
      stage: "workload",
      loadAverage: loadavg(),
    }),
  );
  const entries = Object.entries(records);
  for (let offset = 0; offset < entries.length; offset += 64) {
    const batch = entries.slice(offset, offset + 64);
    assert.equal(
      (await probe({ operation: "seed-trust", records: batch })).seeded,
      batch.length,
    );
  }
  assert.equal(
    (
      await probe({
        operation: "seal-trust",
        state: {
          revision: trust.revision,
          acceptedAt: trust.acceptedAt,
          recordsDigest,
          checksum: trust.checksum,
          stored: encoded.stored,
        },
      })
    ).sealed,
    true,
  );
  for (const chunk of encoded.chunks)
    assert.equal(
      (await probe({ operation: "seed-trust-chunk", chunk })).seeded,
      chunk.part,
    );
  const initial = (await command("auditExport")).audit;
  let previous = initial.headChecksum;
  const rows = [];
  for (let index = 1; index < adminCount / 2; index++) {
    const id = "00000000-0000-4000-8000-" + String(index + 1).padStart(12, "0");
    const common = {
      operator: "fixture:operator",
      requestId: id,
      operation: "refreshTrust",
      commandDigest: "a".repeat(64),
      attemptId: id,
      before: { state: "initialized", trustRevision: 1, authorityRevision: 0 },
    };
    for (const outcome of ["started", "completed"]) {
      const sequence = index * 2 + (outcome === "started" ? 1 : 2);
      const event = {
        ...common,
        outcome,
        occurredAt: initial.records.at(-1).event.occurredAt + sequence,
        ...(outcome === "completed" ? { after: common.before } : {}),
      };
      const canonical = canonicalize(event),
        checksum = auditChecksum(sequence, previous, canonical);
      rows.push({ sequence, event, canonical, previous, checksum });
      previous = checksum;
    }
  }
  assert.equal(
    (await probe({ operation: "seed", records: rows })).seeded,
    adminCount - 2,
  );
  await runtime.restart();
  inspector = await heapInspector(await runtime.inspectorURL(), "xeip");
  await sample("before-cold-open");
  const status = await measure("cold-status", () => command("status"));
  assert.equal(status.status.state, "initialized");
  await sample("after-cold-open");
  const before = await probe({ operation: "state" });
  assert.equal(before.headSequence, adminCount);
  assert.equal(before.headChecksum, previous);
  let begin, beginError;
  let profileDirectory;
  if (profiling) {
    profileDirectory = await mkdtemp(
      join(tmpdir(), `xeip-export-${profileKind}-`),
    );
    await writeFile(
      join(profileDirectory, "worker.mjs"),
      await runtime.inspectorSource(),
      { mode: 0o600, flag: "wx" },
    );
    if (heapProfile) await inspector.startHeapProfile();
    else await inspector.startCpuProfile();
  }
  try {
    begin = await measure("export-begin", () =>
      command("organizationExportBegin"),
    );
  } catch (error) {
    beginError = error;
    throw error;
  } finally {
    if (profiling) {
      try {
        const { profile, profilerDisabled } = heapProfile
          ? await inspector.stopHeapProfile()
          : await inspector.stopCpuProfile();
        await writeFile(
          join(profileDirectory, `capture.${profileKind}profile`),
          JSON.stringify(profile),
          { mode: 0o600, flag: "wx" },
        );
        console.log(
          JSON.stringify({
            ...environment,
            stage: `capture-${profileKind}-profile`,
            directory: profileDirectory,
            samples: profile.samples?.length,
            profilerDisabled,
            ...(heapProfile
              ? { samplingInterval: 32768, includesCollectedObjects: true }
              : {}),
          }),
        );
        if (!profilerDisabled)
          throw Error("local profiler cleanup unconfirmed");
      } catch (error) {
        console.log(
          JSON.stringify({
            ...environment,
            stage: `capture-${profileKind}-profile-failed`,
            primaryCaptureFailed: !!beginError,
          }),
        );
        if (!beginError) throw error;
      }
    }
  }

  const description = validateExportDescription(
    begin.export,
    profile.organization,
  );
  await sample("after-capture");
  for (const [component, descriptor] of Object.entries(
    description.components,
  )) {
    const digest = createHash("sha256");
    let bytes = 0;
    for (let index = 0; index < descriptor.parts; index++) {
      const result = await command("organizationExportPart", {
        exportId: description.exportId,
        component,
        index,
      });
      const part = validateExportReceipt(result.part, {
        operation: "organizationExportPart",
        exportId: description.exportId,
        component,
        index,
        exportContext: { description },
      });
      const data = Buffer.from(part.data, "base64");
      digest.update(data);
      bytes += data.length;
    }
    assert.equal(bytes, descriptor.bytes);
    assert.equal(digest.digest("hex"), descriptor.sha256);
    if (component === "trust")
      assert.equal(descriptor.sha256, hash(canonicalize(trust) + "\n"));
    console.log(
      JSON.stringify({
        ...environment,
        stage: "verified-component",
        component,
        bytes,
        parts: descriptor.parts,
      }),
    );
    await sample("after-" + component + "-parts");
  }
  const closed = await command("organizationExportClose", {
    exportId: description.exportId,
  });
  validateExportReceipt(closed.closed, {
    operation: "organizationExportClose",
    exportId: description.exportId,
  });
  await sample("after-close");
  const after = await probe({ operation: "state" });
  assert.equal(after.headSequence, adminCount);
  assert.equal(after.headChecksum, previous);
  console.log(
    JSON.stringify({
      ...environment,
      stage: "verified-close",
      sameInstance: before.instanceId === after.instanceId,
      outcome: "ok",
    }),
  );
} catch (error) {
  if (inspector) {
    try {
      await sample("after-failure");
    } catch {
      console.log(
        JSON.stringify({ ...environment, stage: "failure-memory-unavailable" }),
      );
    }
  }
  throw error;
} finally {
  inspector?.close();
  await runtime.close();
  assert.equal(outboundCalls, 0);
}
