/** TEST ONLY: independently built historical bundle fixture. */
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import {
  lifecycleChecksum,
  lifecycleCheckpointDigest,
} from "../../../services/organization/cloudflare/lifecycle-checkpoint.mjs";
import { trustStateChecksum } from "../../../services/organization/cloudflare/trust-checkpoint.mjs";
import {
  authorityEventChecksum,
  authorityCheckpointDigest,
} from "../../../services/organization/cloudflare/authority-checkpoint.mjs";
import { adminCheckpointDigest } from "../../../services/organization/cloudflare/admin-checkpoint.mjs";
import { auditChecksum } from "../../../services/organization/cloudflare/admin-record.mjs";
import { actionSnapshotHasher } from "../../../services/organization/cloudflare/action-export.mjs";
import {
  organizationManifest,
  validateOrganizationCheckpoint,
} from "../../../services/organization/cloudflare/organization-checkpoint.mjs";
const zero = "0".repeat(64),
  organization = "bundle-fixture";
const entity =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const hash = (v) => createHash("sha256").update(v).digest("hex");
export function organizationBundleFixture({
  actions = 2,
  revisions = 0,
  attempts = 0,
  records = {},
  firstSequence = 1,
  states,
  trustRevision = 0,
  historicalTrust,
} = {}) {
  const configuration = {
    authentication: {
      issuer: "https://identity.example/realm",
      audience: "xeip",
      clientIds: ["agent"],
      introspectionClientId: "introspection",
      bindings: [{ subject: "agent", entity, kid: entity.slice(16) }],
    },
    policy: { targets: [], sessions: [] },
  };
  const runtime = {
    organization,
    origin: "https://xeip.example",
    gateway: entity,
    trust: { maxAgeSeconds: 300 },
    targets: [
      {
        id: "tool",
        revision: "1",
        recipient: entity,
        tools: ["lookup"],
        endpoint: "https://tool.example/mcp",
        resourceMetadataUrl: "https://tool.example/resource",
        issuer: "https://tool.example",
        tokenEndpoint: "https://tool.example/token",
        clientId: "xeip",
        scope: "tool",
      },
    ],
  };
  const lifecycleBody = {
    schema: "xeip.lifecycle-checkpoint/1",
    organization,
    runtime,
    initialAuthority: configuration,
    phase: "initialized",
    checksum: lifecycleChecksum(
      canonicalize(runtime),
      canonicalize(configuration),
    ),
  };
  const lifecycle = {
    ...lifecycleBody,
    digest: lifecycleCheckpointDigest(lifecycleBody),
  };
  const trust = {
    schema: "xeip.trust-checkpoint/1",
    organization,
    configuration: { maxAgeSeconds: 300, knownExtensions: [] },
    provisioning: { keyDocuments: [], statusDocuments: [] },
    revision: trustRevision,
    acceptedAt: 0,
    records,
  };
  if (historicalTrust) Object.assign(trust, historicalTrust, { organization });
  trust.checksum = trustStateChecksum({
    configuration: canonicalize(trust.configuration),
    provisioning: canonicalize(trust.provisioning),
    revision: trust.revision,
    accepted_at: trust.acceptedAt,
    checkpoints_digest: hash(canonicalize(trust.records)),
  });
  const authorityRows = [];
  for (let revision = 0; revision <= revisions; revision++) {
    const configurationDigest = hash(canonicalize(configuration)),
      previousChecksum = authorityRows.at(-1)?.checksum ?? zero;
    authorityRows.push({
      revision,
      configurationDigest,
      previousChecksum,
      checksum: authorityEventChecksum(
        revision,
        configurationDigest,
        previousChecksum,
      ),
    });
  }
  const last = authorityRows.at(-1),
    authorityBody = {
      schema: "xeip.authority-checkpoint/1",
      organization,
      configuration,
      revision: revisions,
      previousChecksum: last.previousChecksum,
      checksum: last.checksum,
    };
  const authority = {
    ...authorityBody,
    digest: authorityCheckpointDigest(authorityBody),
  };
  const adminRows = [];
  for (let i = 1; i <= attempts; i++) {
    const event = {
        operator: "fixture:owner",
        requestId: randomUUID(),
        operation: "refreshTrust",
        commandDigest: zero,
        attemptId: randomUUID(),
        outcome: "started",
        occurredAt: i,
        before: {
          state: "initialized",
          trustRevision: 0,
          authorityRevision: revisions,
        },
      },
      previous = adminRows.at(-1)?.checksum ?? zero;
    adminRows.push({
      sequence: i,
      event,
      previous,
      checksum: auditChecksum(i, previous, canonicalize(event)),
    });
  }
  const adminBody = {
    schema: "xeip.admin-checkpoint/1",
    organization,
    headSequence: attempts,
    headChecksum: adminRows.at(-1)?.checksum ?? zero,
  };
  const administration = {
    ...adminBody,
    digest: adminCheckpointDigest(adminBody),
  };
  const actionRows = Array.from({ length: actions }, (_, i) => {
    const actor = { subject: "agent", entity, kid: entity.slice(16) },
      request = {
        id: "request-" + i,
        session: "session",
        actor,
        expiresAt: 1000,
        arguments: { private: "argument" },
      },
      canonical = canonicalize(request),
      digest = hash("XEIP organization action v1\n" + canonical);
    return {
      row: {
        session_id: request.session,
        request_id: request.id,
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
          sequence: i + firstSequence,
          session_id: request.session,
          request_id: request.id,
          digest,
          event: "proposed",
          actor: canonicalize(actor),
          occurred_at: 900,
        },
      ],
    };
  });
  let sequence = actions + firstSequence - 1;
  const human =
    "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
  const reviewer = { subject: "human", entity: human, kid: human.slice(16) };
  for (const [i, record] of actionRows.entries()) {
    const state = states?.[i] ?? "pending";
    const add = (event, actor) =>
      record.history.push({
        sequence: ++sequence,
        session_id: record.row.session_id,
        request_id: record.row.request_id,
        digest: record.row.digest,
        event,
        actor: canonicalize(actor),
        occurred_at: 901 + sequence,
      });
    const actor = JSON.parse(record.row.canonical).actor;
    if (state === "revoked") {
      Object.assign(record.row, { state, version: 1 });
      add("revoked", actor);
    } else if (state !== "pending") {
      Object.assign(record.row, {
        state: state === "rejected" ? state : "approved",
        version: 1,
        approver: canonicalize({
          ...reviewer,
          clientId: "console",
          roles: ["approver"],
          expiresAt: 1000,
        }),
        approval_expires_at: 1000,
      });
      add(record.row.state, reviewer);
      if (
        ["executing", "succeeded", "failed", "indeterminate"].includes(state)
      ) {
        Object.assign(record.row, {
          state: "executing",
          version: 2,
          claim_id: randomUUID(),
        });
        add("claimed", actor);
        if (state !== "executing") {
          Object.assign(record.row, {
            state,
            version: 3,
            result_canonical:
              state === "succeeded"
                ? canonicalize({ content: [{ type: "text", text: "result" }] })
                : null,
          });
          add(state, { worker: "execution", claimId: record.row.claim_id });
        }
      }
    }
  }
  const header = {
      schema: "xeip.action-snapshot/1",
      organization,
      cut: actions === 0 ? 0 : sequence,
      actions,
    },
    hasher = actionSnapshotHasher(header);
  for (const row of actionRows) hasher.update(canonicalize(row) + "\n");
  const components = { lifecycle, trust, authority, administration },
    checkpoint = validateOrganizationCheckpoint(
      {
        ...components,
        manifest: organizationManifest(components, {
          ...header,
          digest: hasher.digest("hex"),
        }),
      },
      organization,
    );
  const capture = async () => checkpoint;
  const readPage = async (manifest, { section, cursor }) => {
    assert.equal(manifest.digest, checkpoint.manifest.digest);
    let page;
    if (section === "actions") {
      const record =
        actionRows.find((row) => row.history[0].sequence > cursor) ?? null;
      page = {
        cut: header.cut,
        after: cursor,
        next: record ? record.history[0].sequence : cursor,
        record,
      };
    } else {
      const isAuthority = section === "authority",
        all = isAuthority ? authorityRows : adminRows,
        records = all
          .filter((r) => (isAuthority ? r.revision : r.sequence) > cursor.after)
          .slice(0, cursor.limit),
        next = records.length
          ? isAuthority
            ? records.at(-1).revision
            : records.at(-1).sequence
          : cursor.after;
      page = {
        schema: isAuthority
          ? "xeip.authority-history-page/1"
          : "xeip.admin-history-page/1",
        checkpointDigest: isAuthority
          ? authority.digest
          : administration.digest,
        after: cursor.after,
        records,
        next,
        complete: next === (isAuthority ? revisions : attempts),
      };
    }
    return { checkpointDigest: checkpoint.manifest.digest, section, page };
  };
  return {
    organization,
    capture,
    readPage,
    checkpoint,
    actionRows,
    authorityRows,
    adminRows,
  };
}
