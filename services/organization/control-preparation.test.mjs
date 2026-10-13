import assert from "node:assert/strict";
import test from "node:test";
import { publicAuthority } from "./control-state.mjs";
import { prepareControlInWorker } from "./control-preparation.mjs";

// The worker's `verify` operation has historically accepted a bare canonical
// string. The retained-record transition check added a `{ canonical, previous }`
// form; both must keep working so callers such as the artifact conformance and
// the control store are not broken by either shape. This guards the regression
// where only the object form was accepted and the string form threw
// StoreUnavailable.
function enrollInput() {
  const entity = "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
  const kid = entity.slice("urn:xeip:entity:".length);
  const target = {
    id: "internal",
    revision: "1",
    recipient: entity,
    tools: ["lookup"],
    endpoint: "https://tool.test/mcp",
    resourceMetadataUrl: "https://tool.test/resource",
    issuer: "https://tool-id.test",
    tokenEndpoint: "https://tool-id.test/token",
    clientId: "xeip",
    clientSecret: "preparation-validation-only",
    scope: "tools",
  };
  const authority = publicAuthority({
    origin: "https://xeip.test",
    gateway: entity,
    bind: {},
    tls: {},
    database: {},
    management: {},
    shutdownMs: 1000,
    authentication: {
      issuer: "https://id.test/realm",
      audience: "xeip",
      clientIds: ["agent", "human"],
      bindings: ["agent", "human"].map((subject) => ({ subject, entity, kid })),
      introspectionClientId: "xeip",
      introspectionClientSecret: "preparation-validation-only",
    },
    policy: {
      targets: [{ id: target.id, revision: target.revision, recipient: entity, tools: target.tools }],
      sessions: [
        {
          id: "urn:xeip:session:preparation",
          agents: ["agent"],
          approvers: ["human"],
          targets: ["internal"],
        },
      ],
    },
    targets: [target],
    trust: { directory: "/unused", provisioningFile: "/unused", maxAgeSeconds: 300 },
    provisioning: { keyDocuments: [], statusDocuments: [] },
  });
  return {
    authority,
    provisioning: { keyDocuments: [], statusDocuments: [] },
    retainedRecords: {},
    operation: "enroll",
    acceptedAt: Math.floor(Date.now() / 1000),
  };
}

test("verify accepts a bare canonical string and a {canonical} object alike", async () => {
  const prepared = await prepareControlInWorker("prepare", enrollInput());
  const viaString = await prepareControlInWorker("verify", prepared.canonical);
  assert.equal(viaString.digest, prepared.digest);
  assert.ok(Object.isFrozen(viaString.state));
  const viaObject = await prepareControlInWorker("verify", { canonical: prepared.canonical });
  assert.equal(viaObject.digest, prepared.digest);
});
