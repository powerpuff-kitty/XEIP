/** Synthetic public configuration and signed trust for local tests only. */
import { readFileSync } from "node:fs";
import { signStatusDocument } from "../../../packages/identity/identity-status.mjs";
import { publicAuthority, prepareControlState } from "../control-state.mjs";
export const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
export const base = fixture.vectors[0].options;
export const entity = fixture.envelope.sender;
export const acceptedAt = base.nowSeconds;
export function provisioning(serial = 1, revoked = []) {
  return {
    keyDocuments: base.keyDocuments.map((document) => ({
      document: structuredClone(document),
      anchor: structuredClone(base.anchor),
    })),
    statusDocuments: [
      {
        document: signStatusDocument(
          { ...base.statusDocument, serial, revoked, signatures: [] },
          {
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
}
export function configuration() {
  const target = {
    id: "internal",
    revision: "1",
    recipient: entity,
    tools: ["lookup"],
    endpoint: "https://tool.test/mcp",
    resourceMetadataUrl:
      "https://tool.test/.well-known/oauth-protected-resource",
    issuer: "https://tool-id.test/realm",
    tokenEndpoint: "https://tool-id.test/token",
    clientId: "xeip",
    clientSecret: "synthetic-secret-tool",
    scope: "tools:call",
  };
  return {
    origin: "https://xeip.test",
    gateway: entity,
    bind: { host: "127.0.0.1", port: 8443 },
    tls: { key: "synthetic-secret-tls", cert: "ignored-certificate" },
    database: { password: "synthetic-secret-database" },
    authentication: {
      issuer: "https://id.test/realms/org",
      audience: "xeip",
      clientIds: ["agent", "console"],
      bindings: ["agent", "human"].map((subject) => ({
        subject,
        entity,
        kid: fixture.kid,
      })),
      introspectionClientId: "xeip-introspection",
      introspectionClientSecret: "synthetic-secret-provider",
    },
    policy: {
      targets: [
        {
          id: target.id,
          revision: target.revision,
          recipient: target.recipient,
          tools: [...target.tools],
        },
      ],
      sessions: [
        {
          id: "urn:xeip:session:work",
          agents: ["agent"],
          approvers: ["human"],
          targets: [target.id],
        },
      ],
    },
    targets: [target],
    trust: {
      directory: "/private/secret-path",
      provisioningFile: "/private/provisioning",
      maxAgeSeconds: 300,
    },
    provisioning: provisioning(),
    management: { token: "synthetic-secret-metrics" },
    shutdownMs: 30000,
    console: { clientId: "console" },
  };
}
export function enroll(
  config = configuration(),
  input = provisioning(),
  retainedRecords = {},
) {
  return prepareControlState({
    authority: publicAuthority(config),
    provisioning: input,
    retainedRecords,
    operation: "enroll",
    acceptedAt,
  });
}
export function next(
  previous,
  input = provisioning(2),
  config = configuration(),
  operation = "trust",
) {
  return prepareControlState({
    authority: publicAuthority(config),
    provisioning: input,
    previous: previous.canonical,
    operation,
    acceptedAt: acceptedAt + 1,
  });
}
