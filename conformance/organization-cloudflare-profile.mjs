import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  parseProfile,
  runtimeConfiguration,
  parseOwnerCommand,
  operatorIdentity,
} from "../services/organization/cloudflare/profile.mjs";
const entity =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const profile = () => ({
  organization: "example-org",
  origin: "https://xeip.example",
  gateway: entity,
  trust: { maxAgeSeconds: 300 },
  targets: [
    {
      id: "internal",
      revision: "1",
      recipient: entity,
      tools: ["lookup"],
      endpoint: "https://mcp.example/mcp",
      resourceMetadataUrl: "https://mcp.example/resource",
      issuer: "https://id.example",
      tokenEndpoint: "https://id.example/token",
      clientId: "xeip",
      scope: "tools:lookup",
    },
  ],
});
const secrets = () => ({
  introspectionClientSecret: "idp-secret",
  targets: { internal: "mcp-secret" },
});
const recovery = () => ({
  url: "https://journal.example/v1/recovery",
  stream: "56f243dc-5048-4d1d-8a63-b753ed79844c",
});

test("owner export commands admit only bounded session identifiers, components and cursors", () => {
  const exportId = randomUUID(),
    requestId = randomUUID();
  for (const command of [
    { operation: "organizationExportBegin", requestId },
    {
      operation: "organizationExportPart",
      requestId,
      exportId,
      component: "trust",
      index: 63,
    },
    {
      operation: "organizationExportPage",
      requestId,
      exportId,
      section: "authority",
      cursor: {},
    },
    {
      operation: "organizationExportPage",
      requestId,
      exportId,
      section: "administration",
      cursor: { after: 0, limit: 16 },
    },
    {
      operation: "organizationExportPage",
      requestId,
      exportId,
      section: "actions",
      cursor: 0,
    },
    { operation: "organizationExportClose", requestId, exportId },
  ]) {
    assert.deepEqual(
      JSON.parse(JSON.stringify(parseOwnerCommand(JSON.stringify(command)))),
      command,
    );
    for (const extra of [
      { operator: "spoof" },
      { path: "trust.json" },
      { maximum: 999999 },
    ])
      assert.throws(
        () => parseOwnerCommand(JSON.stringify({ ...command, ...extra })),
        TypeError,
      );
  }
  for (const changes of [
    { exportId: "invalid" },
    { exportId: null },
    { component: "../trust" },
    { component: "__proto__" },
    { index: -1 },
    { index: 0.5 },
    { index: 65 },
  ])
    assert.throws(
      () =>
        parseOwnerCommand(
          JSON.stringify({
            operation: "organizationExportPart",
            requestId,
            exportId,
            component: "trust",
            index: 0,
            ...changes,
          }),
        ),
      TypeError,
    );
  for (const [section, cursor] of [
    ["other", {}],
    ["actions", -1],
    ["actions", {}],
    ["authority", null],
    ["authority", { after: -2 }],
    ["authority", { after: 0 }],
    ["authority", { limit: 257 }],
    ["administration", { limit: 17 }],
    ["administration", { after: 100001, previousChecksum: "0".repeat(64) }],
  ])
    assert.throws(
      () =>
        parseOwnerCommand(
          JSON.stringify({
            operation: "organizationExportPage",
            requestId,
            exportId,
            section,
            cursor,
          }),
        ),
      TypeError,
    );
});
test("recovery profile keeps the transport identity public and requires its separate runtime secret", () => {
  const p = { ...profile(), recovery: recovery() },
    token = "a1".repeat(32);
  const parsed = parseProfile(JSON.stringify(p));
  assert.deepEqual(JSON.parse(JSON.stringify(parsed)), p);
  const config = runtimeConfiguration({
    XEIP_PROFILE: JSON.stringify(p),
    XEIP_CREDENTIALS: JSON.stringify({ ...secrets(), recoveryToken: token }),
  });
  assert.equal(config.recoveryToken, token);
  assert.equal(config.recovery.url, p.recovery.url);
  assert.ok(!JSON.stringify(parsed).includes(token));
});
test("recovery profiles reject ambiguous endpoints, scope overrides, malformed caps and public credentials", () => {
  for (const changes of [
    { url: "http://journal.example/v1/recovery" },
    { url: "https://a:b@journal.example/x" },
    { url: "https://journal.example/x?" },
    { url: "https://JOURNAL.example/x" },
    { url: "https://journal.example/x#" },
    { stream: "invalid" },
    { organization: "other" },
    { token: "a1".repeat(32) },
    { initialize: true },
    { maxEntries: 0 },
    { maxEntries: 1000001 },
    { maxBytes: 0 },
    { maxBytes: 1073741825 },
    { timeoutMs: 99 },
    { timeoutMs: 10001 },
    { timeoutMs: null },
  ])
    assert.throws(() =>
      parseProfile(
        JSON.stringify({
          ...profile(),
          recovery: { ...recovery(), ...changes },
        }),
      ),
    );
  assert.throws(() =>
    parseProfile(JSON.stringify({ ...profile(), recovery: null })),
  );
  assert.throws(() =>
    parseProfile(
      JSON.stringify({ ...profile(), recoveryToken: "a1".repeat(32) }),
    ),
  );
});
test("recovery runtime rejects missing, unexpected or malformed credentials", () => {
  const p = { ...profile(), recovery: recovery() };
  for (const [profileValue, secretValue] of [
    [p, secrets()],
    [profile(), { ...secrets(), recoveryToken: "a1".repeat(32) }],
    ...[
      null,
      "",
      "A".repeat(64),
      "a".repeat(63),
      "b".repeat(65),
      "z".repeat(64),
    ].map((token) => [p, { ...secrets(), recoveryToken: token }]),
  ])
    assert.throws(() =>
      runtimeConfiguration({
        XEIP_PROFILE: JSON.stringify(profileValue),
        XEIP_CREDENTIALS: JSON.stringify(secretValue),
      }),
    );
});
test("production profile combines only exact secret bindings without mutating the public profile", () => {
  const p = profile(),
    raw = JSON.stringify(p);
  const config = runtimeConfiguration({
    XEIP_PROFILE: raw,
    XEIP_CREDENTIALS: JSON.stringify(secrets()),
  });
  assert.equal(config.targets[0].clientSecret, "mcp-secret");
  assert.equal(config.introspectionClientSecret, "idp-secret");
  assert.equal(JSON.stringify(parseProfile(raw)), raw);
  assert.ok(!raw.includes("secret"));
});
for (const [name, mutate] of [
  ["HTTP target", (p) => (p.targets[0].endpoint = "http://mcp.example/mcp")],
  ["insecure target flag", (p) => (p.targets[0].allowInsecureLoopback = false)],
  ["target credential", (p) => (p.targets[0].clientSecret = "leak")],
  ["unknown target field", (p) => (p.targets[0].extraCredential = "leak")],
  ["root credential", (p) => (p.introspectionClientSecret = "leak")],
  ["unknown root field", (p) => (p.objectName = "replacement")],
  ["invalid origin", (p) => (p.origin = "https://xeip.example/path")],
  ["duplicate target", (p) => p.targets.push(p.targets[0])],
  ["invalid gateway", (p) => (p.gateway = "invalid")],
  ["invalid trust", (p) => (p.trust.maxAgeSeconds = 0)],
])
  test("production profile rejects " + name, () => {
    const p = profile();
    mutate(p);
    assert.throws(() => parseProfile(JSON.stringify(p)));
  });
test("binding parser rejects duplicates, oversized text and non-string inputs", () => {
  for (const raw of [
    '{"organization":"one","organization":"two"}',
    " ".repeat(5121),
    profile(),
  ])
    assert.throws(() => parseProfile(raw));
});
for (const [name, mutate] of [
  ["missing target", (s) => delete s.targets.internal],
  ["extra target", (s) => (s.targets.extra = "leak")],
  ["unknown field", (s) => (s.extra = "leak")],
  ["empty secret", (s) => (s.introspectionClientSecret = "")],
  ["control character", (s) => (s.targets.internal = "secret\n")],
])
  test("runtime credentials reject " + name, () => {
    const s = secrets();
    mutate(s);
    assert.throws(() =>
      runtimeConfiguration({
        XEIP_PROFILE: JSON.stringify(profile()),
        XEIP_CREDENTIALS: JSON.stringify(s),
      }),
    );
  });
test("owner status is exact, bounded and cannot override operator or select an object", () => {
  const command = { operation: "status", requestId: randomUUID() };
  assert.deepEqual(
    JSON.parse(JSON.stringify(parseOwnerCommand(JSON.stringify(command)))),
    command,
  );
  for (const extra of [
    { operator: "attacker" },
    { objectName: "new" },
    { expectedRevision: 0 },
    { configuration: {} },
  ])
    assert.throws(() =>
      parseOwnerCommand(JSON.stringify({ ...command, ...extra })),
    );
  for (const raw of [
    JSON.stringify({ ...command, operation: "reset" }),
    JSON.stringify({ ...command, requestId: "bad" }),
    " ".repeat(2097153),
    command,
  ])
    assert.throws(() => parseOwnerCommand(raw));
});
test("owner mutation requires exact revision and forbids fixture authentication", () => {
  const base = {
    operation: "refreshTrust",
    requestId: randomUUID(),
    provisioning: { keyDocuments: [], statusDocuments: [] },
    expectedRevision: 0,
  };
  assert.deepEqual(
    JSON.parse(JSON.stringify(parseOwnerCommand(JSON.stringify(base)))),
    base,
  );
  for (const revision of [-1, 1.5, "0", null])
    assert.throws(() =>
      parseOwnerCommand(
        JSON.stringify({ ...base, expectedRevision: revision }),
      ),
    );
  const init = {
    operation: "initialize",
    requestId: randomUUID(),
    configuration: {
      authentication: {
        issuer: "http://localhost",
        allowInsecureLoopback: true,
      },
      policy: {},
    },
  };
  assert.throws(() => parseOwnerCommand(JSON.stringify(init)));
});
test("operator identity comes from a bounded binding property", () => {
  assert.equal(
    operatorIdentity({ operator: "operations:alice" }),
    "operations:alice",
  );
  for (const props of [
    {},
    { operator: "x\n" },
    { operator: "x".repeat(129) },
    { operator: 1 },
    null,
  ])
    assert.throws(() => operatorIdentity(props));
});

test("audit export accepts only bounded cursors and cannot carry mutation fields", () => {
  const value = {
    operation: "auditExport",
    requestId: randomUUID(),
    after: 0,
    limit: 16,
  };
  assert.equal(
    parseOwnerCommand(JSON.stringify(value)).operation,
    "auditExport",
  );
  for (const changes of [
    { limit: 17 },
    { after: -1 },
    { after: null },
    { limit: null },
    { operator: "spoof" },
    { configuration: {} },
  ]) {
    assert.throws(() =>
      parseOwnerCommand(JSON.stringify({ ...value, ...changes })),
    );
  }
});

test("trust feed is opt-in, pinned and requires exactly its separate credential", () => {
  const p = {
    ...profile(),
    trustFeed: { url: "https://trust.example/current", timeoutMs: 5000 },
  };
  const s = { ...secrets(), trustFeedToken: "publisher-token" };
  const config = runtimeConfiguration({
    XEIP_PROFILE: JSON.stringify(p),
    XEIP_CREDENTIALS: JSON.stringify(s),
  });
  assert.equal(config.trustFeedToken, "publisher-token");
  assert.deepEqual(JSON.parse(JSON.stringify(config.trustFeed)), p.trustFeed);
  for (const [pp, ss] of [
    [p, secrets()],
    [profile(), s],
    [{ ...p, trust: { maxAgeSeconds: 179 } }, s],
    [p, { ...s, trustFeedToken: "contains space" }],
    [p, { ...s, trustFeedToken: "é" }],
  ])
    assert.throws(() =>
      runtimeConfiguration({
        XEIP_PROFILE: JSON.stringify(pp),
        XEIP_CREDENTIALS: JSON.stringify(ss),
      }),
    );
});

test("owner authority setup rejects session identifiers the signed API cannot accept", () => {
  const configuration = {
    authentication: {
      issuer: "https://id.example/realms/org",
      audience: "xeip-api",
      clientIds: ["agent", "console"],
      introspectionClientId: "introspection",
      bindings: [{ subject: "agent", entity, kid: entity.slice(16) }],
    },
    policy: {
      targets: [
        { id: "internal", revision: "1", recipient: entity, tools: ["lookup"] },
      ],
      sessions: [
        {
          id: "urn:xeip:session:work",
          agents: ["agent"],
          approvers: ["human"],
          targets: ["internal"],
        },
      ],
    },
  };
  for (const operation of ["initialize", "updateAuthority"]) {
    const command = {
      operation,
      requestId: randomUUID(),
      configuration,
      ...(operation === "updateAuthority" ? { expectedRevision: 0 } : {}),
    };
    configuration.policy.sessions[0].id = "urn:xeip:session:work";
    assert.doesNotThrow(() => parseOwnerCommand(JSON.stringify(command)));
    for (const invalid of ["operations", "123:work"]) {
      configuration.policy.sessions[0].id = invalid;
      assert.throws(() => parseOwnerCommand(JSON.stringify(command)));
    }
  }
});
