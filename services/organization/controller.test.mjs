import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fixture } from "./test-fixtures/provider.mjs";
import { KeycloakAuthenticator } from "./auth.mjs";
import { EntityTrustPolicy } from "../relay/entity-trust.mjs";
import { signStatusDocument } from "../../tools/identity-status.mjs";
import { signEntityEnvelope } from "../../packages/identity/entity-envelope.mjs";
import { ActionPolicy, PolicyDenied } from "./actions.mjs";
import { ActionStore, StoreConflict, StoreUnavailable } from "./store.mjs";
import { OrganizationController, OperationError } from "./controller.mjs";
const vectors = JSON.parse(
  fs.readFileSync(
    new URL(
      "../../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
const base = vectors.vectors[0].options;
const rootSeed = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const gateway = "urn:xeip:entity:" + vectors.kid;
const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
async function setup(t) {
  const provider = await fixture(t),
    auth = new KeycloakAuthenticator(provider.config);
  const directory = fs.mkdtempSync(join(tmpdir(), "xeip-controller-"));
  const now = Math.floor(Date.now() / 1000);
  function provisioning(serial = 1, revoked = []) {
    return {
      keyDocuments: base.keyDocuments.map((document) => ({
        document,
        anchor: base.anchor,
      })),
      statusDocuments: [
        {
          document: signStatusDocument(
            {
              ...base.statusDocument,
              serial,
              revoked,
              issuedAt: utc(now),
              signatures: [],
            },
            { privateKey: rootSeed, kid: base.keyDocuments[0].genesis },
          ),
        },
      ],
    };
  }
  const initial = provisioning();
  const trust = new EntityTrustPolicy(
    { trustDir: join(directory, "trust"), maxAgeSeconds: 180 },
    initial.keyDocuments,
    initial.statusDocuments,
  );
  t.after(() => {
    trust.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const calls = [],
    state = { failure: null, principal: null };
  const createStore = (authorize) => {
    const method =
      (name) =>
      async (principal, ...args) => {
        state.principal = principal;
        if (!(await authorize(principal, { phase: name, proposal: {} })))
          throw new PolicyDenied();
        if (state.failure) throw state.failure;
        calls.push({ name, args });
        if (name === "propose")
          assert.equal(Object.isFrozen(args[0].arguments), true);
        return {
          state: name === "propose" ? "pending" : "approved",
          proposal: { digest: "a".repeat(64) },
          claimId: "internal-only",
        };
      };
    return {
      propose: method("propose"),
      decide: method("decide"),
      revoke: method("revoke"),
      inspect: method("inspect"),
    };
  };
  const controller = new OrganizationController({
    authentication: auth,
    trust,
    gateway,
    createStore,
  });
  const request = {
    id: "urn:test:action",
    session: "urn:test:session",
    target: "internal",
    tool: "lookup",
    arguments: { query: "status" },
    expiresAt: now + 120,
  };
  const envelope = {
    xeip: "0.1",
    id: request.id,
    kind: "command",
    sender: vectors.envelope.sender,
    recipient: gateway,
    session: request.session,
    timestamp: utc(now),
    expiresAt: utc(now + 60),
    body: {
      contentType: "application/vnd.xeip.organization-action+json",
      data: { operation: "propose", request },
    },
  };
  const signed = (value) =>
    signEntityEnvelope(value, {
      privateKey: Buffer.from(vectors.seed, "hex"),
      kid: vectors.kid,
    });
  const token = await provider.token({
    resource_access: { "xeip-api": { roles: ["agent", "approver"] } },
  });
  const header = "Bearer " + token;
  return {
    provider,
    auth,
    trust,
    provisioning,
    controller,
    calls,
    state,
    envelope,
    signed,
    header,
    now,
  };
}
const code = (status) => (error) =>
  error instanceof OperationError && error.status === status;

for (const [mode, wait] of [
  ["cancel", "INSERT INTO xeip_org.actions"],
  ["cancel", "INSERT INTO xeip_org.audit"],
  ["expiry", "INSERT INTO xeip_org.actions"],
  ["expiry", "INSERT INTO xeip_org.audit"],
])
  test(mode + " during " + wait + " cannot initiate COMMIT", async (t) => {
    const f = await setup(t),
      abort = new AbortController(),
      queries = [];
    const policy = new ActionPolicy({
      targets: [
        {
          id: "internal",
          revision: "1",
          recipient: gateway,
          tools: ["lookup"],
        },
      ],
      sessions: [
        {
          id: f.envelope.session,
          agents: ["user-1"],
          approvers: ["human"],
          targets: ["internal"],
        },
      ],
    });
    const proposal = policy.propose(
      {
        subject: "user-1",
        entity: f.envelope.sender,
        kid: vectors.kid,
        clientId: "xeip-console",
        roles: ["agent", "approver"],
        expiresAt: f.now + 120,
      },
      f.envelope.body.data.request,
    );
    const row = {
      session_id: f.envelope.session,
      request_id: f.envelope.id,
      digest: proposal.digest,
      canonical: JSON.stringify(proposal.action),
      state: "pending",
      claim_id: null,
      result_canonical: null,
    };
    const pool = {
      options: { connectionTimeoutMillis: 3000, query_timeout: 10000 },
      connect: async () => ({
        query: async (sql) => {
          queries.push(sql);
          if (sql.startsWith(wait)) {
            if (mode === "cancel") abort.abort();
            else t.mock.method(Date, "now", () => (f.now + 61) * 1000);
          }
          return { rows: [row] };
        },
        release: () => {},
      }),
    };
    const controller = new OrganizationController({
      authentication: f.auth,
      trust: f.trust,
      gateway,
      createStore: (authorize) => new ActionStore(pool, policy, authorize),
    });
    await assert.rejects(
      controller.handle(f.header, JSON.stringify(f.signed(f.envelope)), {
        signal: abort.signal,
      }),
      code(403),
    );
    assert.equal(queries.includes("COMMIT"), false);
    assert.equal(queries.at(-1), "ROLLBACK");
  });

test("real JWT and entity signature reach the store with immutable arguments and no claim capability", async (t) => {
  const f = await setup(t);
  const result = await f.controller.handle(
    f.header,
    JSON.stringify(f.signed(f.envelope)),
  );
  assert.equal(result.state, "pending");
  assert.equal(Object.hasOwn(result, "claimId"), false);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].name, "propose");
  assert.equal(
    await f.auth.revalidate(f.state.principal),
    false,
    "principal released after request",
  );
});
for (const [name, edit, status] of [
  ["wrong recipient", (e) => (e.recipient = e.sender), 403],
  ["wrong sender", (e) => (e.sender = gateway), 403],
  [
    "cross-session body",
    (e) => (e.body.data.request.session = "urn:test:other"),
    400,
  ],
  [
    "different proposal ID",
    (e) => (e.body.data.request.id = "urn:test:other"),
    400,
  ],
  [
    "future timestamp",
    (e) => (e.timestamp = utc(Math.floor(Date.now() / 1000) + 20)),
    403,
  ],
  [
    "stale timestamp",
    (e) => (e.timestamp = utc(Math.floor(Date.now() / 1000) - 61)),
    403,
  ],
  [
    "expired operation",
    (e) => (e.expiresAt = utc(Math.floor(Date.now() / 1000))),
    403,
  ],
  [
    "overlong operation",
    (e) => (e.expiresAt = utc(Math.floor(Date.now() / 1000) + 120)),
    403,
  ],
  ["wrong content type", (e) => (e.body.contentType = "application/json"), 400],
  ["unknown operation field", (e) => (e.body.data.extra = true), 400],
  ["wrong envelope kind", (e) => (e.kind = "message"), 400],
])
  test("rejects signed " + name, async (t) => {
    const f = await setup(t);
    edit(f.envelope);
    await assert.rejects(
      f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope))),
      code(status),
    );
    assert.equal(f.calls.length, 0);
  });
test("rejects unsigned, edited, wrong-bearer and ambiguously parsed requests", async (t) => {
  const f = await setup(t);
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(f.envelope)),
    code(403),
  );
  const edited = f.signed(f.envelope);
  edited.body.data.request.arguments.query = "changed";
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(edited)),
    code(403),
  );
  await assert.rejects(
    f.controller.handle("Bearer invalid", JSON.stringify(f.signed(f.envelope))),
    code(401),
  );
  for (const body of [
    '{"xeip":"0.1","xeip":"0.1"}',
    "[".repeat(40) + "]".repeat(40),
    " ".repeat(98305),
    f.envelope,
  ]) {
    await assert.rejects(f.controller.handle(f.header, body), code(400));
  }
  assert.equal(f.calls.length, 0);
});
test("revocation and signed-operation expiry during provider revalidation prevent store changes", async (t) => {
  const f = await setup(t);
  f.provider.state.beforeIntrospection = async (count) => {
    if (count === 2)
      f.trust.update(f.provisioning(2, [{ kid: vectors.kid, generation: 1 }]));
  };
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope))),
    code(403),
  );
  assert.equal(f.calls.length, 0);
});
test("envelope deadline is rechecked after asynchronous provider work", async (t) => {
  const f = await setup(t);
  f.provider.state.beforeIntrospection = async (count) => {
    if (count === 2) t.mock.method(Date, "now", () => (f.now + 61) * 1000);
  };
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope))),
    code(403),
  );
  assert.equal(f.calls.length, 0);
});

test("an authorized root signature cannot impersonate the bearer-bound device key", async (t) => {
  const f = await setup(t);
  const envelope = signEntityEnvelope(f.envelope, {
    privateKey: rootSeed,
    kid: base.keyDocuments[0].genesis,
  });
  assert.equal(f.trust.verify(envelope).valid, true);
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(envelope)),
    code(403),
  );
  assert.equal(f.calls.length, 0);
});

test("token deactivation during use-time revalidation prevents a store transition", async (t) => {
  const f = await setup(t);
  f.provider.state.beforeIntrospection = async (count) => {
    if (count === 2) f.provider.state.active = false;
  };
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope))),
    code(403),
  );
  assert.equal(f.calls.length, 0);
});

test("request cancellation during provider work cannot later commit an operation", async (t) => {
  const f = await setup(t),
    cancellation = new AbortController();
  f.provider.state.beforeIntrospection = async (count) => {
    if (count === 2) cancellation.abort();
  };
  await assert.rejects(
    f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope)), {
      signal: cancellation.signal,
    }),
    code(403),
  );
  assert.equal(f.calls.length, 0);
});
test("dispatches exact decision/status operations; errors are secret-free and principals released", async (t) => {
  const f = await setup(t);
  for (const operation of ["approve", "reject", "revoke", "inspect"]) {
    f.envelope.body.data = {
      operation,
      session: f.envelope.session,
      id: "urn:test:action",
      ...(operation === "inspect" ? {} : { digest: "a".repeat(64) }),
    };
    await f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope)));
    assert.equal(
      f.calls.at(-1).name,
      operation === "approve" || operation === "reject" ? "decide" : operation,
    );
  }
  for (const [failure, status] of [
    [new StoreConflict(), 409],
    [new StoreUnavailable(), 503],
    [new Error("private credential detail"), 503],
  ]) {
    f.state.failure = failure;
    await assert.rejects(
      f.controller.handle(f.header, JSON.stringify(f.signed(f.envelope))),
      (error) =>
        code(status)(error) && !String(error).includes("private credential"),
    );
    assert.equal(await f.auth.revalidate(f.state.principal), false);
  }
});
