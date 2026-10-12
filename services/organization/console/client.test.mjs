import { assertEnvelope } from "../../../sdks/typescript/dist/index.js";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ActionPolicy } from "../actions.mjs";
import { ApprovalClient } from "./client.mjs";
import { ed25519PrivateKeyFromSeed } from "../../../sdks/typescript/dist/identity.js";
import { verifyEntityEnvelope } from "../../../sdks/typescript/dist/entity-envelope.js";

test("native fetch retains the browser global receiver", async (t) => {
  const f = await fixture(t);
  t.mock.method(globalThis, "fetch", function (...args) {
    assert.equal(this, globalThis);
    return f.configuration.fetch(...args);
  });
  const client = new ApprovalClient({ ...f.configuration, fetch: undefined });
  assert.equal(
    (await client.inspect("urn:xeip:session:operations", "request-1")).state,
    "pending",
  );
});

const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../../../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
const now = vectors.vectors[0].options.nowSeconds;
const other =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
async function fixture(t, options = {}) {
  const state = {
    now,
    response: null,
    failure: false,
    decisionState: "pending",
    tokenSubject: "human",
    calls: [],
  };
  t.mock.method(Date, "now", () => state.now * 1000);
  const policy = new ActionPolicy({
    targets: [
      {
        id: "internal",
        revision: "deployment-1",
        recipient: other,
        tools: ["lookup"],
      },
    ],
    sessions: [
      {
        id: "urn:xeip:session:operations",
        agents: ["agent"],
        approvers: ["human"],
        targets: ["internal"],
      },
    ],
  });
  const proposal = policy.propose(
    {
      subject: "agent",
      entity: other,
      kid: vectors.kid,
      clientId: "agent",
      roles: ["agent"],
      expiresAt: now + 600,
    },
    {
      id: "request-1",
      session: "urn:xeip:session:operations",
      target: "internal",
      tool: "lookup",
      arguments: { query: '<script>alert("untrusted")</script>', limit: 1 },
      expiresAt: now + 120,
    },
    now,
  );
  const privateKey = await ed25519PrivateKeyFromSeed(
    Buffer.from(vectors.seed, "hex"),
  );
  const configuration = {
    origin: "https://xeip.test",
    gateway: other,
    principal: {
      subject: "human",
      entity: vectors.signed.sender,
      kid: vectors.kid,
    },
    privateKey,
    token: async () => ({
      token: "fixture.access.token",
      subject: state.tokenSubject,
      expiresAt: state.now + 60,
    }),
    fetch: async (url, init) => {
      assert.equal(url, "https://xeip.test/v1/actions");
      assert.equal(init.redirect, "error");
      assert.equal(init.credentials, "omit");
      assert.equal(init.cache, "no-store");
      assert.equal(init.headers.Authorization, "Bearer fixture.access.token");
      const envelope = JSON.parse(init.body);
      assertEnvelope(envelope);
      assert.deepEqual(
        await verifyEntityEnvelope(envelope, {
          ...vectors.vectors[0].options,
          nowSeconds: state.now,
        }),
        { valid: true },
      );
      state.calls.push(envelope);
      const op = envelope.body.data.operation;
      if (op !== "inspect") {
        assert.equal(envelope.body.data.digest, proposal.digest);
        state.decisionState =
          op === "approve"
            ? "approved"
            : op === "reject"
              ? "rejected"
              : "revoked";
      }
      if (state.failure) throw new TypeError("private upstream error");
      return (
        state.response ??
        Response.json({ state: state.decisionState, proposal, result: null })
      );
    },
    ...options,
  };
  return {
    state,
    proposal,
    configuration,
    client: new ApprovalClient(configuration),
  };
}

test("inspects and explicitly approves the exact server policy digest with an entity signature", async (t) => {
  const f = await fixture(t);
  const review = await f.client.inspect(
    "urn:xeip:session:operations",
    "request-1",
  );
  assert.equal(
    review.proposal.action.arguments.query,
    '<script>alert("untrusted")</script>',
  );
  assert.equal(Object.isFrozen(review.proposal.action.arguments), true);
  const result = await f.client.decide(review, "approve");
  assert.equal(result.state, "approved");
  assert.deepEqual(
    f.state.calls.map((e) => e.body.data.operation),
    ["inspect", "approve"],
  );
  assert.notEqual(f.state.calls[0].id, f.state.calls[1].id);
  assert.equal(f.state.calls[1].recipient, other);
});

test("reject and explicit revoke use the reviewed digest without executing a tool", async (t) => {
  const f = await fixture(t);
  assert.equal(
    (
      await f.client.decide(
        await f.client.inspect("urn:xeip:session:operations", "request-1"),
        "reject",
      )
    ).state,
    "rejected",
  );
  f.state.decisionState = "approved";
  assert.equal(
    (
      await f.client.revoke(
        await f.client.inspect("urn:xeip:session:operations", "request-1"),
      )
    ).state,
    "revoked",
  );
  assert.deepEqual(
    f.state.calls.map((e) => e.body.data.operation),
    ["inspect", "reject", "inspect", "revoke"],
  );
});

test("caller-created, cloned and superseded reviews never authorize decisions", async (t) => {
  const f = await fixture(t),
    review = await f.client.inspect("urn:xeip:session:operations", "request-1");
  await assert.rejects(f.client.decide(structuredClone(review), "approve"), {
    code: "review_required",
  });
  const next = await f.client.inspect(
    "urn:xeip:session:operations",
    "request-1",
  );
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "review_required",
  });
  assert.throws(() => {
    next.proposal.action.arguments.limit = 900;
  }, TypeError);
  assert.equal(f.state.calls.length, 2);
});

test("expired and terminal reviews can be inspected but cannot be approved", async (t) => {
  const f = await fixture(t),
    review = await f.client.inspect("urn:xeip:session:operations", "request-1");
  f.state.now = now + 120;
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "not_actionable",
  });
  f.state.now = now;
  f.state.decisionState = "succeeded";
  const terminal = await f.client.inspect(
    "urn:xeip:session:operations",
    "request-1",
  );
  await assert.rejects(f.client.decide(terminal, "approve"), {
    code: "not_actionable",
  });
  await assert.rejects(f.client.revoke(terminal), { code: "not_actionable" });
  assert.equal(f.state.calls.length, 2);
});

test("the requester cannot approve through the browser client", async (t) => {
  const f = await fixture(t, {
    principal: {
      subject: "agent",
      entity: vectors.signed.sender,
      kid: vectors.kid,
    },
    token: async () => ({
      token: "fixture.access.token",
      subject: "agent",
      expiresAt: now + 60,
    }),
  });
  const review = await f.client.inspect(
    "urn:xeip:session:operations",
    "request-1",
  );
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "not_actionable",
  });
  assert.equal(f.state.calls.length, 1);
});

test("refresh to another account invalidates the review before a decision is sent", async (t) => {
  const f = await fixture(t),
    review = await f.client.inspect("urn:xeip:session:operations", "request-1");
  f.state.tokenSubject = "another-human";
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "session_changed",
  });
  assert.equal(f.state.calls.length, 1);
});

test("a lost decision response requires inspection and never retries automatically", async (t) => {
  const f = await fixture(t),
    review = await f.client.inspect("urn:xeip:session:operations", "request-1");
  f.state.failure = true;
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "unavailable",
  });
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "review_required",
  });
  assert.equal(f.state.calls.length, 2);
  f.state.failure = false;
  assert.equal(
    (await f.client.inspect("urn:xeip:session:operations", "request-1")).state,
    "approved",
  );
  assert.equal(f.state.calls.length, 3);
});

test("builds the signed envelope after token refresh and caps it at token expiry", async (t) => {
  let f;
  f = await fixture(t, {
    token: async () => {
      f.state.now += 5;
      return {
        token: "fixture.access.token",
        subject: "human",
        expiresAt: now + 17,
      };
    },
  });
  await f.client.inspect("urn:xeip:session:operations", "request-1");
  assert.equal(
    f.state.calls[0].timestamp,
    new Date((now + 5) * 1000).toISOString().replace(".000Z", "Z"),
  );
  assert.equal(
    f.state.calls[0].expiresAt,
    new Date((now + 17) * 1000).toISOString().replace(".000Z", "Z"),
  );
});

for (const mutation of [
  (r) => {
    r.proposal.action.arguments.limit = 2;
  },
  (r) => {
    r.proposal.action.session = "another-session";
  },
  (r) => {
    r.proposal.action.id = "another-request";
  },
  (r) => {
    r.state = "unknown";
  },
  (r) => {
    r.claimId = "must-not-leak";
  },
])
  test(
    "rejects altered or unexpected inspection responses: " +
      mutation.toString(),
    async (t) => {
      const f = await fixture(t),
        response = structuredClone({
          state: "pending",
          proposal: f.proposal,
          result: null,
        });
      mutation(response);
      f.state.response = Response.json(response);
      await assert.rejects(
        f.client.inspect("urn:xeip:session:operations", "request-1"),
        {
          code: "invalid_response",
        },
      );
    },
  );

for (const [body, headers] of [
  [
    '{"state":"pending","state":"approved"}',
    { "content-type": "application/json" },
  ],
  ["x".repeat(262145), { "content-type": "application/json" }],
  ["{}", { "content-type": "text/html" }],
  ["[".repeat(50) + "]".repeat(50), { "content-type": "application/json" }],
])
  test(
    "rejects malformed, oversized, non-JSON or deeply nested responses " +
      body.length,
    async (t) => {
      const f = await fixture(t);
      f.state.response = new Response(body, { headers });
      await assert.rejects(
        f.client.inspect("urn:xeip:session:operations", "request-1"),
        {
          code: "invalid_response",
        },
      );
    },
  );

test("expiry during refresh prevents approving an old review", async (t) => {
  let expire = false;
  const f = await fixture(t, {
    token: async () => {
      if (expire) f.state.now = now + 121;
      return {
        token: "fixture.access.token",
        subject: "human",
        expiresAt: now + 180,
      };
    },
  });
  const review = await f.client.inspect(
    "urn:xeip:session:operations",
    "request-1",
  );
  expire = true;
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "not_actionable",
  });
  assert.equal(f.state.calls.length, 1);
});

test("closing during token acquisition prevents later network submission", async (t) => {
  let release;
  const token = new Promise((resolve) => {
    release = resolve;
  });
  const f = await fixture(t, { token: () => token });
  const request = f.client.inspect("urn:xeip:session:operations", "request-1");
  const rejected = assert.rejects(request, { code: "unavailable" });
  f.client.close();
  release({
    token: "fixture.access.token",
    subject: "human",
    expiresAt: now + 60,
  });
  await rejected;
  assert.equal(f.state.calls.length, 0);
});

test("a token deadline releases the UI but prevents late network submission", async (t) => {
  let release;
  const token = new Promise((resolve) => {
    release = resolve;
  });
  const f = await fixture(t, { timeoutMs: 100, token: () => token });
  await assert.rejects(
    f.client.inspect("urn:xeip:session:operations", "request-1"),
    {
      code: "unavailable",
    },
  );
  release({
    token: "fixture.access.token",
    subject: "human",
    expiresAt: now + 60,
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.state.calls.length, 0);
});

test("a second click cannot submit another decision while the first is pending", async (t) => {
  let release,
    hold = false;
  const f = await fixture(t, {
    token: async () => {
      if (hold)
        await new Promise((resolve) => {
          release = resolve;
        });
      return {
        token: "fixture.access.token",
        subject: "human",
        expiresAt: now + 60,
      };
    },
  });
  const review = await f.client.inspect(
    "urn:xeip:session:operations",
    "request-1",
  );
  hold = true;
  const decision = f.client.decide(review, "approve");
  await assert.rejects(f.client.decide(review, "approve"), {
    code: "review_required",
  });
  release();
  await decision;
  assert.equal(
    f.state.calls.filter((e) => e.body.data.operation === "approve").length,
    1,
  );
});
