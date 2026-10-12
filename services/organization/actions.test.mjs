import test from "node:test";
import assert from "node:assert/strict";
import { ActionPolicy, PolicyDenied } from "./actions.mjs";
const entity =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const other =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const kid = "z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const now = 1800000000;
const agent = {
  subject: "agent-1",
  entity,
  kid,
  clientId: "agent",
  roles: ["agent"],
  expiresAt: now + 600,
};
const human = {
  subject: "human-1",
  entity: other,
  kid,
  clientId: "console",
  roles: ["approver"],
  expiresAt: now + 600,
};
const config = () => ({
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
      id: "session-1",
      agents: ["agent-1"],
      approvers: ["human-1"],
      targets: ["internal"],
    },
  ],
});
const request = () => ({
  id: "request-1",
  session: "session-1",
  target: "internal",
  tool: "lookup",
  arguments: { query: "status", limit: 1 },
  expiresAt: now + 120,
});

test("authorized status inspection survives expiry and policy revision but never crosses membership", () => {
  const policy = new ActionPolicy(config()),
    proposal = policy.propose(agent, request(), now);
  const c = config();
  c.targets[0].revision = "new";
  const updated = new ActionPolicy(c);
  assert.equal(updated.canInspect(agent, proposal, now + 121), true);
  assert.equal(updated.canInspect(human, proposal, now + 121), true);
  assert.equal(
    updated.canInspect({ ...agent, subject: "outsider" }, proposal, now),
    false,
  );
  assert.equal(
    updated.canInspect({ ...agent, entity: other }, proposal, now),
    false,
  );
  const tampered = structuredClone(proposal);
  tampered.action.arguments.query = "changed";
  assert.equal(updated.canInspect(agent, tampered, now), false);
});

test("exact action is immutable, canonically hashed and scoped to separate approver", () => {
  const policy = new ActionPolicy(config()),
    input = request();
  const proposal = policy.propose(agent, input, now);
  assert.match(proposal.digest, /^[a-f0-9]{64}$/);
  assert.equal(proposal.action.actor.subject, agent.subject);
  assert.equal(proposal.action.target.recipient, other);
  assert.equal(policy.canApprove(human, proposal, now), true);
  assert.equal(policy.canExecute(agent, proposal, now), true);
  assert.equal(policy.canApprove(agent, proposal, now), false);
  assert.equal(Object.isFrozen(proposal.action.arguments), true);
  input.arguments.query = "edited";
  assert.equal(proposal.action.arguments.query, "status");
  const reordered = request();
  reordered.arguments = { limit: 1, query: "status" };
  assert.equal(policy.propose(agent, reordered, now).digest, proposal.digest);
});

for (const [name, principal, patch] of [
  ["unknown subject", { ...agent, subject: "intruder" }, {}],
  ["wrong role", { ...agent, roles: ["approver"] }, {}],
  ["expired principal", { ...agent, expiresAt: now }, {}],
  ["unknown session", agent, { session: "other" }],
  ["unknown target", agent, { target: "other" }],
  ["unlisted tool", agent, { tool: "delete" }],
  ["expired action", agent, { expiresAt: now }],
  ["overlong action", agent, { expiresAt: now + 301 }],
  ["fractional expiry", agent, { expiresAt: now + 1.5 }],
  ["endpoint injection", agent, { url: "https://attacker.example" }],
  ["non-object arguments", agent, { arguments: [] }],
  ["oversized arguments", agent, { arguments: { text: "x".repeat(65536) } }],
  ["non-JSON argument", agent, { arguments: { x: undefined } }],
  ["nonfinite argument", agent, { arguments: { x: NaN } }],
  ["ambiguous identifier", agent, { id: "bad\nid" }],
])
  test("denies " + name, () => {
    assert.throws(
      () =>
        new ActionPolicy(config()).propose(
          principal,
          { ...request(), ...patch },
          now,
        ),
      PolicyDenied,
    );
  });

test("approval denies self through another subject, wrong role, expiry and forged content", () => {
  const policy = new ActionPolicy(config()),
    proposal = policy.propose(agent, request(), now);
  assert.equal(policy.canApprove({ ...human, entity }, proposal, now), false);
  assert.equal(
    policy.canApprove({ ...human, roles: [] }, proposal, now),
    false,
  );
  assert.equal(policy.canApprove(human, proposal, now + 120), false);
  for (const edit of [
    (p) => (p.action.arguments.query = "delete"),
    (p) => (p.action.session = "other"),
    (p) => (p.action.actor.kid = entity.slice("urn:xeip:entity:".length)),
    (p) => (p.action.target.revision = "deployment-2"),
    (p) => (p.action.target.recipient = entity),
    (p) => p.action.expiresAt++,
    (p) => (p.action.extra = true),
    (p) => (p.digest = "0".repeat(64)),
  ]) {
    const changed = structuredClone(proposal);
    edit(changed);
    assert.equal(policy.canApprove(human, changed, now), false);
    assert.equal(policy.canExecute(agent, changed, now), false);
  }
});

test("only exact current requester can execute and every policy revision invalidates old proposals", () => {
  const configuration = config(),
    policy = new ActionPolicy(configuration),
    proposal = policy.propose(agent, request(), now);
  assert.equal(policy.canExecute(human, proposal, now), false);
  assert.equal(
    policy.canExecute(
      { ...agent, kid: entity.slice("urn:xeip:entity:".length) },
      proposal,
      now,
    ),
    false,
  );
  configuration.sessions[0].agents = []; // Owner input mutations do not mutate a running policy.
  assert.equal(policy.canExecute(agent, proposal, now), true);
  const revised = config();
  revised.targets[0].revision = "deployment-2";
  assert.equal(
    new ActionPolicy(revised).canApprove(human, proposal, now),
    false,
  );
  assert.equal(
    new ActionPolicy(configuration).canExecute(agent, proposal, now),
    false,
  );
});

test("rejects ambiguous or unbounded configurations and non-JSON object graphs", () => {
  for (const mutate of [
    (c) => c.sessions.push(c.sessions[0]),
    (c) => c.targets.push(c.targets[0]),
    (c) => c.sessions[0].targets.push("missing"),
    (c) => c.targets[0].tools.push("*"),
    (c) => (c.targets[0].recipient = "urn:xeip:entity:invalid"),
    (c) => (c.extra = true),
  ]) {
    const c = config();
    mutate(c);
    assert.throws(() => new ActionPolicy(c), TypeError);
  }
  const policy = new ActionPolicy(config());
  const cyclic = {};
  cyclic.self = cyclic;
  const accessor = {};
  Object.defineProperty(accessor, "secret", {
    enumerable: true,
    get() {
      throw new Error("must not execute");
    },
  });
  const deep = {};
  let cursor = deep;
  for (let i = 0; i < 40; i++) {
    cursor.next = {};
    cursor = cursor.next;
  }
  for (const args of [
    cyclic,
    accessor,
    deep,
    { date: new Date() },
    { sparse: new Array(4) },
  ]) {
    assert.throws(
      () => policy.propose(agent, { ...request(), arguments: args }, now),
      PolicyDenied,
    );
  }
});
