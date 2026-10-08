import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { LocalAdmission } from "./admission.mjs";

const a = "urn:xeip:entity:a", b = "urn:xeip:entity:b", c = "urn:xeip:entity:c";
const room = "urn:xeip:session:admitted";
const secret = () => randomBytes(32).toString("base64url");
function setup() {
  const credentials = [a, b, c].map(entity => ({ entity, token: secret() }));
  const sessions = [{ xeip: "0.1", id: room, mode: "group", members: [a, b], createdAt: "2026-10-09T00:00:00Z" }];
  const config = { credentials, sessions };
  const policy = new LocalAdmission(config);
  const principal = entity => policy.authenticate("Bearer " + credentials.find(row => row.entity === entity).token);
  return { policy, config, credentials, principal };
}

test("binds credentials to immutable principal records and defaults to denial", () => {
  const { policy, principal } = setup();
  const identity = principal(a);
  assert.equal(identity?.entity, a);
  assert.equal(policy.isCurrent(identity), true);
  assert.throws(() => { identity.entity = b; }, TypeError);
  assert.equal(policy.isCurrent({ entity: a }), false);
  for (const header of [undefined, "Bearer bad", "Basic " + secret(), "Bearer " + secret()]) {
    assert.equal(policy.authenticate(header), null);
  }
  assert.equal(policy.canSubscribe(identity, room), true);
  assert.equal(policy.canSubscribe(principal(c), room), false);
  assert.equal(policy.canSubscribe(identity, "urn:xeip:session:unknown"), false);
  assert.equal(policy.canSend(identity, { session: room, sender: a, recipient: b }), true);
  assert.equal(policy.canSend(identity, { session: room, sender: a }), true);
  assert.equal(policy.canSend(identity, { session: room, sender: b, recipient: a }), false);
  assert.equal(policy.canSend(identity, { session: room, sender: a, recipient: c }), false);
});

test("rejects ambiguous, malformed or excessive provisioning", () => {
  const token = secret();
  for (const config of [
    {}, { credentials: [], sessions: [] },
    { credentials: [{ entity: a, token: "short" }], sessions: [] },
    { credentials: [{ entity: "not-uri", token }], sessions: [] },
    { credentials: [{ entity: a, token }, { entity: a, token: secret() }], sessions: [] },
    { credentials: [{ entity: a, token }, { entity: b, token }], sessions: [] },
    { credentials: [{ entity: a, token }], sessions: [{ xeip: "0.1", id: room, mode: "group", members: [b], createdAt: "2026-10-09T00:00:00Z" }] },
    { credentials: Array.from({ length: 257 }, (_, index) => ({ entity: a + index, token: secret() })), sessions: [] },
  ]) assert.throws(() => new LocalAdmission(config));
  const { config } = setup();
  assert.throws(() => new LocalAdmission({ ...config, sessions: [config.sessions[0], config.sessions[0]] }));
  assert.throws(() => new LocalAdmission({ ...config, sessions: Array.from({ length: 257 }, (_, index) => ({ ...config.sessions[0], id: room + index })) }));
  assert.throws(() => new LocalAdmission({ ...config, sessions: [{ ...config.sessions[0], mode: "direct", members: [a] }] }));
  assert.throws(() => new LocalAdmission({ ...config, sessions: [{ ...config.sessions[0], extensions: { data: "x".repeat(66000) } }] }));
  assert.doesNotThrow(() => new LocalAdmission({ ...config, sessions: [{ ...config.sessions[0], mode: "direct" }] }));
  const direct = new LocalAdmission({ ...config, sessions: [{ ...config.sessions[0], mode: "direct" }] });
  assert.throws(() => direct.setMembers(room, [a]));
  assert.equal(direct.canSubscribe(direct.authenticate("Bearer " + config.credentials[1].token), room), true);
});

test("copies caller configuration so mutation cannot create privileges", () => {
  const { policy, config, credentials, principal } = setup();
  const identity = principal(a), outsider = principal(c);
  config.sessions[0].members.push(c);
  config.sessions[0].id = "urn:xeip:session:changed";
  credentials[0].entity = c;
  assert.equal(policy.canSubscribe(outsider, room), false);
  assert.equal(policy.canSubscribe(identity, room), true);
  assert.equal(policy.canSubscribe(identity, "urn:xeip:session:changed"), false);
  assert.equal(identity.entity, a);
});

test("validates the serialized policy snapshot when configuration has JSON hooks", () => {
  for (const [replacement, mode] of [[ ["urn:xeip:entity:unknown"], "group" ], [ [a], "direct" ]]) {
    const { config } = setup();
    config.sessions[0].mode = mode;
    config.sessions[0].members.toJSON = () => replacement;
    assert.throws(() => new LocalAdmission(config));
  }
});

test("revocation and rotation invalidate stale records and prohibit reusing issued secrets", () => {
  const { policy, credentials, principal } = setup();
  const identity = principal(a), oldToken = credentials[0].token;
  let changes = 0;
  const stop = policy.onChange(() => changes++);
  policy.revokeCredential(a);
  assert.equal(policy.isCurrent(identity), false);
  assert.equal(policy.authenticate("Bearer " + oldToken), null);
  assert.equal(policy.canSend(identity, { session: room, sender: a, recipient: b }), false);
  const replacement = secret();
  policy.rotateCredential(a, replacement);
  const current = policy.authenticate("Bearer " + replacement);
  assert.equal(current?.entity, a);
  assert.notEqual(current, identity);
  assert.equal(policy.isCurrent(identity), false);
  assert.equal(policy.canSubscribe(current, room), true);
  assert.throws(() => policy.rotateCredential(b, oldToken));
  assert.throws(() => policy.rotateCredential(a, credentials[1].token));
  assert.throws(() => policy.rotateCredential(a, "short"));
  assert.throws(() => policy.revokeCredential("urn:xeip:entity:unknown"));
  assert.equal(policy.authenticate("Bearer " + replacement), current);
  assert.equal(changes, 2);
  stop();
  policy.revokeCredential(a);
  assert.equal(changes, 2);
});

test("membership replacement is validated atomically and copied", () => {
  const { policy, principal } = setup();
  const identity = principal(a);
  for (const members of [[a, a], ["urn:xeip:entity:unknown"], ["invalid-uri"]]) {
    assert.throws(() => policy.setMembers(room, members));
    assert.equal(policy.canSubscribe(identity, room), true);
  }
  assert.throws(() => policy.setMembers("urn:xeip:session:unknown", [a]));
  const members = [b];
  policy.setMembers(room, members);
  members.push(a);
  assert.equal(policy.canSubscribe(identity, room), false);
  assert.equal(policy.canSubscribe(principal(b), room), true);
  policy.setMembers(room, [a, b]);
  assert.equal(policy.canSubscribe(identity, room), true);
});

test("bounds credential history without replacing the current credential on exhaustion", () => {
  const { policy, credentials } = setup();
  let latest = credentials[0].token;
  for (let issued = 3; issued < 4096; issued++) {
    latest = secret();
    policy.rotateCredential(a, latest);
  }
  const current = policy.authenticate("Bearer " + latest);
  assert.throws(() => policy.rotateCredential(a, secret()), /history/);
  assert.equal(policy.authenticate("Bearer " + latest), current);
  assert.equal(policy.isCurrent(current), true);
});
