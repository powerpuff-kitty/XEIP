import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../../packages/identity/signed-envelope.mjs";
import {
  publicAuthority,
  prepareControlState,
  verifyControlState,
  ControlStateError,
} from "./control-state.mjs";

import {
  fixture,
  base,
  entity,
  acceptedAt,
  provisioning,
  configuration,
  enroll,
  next,
} from "./test-fixtures/control.mjs";

const denied = (fn) =>
  assert.throws(
    fn,
    (error) =>
      error instanceof ControlStateError &&
      error.message === "invalid organization control state" &&
      error.cause === undefined,
  );

test("public authority excludes credentials and host paths, isolates values and normalizes token default", () => {
  const source = configuration(),
    authority = publicAuthority(source);
  assert.doesNotMatch(
    authority.canonical,
    /synthetic-secret|private\/|ignored-certificate/,
  );
  const rotated = configuration();
  rotated.authentication.introspectionClientSecret = "rotated";
  rotated.targets[0].clientSecret = "rotated";
  rotated.database.password = "rotated";
  rotated.tls.key = "rotated";
  rotated.management.token = "rotated";
  rotated.trust.directory = "/other";
  rotated.authentication.maxTokenLifetimeSeconds = 300;
  rotated.authentication.timeoutMs = 500;
  assert.equal(publicAuthority(rotated).digest, authority.digest);
  source.policy.sessions[0].agents.push("changed");
  assert.equal(authority.value.policy.sessions[0].agents.length, 1);
  assert.throws(
    () => authority.value.targets[0].tools.push("changed"),
    TypeError,
  );
  assert.equal(authority.value.authentication.maxTokenLifetimeSeconds, 300);
});

test("every accepted public authority dimension changes the canonical digest", () => {
  const changes = [
    (c) => (c.origin = "https://other.test"),
    (c) => (c.gateway = "urn:xeip:entity:" + fixture.kid),
    (c) => (c.authentication.issuer = "https://other.test/realm"),
    (c) => (c.authentication.audience = "other"),
    (c) => c.authentication.clientIds.push("other"),
    (c) => (c.authentication.bindings[0].kid = base.keyDocuments[0].genesis),
    (c) => (c.authentication.introspectionClientId = "other"),
    (c) => (c.authentication.maxTokenLifetimeSeconds = 600),
    (c) => (c.policy.sessions[0].approvers = []),
    (c) => (c.targets[0].endpoint = "https://tool.test/other-mcp"),
    (c) => (c.targets[0].scope = "other"),
    (c) => (c.targets[0].clientId = "other"),
    (c) => (c.targets[0].issuer = "https://tool-id.test/other-realm"),
    (c) => (c.targets[0].tokenEndpoint = "https://tool-id.test/other-token"),
    (c) =>
      (c.targets[0].resourceMetadataUrl = "https://tool.test/other-metadata"),
    (c) => (c.trust.maxAgeSeconds = 600),
    (c) => (c.console.clientId = "agent"),
    (c) => {
      c.targets[0].revision = "2";
      c.policy.targets[0].revision = "2";
    },
  ];
  const original = publicAuthority(configuration()).digest;
  for (const change of changes) {
    const c = configuration();
    change(c);
    assert.notEqual(publicAuthority(c).digest, original);
  }
});

test("projection rejects unknown authority fields, unsafe getters and mismatched policy without leaking errors", () => {
  for (const change of [
    (c) => (c.futureAuthority = "secret"),
    (c) => (c.authentication.bindings[0].extra = "secret"),
    (c) => (c.targets[0].extra = "secret"),
    (c) => (c.policy.targets[0].revision = "wrong"),
    (c) => (c.authentication.allowInsecureLoopback = true),
  ]) {
    const c = configuration();
    change(c);
    denied(() => publicAuthority(c));
  }
  let calls = 0;
  const c = configuration();
  Object.defineProperty(c.targets[0], "scope", {
    enumerable: true,
    get() {
      calls++;
      throw new Error("synthetic-secret");
    },
  });
  denied(() => publicAuthority(c));
  assert.equal(calls, 0);
});

test("valid control state round trips with immutable signed data and no credential fields", () => {
  const input = provisioning(),
    state = enroll(configuration(), input);
  assert.deepEqual(verifyControlState(state.canonical), state);
  assert.equal(state.state.records[entity].serial, 1);
  assert.equal(state.state.targetRevisions.length, 1);
  assert.doesNotMatch(
    state.canonical,
    /synthetic-secret|private\/|clientSecret/,
  );
  input.statusDocuments[0].document.serial = 900;
  assert.equal(state.state.provisioning.statusDocuments[0].document.serial, 1);
  assert.throws(() => (state.state.records[entity].serial = 900), TypeError);
});

test("control transitions preserve revocation high-water records and reject rollback, fork and bad signature", () => {
  const current = next(
    enroll(),
    provisioning(2, [{ kid: fixture.kid, generation: 1 }]),
  );
  assert.equal(current.state.records[entity].serial, 2);
  denied(() => next(current, provisioning(1)));
  denied(() => next(current, provisioning(2)));
  const damaged = provisioning(3);
  damaged.statusDocuments[0].document.signatures[0].sig = "A".repeat(86);
  denied(() => next(current, damaged));
});

test("removed entities retain counters and require an explicit owner re-addition", () => {
  const original = enroll();
  const removed = next(original, { keyDocuments: [], statusDocuments: [] });
  assert.deepEqual(removed.state.records, original.state.records);
  denied(() => next(removed, provisioning(1)));
  const restored = next(removed, provisioning(1), configuration(), "authority");
  assert.equal(restored.state.records[entity].serial, 1);
});

test("bounded transition verification checks retained records for removed entities", () => {
  const original = enroll();
  const removed = next(original, { keyDocuments: [], statusDocuments: [] });
  // A legitimate removal transition verifies against its predecessor.
  assert.deepEqual(
    verifyControlState(removed.canonical, original.canonical),
    removed,
  );
  // Forged retained metadata is refused even though only inactive verification
  // (not the active checkpoint loop) can see it.
  const forged = structuredClone(removed.state);
  forged.records[entity].serial += 1;
  forged.records[entity].statusDigest = "a".repeat(64);
  denied(() => verifyControlState(canonicalize(forged), original.canonical));
  // An invented inactive identity is refused because no predecessor carries it.
  const invented = structuredClone(removed.state);
  invented.records["urn:xeip:entity:" + "A".repeat(43)] = structuredClone(
    removed.state.records[entity],
  );
  denied(() => verifyControlState(canonicalize(invented), original.canonical));
});

test("trust-only publication cannot change authority; owner change cannot change organization", () => {
  const previous = enroll(),
    changed = configuration();
  changed.authentication.audience = "other";
  denied(() => next(previous, provisioning(2), changed));
  assert.notEqual(
    next(previous, provisioning(2), changed, "authority").state.authorityDigest,
    previous.state.authorityDigest,
  );
  changed.gateway = "urn:xeip:entity:" + fixture.kid;
  denied(() => next(previous, provisioning(2), changed, "authority"));
});

test("target ID/revision settings remain immutable across changes, removal and re-addition", () => {
  const original = enroll();
  const changed = configuration();
  changed.targets[0].endpoint = "https://tool.test/replacement-mcp";
  denied(() => next(original, provisioning(2), changed, "authority"));
  changed.targets[0].revision = changed.policy.targets[0].revision = "2";
  const second = next(original, provisioning(2), changed, "authority");
  assert.equal(second.state.targetRevisions.length, 2);
  changed.targets[0].revision = changed.policy.targets[0].revision = "1";
  denied(() => next(second, provisioning(3), changed, "authority"));
  // Remove the original target entirely; retained mappings must still constrain reuse.
  changed.targets[0].id = changed.policy.targets[0].id = "replacement";
  changed.policy.sessions[0].targets = ["replacement"];
  const removed = next(second, provisioning(3), changed, "authority");
  assert.equal(removed.state.targetRevisions.length, 3);
  const reused = configuration();
  reused.targets[0].endpoint = "https://tool.test/replacement-mcp";
  denied(() => next(removed, provisioning(4), reused, "authority"));
});

test("enrollment imports removed records, but later transitions cannot replace history or move time backward", () => {
  const prior = enroll();
  const imported = enroll(
    configuration(),
    { keyDocuments: [], statusDocuments: [] },
    prior.state.records,
  );
  assert.equal(imported.state.records[entity].serial, 1);
  for (const args of [
    {
      authority: publicAuthority(configuration()),
      provisioning: provisioning(),
      operation: "enroll",
      acceptedAt,
    },
    {
      authority: publicAuthority(configuration()),
      provisioning: provisioning(),
      operation: "enroll",
      acceptedAt,
      retainedRecords: {},
      previous: prior.canonical,
    },
    {
      authority: publicAuthority(configuration()),
      provisioning: provisioning(),
      operation: "trust",
      acceptedAt,
    },
    {
      authority: publicAuthority(configuration()),
      provisioning: provisioning(),
      operation: "trust",
      acceptedAt: acceptedAt - 1,
      previous: prior.canonical,
    },
    {
      authority: publicAuthority(configuration()),
      provisioning: provisioning(),
      operation: "trust",
      acceptedAt,
      previous: prior.canonical,
      retainedRecords: {},
    },
  ])
    denied(() => prepareControlState(args));
});

test("historical verification rejects tampered sections and noncanonical bytes", () => {
  const valid = enroll();
  for (const change of [
    (s) => (s.authorityDigest = "0".repeat(64)),
    (s) => s.records[entity].serial++,
    (s) => delete s.records[entity],
    (s) => (s.targetRevisions = []),
    (s) => (s.targetRevisions[0].digest = "0".repeat(64)),
    (s) => (s.extra = "secret"),
    (s) => (s.acceptedAt += 301),
  ]) {
    const state = structuredClone(valid.state);
    change(state);
    denied(() => verifyControlState(canonicalize(state)));
  }
  denied(() => verifyControlState(" " + valid.canonical));
  denied(() => verifyControlState("x".repeat(24 * 1024 * 1024 + 1)));
});

test("operation tags are primitive strings and cannot bypass trust-only transition rules", () => {
  const previous = enroll(),
    config = configuration();
  config.authentication.audience = "changed";
  let coercions = 0;
  for (const operation of [
    ["trust"],
    ["authority"],
    {
      toString() {
        coercions++;
        return "authority";
      },
    },
  ]) {
    denied(() =>
      prepareControlState({
        authority: publicAuthority(config),
        provisioning: provisioning(2),
        previous: previous.canonical,
        operation,
        acceptedAt,
      }),
    );
  }
  for (const operation of [["trust"], ["authority"], ["enroll"]]) {
    const state = structuredClone(previous.state);
    state.operation = operation;
    denied(() => verifyControlState(canonicalize(state)));
  }
  assert.equal(coercions, 0);
});

test("an invalid explicit token lifetime is not silently replaced by the default", () => {
  const config = configuration();
  config.authentication.maxTokenLifetimeSeconds = null;
  denied(() => publicAuthority(config));
});

test("permission array order retains the existing policy revision semantics", () => {
  const source = configuration();
  source.policy.sessions[0].agents.push("human");
  const forward = publicAuthority(source);
  source.policy.sessions[0].agents.reverse();
  assert.notEqual(publicAuthority(source).digest, forward.digest);
});

test("individually valid bounded sections cannot overflow the combined prepared state", () => {
  const config = configuration();
  config.authentication.clientIds.push(
    ...Array.from({ length: 15000 }, (_, i) => "client-" + i + "x".repeat(235)),
  );
  const record = enroll().state.records[entity];
  const retained = Object.fromEntries(
    Array.from({ length: 4095 }, (_, i) => [
      "entity:" + i + "x".repeat(1720),
      record,
    ]),
  );
  const original = enroll(config, provisioning(), retained);
  const state = structuredClone(original.state);
  state.targetRevisions.push(
    ...Array.from({ length: 21000 }, (_, i) => ({
      id: "target" + i + "x".repeat(110),
      revision: "r".repeat(128),
      digest: "a".repeat(64),
    })),
  );
  const priorCanonical = canonicalize(state);
  assert.ok(Buffer.byteLength(priorCanonical) < 24 * 1024 * 1024);
  assert.equal(verifyControlState(priorCanonical).canonical, priorCanonical);
  // Additional well-formed signatures do not change the signed status payload.
  const large = provisioning(2);
  large.statusDocuments[0].document.signatures = Array(40000).fill(
    large.statusDocuments[0].document.signatures[0],
  );
  assert.ok(Buffer.byteLength(canonicalize(large)) < 8 * 1024 * 1024);
  const smallHistory = enroll(config, large);
  assert.equal(smallHistory.state.records[entity].serial, 2);
  assert.ok(
    Buffer.byteLength(priorCanonical) + Buffer.byteLength(canonicalize(large)) >
      24 * 1024 * 1024,
  );
  denied(() =>
    prepareControlState({
      authority: publicAuthority(config),
      provisioning: large,
      previous: priorCanonical,
      operation: "trust",
      acceptedAt: acceptedAt + 1,
    }),
  );
});

test("provisioning and retained history enforce their independent byte and entry limits", () => {
  const input = provisioning();
  input.statusDocuments = Array(4097).fill(input.statusDocuments[0]);
  denied(() => enroll(configuration(), input));
  const giant = provisioning();
  giant.keyDocuments[0].document.extra = "x".repeat(8 * 1024 * 1024);
  denied(() => enroll(configuration(), giant));
  const record = enroll().state.records[entity];
  const tooMany = Object.fromEntries(
    Array.from({ length: 4097 }, (_, i) => ["entity:" + i, record]),
  );
  denied(() =>
    enroll(configuration(), { keyDocuments: [], statusDocuments: [] }, tooMany),
  );
  const tooLarge = Object.fromEntries(
    Array.from({ length: 4096 }, (_, i) => [
      "entity:" + i + "x".repeat(2040),
      record,
    ]),
  );
  denied(() =>
    enroll(
      configuration(),
      { keyDocuments: [], statusDocuments: [] },
      tooLarge,
    ),
  );
});
