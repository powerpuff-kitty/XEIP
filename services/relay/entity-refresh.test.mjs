import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EntityTrustPolicy } from "./entity-trust.mjs";
import { signStatusDocument } from "../../tools/identity-status.mjs";
const f = JSON.parse(
  fs.readFileSync(
    new URL(
      "../../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
const base = f.vectors[0].options;
const principal = { entity: f.envelope.sender, kid: f.kid };
function provision(
  serial = 1,
  revoked = [],
  issuedAt = base.statusDocument.issuedAt,
) {
  return {
    keyDocuments: base.keyDocuments.map((document) => ({
      document,
      anchor: base.anchor,
    })),
    statusDocuments: [
      {
        document: signStatusDocument(
          { ...base.statusDocument, serial, revoked, issuedAt, signatures: [] },
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
function setup(t) {
  let now = base.nowSeconds;
  t.mock.method(Date, "now", () => now * 1000);
  const dir = fs.mkdtempSync(join(tmpdir(), "xeip-refresh-"));
  const configuration = {
    trustDir: join(dir, "trust"),
    maxAgeSeconds: 60,
    knownExtensions: ["app.action"],
  };
  const initial = provision();
  const policy = new EntityTrustPolicy(
    configuration,
    initial.keyDocuments,
    initial.statusDocuments,
  );
  t.after(() => {
    policy.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return {
    policy,
    configuration,
    setNow: (value) => {
      now = value;
    },
  };
}
test("live refresh revokes a bound device and persists the new serial", (t) => {
  const { policy, configuration } = setup(t);
  assert.equal(policy.allows(principal), true);
  assert.equal(policy.allows({ entity: principal.entity }), false);
  policy.update(provision(2, [{ kid: f.kid, generation: 1 }]));
  assert.equal(policy.allows(principal), false);
  assert.deepEqual(policy.verify(f.signed), {
    valid: false,
    reason: "revoked key",
  });
  policy.close();
  const old = provision();
  assert.throws(
    () =>
      new EntityTrustPolicy(
        configuration,
        old.keyDocuments,
        old.statusDocuments,
      ),
    /rollback/,
  );
});
test("invalid refresh leaves the active verified snapshot intact", (t) => {
  const { policy } = setup(t);
  const bad = provision(2);
  bad.statusDocuments[0].document.signatures[0].sig = "A".repeat(86);
  assert.throws(() => policy.update(bad), /trust/);
  assert.equal(policy.allows(principal), true);
  const good = provision(2);
  policy.update(good);
  good.statusDocuments[0].document.revoked.push({ kid: f.kid, generation: 1 });
  assert.equal(policy.allows(principal), true);
  assert.throws(() => policy.update(provision()), /rollback/);
  assert.equal(policy.allows(principal), true);
});
test("expiry is monotonic and valid refresh restores authorization", (t) => {
  const { policy, setNow } = setup(t);
  setNow(base.nowSeconds + 61);
  assert.equal(policy.allows(principal), false);
  assert.equal(policy.status().state, "stale");
  setNow(base.nowSeconds);
  assert.equal(policy.allows(principal), false);
  setNow(base.nowSeconds + 61);
  policy.update(provision(2, [], "2026-10-10T00:01:01Z"));
  assert.equal(policy.allows(principal), true);
});
test("omitted entities lose authorization but retain rollback protection", (t) => {
  const { policy } = setup(t);
  policy.update(provision(2));
  policy.update({ keyDocuments: [], statusDocuments: [] });
  assert.equal(policy.allows(principal), false);
  assert.throws(() => policy.update(provision()), /rollback/);
  policy.update(provision(2));
  assert.equal(policy.allows(principal), true);
});
test("a failed durable refresh disables old authorization until reopen", (t) => {
  const { policy, configuration } = setup(t);
  fs.mkdirSync(join(configuration.trustDir, "trust.json.tmp"));
  assert.throws(() => policy.update(provision(2)));
  assert.equal(policy.allows(principal), false);
  assert.deepEqual(policy.verify(f.signed), {
    valid: false,
    reason: "untrusted identity",
  });
  assert.equal(policy.status().state, "failed");
  assert.throws(() => policy.update(provision()), /reopen/);
});

for (const boundary of [
  "partial write",
  "file sync",
  "rename",
  "directory sync",
]) {
  test("live refresh fails closed at " + boundary, async (t) => {
    const { syncBuiltinESMExports } = await import("node:module");
    const { policy, configuration } = setup(t);
    const originalWrite = fs.writeSync,
      originalSync = fs.fsyncSync;
    let partial = false;
    let mocked;
    const fault = () => {
      throw Object.assign(new Error("injected storage fault"), { code: "EIO" });
    };
    if (boundary === "partial write")
      mocked = t.mock.method(fs, "writeSync", (fd, buffer, offset, length) => {
        if (partial) return fault();
        partial = true;
        return originalWrite(fd, buffer, offset, Math.min(7, length));
      });
    if (boundary === "rename") mocked = t.mock.method(fs, "renameSync", fault);
    if (boundary.endsWith("sync"))
      mocked = t.mock.method(fs, "fsyncSync", (fd) => {
        if (fs.fstatSync(fd).isDirectory() === (boundary === "directory sync"))
          return fault();
        return originalSync(fd);
      });
    syncBuiltinESMExports();
    try {
      assert.throws(() => policy.update(provision(2)), /storage fault/);
    } finally {
      mocked.mock.restore();
      syncBuiltinESMExports();
    }
    assert.equal(policy.allows(principal), false);
    assert.equal(policy.status().state, "failed");
    assert.equal(fs.existsSync(join(configuration.trustDir, "LOCK")), true);
    assert.throws(() => policy.update(provision(2)), /reopen/);
    policy.close();
    const old = provision();
    if (boundary === "directory sync") {
      assert.throws(
        () =>
          new EntityTrustPolicy(
            configuration,
            old.keyDocuments,
            old.statusDocuments,
          ),
        /rollback/,
      );
    } else {
      new EntityTrustPolicy(
        configuration,
        old.keyDocuments,
        old.statusDocuments,
      ).close();
    }
    const newer = provision(2);
    new EntityTrustPolicy(
      configuration,
      newer.keyDocuments,
      newer.statusDocuments,
    ).close();
  });
}

test("async trust preparation yields before commit and preserves revocation and rollback", async (t) => {
  const { policy } = setup(t);
  let yielded = false;
  setImmediate(() => {
    yielded = true;
  });
  const candidate = provision(2, [{ kid: f.kid, generation: 1 }]);
  const updating = policy.updateAsync(candidate);
  // The current verified policy remains usable while a candidate is uncommitted.
  assert.equal(policy.allows(principal), true);
  await updating;
  assert.equal(yielded, true);
  assert.equal(policy.allows(principal), false);
  assert.deepEqual(policy.verify(f.signed), {
    valid: false,
    reason: "revoked key",
  });
  await assert.rejects(policy.updateAsync(provision(1)), /rollback/);
  assert.equal(policy.allows(principal), false);
});

test("async trust preparation snapshots input and serializes all update paths", async (t) => {
  const { policy } = setup(t);
  const candidate = provision(2, [{ kid: f.kid, generation: 1 }]);
  const updating = policy.updateAsync(candidate);
  candidate.statusDocuments.length = 0;
  assert.throws(() => policy.update(provision(3)), /in progress/);
  await assert.rejects(policy.updateAsync(provision(3)), /in progress/);
  await updating;
  assert.equal(policy.allows(principal), false);
});

test("cancelled, closed and expired async candidates never activate", async (t) => {
  const { policy, setNow } = setup(t);
  const abort = new AbortController();
  const updating = policy.updateAsync(
    provision(2, [{ kid: f.kid, generation: 1 }]),
    { signal: abort.signal },
  );
  abort.abort();
  await assert.rejects(updating);
  assert.equal(policy.allows(principal), true);
  const expired = policy.updateAsync(provision(2));
  setNow(base.nowSeconds + 61);
  await assert.rejects(expired, /stale/);
  assert.equal(policy.status().state, "stale");
  const future = new Date((base.nowSeconds + 61) * 1000)
    .toISOString()
    .replace(".000Z", "Z");
  const closing = policy.updateAsync(provision(3, [], future));
  policy.close();
  await assert.rejects(closing);
  assert.equal(policy.status().state, "closed");
});

test("invalid async candidates retain prior trust and release reload admission", async (t) => {
  const { policy } = setup(t);
  const invalid = provision(2);
  invalid.statusDocuments[0].document.signatures[0].sig = "invalid";
  await assert.rejects(policy.updateAsync(invalid));
  assert.equal(policy.allows(principal), true);
  await policy.updateAsync(provision(2, [{ kid: f.kid, generation: 1 }]));
  assert.equal(policy.allows(principal), false);
});

test("async checkpoint persistence failure poisons prior authorization", async (t) => {
  const { policy, configuration } = setup(t);
  fs.mkdirSync(join(configuration.trustDir, "trust.json.tmp"));
  await assert.rejects(policy.updateAsync(provision(2)));
  assert.equal(policy.allows(principal), false);
  assert.equal(policy.status().state, "failed");
  await assert.rejects(policy.updateAsync(provision(3)), /reopen/);
});

test("aborted and invalid async options cannot consume update admission", async (t) => {
  const { policy } = setup(t);
  await assert.rejects(
    policy.updateAsync(provision(2), { signal: AbortSignal.abort() }),
  );
  await assert.rejects(policy.updateAsync(provision(2), { signal: {} }));
  assert.equal(policy.allows(principal), true);
  await policy.updateAsync(provision(2, [{ kid: f.kid, generation: 1 }]));
  assert.equal(policy.allows(principal), false);
});

test("async preparation refuses a response after its monotonic deadline", async (t) => {
  const { policy } = setup(t);
  const now = performance.now();
  const updating = policy.updateAsync(
    provision(2, [{ kid: f.kid, generation: 1 }]),
  );
  // Model a delayed owner event loop: a queued worker message may beat the timer.
  const clock = t.mock.method(performance, "now", () => now + 60000);
  try {
    await assert.rejects(updating, /preparation failed/);
  } finally {
    clock.mock.restore();
  }
  assert.equal(policy.allows(principal), true);
  await policy.updateAsync(provision(2));
});
