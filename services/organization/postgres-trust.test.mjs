import test from "node:test";
import assert from "node:assert/strict";
import { openPostgresTrust } from "./postgres-trust.mjs";
import { publicAuthority, prepareControlState } from "./control-state.mjs";
import { controlEventDigest } from "./control-store.mjs";
import { StoreUnavailable, StoreConflict } from "./errors.mjs";
import { signEntityEnvelope } from "../../packages/identity/entity-envelope.mjs";
import {
  fixture,
  configuration,
  provisioning,
  acceptedAt,
  entity,
} from "./test-fixtures/control.mjs";
const authority = publicAuthority(configuration());
const principal = { entity, kid: fixture.kid };
const signed = signEntityEnvelope(fixture.envelope, {
  privateKey: Buffer.from(fixture.seed, "hex"),
  kid: fixture.kid,
});
const gate = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function storage() {
  let current;
  const state = {
    opens: 0,
    publications: 0,
    failOpen: false,
    failPublish: false,
    afterPublish: undefined,
    entered: undefined,
    wait: undefined,
  };
  const install = (input, operation = "enroll") => {
    const snapshot = prepareControlState({
      authority,
      provisioning: input,
      acceptedAt,
      operation,
      ...(current
        ? { previous: current.snapshot.canonical }
        : { retainedRecords: {} }),
    });
    const revision = (current?.revision ?? 0) + 1;
    const digest = controlEventDigest(
      revision,
      current?.digest ?? "0".repeat(64),
      snapshot.digest,
    );
    current = Object.freeze({ revision, digest, snapshot });
    return current;
  };
  install(provisioning());
  const store = {
    async open(input) {
      state.opens++;
      if (state.failOpen) throw new StoreUnavailable();
      if (
        JSON.stringify(input.provisioning) !==
        JSON.stringify(current.snapshot.state.provisioning)
      ) {
        // Compare canonical data, not incidental object key insertion order.
        const { canonicalize } = await import(
          "../../packages/identity/signed-envelope.mjs"
        );
        if (
          canonicalize(input.provisioning) !==
          canonicalize(current.snapshot.state.provisioning)
        )
          throw new StoreConflict();
      }
      return current;
    },
    async publishTrust(expected, input) {
      state.publications++;
      state.entered?.resolve();
      await state.wait?.promise;
      if (expected.digest !== current.digest) throw new StoreConflict();
      const result = install(input.provisioning, "trust");
      state.afterPublish?.();
      if (state.failPublish) throw new StoreUnavailable();
      return result;
    },
  };
  return { store, state, install, current: () => current };
}
async function open(f, options = {}) {
  return openPostgresTrust({
    store: f.store,
    authority,
    provisioning: provisioning(),
    nowSeconds: () => acceptedAt,
    ...options,
  });
}
test("opens enrolled signed state, exposes only immutable token, verifies and closes", async () => {
  const f = storage(),
    trust = await open(f);
  assert.equal(trust.status().state, "ready");
  assert.equal(trust.entityCount, 1);
  assert.equal(trust.allows(principal), true);
  assert.equal(trust.verify(signed).valid, true);
  assert.deepEqual(trust.token, { revision: 1, digest: f.current().digest });
  assert.ok(Object.isFrozen(trust.token));
  assert.equal(f.state.opens, 2);
  trust.close();
  trust.close();
  assert.equal(trust.status().state, "closed");
  assert.equal(trust.allows(principal), false);
  assert.equal(trust.verify(fixture.signed).valid, false);
  assert.equal(trust.token, null);
  await assert.rejects(trust.updateAsync(provisioning(2)));
});
test("startup rejects absent/mismatched storage, expired signed trust and cancellation", async () => {
  const unavailable = storage();
  unavailable.state.failOpen = true;
  await assert.rejects(open(unavailable));
  const changed = storage();
  changed.install(provisioning(2), "trust");
  await assert.rejects(open(changed));
  await assert.rejects(open(storage(), { nowSeconds: () => acceptedAt + 301 }));
  const signal = AbortSignal.abort();
  const cancelled = storage();
  await assert.rejects(open(cancelled, { signal }));
  assert.equal(cancelled.state.opens, 0);
});
test("revocation activates only after durable publication and blocks authority in between", async () => {
  const f = storage(),
    trust = await open(f);
  f.state.entered = gate();
  f.state.wait = gate();
  const pending = trust.updateAsync(
    provisioning(2, [{ kid: fixture.kid, generation: 1 }]),
  );
  await f.state.entered.promise;
  assert.equal(trust.status().state, "publishing");
  assert.equal(trust.allows(principal), false);
  assert.equal(trust.verify(fixture.signed).valid, false);
  assert.equal(trust.token, null);
  await assert.rejects(trust.updateAsync(provisioning(3)));
  f.state.wait.resolve();
  await pending;
  assert.equal(trust.status().state, "ready");
  assert.equal(trust.token.revision, 2);
  assert.equal(trust.allows(principal), false);
  trust.close();
});
test("uncertain publication never restores old authority and requires reopen", async () => {
  const f = storage(),
    trust = await open(f);
  f.state.failPublish = true;
  await assert.rejects(
    trust.updateAsync(provisioning(2, [{ kid: fixture.kid, generation: 1 }])),
  );
  assert.equal(
    f.current().revision,
    2,
    "models commit followed by lost response",
  );
  assert.equal(trust.status().state, "failed");
  assert.equal(trust.allows(principal), false);
  assert.equal(trust.token, null);
  await assert.rejects(trust.updateAsync(provisioning(3)));
  assert.equal(f.state.publications, 1);
  await assert.rejects(open(f));
  const reopened = await open(f, {
    provisioning: f.current().snapshot.state.provisioning,
  });
  assert.equal(reopened.allows(principal), false);
  reopened.close();
  trust.close();
});
for (const cancellation of ["close", "abort"])
  test(`${cancellation} during publication cannot activate a late commit`, async () => {
    const f = storage(),
      trust = await open(f),
      controller = new AbortController();
    f.state.entered = gate();
    f.state.wait = gate();
    const pending = trust.updateAsync(provisioning(2), {
      signal: controller.signal,
    });
    const rejection = assert.rejects(pending);
    await f.state.entered.promise;
    if (cancellation === "close") trust.close();
    else controller.abort();
    f.state.wait.resolve();
    await rejection;
    assert.equal(trust.allows(principal), false);
    assert.equal(trust.token, null);
    assert.equal(
      trust.status().state,
      cancellation === "close" ? "closed" : "failed",
    );
    trust.close();
  });
test("invalid or cancelled preparation does not mutate durable state", async () => {
  const f = storage(),
    trust = await open(f);
  const invalid = provisioning(2);
  invalid.statusDocuments[0].document.signatures[0].sig = "invalid";
  await assert.rejects(trust.updateAsync(invalid));
  await assert.rejects(
    trust.updateAsync(provisioning(2), { signal: AbortSignal.abort() }),
  );
  assert.equal(f.state.publications, 0);
  assert.equal(trust.allows(principal), true);
  trust.close();
});
test("freshness is rechecked after publication and never moves backwards locally", async () => {
  let now = acceptedAt;
  const f = storage(),
    trust = await open(f, { nowSeconds: () => now });
  f.state.afterPublish = () => {
    now = acceptedAt + 301;
  };
  await assert.rejects(trust.updateAsync(provisioning(2)));
  now = acceptedAt;
  assert.equal(trust.allows(principal), false);
  assert.equal(trust.status().state, "failed");
  trust.close();
});
test("removal makes runtime unready and keeps removed records in durable history", async () => {
  const f = storage(),
    trust = await open(f);
  await trust.updateAsync({ keyDocuments: [], statusDocuments: [] });
  assert.equal(trust.status().state, "empty");
  assert.equal(trust.allows(principal), false);
  assert.equal(f.current().snapshot.state.records[entity].serial, 1);
  await assert.rejects(trust.updateAsync(provisioning(2)));
  trust.close();
});
test("startup rechecks durable head after asynchronous preparation", async () => {
  const f = storage(),
    original = f.store.open;
  f.store.open = async (input) => {
    if (f.state.opens === 1) f.install(provisioning(2), "trust");
    return original(input);
  };
  await assert.rejects(open(f));
  assert.equal(f.state.opens, 2);
});
test("startup cancellation after durable reopen cannot return live authority", async () => {
  const f = storage(),
    original = f.store.open,
    controller = new AbortController();
  f.store.open = async (input) => {
    const result = await original(input);
    if (f.state.opens === 2) controller.abort();
    return result;
  };
  await assert.rejects(open(f, { signal: controller.signal }));
});
test("closing during worker preparation never publishes or reactivates", async () => {
  const f = storage(),
    trust = await open(f);
  const pending = trust.updateAsync(provisioning(2));
  const rejection = assert.rejects(pending);
  trust.close();
  await rejection;
  assert.equal(f.state.publications, 0);
  assert.equal(trust.status().state, "closed");
  assert.equal(trust.allows(principal), false);
});
for (const cancellation of ["close", "abort"])
  test(`${cancellation} immediately after commit still refuses activation`, async () => {
    const f = storage(),
      trust = await open(f),
      controller = new AbortController();
    f.state.afterPublish = () => {
      if (cancellation === "close") trust.close();
      else controller.abort();
    };
    await assert.rejects(
      trust.updateAsync(provisioning(2), { signal: controller.signal }),
    );
    assert.equal(f.current().revision, 2);
    assert.equal(trust.allows(principal), false);
    assert.equal(trust.token, null);
    trust.close();
  });

test("captured control fence stays bound to its head across publication", async () => {
  const f = storage(),
    trust = await open(f);
  const expected = trust.token;
  let observed;
  f.store.assertCurrent = async (client, token) => {
    observed = { client, token };
  };
  const fence = trust.controlFence(),
    client = {};
  assert.equal(fence.current(), true);
  await fence.lock(client);
  assert.deepEqual(observed, { client, token: expected });
  await trust.updateAsync(provisioning(2));
  assert.equal(fence.current(), false);
  await assert.rejects(fence.lock(client));
  assert.equal(trust.controlFence().current(), true);
  trust.close();
});

test("control fence rejects publication or close while waiting on its SQL lock", async () => {
  for (const mode of ["publish", "close"]) {
    const f = storage(),
      trust = await open(f),
      entered = gate(),
      resume = gate();
    f.store.assertCurrent = async () => {
      entered.resolve();
      await resume.promise;
    };
    const fence = trust.controlFence();
    const locked = fence.lock({});
    const denied = assert.rejects(locked);
    await entered.promise;
    if (mode === "publish") await trust.updateAsync(provisioning(2));
    else trust.close();
    resume.resolve();
    await denied;
    assert.equal(fence.current(), false);
    trust.close();
  }
});

test("publication after asynchronous head validation prevents old dispatch", async () => {
  const f = storage(),
    trust = await open(f);
  f.store.checkCurrent = async (expected) => {
    if (expected.digest !== f.current().digest) throw new StoreConflict();
  };
  const fence = trust.controlFence();
  await fence.validate();
  await trust.updateAsync(provisioning(2));
  let effects = 0;
  assert.throws(() =>
    fence.dispatch(() => {
      effects++;
    }),
  );
  assert.equal(effects, 0);
  const newer = trust.controlFence();
  await newer.validate();
  const events = [];
  const response = gate();
  const pending = newer.dispatch(() => {
    events.push("invoked");
    return response.promise;
  });
  await trust.updateAsync(provisioning(3));
  events.push("published");
  response.resolve("result");
  assert.equal(await pending, "result");
  assert.deepEqual(events, ["invoked", "published"]);
  trust.close();
  assert.throws(() =>
    newer.dispatch(() => {
      effects++;
    }),
  );
  assert.equal(effects, 0);
});
