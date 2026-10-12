import { test } from "node:test";
import assert from "node:assert/strict";
import {
  fetchTrustFeed,
  validateTrustFeed,
} from "../services/organization/cloudflare/refresh.mjs";
const feed = { url: "https://trust.example/current", timeoutMs: 100 };
const body = { keyDocuments: [], statusDocuments: [] };
const response = (value = JSON.stringify(body), init = {}) =>
  new Response(value, {
    headers: { "content-type": "application/json" },
    ...init,
  });
test("feed fetch is pinned, authenticated, uncached and strict JSON", async () => {
  let seen;
  const result = await fetchTrustFeed(
    feed,
    "fixture-token",
    async (url, options) => {
      seen = { url, ...options };
      return response();
    },
  );
  assert.deepEqual(JSON.parse(JSON.stringify(result)), body);
  assert.equal(seen.url, feed.url);
  assert.equal(seen.redirect, "manual");
  assert.equal(seen.cache, "no-store");
  assert.equal(seen.headers.authorization, "Bearer fixture-token");
  assert.equal(seen.signal.aborted, true);
});
test("feed profile rejects ambiguous URLs and invalid bounds", () => {
  assert.deepEqual(validateTrustFeed(feed), feed);
  for (const value of [
    null,
    {},
    { ...feed, extra: 1 },
    { ...feed, timeoutMs: null },
    { ...feed, timeoutMs: 99 },
    { ...feed, timeoutMs: 10001 },
    ...[
      "http://trust.example/current",
      "https://a:b@trust.example/current",
      "https://trust.example/current?token=x",
      "https://trust.example/current#x",
      "https://TRUST.example/current",
    ].map((url) => ({ ...feed, url })),
  ])
    assert.throws(() => validateTrustFeed(value));
});
for (const [name, value, init] of [
  [
    "redirect",
    "",
    { status: 302, headers: { location: "https://evil.example/" } },
  ],
  ["partial content", "{}", { status: 206 }],
  ["wrong media", "{}", { headers: { "content-type": "text/plain" } }],
  [
    "wrong encoding",
    "{}",
    {
      headers: {
        "content-type": "application/json",
        "content-encoding": "gzip",
      },
    },
  ],
  [
    "declared oversized",
    "{}",
    {
      headers: {
        "content-type": "application/json",
        "content-length": "2000001",
      },
    },
  ],
  [
    "malformed length",
    "{}",
    {
      headers: { "content-type": "application/json", "content-length": "1e6" },
    },
  ],
  [
    "duplicate keys",
    '{"keyDocuments":[],"keyDocuments":[],"statusDocuments":[]}',
  ],
  [
    "extra property",
    '{"keyDocuments":[],"statusDocuments":[],"operator":"spoof"}',
  ],
  ["invalid UTF8", new Uint8Array([0xff])],
  ["stream oversized", " ".repeat(2000001)],
  ["too deep", "[".repeat(33) + "0" + "]".repeat(33)],
])
  test("feed rejects " + name + " with redacted error", async () => {
    let calls = 0;
    await assert.rejects(
      fetchTrustFeed(feed, "sensitive-token", async () => {
        calls++;
        return response(value, init);
      }),
      { message: "trust feed unavailable" },
    );
    assert.equal(calls, 1);
  });
test("feed timeout bounds headers and cancels a late response without returning it", async () => {
  let release,
    cancelled = false;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  await assert.rejects(
    fetchTrustFeed(feed, "token", () => pending),
    { message: "trust feed unavailable" },
  );
  release(
    response(
      new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
    ),
  );
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(cancelled, true);
});
test("feed timeout bounds a stalled body and cancels its reader", async () => {
  let cancelled = false;
  await assert.rejects(
    fetchTrustFeed(feed, "token", async () =>
      response(
        new ReadableStream({
          cancel() {
            cancelled = true;
          },
        }),
      ),
    ),
    { message: "trust feed unavailable" },
  );
  assert.equal(cancelled, true);
});

import { randomUUID } from "node:crypto";
import { harness } from "./fixtures/cloudflare/worker-harness.mjs";
import {
  identity,
  provisioning,
  configuration,
} from "./fixtures/cloudflare/authority-harness.mjs";
const actors = [identity("agent"), identity("human")];
const profile = {
  organization: "refresh-fixture",
  origin: "https://xeip.example",
  gateway: actors[0].entity,
  trust: { maxAgeSeconds: 300 },
  targets: [
    {
      id: "internal",
      revision: "1",
      recipient: actors[0].entity,
      tools: ["lookup"],
      endpoint: "https://mcp.example/mcp",
      resourceMetadataUrl: "https://mcp.example/resource",
      issuer: "https://mcp.example",
      tokenEndpoint: "https://mcp.example/token",
      clientId: "xeip",
      scope: "tools:lookup",
    },
  ],
  trustFeed: { url: "https://trust.example/current", timeoutMs: 1000 },
};
const bindings = (p = profile, token = "fixture-token") => ({
  XEIP_PROFILE: JSON.stringify(p),
  XEIP_CREDENTIALS: JSON.stringify({
    introspectionClientSecret: "fixture-secret",
    targets: { internal: "target-secret" },
    ...(p.trustFeed ? { trustFeedToken: token } : {}),
  }),
});
const raw = (operation, extra = {}) =>
  JSON.stringify({ operation, requestId: randomUUID(), ...extra });
async function native(t, p = profile) {
  let candidate = provisioning(actors),
    requests = 0,
    transport;
  const h = await harness(bindings(p), {
    outboundService: async (r) => {
      requests++;
      assert.equal(r.url, profile.trustFeed.url);
      assert.equal(r.headers.get("authorization"), "Bearer fixture-token");
      return transport ? transport(r) : response(JSON.stringify(candidate));
    },
  });
  t.after(() => h.close());
  const config = configuration(
    {
      config: {
        issuer: "https://id.example/realms/xeip",
        audience: "xeip-api",
        clientIds: ["xeip-agent", "xeip-console"],
        introspectionClientId: "xeip-introspection",
      },
    },
    actors,
  );
  delete config.authentication.allowInsecureLoopback;
  return {
    ...h,
    get requests() {
      return requests;
    },
    set candidate(v) {
      candidate = v;
    },
    set transport(v) {
      transport = v;
    },
    status: async () => (await h.send({ raw: raw("status") })).body,
    audit: async () => (await h.send({ raw: raw("auditExport") })).body,
    tick: async () => h.send({ kind: "scheduled" }),
    init: async () => {
      const r = await h.send({
        raw: raw("initialize", { configuration: config }),
      });
      assert.equal(r.body.ok, true, JSON.stringify(r));
    },
    provision: async (value, revision = 0) =>
      h.send({
        raw: raw("refreshTrust", {
          provisioning: value,
          expectedRevision: revision,
        }),
      }),
  };
}
test("native Cron never bootstraps, updates only provisioned trust, audits changed data and deduplicates across restart", async (t) => {
  const h = await native(t);
  const first = await h.tick();
  assert.equal(first.body.outcome, "exception", JSON.stringify(first));
  assert.equal(h.requests, 0);
  assert.equal((await h.status()).status.state, "uninitialized");
  await h.init();
  await h.tick();
  assert.equal(h.requests, 0);
  const initial = provisioning(actors);
  h.candidate = initial;
  assert.equal((await h.provision(initial)).body.ok, true);
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal((await h.status()).status.trust.revision, 1);
  assert.equal((await h.audit()).audit.headSequence, 4);
  h.candidate = provisioning(actors, 2);
  assert.equal((await h.tick()).body.outcome, "ok");
  const page = (await h.audit()).audit;
  assert.equal(page.headSequence, 6);
  assert.equal(page.records[4].event.operator, "automation:trust-feed");
  assert.equal(page.records[5].event.outcome, "completed");
  assert.equal((await h.status()).status.trust.revision, 2);
  await h.restart();
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal((await h.audit()).audit.headSequence, 6);
});
test("native feed rejects roster expansion, removal, rollback and invalid signatures without changing authority", async (t) => {
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(actors, 2));
  const invalid = provisioning(actors, 3);
  invalid.statusDocuments[0].document.serial = 4;
  for (const value of [
    provisioning([...actors, identity("stranger")], 3),
    provisioning([actors[0]], 3),
    provisioning(actors, 1),
    invalid,
  ]) {
    h.candidate = value;
    assert.equal((await h.tick()).body.outcome, "exception");
    assert.equal((await h.status()).status.trust.revision, 1);
    assert.equal((await h.audit()).audit.headSequence, 4);
  }
  h.candidate = provisioning(actors, 3, "agent");
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal((await h.status()).status.trust.revision, 2);
});
test("native refresh discards a response superseded by an owner mutation", async (t) => {
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(actors));
  let release, entered;
  const started = new Promise((r) => (entered = r));
  h.transport = async () => {
    entered();
    return new Promise((r) => (release = r));
  };
  const pending = h.tick();
  await started;
  assert.equal((await h.provision(provisioning(actors, 3), 1)).body.ok, true);
  release(response(JSON.stringify(provisioning(actors, 2))));
  assert.equal((await pending).body.outcome, "exception");
  assert.equal((await h.status()).status.trust.revision, 2);
  assert.equal((await h.audit()).audit.headSequence, 6);
});
test("native public requests cannot refresh and source drift fails closed while token rotation preserves intent", async (t) => {
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(actors));
  for (const path of ["/refresh", "/scheduled", "/cdn-cgi/handler/scheduled"])
    assert.equal(
      (await h.send({ kind: "public", url: "https://xeip.example" + path }))
        .status,
      404,
    );
  assert.equal(h.requests, 0);
  await h.restart(bindings(profile, "rotated-token"));
  assert.equal((await h.status()).status.state, "initialized");
  await h.restart(
    bindings({
      ...profile,
      trustFeed: {
        ...profile.trustFeed,
        url: "https://different.example/current",
      },
    }),
  );
  assert.equal((await h.status()).status.state, "failed");
  await h.tick();
  assert.equal(h.requests, 0);
});
test("native disabled feed does not fetch or alter the existing lifecycle", async (t) => {
  const { trustFeed, ...p } = profile;
  const h = await native(t, p);
  await h.init();
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal(h.requests, 0);
});

test("native overlapping polls admit one fetch and a timeout never applies a late candidate", async (t) => {
  const h = await native(t, {
    ...profile,
    trustFeed: { ...profile.trustFeed, timeoutMs: 10000 },
  });
  await h.init();
  await h.provision(provisioning(actors));
  let release, entered;
  const started = new Promise((r) => (entered = r));
  h.transport = async () => {
    entered();
    return new Promise((r) => (release = r));
  };
  let completed = false;
  const pending = h.tick().then((result) => {
    completed = true;
    return result;
  });
  try {
    await started;
    assert.equal(completed, false, "first poll expired before overlap check");
    assert.equal((await h.tick()).body.outcome, "exception");
    assert.equal(completed, false, "overlap check exceeded the held deadline");
    assert.equal(h.requests, 1);
    assert.equal((await pending).body.outcome, "exception");
  } finally {
    release?.(response(JSON.stringify(provisioning(actors, 2))));
  }
  await new Promise((r) => setTimeout(r, 20));
  assert.equal((await h.status()).status.trust.revision, 1);
  assert.equal((await h.audit()).audit.headSequence, 4);
  h.transport = undefined;
  h.candidate = provisioning(actors, 2);
  assert.equal((await h.tick()).body.outcome, "ok");
});
test("native feed cannot restore a roster member omitted by its owner", async (t) => {
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(actors));
  await h.provision(provisioning([actors[0]], 2), 1);
  h.candidate = provisioning(actors, 3);
  assert.equal((await h.tick()).body.outcome, "exception");
  assert.equal((await h.status()).status.trust.entities, 1);
  assert.equal((await h.status()).status.trust.revision, 2);
});
test("native feed rejects signed stale statuses and changed anchors", async (t) => {
  const { signStatusDocument } = await import("../tools/identity-status.mjs");
  const { utc, now } = await import(
    "./fixtures/cloudflare/authority-harness.mjs"
  );
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(actors));
  const stale = provisioning(actors, 2);
  stale.statusDocuments[0].document = signStatusDocument(
    {
      ...stale.statusDocuments[0].document,
      issuedAt: utc(now() - 1000),
      signatures: [],
    },
    { privateKey: actors[0].seed, kid: actors[0].kid },
  );
  const changed = provisioning(actors, 2);
  changed.keyDocuments[0] = structuredClone(changed.keyDocuments[0]);
  changed.keyDocuments[0].anchor = { genesisKid: identity("stranger").kid };
  for (const value of [stale, changed]) {
    h.candidate = value;
    assert.equal((await h.tick()).body.outcome, "exception");
  }
  assert.equal((await h.status()).status.trust.revision, 1);
});
test("native full 700-identity feed stays within provisioning bounds and survives restart", async (t) => {
  const population = [
    ...actors,
    ...Array.from({ length: 698 }, (_, i) => identity("population-" + i)),
  ];
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(population));
  h.candidate = provisioning(population, 2);
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal((await h.status()).status.trust.entities, 700);
  await h.restart();
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal((await h.status()).status.trust.revision, 2);
});

import { harness as lifecycleHarness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
import { runtimeConfiguration } from "../services/organization/cloudflare/profile.mjs";
for (const offset of [1, 2, 3])
  test(
    "automatic refresh quarantines on durability barrier " +
      offset +
      " without replaying uncertain results",
    async (t) => {
      let candidate = provisioning(actors, 2),
        requests = 0;
      const runtime = await lifecycleHarness({
        outboundService: async () => {
          requests++;
          return response(JSON.stringify(candidate));
        },
      });
      t.after(() => runtime.close());
      const f = await runtime.fixture();
      const settings = runtimeConfiguration(bindings());
      const config = configuration(
        {
          config: {
            issuer: "https://id.example/realms/xeip",
            audience: "xeip-api",
            clientIds: ["xeip-agent", "xeip-console"],
            introspectionClientId: "xeip-introspection",
          },
        },
        actors,
      );
      delete config.authentication.allowInsecureLoopback;
      assert.equal(
        (await f.send({ operation: "open", configuration: settings })).status,
        200,
      );
      assert.equal(
        (
          await f.send({
            operation: "manage",
            operator: "fixture:owner",
            raw: raw("initialize", { configuration: config }),
          })
        ).status,
        200,
      );
      assert.equal(
        (
          await f.send({
            operation: "manage",
            operator: "fixture:owner",
            raw: raw("refreshTrust", {
              provisioning: provisioning(actors),
              expectedRevision: 0,
            }),
          })
        ).status,
        200,
      );
      const controls = (await f.send({ operation: "controls", control: {} }))
        .body;
      await f.send({
        operation: "controls",
        control: { failSync: controls.syncs + offset },
      });
      assert.equal((await f.send({ operation: "pollTrustFeed" })).status, 500);
      assert.equal(
        (await f.send({ operation: "status" })).body.state,
        "failed",
      );
      assert.equal((await f.send({ operation: "pollTrustFeed" })).status, 500);
      assert.equal(requests, 1);
      const history = (
        await f.sql("SELECT canonical FROM xeip_owner_events ORDER BY sequence")
      ).body.rows;
      await f.send({ operation: "controls", control: { failSync: 0 } });
      assert.equal(
        (await f.send({ operation: "open", configuration: settings })).body
          .state,
        "initialized",
      );
      if (offset > 1) {
        assert.equal(
          (await f.send({ operation: "pollTrustFeed" })).body.outcome,
          "unchanged",
        );
        assert.deepEqual(
          (
            await f.sql(
              "SELECT canonical FROM xeip_owner_events ORDER BY sequence",
            )
          ).body.rows,
          history,
        );
      } else {
        assert.equal(
          (await f.send({ operation: "pollTrustFeed" })).body.outcome,
          "updated",
        );
        const after = (
          await f.sql(
            "SELECT canonical FROM xeip_owner_events ORDER BY sequence",
          )
        ).body.rows;
        assert.deepEqual(after.slice(0, history.length), history);
        assert.equal(after.length, history.length + 2);
      }
    },
  );

test("default service binding cannot invoke scheduled refresh or its administrative effect", async (t) => {
  const h = await native(t);
  await h.init();
  await h.provision(provisioning(actors));
  h.candidate = provisioning(actors, 2);
  for (const kind of ["default-scheduled", "default-refresh"])
    assert.equal((await h.send({ kind })).status, 502);
  assert.equal((await h.send({ kind: "refresh-http" })).status, 404);
  assert.equal((await h.send({ kind: "unlabelled-refresh" })).status, 403);
  assert.equal(h.requests, 0);
  assert.equal((await h.status()).status.trust.revision, 1);
  assert.equal((await h.audit()).audit.headSequence, 4);
  assert.equal((await h.tick()).body.outcome, "ok");
  assert.equal((await h.status()).status.trust.revision, 2);
});
