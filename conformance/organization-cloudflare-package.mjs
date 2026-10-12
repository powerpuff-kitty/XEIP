import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { buildPackage } from "../services/organization/cloudflare/build.mjs";
const entity =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const profile = {
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
      issuer: "https://mcp.example",
      tokenEndpoint: "https://mcp.example/token",
      clientId: "xeip",
      scope: "tools:lookup",
    },
  ],
};
test("offline package has no public exposure or fixture controls and hashes the exact deployment bytes", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "xeip-package-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const outdir = join(directory, "artifact");
  await buildPackage({
    profile: JSON.stringify(profile),
    name: "xeip-fixture",
    outdir,
  });
  assert.deepEqual((await readdir(outdir)).sort(), [
    "manifest.json",
    "worker.mjs",
    "wrangler.json",
  ]);
  const config = JSON.parse(
    await readFile(join(outdir, "wrangler.json"), "utf8"),
  );
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.routes, []);
  assert.equal(config.no_bundle, true);
  assert.deepEqual(config.migrations, [
    { tag: "v1", new_sqlite_classes: ["OrganizationObject"] },
  ]);
  assert.deepEqual(Object.keys(config.vars), ["XEIP_PROFILE"]);
  assert.deepEqual(JSON.parse(config.vars.XEIP_PROFILE), profile);
  const bundle = await readFile(join(outdir, "worker.mjs"), "utf8");
  for (const forbidden of [
    "AdminFixture",
    "LifecycleFixture",
    "TransportFixture",
    "AuthorityFixture",
    "injected SQL failure",
    "test-fixtures",
  ])
    assert.ok(!bundle.includes(forbidden), forbidden);
  const manifest = JSON.parse(
    await readFile(join(outdir, "manifest.json"), "utf8"),
  );
  for (const file of manifest.files)
    assert.equal(
      file.sha256,
      createHash("sha256")
        .update(await readFile(join(outdir, file.path)))
        .digest("hex"),
    );
  assert.ok(manifest.packages.some((p) => p.name === "jose"));
  assert.ok(
    !manifest.packages.some((p) =>
      ["pg", "miniflare", "wrangler"].includes(p.name),
    ),
  );
  await assert.rejects(
    buildPackage({
      profile: JSON.stringify(profile),
      name: "xeip-fixture",
      outdir,
    }),
  );
});
test("package rejects secret-bearing profiles and invalid names before creating an artifact", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "xeip-package-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [i, p, name] of [
    [1, { ...profile, introspectionClientSecret: "sentinel-secret" }, "xeip"],
    [2, profile, "../bad"],
  ])
    await assert.rejects(
      buildPackage({
        profile: JSON.stringify(p),
        name,
        outdir: join(directory, String(i)),
      }),
    );
  assert.deepEqual(await readdir(directory), []);
});

for (const recoveryEnabled of [false, true])
  test(`exact packaged artifact passes Wrangler dry-run and private operator RPC through the local registry (recovery=${recoveryEnabled})`, async (t) => {
    const { writeFile } = await import("node:fs/promises");
    const { promisify } = await import("node:util");
    const { execFile } = await import("node:child_process");
    const { randomUUID } = await import("node:crypto");
    const directory = await mkdtemp(join(tmpdir(), "xeip-package-rpc-"));
    let worker;
    t.after(async () => {
      try {
        await worker?.stop();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
    const outdir = join(directory, "artifact"),
      name = "xeip-fixture-" + randomUUID().slice(0, 8);
    const candidateProfile = {
      ...profile,
      ...(recoveryEnabled
        ? {
            recovery: {
              url: "https://journal.example/v1/recovery",
              stream: randomUUID(),
            },
          }
        : {}),
    };
    await buildPackage({
      profile: JSON.stringify(candidateProfile),
      name,
      outdir,
    });
    await promisify(execFile)(
      process.execPath,
      [
        "node_modules/wrangler/bin/wrangler.js",
        "deploy",
        "--dry-run",
        "--config",
        join(outdir, "wrangler.json"),
        "--outdir",
        join(directory, "dry-run"),
      ],
      {
        cwd: process.cwd(),
        env: {
          PATH: process.env.PATH,
          WRANGLER_SEND_METRICS: "false",
          CI: "true",
        },
        timeout: 30000,
        maxBuffer: 1048576,
      },
    );
    const { unstable_dev } = await import("wrangler");
    worker = await unstable_dev(join(outdir, "worker.mjs"), {
      config: join(outdir, "wrangler.json"),
      local: true,
      ip: "127.0.0.1",
      port: 0,
      inspectorPort: 0,
      logLevel: "none",
      persistTo: join(directory, "state"),
      vars: {
        XEIP_CREDENTIALS: JSON.stringify({
          introspectionClientSecret: "fixture-only",
          targets: { internal: "fixture-only" },
          ...(recoveryEnabled ? { recoveryToken: "a1".repeat(32) } : {}),
        }),
      },
      experimental: {
        disableExperimentalWarning: true,
        disableDevRegistry: false,
      },
    });
    const operatorPath = join(directory, "operator.json"),
      commandPath = join(directory, "command.json"),
      requestId = randomUUID();
    await writeFile(
      operatorPath,
      JSON.stringify({
        name: "xeip-operator",
        compatibility_date: "2026-07-30",
        services: [
          {
            binding: "OWNER",
            service: name,
            entrypoint: "OwnerEntrypoint",
            remote: false,
            props: { operator: "fixture:local-runner" },
          },
        ],
      }),
    );
    await writeFile(
      commandPath,
      JSON.stringify({ operation: "status", requestId }),
    );
    const { invokeOwner } = await import(
      "../services/organization/cloudflare/owner.mjs"
    );
    // Wrangler may return its live handle before publishing the local registry.
    // Probe status only; the production client never retries owner commands.
    let receipt;
    const until = Date.now() + 20000;
    for (;;) {
      try {
        receipt = await invokeOwner({
          configPath: operatorPath,
          commandPath,
          remote: false,
        });
        break;
      } catch (error) {
        if (!/Worker .* not found/.test(String(error)) || Date.now() >= until)
          throw error;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    assert.equal(receipt.ok, true);
    assert.equal(receipt.requestId, requestId);
    assert.equal(receipt.operator, "fixture:local-runner");
    assert.equal(receipt.status.state, "uninitialized");
    const { collectOwnerArchive, verifyArchive } = await import(
      "../services/organization/cloudflare/archive.mjs"
    );
    const archive = join(directory, "collected");
    const manifest = await collectOwnerArchive({
      configPath: operatorPath,
      directory: archive,
      remote: false,
    });
    assert.equal(manifest.records, 0);
    assert.equal(
      (await verifyArchive(archive)).manifestChecksum,
      manifest.manifestChecksum,
    );
    // This startup check has no hosted TLS journal. The exact packaged signed
    // recovery flow is exercised with explicit local outbound mapping separately.
    if (recoveryEnabled) return;
    const { configuration, identity } = await import(
      "./fixtures/cloudflare/authority-harness.mjs"
    );
    const configurationValue = configuration(
      {
        config: {
          issuer: "https://id.example/realms/xeip",
          audience: "xeip-api",
          clientIds: ["agent", "console"],
          introspectionClientId: "introspection",
        },
      },
      [{ subject: "agent", entity, kid: entity.slice(16) }, identity("human")],
    );
    await writeFile(
      commandPath,
      JSON.stringify({
        operation: "initialize",
        requestId: randomUUID(),
        configuration: configurationValue,
      }),
    );
    assert.equal(
      (
        await invokeOwner({
          configPath: operatorPath,
          commandPath,
          remote: false,
        })
      ).ok,
      true,
    );
    const { collectOwnerActions, verifyActionArchive } = await import(
      "../services/organization/cloudflare/action-archive.mjs"
    );
    const actionDirectory = join(directory, "actions");
    const actions = await collectOwnerActions({
      configPath: operatorPath,
      directory: actionDirectory,
      remote: false,
    });
    assert.equal(actions.snapshot.actions, 0);
    assert.equal(
      (await verifyActionArchive(actionDirectory)).manifestChecksum,
      actions.manifestChecksum,
    );
    // A single reusable proxy session supports multiple validated read-only calls.
    const { withOwnerSession } = await import(
      "../services/organization/cloudflare/owner.mjs"
    );
    await withOwnerSession(
      { configPath: operatorPath, remote: false },
      async ({ send }) => {
        for (const operation of ["status", "auditExport"])
          assert.equal(
            (await send(JSON.stringify({ operation, requestId: randomUUID() })))
              .ok,
            true,
          );
      },
    );
  });

test("offline package enables the fixed minute cron only for an explicit pinned feed", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "xeip-feed-package-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const enabled of [false, true]) {
    const outdir = join(directory, String(enabled));
    await buildPackage({
      profile: JSON.stringify({
        ...profile,
        ...(enabled
          ? { trustFeed: { url: "https://trust.example/current" } }
          : {}),
      }),
      name: "xeip-feed",
      outdir,
    });
    const config = JSON.parse(
      await readFile(join(outdir, "wrangler.json"), "utf8"),
    );
    assert.deepEqual(config.triggers, { crons: [] });
    if (enabled) {
      const scheduler = JSON.parse(
        await readFile(join(outdir, "scheduler.wrangler.json"), "utf8"),
      );
      assert.deepEqual(scheduler.triggers, { crons: ["* * * * *"] });
      assert.deepEqual(scheduler.services, [
        {
          binding: "REFRESH",
          service: "xeip-feed",
          entrypoint: "RefreshEntrypoint",
          props: { purpose: "trust-refresh" },
        },
      ]);
      assert.deepEqual(scheduler.routes, []);
      assert.equal(scheduler.workers_dev, false);
      const manifest = JSON.parse(
        await readFile(join(outdir, "manifest.json"), "utf8"),
      );
      for (const file of manifest.files)
        assert.equal(
          createHash("sha256")
            .update(await readFile(join(outdir, file.path)))
            .digest("hex"),
          file.sha256,
        );
      assert.deepEqual(manifest.files.map((f) => f.path).sort(), [
        "scheduler.mjs",
        "scheduler.wrangler.json",
        "worker.mjs",
        "wrangler.json",
      ]);
    }
    assert.ok(!JSON.stringify(config).includes("trustFeedToken"));
  }
});

test("feed-enabled package reserves a unique valid scheduler name before writing files", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "xeip-scheduler-name-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await assert.rejects(
    buildPackage({
      profile: JSON.stringify({
        ...profile,
        trustFeed: { url: "https://trust.example/current" },
      }),
      name: "a".repeat(56),
      outdir: join(directory, "invalid"),
    }),
    /invalid Worker name/,
  );
  assert.deepEqual(await readdir(directory), []);
});
