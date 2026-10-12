// Actual PostgreSQL and launcher composition; synthetic provider readiness only.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, mkdtempSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Server } from "node:https";
import pg from "pg";
import { withPostgres } from "./postgres.mjs";
import { ControlStore } from "../services/organization/control-store.mjs";
import { ActionStore } from "../services/organization/store.mjs";
import {
  ActionPolicy,
  PolicyDenied,
} from "../services/organization/actions.mjs";
import { liveActionAuthorizer } from "../services/organization/authorization.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { publicAuthority } from "../services/organization/control-state.mjs";
import { openControlLease } from "../services/organization/control-lease.mjs";
import { openPostgresTrust } from "../services/organization/postgres-trust.mjs";
import * as launcher from "../services/organization/main.mjs";
import { KeycloakAuthenticator } from "../services/organization/auth.mjs";
import { grantRuntime } from "../services/organization/database.mjs";
import { signStatusDocument } from "../packages/identity/identity-status.mjs";
import { signKeyDocument } from "../packages/identity/key-document.mjs";
import {
  configuration,
  provisioning,
  fixture,
  entity,
} from "../services/organization/test-fixtures/control.mjs";
const config = configuration();
const now = () => Math.floor(Date.now() / 1000);
const humanEntity = "urn:xeip:entity:" + fixture.kid;
const humanSigning = {
  privateKey: Buffer.from(fixture.seed, "hex"),
  kid: fixture.kid,
};
const humanKey = {
  document: signKeyDocument(
    {
      xeip: "xeip.keydoc/0.1",
      entity: humanEntity,
      genesis: fixture.kid,
      generation: 1,
      issuedAt: new Date(now() * 1000).toISOString().replace(".000Z", "Z"),
      roots: [fixture.kid],
      devices: [],
      signatures: [],
    },
    humanSigning,
  ),
  anchor: { genesisKid: fixture.kid },
};
const humanStatus = {
  document: signStatusDocument(
    {
      xeip: "xeip.status/0.1",
      entity: humanEntity,
      serial: 1,
      issuedAt: new Date(now() * 1000).toISOString().replace(".000Z", "Z"),
      revoked: [],
      signatures: [],
    },
    humanSigning,
  ),
};
config.authentication.bindings.find(
  (binding) => binding.subject === "human",
).entity = humanEntity;
function fresh(serial, revoked = false) {
  const p = provisioning(serial);
  p.statusDocuments[0].document = signStatusDocument(
    {
      ...p.statusDocuments[0].document,
      issuedAt: new Date(now() * 1000).toISOString().replace(".000Z", "Z"),
      revoked: revoked ? [{ kid: fixture.kid, generation: 1 }] : [],
      signatures: [],
    },
    {
      privateKey: Buffer.from(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "hex",
      ),
      kid: p.keyDocuments[0].document.genesis,
    },
  );
  p.keyDocuments.push(humanKey);
  p.statusDocuments.push(humanStatus);
  return p;
}
await withPostgres(
  async ({ pool }) => {
    const role = "xeip_trust_" + randomBytes(6).toString("hex"),
      password = randomBytes(32).toString("hex");
    await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await grantRuntime(pool, role);
    const runtime = new pg.Pool({
      ...pool.options,
      password,
      user: role,
      max: 1,
    });
    runtime.on("error", () => {});
    const store = new ControlStore(runtime),
      owner = new ControlStore(pool);
    const dir = mkdtempSync(join(tmpdir(), "xeip-pg-trust-"));
    const old = fresh(1),
      revoked = fresh(2, true);
    config.provisioning = old;
    config.trust.directory = join(dir, "unused-checkpoint");
    config.tls = {
      cert: readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/cert.pem",
          import.meta.url,
        ),
      ),
      key: readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/key.pem",
          import.meta.url,
        ),
      ),
    };
    config.bind = { host: "127.0.0.1", port: 0 };
    config.management = { host: "127.0.0.1", port: 0, token: "a".repeat(48) };
    delete config.console;
    config.shutdownMs = 1000;
    const authority = publicAuthority(config);
    let trust, service;
    const originalReady = KeycloakAuthenticator.prototype.ready;
    const originalListen = Server.prototype.listen;
    let providerProbes = 0,
      listens = 0;
    KeycloakAuthenticator.prototype.ready = async function () {
      providerProbes++;
      return true;
    };
    Server.prototype.listen = function (...args) {
      listens++;
      return originalListen.apply(this, args);
    };
    try {
      assert.equal(
        typeof launcher.startOrganization,
        "function",
        "test requires actual launcher composition",
      );
      await assert.rejects(launcher.startOrganization(config, runtime));
      assert.equal(listens, 0);
      await owner.enroll({
        authority,
        provisioning: old,
        acceptedAt: now(),
        retainedRecords: {},
      });
      trust = await openPostgresTrust({ store, authority, provisioning: old });
      assert.equal(trust.allows({ entity, kid: fixture.kid }), true);
      const policy = new ActionPolicy(config.policy);
      const agent = Object.freeze({
        subject: "agent",
        entity,
        kid: fixture.kid,
        clientId: "agent",
        roles: Object.freeze(["agent"]),
        expiresAt: now() + 300,
      });
      const human = Object.freeze({
        ...agent,
        subject: "human",
        entity: humanEntity,
        clientId: "console",
        roles: Object.freeze(["approver"]),
      });
      const authorize = liveActionAuthorizer(
        { revalidate: async () => true },
        trust,
      );
      const actions = new ActionStore(runtime, policy, authorize);
      const session = config.policy.sessions[0].id,
        id = "urn:xeip:action:stale-runtime-restore";
      const proposed = await actions.propose(agent, {
        id,
        session,
        target: "internal",
        tool: "lookup",
        arguments: { synthetic: true },
        expiresAt: now() + 240,
      });
      await actions.decide(
        human,
        session,
        id,
        proposed.proposal.digest,
        "approve",
      );
      let effects = 0;
      const execute = createActionExecutor(policy, {
        call: async (_action, { beforeSend }) => {
          assert.equal(await beforeSend(), true);
          effects++;
          return { synthetic: true };
        },
      });
      const actionsBefore = (await pool.query("SELECT * FROM xeip_org.actions"))
        .rows;
      const auditBefore = (
        await pool.query("SELECT * FROM xeip_org.audit ORDER BY sequence")
      ).rows;
      await trust.updateAsync(revoked);
      assert.equal(trust.allows({ entity, kid: fixture.kid }), false);
      assert.equal(trust.token.revision, 2);
      await assert.rejects(
        execute(
          agent,
          { id, session, digest: proposed.proposal.digest },
          { store: actions, authorize },
        ),
        PolicyDenied,
      );
      assert.equal(effects, 0);
      trust.close();
      assert.deepEqual(
        (await pool.query("SELECT * FROM xeip_org.actions")).rows,
        actionsBefore,
      );
      assert.deepEqual(
        (await pool.query("SELECT * FROM xeip_org.audit ORDER BY sequence"))
          .rows,
        auditBefore,
      );
      await assert.rejects(
        openPostgresTrust({ store, authority, provisioning: old }),
      );
      await assert.rejects(launcher.startOrganization(config, runtime));
      assert.equal(
        providerProbes,
        0,
        "stale trust fails before provider readiness or listeners",
      );
      assert.equal(
        listens,
        0,
        "older signed provisioning cannot expose a listener",
      );
      assert.equal(
        existsSync(config.trust.directory),
        false,
        "no filesystem checkpoint is created",
      );
      config.provisioning = revoked;
      const maintenance = await openControlLease(pool.options);
      let forbiddenStartup;
      try {
        await assert.rejects(
          (async () => {
            forbiddenStartup = await launcher.startOrganization(
              config,
              runtime,
            );
          })(),
        );
        assert.equal(
          listens,
          0,
          "maintenance excludes runtime before listeners",
        );
      } finally {
        await forbiddenStartup?.stop();
        await maintenance.close();
      }
      service = await launcher.startOrganization(config, runtime);
      assert.equal(await service.ready(), true);
      assert.equal(listens, 2);
      const reopened = await openPostgresTrust({
        store,
        authority,
        provisioning: revoked,
      });
      assert.equal(reopened.allows({ entity, kid: fixture.kid }), false);
      reopened.close();
      assert.equal(existsSync(config.trust.directory), false);
      await assert.rejects(openControlLease(pool.options));
      const otherPool = new pg.Pool({ ...runtime.options, password, max: 1 });
      otherPool.on("error", () => {});
      let duplicate;
      try {
        await assert.rejects(
          (async () => {
            duplicate = await launcher.startOrganization(config, otherPool);
          })(),
        );
      } finally {
        await duplicate?.stop();
        if (!otherPool.ended) await otherPool.end();
      }
      const leases = (
        await pool.query(
          "SELECT pid FROM pg_stat_activity WHERE application_name='xeip-control-lease' AND usename=$1",
          [role],
        )
      ).rows;
      assert.equal(leases.length, 1);
      let deadline;
      try {
        const failed = Promise.race([
          service.failed,
          new Promise((_, reject) => {
            deadline = setTimeout(
              () => reject(new Error("lease-loss fixture deadline")),
              12000,
            );
          }),
        ]);
        await pool.query("SELECT pg_terminate_backend($1)", [leases[0].pid]);
        assert.equal(await failed, "control_lease_lost");
      } finally {
        clearTimeout(deadline);
      }
      assert.equal(await service.ready(), false);
      await service.stop();
      const afterDrain = await openControlLease(pool.options);
      await afterDrain.close();
      console.log(
        JSON.stringify({
          result: "pass",
          staleStartupRefused: true,
          listenersBeforeCurrentInputs: 0,
          revocationPreserved: true,
          approvedUnconsumedActions: 1,
          syntheticEffects: effects,
          filesystemCheckpointCreated: false,
          currentStartupReady: true,
          workPoolMax: 1,
          maintenanceExcludesStartup: true,
          observedLeaseLossStopsRuntime: true,
          scope:
            "actual PostgreSQL and launcher TLS listener; provider readiness synthetic; runtime lease verified; owner commands and combined recovery remain open",
        }),
      );
    } finally {
      await service?.stop();
      trust?.close();
      KeycloakAuthenticator.prototype.ready = originalReady;
      Server.prototype.listen = originalListen;
      if (!runtime.ended) await runtime.end();
      rmSync(dir, { recursive: true, force: true });
    }
  },
  { baselineChecks: false },
);
