// Actual restricted PostgreSQL, runtime trust and executor; synthetic tool effects.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { withPostgres } from "./postgres.mjs";
import { ControlStore } from "../services/organization/control-store.mjs";
import {
  ActionStore,
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/store.mjs";
import {
  ActionPolicy,
  PolicyDenied,
} from "../services/organization/actions.mjs";
import { ConnectorFailure } from "../services/organization/errors.mjs";
import { openPostgresTrust } from "../services/organization/postgres-trust.mjs";
import { publicAuthority } from "../services/organization/control-state.mjs";
import { liveActionAuthorizer } from "../services/organization/authorization.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { grantRuntime } from "../services/organization/database.mjs";
import { signKeyDocument } from "../packages/identity/key-document.mjs";
import { signStatusDocument } from "../packages/identity/identity-status.mjs";
import {
  configuration,
  provisioning,
  fixture,
  entity,
} from "../services/organization/test-fixtures/control.mjs";
const now = () => Math.floor(Date.now() / 1000);
const utc = () => new Date(now() * 1000).toISOString().replace(".000Z", "Z");
const gate = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
const config = configuration();
const humanEntity = "urn:xeip:entity:" + fixture.kid;
config.authentication.bindings.find((b) => b.subject === "human").entity =
  humanEntity;
const signing = {
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
      issuedAt: utc(),
      roots: [fixture.kid],
      devices: [],
      signatures: [],
    },
    signing,
  ),
  anchor: { genesisKid: fixture.kid },
};
const humanStatus = {
  document: signStatusDocument(
    {
      xeip: "xeip.status/0.1",
      entity: humanEntity,
      serial: 1,
      issuedAt: utc(),
      revoked: [],
      signatures: [],
    },
    signing,
  ),
};
function fresh(serial, revoked = false) {
  const p = provisioning(serial);
  p.statusDocuments[0].document = signStatusDocument(
    {
      ...p.statusDocuments[0].document,
      issuedAt: utc(),
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
    const role = "xeip_fence_" + randomBytes(6).toString("hex"),
      password = randomBytes(32).toString("hex");
    await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await grantRuntime(pool, role);
    const runtime = new pg.Pool({
      ...pool.options,
      user: role,
      password,
      max: 5,
      application_name: "xeip-control-fence-fixture",
    });
    runtime.on("error", () => {});
    const control = new ControlStore(runtime),
      authority = publicAuthority(config),
      old = fresh(1);
    let trust, stale;
    const resumes = [];
    const running = [];
    try {
      await new ControlStore(pool).enroll({
        authority,
        provisioning: old,
        acceptedAt: now(),
        retainedRecords: {},
      });
      trust = await openPostgresTrust({
        store: control,
        authority,
        provisioning: old,
      });
      stale = await openPostgresTrust({
        store: control,
        authority,
        provisioning: old,
      });
      const policy = new ActionPolicy(config.policy),
        session = config.policy.sessions[0].id;
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
      const actions = () =>
        new ActionStore(runtime, policy, authorize, trust.controlFence());
      const commands = {};
      for (const id of [
        "stale",
        "publication-wins",
        "dispatch-wins",
        "claim-race",
      ]) {
        const proposed = await actions().propose(agent, {
          id,
          session,
          target: "internal",
          tool: "lookup",
          arguments: { synthetic: true },
          expiresAt: now() + 240,
        });
        commands[id] = { id, session, digest: proposed.proposal.digest };
        await actions().decide(
          human,
          session,
          id,
          proposed.proposal.digest,
          "approve",
        );
      }
      let effects = 0;
      function startEffect(id, pauseBefore) {
        const entered = gate(),
          resume = gate();
        resumes.push(resume);
        const connector = {
          call: async (_action, { beforeSend, dispatch }) => {
            let sent = false;
            try {
              assert.equal(await beforeSend(), true);
              if (pauseBefore) {
                entered.resolve();
                await resume.promise;
              }
              return await dispatch(() => {
                sent = true;
                effects++;
                if (!pauseBefore) entered.resolve();
                return (pauseBefore ? Promise.resolve() : resume.promise).then(
                  () => ({ synthetic: true }),
                );
              });
            } catch {
              throw new ConnectorFailure(sent);
            }
          },
        };
        const result = createActionExecutor(policy, connector, () =>
          trust.controlFence(),
        )(agent, commands[id], { store: actions(), authorize });
        running.push(result);
        return { entered, resume, result };
      }
      const sent = startEffect("dispatch-wins", false);
      await Promise.race([
        sent.entered.promise,
        sent.result.then(() => {
          throw new Error("effect did not enter");
        }),
      ]);
      const paused = startEffect("publication-wins", true);
      await Promise.race([
        paused.entered.promise,
        paused.result.then(() => {
          throw new Error("effect did not pause");
        }),
      ]); // Exact gap after successful asynchronous head check.
      const checked = gate(),
        resumeClaim = gate();
      resumes.push(resumeClaim);
      const racing = new ActionStore(
        runtime,
        policy,
        async (p, c) => {
          checked.resolve();
          await resumeClaim.promise;
          return authorize(p, c);
        },
        trust.controlFence(),
      );
      const claim = racing.claim(
        agent,
        session,
        "claim-race",
        commands["claim-race"].digest,
      );
      const denied = assert.rejects(
        claim,
        (e) => e instanceof PolicyDenied || e instanceof StoreUnavailable,
      );
      running.push(denied);
      await checked.promise;
      const publication = trust.updateAsync(fresh(2, true));
      running.push(publication);
      let waiting = false;
      for (let i = 0; i < 150; i++) {
        const result = await pool.query(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name='xeip-control-fence-fixture' AND wait_event_type='Lock' AND query LIKE '%control_head%FOR UPDATE%'",
        );
        if (result.rows[0].n) {
          waiting = true;
          break;
        }
        await delay(10);
      }
      assert.equal(
        waiting,
        true,
        "publisher must wait for the action control-head lock",
      );
      assert.equal(
        Number(
          (await pool.query("SELECT revision FROM xeip_org.control_head"))
            .rows[0].revision,
        ),
        1,
      );
      resumeClaim.resolve();
      await denied;
      await publication;
      paused.resume.resolve();
      sent.resume.resolve();
      assert.equal((await paused.result).state, "failed");
      assert.equal((await sent.result).state, "succeeded");
      assert.equal(
        effects,
        1,
        "only the invocation preceding publication reaches a synthetic effect",
      );
      assert.equal(
        stale.allows(agent),
        true,
        "separate stale cache is still cryptographically valid",
      );
      const staleStore = new ActionStore(
        runtime,
        policy,
        async () => true,
        stale.controlFence(),
      );
      await assert.rejects(
        staleStore.claim(agent, session, "stale", commands.stale.digest),
        StoreConflict,
      );
      const rows = (
        await pool.query(
          "SELECT request_id,state,claim_id FROM xeip_org.actions ORDER BY request_id",
        )
      ).rows;
      assert.deepEqual(
        rows.map((r) => [r.request_id, r.state, !!r.claim_id]),
        [
          ["claim-race", "approved", false],
          ["dispatch-wins", "succeeded", true],
          ["publication-wins", "failed", true],
          ["stale", "approved", false],
        ],
      );
      // Isolated ledger check proves consumed claims cannot be acquired again even
      // with a permissive authorizer; production is always composed with the fence.
      for (const id of ["dispatch-wins", "publication-wins"])
        await assert.rejects(
          new ActionStore(runtime, policy, async () => true).claim(
            agent,
            session,
            id,
            commands[id].digest,
          ),
          StoreConflict,
        );
      console.log(
        JSON.stringify({
          result: "pass",
          actions: 4,
          consumedClaims: 2,
          syntheticEffects: effects,
          staleCacheRefused: true,
          publicationWaitsForAction: true,
          scope:
            "actual restricted PostgreSQL and runtime/executor; provider and tool effect synthetic; owner lease and physical recovery remain open",
        }),
      );
    } finally {
      for (const resume of resumes) resume.resolve();
      await Promise.allSettled(running);
      trust?.close();
      stale?.close();
      await runtime.end();
    }
  },
  { baselineChecks: false },
);
