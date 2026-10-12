/** TEST ONLY. Synthetic authority and SQL controls. Never deploy this worker. */
import { DurableObject } from "cloudflare:workers";
import { initializeLedger } from "../services/organization/cloudflare/schema.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { ConnectorFailure } from "../services/organization/errors.mjs";
const agent =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const human =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const policy = (blocked = false) =>
  new ActionPolicy({
    targets: [
      { id: "internal", revision: "1", recipient: agent, tools: ["lookup"] },
    ],
    sessions: [
      {
        id: "operations",
        agents: ["agent"],
        approvers: blocked ? [] : ["human", "agent", "entity-clone"],
        targets: ["internal"],
      },
    ],
  });
function principal(name, expiresAt, clientId = "fixture-client") {
  const roles =
    name === "agent"
      ? ["agent"]
      : name === "self"
        ? ["agent", "approver"]
        : ["approver"];
  const entity = ["agent", "self", "entity-clone"].includes(name)
    ? agent
    : human;
  return Object.freeze({
    subject: name === "self" ? "agent" : name,
    entity,
    kid: entity.slice(16),
    clientId,
    roles: Object.freeze(roles),
    expiresAt: expiresAt ?? Math.floor(Date.now() / 1000) + 600,
  });
}
export class LedgerFixture extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    initializeLedger(ctx.storage, "fixture-organization");
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS fixture_authority(singleton INTEGER PRIMARY KEY,revision INTEGER NOT NULL,revoked TEXT NOT NULL,blocked INTEGER NOT NULL); INSERT OR IGNORE INTO fixture_authority VALUES (1,1,'[]',0)",
    );
    this.control = {
      allowed: true,
      hold: null,
      entered: 0,
      holdSync: false,
      syncEntered: 0,
      fault: null,
      effects: 0,
      maxActions: 10000,
      timeoutMs: 10000,
      effectFailure: false,
      readCorruption: null,
      orphanAudit: false,
    };
    this.policy = policy(!!this.authorityRow().blocked);
    this.storage = {
      sql: {
        exec: (query, ...bindings) => {
          if (
            query.startsWith("INSERT INTO xeip_audit") &&
            (this.control.fault === "audit" ||
              (this.control.fault === "finish-audit" &&
                ["succeeded", "failed", "indeterminate"].includes(bindings[3])))
          ) {
            this.control.fault = null;
            throw Error("injected audit storage failure");
          }
          if (
            this.control.orphanAudit &&
            query.startsWith("SELECT 1 FROM xeip_audit e LEFT JOIN")
          )
            return { toArray: () => [{ orphan: 1 }] };
          const cursor = ctx.storage.sql.exec(query, ...bindings);
          if (
            this.control.readCorruption &&
            query.startsWith("SELECT * FROM xeip_actions")
          )
            return {
              toArray: () =>
                cursor
                  .toArray()
                  .map((row) => ({ ...row, ...this.control.readCorruption })),
            };
          return cursor;
        },
      },
      transactionSync: (callback) => ctx.storage.transactionSync(callback),
      sync: async () => {
        await ctx.storage.sync();
        this.control.syncEntered++;
        while (this.control.holdSync)
          await new Promise((resolve) => setTimeout(resolve, 10));
        if (this.control.fault === "sync") {
          this.control.fault = null;
          throw Error("injected uncertain synchronization");
        }
      },
    };
    this.authority = {
      revision: () => String(this.authorityRow().revision),
      policy: () => this.policy,
      allows: (p) => !JSON.parse(this.authorityRow().revoked).includes(p.kid),
      authorize: async (p, context) => {
        this.control.entered++;
        while (this.control.hold === context.phase)
          await new Promise((resolve) => setTimeout(resolve, 10));
        return this.control.allowed;
      },
    };
    this.openStore();
  }
  authorityRow() {
    return this.ctx.storage.sql
      .exec("SELECT * FROM fixture_authority WHERE singleton=1")
      .toArray()[0];
  }
  openStore() {
    this.store = new DurableActionStore(this.storage, this.authority, {
      organization: "fixture-organization",
      maxActions: this.control.maxActions,
      timeoutMs: this.control.timeoutMs,
    });
  }
  async fetch(request) {
    const input = await request.json();
    try {
      if (input.operation === "initialize") {
        initializeLedger(this.ctx.storage, input.organization);
        return Response.json({ ok: true });
      }
      if (input.operation === "sql")
        return Response.json({
          rows: this.ctx.storage.sql
            .exec(input.query, ...(input.bindings ?? []))
            .toArray(),
        });
      if (input.operation === "controls") {
        if (Object.hasOwn(input, "clock")) {
          if (
            input.clock !== null &&
            (!Number.isSafeInteger(input.clock) || input.clock < 0)
          )
            throw new TypeError("invalid fixture clock");
          globalThis.__xeipFixtureClock = input.clock;
        }
        for (const name of [
          "allowed",
          "hold",
          "holdSync",
          "fault",
          "maxActions",
          "timeoutMs",
          "effectFailure",
          "readCorruption",
          "orphanAudit",
        ])
          if (Object.hasOwn(input, name)) this.control[name] = input[name];
        if (input.bump || input.revoked || Object.hasOwn(input, "blocked")) {
          const previous = this.authorityRow();
          this.ctx.storage.sql.exec(
            "UPDATE fixture_authority SET revision=revision+1,revoked=?,blocked=? WHERE singleton=1",
            JSON.stringify(input.revoked ?? JSON.parse(previous.revoked)),
            input.blocked === undefined
              ? previous.blocked
              : Number(input.blocked),
          );
          this.policy = policy(!!this.authorityRow().blocked);
        }
        if (input.reopen) this.openStore();
        return Response.json({
          ...this.control,
          revision: this.authorityRow().revision,
        });
      }
      if (input.operation === "actionSnapshot")
        return Response.json(this.store.actionSnapshot(input.cut));
      if (input.operation === "actionPage")
        return Response.json(this.store.actionPage(input.cut, input.after));
      const bound = principal(
        input.principal,
        input.principalExpires,
        input.principalClientId,
      );
      const p = input.mutable ? { ...bound, roles: [...bound.roles] } : bound;
      let result;
      if (input.operation === "propose")
        result = await this.store.propose(p, input.request);
      else if (input.operation === "inspect")
        result = await this.store.inspect(p, input.session, input.id);
      else if (input.operation === "decide")
        result = await this.store.decide(
          p,
          input.session,
          input.id,
          input.digest,
          input.decision,
        );
      else if (input.operation === "revoke")
        result = await this.store.revoke(
          p,
          input.session,
          input.id,
          input.digest,
        );
      else if (input.operation === "claim")
        result = await this.store.claim(
          p,
          input.session,
          input.id,
          input.digest,
        );
      else if (input.operation === "finish")
        result = await this.store.finish(
          input.session,
          input.id,
          input.claimId,
          input.outcome,
          input.result,
        );
      else if (input.operation === "execute") {
        const executor = createActionExecutor(this.policy, {
          call: async (action, { beforeSend }) => {
            if (!(await beforeSend())) throw new ConnectorFailure(false);
            this.control.effects++;
            if (this.control.effectFailure) throw new ConnectorFailure(true);
            return { content: [{ type: "text", text: "fixture result" }] };
          },
        });
        result = await executor(p, input, {
          store: this.store,
          authorize: async (principal, context) => {
            const revision = this.authority.revision();
            const allowed = await this.authority.authorize(principal, context);
            return (
              allowed &&
              revision === this.authority.revision() &&
              this.authority.allows(principal) &&
              !!context.approver &&
              this.authority.allows(context.approver) &&
              this.policy.canExecute(principal, context.proposal) &&
              this.policy.canApprove(context.approver, context.proposal)
            );
          },
        });
      } else
        return Response.json({ error: "not_implemented" }, { status: 501 });
      return Response.json(result);
    } catch (error) {
      return Response.json({ error: error.name }, { status: 409 });
    }
  }
}
// Deliberately no public ingress, even for this local harness.
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
};
