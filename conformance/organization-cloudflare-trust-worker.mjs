/** TEST ONLY. Privileged SQL and synthetic controls; never deploy. */
import { DurableObject } from "cloudflare:workers";
import { initializeLedger } from "../services/organization/cloudflare/schema.mjs";
import { initializeLedger as initializeV5 } from "./fixtures/cloudflare/schema-v5.mjs";
import { initializeLedger as initializeV1 } from "./fixtures/cloudflare/schema-v1.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { DurableEntityTrust } from "../services/organization/cloudflare/trust.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { ConnectorFailure } from "../services/organization/errors.mjs";
const agent =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const human =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const organization = "trust-fixture";
export class TrustFixture extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.control = {
      holdSync: false,
      syncEntered: 0,
      fault: null,
      holdProvider: null,
      providerEntered: 0,
      effects: 0,
    };
    this.trustStorage = {
      sql: {
        exec: (query, ...bindings) => {
          if (
            this.control.fault === "trust-write" &&
            query.startsWith("UPDATE xeip_trust_state")
          ) {
            this.control.fault = null;
            throw Error("injected trust write failure");
          }
          if (
            this.control.fault === "chunk-migration" &&
            query.includes("CREATE TABLE xeip_trust_chunks")
          ) {
            ctx.storage.sql.exec(query, ...bindings);
            this.control.chunkMigrationApplied =
              ctx.storage.sql
                .exec(
                  "SELECT COUNT(*) AS count FROM sqlite_master WHERE name IN ('xeip_trust_chunks','xeip_trust_chunk_new','xeip_trust_chunk_update','xeip_trust_chunk_delete')",
                )
                .toArray()[0].count === 4;
            this.control.fault = null;
            throw Error("injected chunk migration failure");
          }
          if (
            this.control.fault === "chunk-write" &&
            query.startsWith("INSERT INTO xeip_trust_chunks")
          ) {
            this.control.fault = null;
            throw Error("injected chunk write failure");
          }
          return ctx.storage.sql.exec(query, ...bindings);
        },
      },
      transactionSync: (callback) => ctx.storage.transactionSync(callback),
      sync: async () => {
        await ctx.storage.sync();
        this.control.syncEntered++;
        while (this.control.holdSync)
          await new Promise((resolve) => setTimeout(resolve, 10));
        if (this.control.fault === "trust-sync") {
          this.control.fault = null;
          throw Error("injected trust sync failure");
        }
      },
    };
    this.policy = new ActionPolicy({
      targets: [
        { id: "internal", revision: "1", recipient: agent, tools: ["lookup"] },
      ],
      sessions: [
        {
          id: "operations",
          agents: ["agent"],
          approvers: ["human"],
          targets: ["internal"],
        },
      ],
    });
    this.authorize = async (principal, context) => {
      const revision = this.trust.revision();
      this.control.providerEntered++;
      while (this.control.holdProvider === context.phase)
        await new Promise((resolve) => setTimeout(resolve, 10));
      return (
        revision === this.trust.revision() &&
        this.trust.allows(principal) &&
        (!context.approver || this.trust.allows(context.approver))
      );
    };
  }
  async fetch(request) {
    try {
      const input = await request.json(),
        storage = this.ctx.storage;
      if (input.operation === "controls") {
        for (const name of ["holdSync", "fault", "holdProvider"])
          if (Object.hasOwn(input, name)) this.control[name] = input[name];
        return Response.json({
          ...this.control,
          revision: this.trust?.revision(),
        });
      }
      if (input.operation === "trust-open") {
        this.trust?.close();
        this.trust = undefined;
        this.trust = await DurableEntityTrust.open(this.trustStorage, {
          organization,
          configuration: input.configuration,
          initialize: input.initialize,
          timeoutMs: input.timeoutMs,
        });
        this.ledger = new DurableActionStore(
          storage,
          {
            revision: () => this.trust.revision() + ":" + this.policy.revision,
            policy: () => this.policy,
            allows: (p) => this.trust.allows(p),
            authorize: this.authorize,
          },
          { organization },
        );
        return Response.json(this.trust.status());
      }
      if (input.operation === "initialize-v5") {
        initializeV5(storage, organization);
        return Response.json({ ok: true });
      }
      if (input.operation === "trust-update") {
        if (
          Number.isInteger(input.signatureCopies) &&
          input.signatureCopies > 0 &&
          input.signatureCopies <= 50000
        ) {
          const signature =
            input.provisioning.keyDocuments[0].document.signatures[0];
          input.provisioning.keyDocuments[0].document.signatures = Array.from(
            { length: input.signatureCopies },
            () => ({ ...signature }),
          );
        }
        return Response.json(await this.trust.update(input.provisioning));
      }
      if (input.operation === "trust-update-mutate") {
        const pending = this.trust.update(input.provisioning);
        input.provisioning.statusDocuments[0].document.revoked.push({
          kid: input.kid,
          generation: 1,
        });
        return Response.json(await pending);
      }
      if (input.operation === "trust-allows")
        return Response.json({ allowed: this.trust.allows(input.principal) });
      if (input.operation === "trust-verify")
        return Response.json(this.trust.verify(input.envelope));
      if (input.operation === "trust-status")
        return Response.json(this.trust.status());
      if (input.operation === "trust-checkpoint")
        return Response.json(this.trust.checkpoint());
      if (input.operation === "trust-close") {
        this.trust.close();
        return Response.json(this.trust.status());
      }
      if (input.operation === "ledger") {
        const isAgent = input.principal === "agent",
          entity = isAgent ? agent : human;
        const principal = Object.freeze({
          subject: isAgent ? "agent" : "human",
          entity,
          kid: entity.slice(16),
          roles: Object.freeze([isAgent ? "agent" : "approver"]),
          clientId: "fixture",
          expiresAt: Math.floor(Date.now() / 1000) + 300,
        });
        let result;
        if (input.method === "propose")
          result = await this.ledger.propose(principal, input.request);
        else if (input.method === "decide")
          result = await this.ledger.decide(
            principal,
            input.session,
            input.id,
            input.digest,
            "approve",
          );
        else if (input.method === "claim")
          result = await this.ledger.claim(
            principal,
            input.session,
            input.id,
            input.digest,
          );
        else if (input.method === "finish")
          result = await this.ledger.finish(
            input.session,
            input.id,
            input.claimId,
            "succeeded",
            { ok: true },
          );
        else if (input.method === "execute") {
          const execute = createActionExecutor(this.policy, {
            call: async (action, { beforeSend }) => {
              if (!(await beforeSend())) throw new ConnectorFailure(false);
              this.control.effects++;
              return { ok: true };
            },
          });
          result = await execute(principal, input, {
            store: this.ledger,
            authorize: this.authorize,
          });
        }
        return Response.json(result);
      }
      if (input.operation === "sql")
        return Response.json({
          rows: storage.sql
            .exec(input.query, ...(input.bindings ?? []))
            .toArray(),
        });
      if (input.operation === "initialize") {
        const migrationStorage = input.failMigration
          ? {
              sql: {
                exec: (query, ...bindings) => {
                  const result = storage.sql.exec(query, ...bindings);
                  if (query.includes("CREATE TABLE xeip_trust_state"))
                    throw Error("injected migration fault");
                  return result;
                },
              },
              transactionSync: (callback) => storage.transactionSync(callback),
              sync: () => storage.sync(),
            }
          : storage;
        initializeLedger(migrationStorage, organization);
        await storage.sync();
        return Response.json({ ok: true });
      }
      if (input.operation === "initialize-v1") {
        initializeV1(storage, organization);
        const policy = new ActionPolicy({
          targets: [
            {
              id: "internal",
              revision: "1",
              recipient: agent,
              tools: ["lookup"],
            },
          ],
          sessions: [
            {
              id: "operations",
              agents: ["agent"],
              approvers: ["human"],
              targets: ["internal"],
            },
          ],
        });
        const expiresAt = Math.floor(Date.now() / 1000) + 300;
        const principal = {
          subject: "agent",
          entity: agent,
          kid: agent.slice(16),
          roles: ["agent"],
          clientId: "fixture",
          expiresAt,
        };
        const proposal = policy.propose(principal, {
          id: "preserved",
          session: "operations",
          target: "internal",
          tool: "lookup",
          arguments: { value: 1 },
          expiresAt,
        });
        const grant = {
          subject: "human",
          entity: human,
          kid: human.slice(16),
          roles: ["approver"],
          clientId: "fixture",
          expiresAt,
        };
        const claimId = crypto.randomUUID();
        storage.transactionSync(() => {
          storage.sql.exec(
            "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) VALUES ('operations','preserved',?,?,?,'pending')",
            proposal.digest,
            canonicalize(proposal.action),
            expiresAt,
          );
          for (const [event, query, args] of [
            ["proposed", null, []],
            [
              "approved",
              "UPDATE xeip_actions SET state='approved',version=1,approver=?,approval_expires_at=?",
              [canonicalize(grant), expiresAt],
            ],
            [
              "claimed",
              "UPDATE xeip_actions SET state='executing',version=2,claim_id=?",
              [claimId],
            ],
          ]) {
            if (query) storage.sql.exec(query, ...args);
            storage.sql.exec(
              "INSERT INTO xeip_audit(session_id,request_id,digest,event,actor,occurred_at) VALUES ('operations','preserved',?,?,'{}',?)",
              proposal.digest,
              event,
              Math.floor(Date.now() / 1000),
            );
          }
        });
        await storage.sync();
        return Response.json({ proposal, claimId });
      }
      return Response.json({ error: "not_implemented" }, { status: 501 });
    } catch (error) {
      return Response.json({ error: error.name }, { status: 409 });
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
};
