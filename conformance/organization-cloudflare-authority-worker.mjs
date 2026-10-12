/** TEST ONLY: unrestricted private SQL and fault controls. Never deploy. */
import { initializeLedger as initializeV2 } from "./fixtures/cloudflare/schema-v2.mjs";
import { DurableObject } from "cloudflare:workers";
import { DurableEntityTrust } from "../services/organization/cloudflare/trust.mjs";
import { DurableOrganizationAuthority } from "../services/organization/cloudflare/authority.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
import { OrganizationController } from "../services/organization/controller.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { ConnectorFailure } from "../services/organization/errors.mjs";
export class AuthorityFixture extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.principals = new Map();
    this.control = {
      fault: null,
      holdSync: false,
      syncEntered: 0,
      denyGuard: false,
      effects: 0,
      holdPhase: null,
      phaseEntered: 0,
      holdEffect: false,
      holdAfterEffect: false,
      effectEntered: 0,
      historyRows: 0,
    };
    this.storage = {
      sql: {
        exec: (query, ...bindings) => {
          if (
            this.control.fault === "ledger" &&
            query.startsWith("INSERT INTO xeip_actions")
          ) {
            this.control.fault = null;
            throw Error("injected ledger write failure");
          }
          if (
            this.control.fault === "write" &&
            query.startsWith("UPDATE xeip_authority_state")
          ) {
            this.control.fault = null;
            throw Error("injected write failure");
          }
          const cursor = ctx.storage.sql.exec(query, ...bindings);
          return {
            toArray: () => {
              const rows = cursor.toArray();
              if (query.includes("FROM xeip_authority_events"))
                this.control.historyRows += rows.length;
              return rows;
            },
          };
        },
      },
      transactionSync: (fn) => ctx.storage.transactionSync(fn),
      sync: async () => {
        await ctx.storage.sync();
        this.control.syncEntered++;
        while (this.control.holdSync)
          await new Promise((r) => setTimeout(r, 10));
        if (this.control.fault === "sync") {
          this.control.fault = null;
          throw Error("injected sync failure");
        }
      },
    };
  }
  async fetch(request) {
    try {
      const input = await request.json();
      if (input.operation === "seed-v2") {
        initializeV2(this.ctx.storage, "authority-fixture");
        const sql = this.ctx.storage.sql;
        this.ctx.storage.transactionSync(() => {
          for (const checkpoint of input.checkpoints)
            sql.exec(
              "INSERT INTO xeip_trust_checkpoints(entity,anchor,generation,key_digest,serial,status_digest) VALUES (?,?,?,?,?,?)",
              checkpoint.entity,
              checkpoint.anchor,
              checkpoint.generation,
              checkpoint.key_digest,
              checkpoint.serial,
              checkpoint.status_digest,
            );
          const trust = input.trust;
          sql.exec(
            "INSERT INTO xeip_trust_state(singleton,configuration,provisioning,revision,accepted_at,checkpoints_digest,checksum) VALUES (1,?,?,0,?,?,?)",
            trust.configuration,
            trust.provisioning,
            trust.accepted_at,
            trust.checkpoints_digest,
            trust.checksum,
          );
          if (trust.revision === 1)
            sql.exec("UPDATE xeip_trust_state SET revision=1");
          const a = input.action;
          sql.exec(
            "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) VALUES (?,?,?,?,?,'pending')",
            a.session_id,
            a.request_id,
            a.digest,
            a.canonical,
            a.expires_at,
          );
          sql.exec(
            "UPDATE xeip_actions SET state='approved',version=1,approver=?,approval_expires_at=?",
            a.approver,
            a.approval_expires_at,
          );
          sql.exec(
            "UPDATE xeip_actions SET state='executing',version=2,claim_id=?",
            a.claim_id,
          );
          sql.exec(
            "UPDATE xeip_actions SET state='succeeded',version=3,result_canonical=?",
            a.result_canonical,
          );
          for (const row of input.audit)
            sql.exec(
              "INSERT INTO xeip_audit(sequence,session_id,request_id,digest,event,actor,occurred_at) VALUES (?,?,?,?,?,?,?)",
              row.sequence,
              row.session_id,
              row.request_id,
              row.digest,
              row.event,
              row.actor,
              row.occurred_at,
            );
        });
        await this.ctx.storage.sync();
        return Response.json({ ok: true });
      }
      if (input.operation === "sql")
        return Response.json({
          rows: this.ctx.storage.sql
            .exec(input.query, ...(input.bindings ?? []))
            .toArray(),
        });
      if (input.operation === "controls") {
        for (const key of [
          "fault",
          "holdSync",
          "holdPhase",
          "holdEffect",
          "holdAfterEffect",
          "denyGuard",
          "historyRows",
        ])
          if (Object.hasOwn(input, key)) this.control[key] = input[key];
        return Response.json({
          ...this.control,
          authority: this.authority?.status(),
        });
      }
      if (input.operation === "open") {
        this.authority?.close();
        this.trust?.close();
        this.trust = await DurableEntityTrust.open(this.ctx.storage, {
          organization: "authority-fixture",
          configuration: { maxAgeSeconds: 300 },
          initialize: input.initializeTrust ?? false,
        });
        if (input.provisioning) await this.trust.update(input.provisioning);
        this.authority = await DurableOrganizationAuthority.open(this.storage, {
          organization: "authority-fixture",
          trust: this.trust,
          introspectionClientSecret: input.secret,
          initialize: input.configuration,
          timeoutMs: input.timeoutMs,
        });
        this.ledger = new DurableActionStore(this.storage, this.authority, {
          organization: "authority-fixture",
        });
        const authority = this.authority;
        const guarded = async (p, c) => {
          this.control.phaseEntered++;
          while (this.control.holdPhase === c.phase)
            await new Promise((r) => setTimeout(r, 10));
          return authority.authorize(p, c);
        };
        const connector = {
          call: async (action, { beforeSend }) => {
            this.control.effectEntered++;
            while (this.control.holdEffect)
              await new Promise((r) => setTimeout(r, 10));
            if (!(await beforeSend())) throw new ConnectorFailure(false);
            this.control.effects++;
            while (this.control.holdAfterEffect)
              await new Promise((r) => setTimeout(r, 10));
            return { ok: true };
          },
        };
        this.gateway = input.gateway ?? this.gateway;
        this.controller = new OrganizationController({
          authentication: authority,
          trust: this.trust,
          gateway: this.gateway,
          createStore: (requestGuard) =>
            this.ledger.withAuthorization(
              async (p, c) =>
                (await guarded(p, c)) &&
                !this.control.denyGuard &&
                (await requestGuard(p, c)),
            ),
          execute: (p, c, context) =>
            createActionExecutor(authority.policy(), connector)(p, c, {
              ...context,
              authorize: async (p, c) =>
                (await guarded(p, c)) && (await context.authorize(p, c)),
            }),
        });
        return Response.json(this.authority.status());
      }
      if (input.operation === "controller")
        return Response.json(
          await this.controller.handle(input.header, input.envelope),
        );
      if (input.operation === "batch-update") {
        for (let i = 0; i < input.count; i++)
          await this.authority.update(input.configuration, {
            expectedRevision: this.authority.status().revision,
          });
        return Response.json(this.authority.status());
      }
      if (input.operation === "update")
        return Response.json(
          await this.authority.update(input.configuration, {
            expectedRevision: input.expectedRevision,
          }),
        );
      if (input.operation === "checkpoint")
        return Response.json(this.authority.checkpoint());
      if (input.operation === "history-page")
        return Response.json(
          this.authority.historyPage(input.checkpoint, input.cursor),
        );
      if (input.operation === "history-page-at")
        return Response.json(
          this.authority.historyPageAt(input.checkpoint, input.cursor),
        );
      if (input.operation === "capture-reader") {
        const captured = this.authority.captureHistoryReader();
        this.reader = captured.reader;
        return Response.json(captured.checkpoint);
      }
      if (input.operation === "history-reader") {
        this.reader = this.authority.historyReaderAt(input.checkpoint);
        return Response.json({ ok: true });
      }
      if (input.operation === "reader-page")
        return Response.json(this.reader.page(input.cursor));
      if (input.operation === "reader-close") {
        this.reader.close();
        return Response.json({ ok: true });
      }
      if (input.operation === "trust-update")
        return Response.json(await this.trust.update(input.provisioning));
      if (input.operation === "close") {
        this.authority.close();
        return Response.json(this.authority.status());
      }
      if (input.operation === "authenticate") {
        const principal = await this.authority.authenticate(input.header);
        if (principal)
          this.principals.set(input.name ?? "principal", principal);
        return Response.json({ principal });
      }
      if (input.operation === "revalidate") {
        const principal = this.principals.get(input.name ?? "principal");
        return Response.json({
          allowed: await this.authority.revalidate(
            input.clone ? { ...principal } : principal,
          ),
        });
      }
      if (input.operation === "release") {
        this.authority.release(this.principals.get(input.name ?? "principal"));
        return Response.json({ ok: true });
      }
      return Response.json({ error: "unknown operation" }, { status: 400 });
    } catch (error) {
      return Response.json(
        { error: error.name, status: error.status },
        { status: 500 },
      );
    }
  }
}
export default {
  fetch() {
    return new Response("Not found", { status: 404 });
  },
};
