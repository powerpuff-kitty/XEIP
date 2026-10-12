/** TEST ONLY: private lifecycle/storage controls. Never deploy. */
import { OrganizationService } from "../services/organization/cloudflare/service.mjs";
import { DurableObject } from "cloudflare:workers";
import { initializeLedger } from "../services/organization/cloudflare/schema.mjs";
import { initializeLedger as initializeV3 } from "./fixtures/cloudflare/schema-v3.mjs";
export class LifecycleFixture extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.instanceId = crypto.randomUUID();
    this.control = {
      syncs: 0,
      failSync: 0,
      failQuery: null,
      holdSync: 0,
      administrativeRows: 0,
      authorityRows: 0,
    };
    this.storage = {
      sql: {
        exec: (query, ...bindings) => {
          if (
            this.control.failQuery &&
            query.startsWith(this.control.failQuery)
          )
            throw Error("injected SQL failure");
          const cursor = ctx.storage.sql.exec(query, ...bindings);
          return {
            toArray: () => {
              const rows = cursor.toArray();
              if (query.includes("FROM xeip_owner_events"))
                this.control.administrativeRows += rows.length;
              if (query.includes("FROM xeip_authority_events"))
                this.control.authorityRows += rows.length;
              return rows;
            },
          };
        },
      },
      transactionSync: (fn) => {
        const outer = !this.transactionDepth;
        if (outer && this.control.failTransaction === "before")
          throw Error("injected transaction failure");
        this.transactionDepth = (this.transactionDepth ?? 0) + 1;
        try {
          const result = ctx.storage.transactionSync(fn);
          if (outer && this.control.failTransaction === "after")
            throw Error("injected ambiguous transaction failure");
          return result;
        } finally {
          this.transactionDepth--;
        }
      },
      sync: async () => {
        this.control.syncs++;
        const n = this.control.syncs;
        await ctx.storage.sync();
        while (this.control.holdSync === n)
          await new Promise((r) => setTimeout(r, 5));
        if (this.control.failSync === n) throw Error("injected sync failure");
      },
    };
  }
  async fetch(request) {
    const input = await request.json();
    try {
      const recoveryCall = async (value) => {
        const namespace = this.env.JOURNAL;
        const stub = namespace.get(
          namespace.idFromName(this.ctx.id.toString()),
        );
        const response = await stub.fetch("https://journal.invalid/", {
          method: "POST",
          body: JSON.stringify(value),
        });
        const body = await response.json();
        if (response.status !== 200) throw Error("journal unavailable");
        return body;
      };
      if (input.operation === "recoveryJournal")
        return Response.json(await recoveryCall(input.value));
      if (input.operation === "open") {
        this.service?.close();
        this.service = await OrganizationService.open(
          this.storage,
          input.configuration,
          input.recovery
            ? {
                options: input.recovery,
                client: {
                  head: () => recoveryCall({ operation: "head" }),
                  entry: (sequence) =>
                    recoveryCall({ operation: "entry", sequence }),
                  append: (value) =>
                    recoveryCall({ operation: "append", value }),
                },
              }
            : undefined,
        );
        return Response.json(this.service.status());
      }
      if (input.operation === "pollTrustFeed")
        return Response.json({ outcome: await this.service.pollTrustFeed() });
      if (input.operation === "manage")
        return Response.json(
          await this.service.manage(input.raw, input.operator),
        );
      if (input.operation === "initialize")
        return Response.json(
          await this.service.initialize(input.configuration),
        );
      if (input.operation === "refresh")
        return Response.json(
          await this.service.refreshTrust(input.provisioning, {
            expectedRevision: input.expectedRevision,
          }),
        );
      if (input.operation === "update")
        return Response.json(
          await this.service.updateAuthority(input.configuration, {
            expectedRevision: input.expectedRevision,
          }),
        );
      if (input.operation === "status")
        return Response.json(this.service.status());
      if (input.operation === "lifecycleCheckpoint")
        return Response.json(await this.service.lifecycleCheckpoint());
      if (input.operation === "recoveryCheckpoint")
        return Response.json(await this.service.recoveryCheckpoint());
      if (input.operation === "exportBegin")
        return Response.json(
          await this.service.beginRecoveryExport(input.operator),
        );
      if (input.operation === "exportPart")
        return Response.json(
          this.service.recoveryExportPart(
            input.operator,
            input.exportId,
            input.component,
            input.index,
          ),
        );
      if (input.operation === "exportPage")
        return Response.json(
          await this.service.recoveryExportPage(
            input.operator,
            input.exportId,
            input.options,
          ),
        );
      if (input.operation === "exportClose") {
        this.service.closeRecoveryExport(input.operator, input.exportId);
        return Response.json({ ok: true });
      }
      if (input.operation === "recoveryPage")
        return Response.json(
          this.service.recoveryPage(input.manifest, input.options),
        );
      if (input.operation === "ready")
        return Response.json({ ready: await this.service.ready() });
      if (input.operation === "close") {
        this.service.close();
        return Response.json(this.service.status());
      }
      if (input.operation === "http") {
        const response = await this.service.fetch(
          new Request(input.url ?? "https://xeip.example/v1/actions", {
            method: input.method ?? "POST",
            headers: input.headers ?? { "content-type": "application/json" },
            ...(input.method === "GET" ? {} : { body: input.body ?? "{}" }),
          }),
          { waitUntil: (p) => this.ctx.waitUntil(p) },
        );
        return Response.json({
          status: response.status,
          body: await response.json(),
        });
      }
      if (input.operation === "schema") {
        initializeLedger(this.storage, "lifecycle-fixture");
        return Response.json({ ok: true });
      }
      if (input.operation === "seed-v3") {
        initializeV3(this.storage, "lifecycle-fixture");
        const insert = (table, row) =>
          this.ctx.storage.sql.exec(
            "INSERT INTO " +
              table +
              "(" +
              Object.keys(row).join(",") +
              ") VALUES (" +
              Object.keys(row)
                .map(() => "?")
                .join(",") +
              ")",
            ...Object.values(row),
          );
        this.ctx.storage.transactionSync(() => {
          for (const row of input.rows.xeip_trust_checkpoints)
            insert("xeip_trust_checkpoints", row);
          for (const row of input.rows.xeip_trust_state) {
            insert("xeip_trust_state", { ...row, revision: 0 });
            for (let rev = 1; rev <= row.revision; rev++)
              this.ctx.storage.sql.exec(
                "UPDATE xeip_trust_state SET revision=?",
                rev,
              );
          }
          for (const row of input.rows.xeip_authority_state)
            insert("xeip_authority_state", row);
          for (const row of input.rows.xeip_authority_events)
            insert("xeip_authority_events", row);
          for (const row of input.rows.xeip_actions) {
            insert("xeip_actions", {
              ...row,
              state: "pending",
              version: 0,
              approver: null,
              approval_expires_at: null,
              claim_id: null,
              result_canonical: null,
            });
            this.ctx.storage.sql.exec(
              "UPDATE xeip_actions SET state='approved',version=1,approver=?,approval_expires_at=?",
              row.approver,
              row.approval_expires_at,
            );
            this.ctx.storage.sql.exec(
              "UPDATE xeip_actions SET state='executing',version=2,claim_id=?",
              row.claim_id,
            );
            this.ctx.storage.sql.exec(
              "UPDATE xeip_actions SET state='succeeded',version=3,result_canonical=?",
              row.result_canonical,
            );
          }
          for (const row of input.rows.xeip_audit) insert("xeip_audit", row);
        });
        await this.ctx.storage.sync();
        return Response.json({ ok: true });
      }
      if (input.operation === "v3") {
        initializeV3(this.storage, "lifecycle-fixture");
        return Response.json({ ok: true });
      }
      if (input.operation === "seedAdministration") {
        this.ctx.storage.transactionSync(() => {
          for (const row of input.records)
            this.ctx.storage.sql.exec(
              "INSERT INTO xeip_owner_events(sequence,attempt_id,outcome,canonical,previous,checksum) VALUES(?,?,?,?,?,?)",
              row.sequence,
              row.event.attemptId,
              row.event.outcome,
              row.canonical,
              row.previous,
              row.checksum,
            );
        });
        await this.ctx.storage.sync();
        return Response.json({ ok: true });
      }
      if (input.operation === "probeInstance")
        return Response.json({
          instanceId: this.instanceId,
          serviceState: this.service?.status().state ?? null,
        });
      if (input.operation === "controls") {
        Object.assign(this.control, input.control);
        return Response.json(this.control);
      }
      if (input.operation === "sql")
        return Response.json({
          rows: this.ctx.storage.sql
            .exec(input.query, ...(input.bindings ?? []))
            .toArray(),
        });
      return Response.json({ error: "unknown" }, { status: 404 });
    } catch (error) {
      return Response.json({ error: error.name }, { status: 500 });
    }
  }
}
export default {
  fetch() {
    return Response.json({ error: "not_found" }, { status: 404 });
  },
};
