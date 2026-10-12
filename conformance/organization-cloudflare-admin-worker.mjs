/** TEST ONLY: never included in the deployed Worker. */
import { DurableObject } from "cloudflare:workers";
import { canonicalize } from "../sdks/typescript/dist/identity.js";
import { initializeLedger } from "../services/organization/cloudflare/schema.mjs";
import { initializeLedger as initializeV4 } from "./fixtures/cloudflare/schema-v4.mjs";
import { OwnerJournal } from "../services/organization/cloudflare/admin-audit.mjs";
export class AdminFixture extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.tickets = new Map();
    this.controls = {
      failSync: false,
      failQuery: null,
      clock: 1000,
      historyRows: 0,
    };
    this.storage = {
      sql: {
        exec: (q, ...b) => {
          if (this.controls.failQuery && q.startsWith(this.controls.failQuery))
            throw Error("SQL fault");
          const cursor = ctx.storage.sql.exec(q, ...b);
          return {
            toArray: () => {
              const rows = cursor.toArray();
              if (q.includes("FROM xeip_owner_events"))
                this.controls.historyRows += rows.length;
              return rows;
            },
          };
        },
      },
      transactionSync: (fn) => ctx.storage.transactionSync(fn),
      sync: async () => {
        await ctx.storage.sync();
        if (this.controls.failSync) throw Error("sync fault");
      },
    };
  }
  async fetch(request) {
    const i = await request.json();
    try {
      if (i.operation === "v4") {
        initializeV4(this.storage, "audit-fixture");
        return Response.json({ ok: true });
      }
      if (i.operation === "open") {
        if (i.initialize) initializeLedger(this.storage, "audit-fixture");
        this.journal = new OwnerJournal(this.storage, {
          maxRecords: i.maxRecords,
          clock: () => this.controls.clock,
        });
        return Response.json(this.journal.export());
      }
      if (i.operation === "start") {
        const ticket = this.journal.start(i.metadata, i.state);
        this.tickets.set(i.key ?? "current", ticket);
        if (i.sync !== false) await this.journal.sync();
        return Response.json({ ok: true });
      }
      if (i.operation === "finish") {
        this.journal.finish(
          i.forged ? {} : this.tickets.get(i.key ?? "current"),
          i.outcome,
          i.state,
        );
        if (i.sync !== false) await this.journal.sync();
        return Response.json({ ok: true });
      }
      if (i.operation === "sync") {
        await this.journal.sync();
        return Response.json({ ok: true });
      }
      if (i.operation === "export")
        return Response.json(this.journal.export(i.options));
      if (i.operation === "checkpoint")
        return Response.json(this.journal.checkpoint());
      if (i.operation === "historyPage")
        return Response.json(this.journal.historyPage(i.checkpoint, i.options));
      if (i.operation === "historyPageAt")
        return Response.json(
          this.journal.historyPageAt(i.checkpoint, i.options),
        );
      if (i.operation === "captureReader") {
        const captured = this.journal.captureHistoryReader();
        this.reader = captured.reader;
        return Response.json(captured.checkpoint);
      }
      if (i.operation === "historyReader") {
        this.reader = this.journal.historyReaderAt(i.checkpoint);
        return Response.json({ ok: true });
      }
      if (i.operation === "readerPage")
        return Response.json(this.reader.page(i.options));
      if (i.operation === "readerClose") {
        this.reader.close();
        return Response.json({ ok: true });
      }
      if (i.operation === "seedHistory") {
        this.ctx.storage.transactionSync(() => {
          for (const row of i.records)
            this.ctx.storage.sql.exec(
              "INSERT INTO xeip_owner_events(sequence,attempt_id,outcome,canonical,previous,checksum) VALUES (?,?,?,?,?,?)",
              row.sequence,
              row.event.attemptId,
              row.event.outcome,
              canonicalize(row.event),
              row.previous,
              row.checksum,
            );
        });
        await this.ctx.storage.sync();
        return Response.json({ ok: true });
      }
      if (i.operation === "controls") {
        Object.assign(this.controls, i.values);
        return Response.json({ ok: true, ...this.controls });
      }
      if (i.operation === "sql")
        return Response.json({
          rows: this.ctx.storage.sql.exec(i.query, ...i.bindings).toArray(),
        });
      throw Error("unknown operation");
    } catch (e) {
      return Response.json({ error: e.constructor.name }, { status: 409 });
    }
  }
}
export default {
  fetch() {
    return new Response("private fixture", { status: 404 });
  },
};
