/** TEST ONLY: private journal/SQL/fault controls. Never deploy. */
import { DurableObject } from "cloudflare:workers";
import { createHash, randomUUID } from "node:crypto";
import { RecoveryJournal } from "../services/organization/cloudflare/recovery-journal.mjs";
export class RecoveryFixture extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.control = {
      syncs: 0,
      holdSync: 0,
      failSync: 0,
      failQuery: null,
      afterQuery: null,
      transaction: null,
    };
    this.storage = {
      sql: {
        exec: (query, ...bindings) => {
          if (
            this.control.failQuery &&
            query.startsWith(this.control.failQuery)
          )
            throw Error("injected SQL failure");
          const result = ctx.storage.sql.exec(query, ...bindings);
          if (
            this.control.afterQuery &&
            query.startsWith(this.control.afterQuery)
          )
            throw Error("injected post-SQL failure");
          return result;
        },
      },
      transactionSync: (callback) => {
        if (this.control.transaction === "before")
          throw Error("injected transaction failure");
        const result = ctx.storage.transactionSync(callback);
        if (this.control.transaction === "after")
          throw Error("injected ambiguous transaction");
        return result;
      },
      sync: async () => {
        const n = ++this.control.syncs;
        await ctx.storage.sync();
        while (this.control.holdSync === n)
          await new Promise((resolve) => setTimeout(resolve, 5));
        if (this.control.failSync === n) throw Error("injected sync failure");
      },
    };
  }
  async fetch(request) {
    try {
      const input = await request.json();
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
      if (input.operation === "initialize" || input.operation === "open") {
        this.journal?.close();
        this.journal = undefined;
        this.journal = await RecoveryJournal[input.operation](
          this.storage,
          input.options,
        );
        return Response.json(this.journal.head());
      }
      if (input.operation === "head") return Response.json(this.journal.head());
      if (input.operation === "healthy")
        return Response.json({ healthy: this.journal?.healthy() ?? false });
      if (input.operation === "close") {
        this.journal.close();
        return Response.json({ closed: true });
      }
      if (input.operation === "entry")
        return Response.json(this.journal.entry(input.sequence));
      if (input.operation === "part")
        return Response.json(this.journal.part(input.sequence, input.part));
      if (input.operation === "append") {
        let value = input.value;
        if (!value) {
          const bytes = input.bytes ?? 16;
          if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 16777217)
            throw new TypeError();
          const data = Buffer.alloc(bytes, input.fill ?? 97),
            chunks = [];
          for (let i = 0; i < data.length; i += 262144)
            chunks.push(data.subarray(i, i + 262144).toString("base64"));
          value = {
            expected: input.expected ?? this.journal.head(),
            id: input.id ?? randomUUID(),
            bytes,
            payloadDigest: createHash("sha256").update(data).digest("hex"),
            chunks,
          };
        }
        return Response.json(await this.journal.append(value));
      }
      return Response.json({ error: "not_found" }, { status: 404 });
    } catch (error) {
      return Response.json(
        { error: error.name },
        {
          status:
            error.name === "StoreConflict"
              ? 409
              : error.name === "TypeError"
                ? 400
                : 503,
        },
      );
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
};
