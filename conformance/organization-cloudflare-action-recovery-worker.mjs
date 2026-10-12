import { DurableObject } from "cloudflare:workers";
import { initializeLedger as initializeV6 } from "./fixtures/cloudflare/schema-v6.mjs";
import { initializeLedger } from "../services/organization/cloudflare/schema.mjs";
export { LifecycleFixture } from "./organization-cloudflare-lifecycle-worker.mjs";
/** TEST ONLY: separate source/journal databases and fault controls. Never deploy. */
import { LedgerFixture } from "./organization-cloudflare-worker.mjs";
export { RecoveryFixture } from "./organization-cloudflare-recovery-worker.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
export class RecoveredLedgerFixture extends LedgerFixture {
  openStore() {} // Explicit asynchronous open only; never bypass persisted enrollment.
  async fetch(request) {
    const input = await request.clone().json();
    const journal = this.env.JOURNAL.get(
      this.env.JOURNAL.idFromName(input.journalName ?? this.ctx.id.toString()),
    );
    const send = async (value) => {
      const response = await journal.fetch("https://journal.invalid/", {
        method: "POST",
        body: JSON.stringify(value),
      });
      const body = await response.json();
      if (response.status !== 200) throw Error("journal unavailable");
      return body;
    };
    try {
      if (input.operation === "journal")
        return Response.json(await send(input.value));
      if (input.operation === "openRecovery") {
        this.store?.close();
        const client = {
          head: async () => ({
            ...(await send({ operation: "head" })),
            ...this.control.headCorruption,
          }),
          entry: async (sequence) => ({
            ...(await send({ operation: "entry", sequence })),
            ...this.control.entryCorruption,
          }),
          append: async (value) => {
            const receipt = await send({ operation: "append", value });
            if (this.control.lostReceipt) throw Error("lost receipt");
            return { ...receipt, ...this.control.receiptCorruption };
          },
        };
        this.store = await DurableActionStore.open(
          this.storage,
          this.authority,
          {
            organization: "fixture-organization",
            timeoutMs: input.timeoutMs ?? 1000,
            recovery: {
              options: input.options,
              client,
              initialize: input.initialize === true,
            },
          },
        );
        return Response.json({ healthy: this.store.healthy() });
      }
      if (input.operation === "openWithoutRecovery") {
        this.store?.close();
        this.store = new DurableActionStore(this.storage, this.authority, {
          organization: "fixture-organization",
        });
        return Response.json({ healthy: this.store.healthy() });
      }
      if (input.operation === "restoreSource") {
        this.store?.close();
        this.ctx.storage.transactionSync(() => {
          const triggers = this.ctx.storage.sql
            .exec(
              "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('xeip_actions','xeip_audit')",
            )
            .toArray();
          for (const trigger of triggers)
            this.ctx.storage.sql.exec("DROP TRIGGER " + trigger.name);
          this.ctx.storage.sql.exec(
            "DELETE FROM xeip_audit; DELETE FROM xeip_actions",
          );
          for (const table of ["xeip_actions", "xeip_audit"])
            for (const row of input.rows[table])
              this.ctx.storage.sql.exec(
                "INSERT INTO " +
                  table +
                  "(" +
                  Object.keys(row).join(",") +
                  ") VALUES(" +
                  Object.keys(row)
                    .map(() => "?")
                    .join(",") +
                  ")",
                ...Object.values(row),
              );
          this.ctx.storage.sql.exec(
            "UPDATE xeip_metadata SET action_count=?",
            input.rows.xeip_actions.length,
          );
          for (const trigger of triggers)
            this.ctx.storage.sql.exec(trigger.sql);
        });
        return Response.json({ restored: true });
      }
      if (input.operation === "recoveryControls") {
        Object.assign(this.control, input.control);
        return Response.json({ ok: true });
      }
      if (input.operation === "closeRecovery") {
        this.store.close();
        return Response.json({ ok: true });
      }
      if (input.operation === "recoveryHealth")
        return Response.json({ healthy: this.store?.healthy() ?? false });
      return super.fetch(request);
    } catch (error) {
      return Response.json(
        { error: error.name },
        { status: error.name === "StoreConflict" ? 409 : 503 },
      );
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
};

export class RecoveryMigrationFixture extends DurableObject {
  async fetch(request) {
    const input = await request.json();
    try {
      if (input.operation === "v6") {
        initializeV6(this.ctx.storage, "fixture-organization");
        return Response.json({ ok: true });
      }
      if (input.operation === "v7") {
        const storage = {
          ...this.ctx.storage,
          sql: {
            exec: (query, ...bindings) => {
              const cursor = this.ctx.storage.sql.exec(query, ...bindings);
              if (
                input.fail &&
                query.startsWith("\nCREATE TABLE xeip_action_recovery")
              ) {
                this.applied = this.ctx.storage.sql
                  .exec(
                    "SELECT COUNT(*) AS n FROM sqlite_master WHERE name GLOB 'xeip_action_recovery*'",
                  )
                  .toArray()[0].n;
                throw Error("DDL applied before injected failure");
              }
              return cursor;
            },
          },
          transactionSync: (fn) => this.ctx.storage.transactionSync(fn),
          sync: () => this.ctx.storage.sync(),
        };
        initializeLedger(storage, "fixture-organization");
        return Response.json({ ok: true });
      }
      if (input.operation === "applied")
        return Response.json({ applied: this.applied });
      if (input.operation === "sql")
        return Response.json({
          rows: this.ctx.storage.sql
            .exec(input.query, ...(input.bindings ?? []))
            .toArray(),
        });
      return new Response(null, { status: 404 });
    } catch (error) {
      return Response.json({ error: error.name }, { status: 503 });
    }
  }
}
