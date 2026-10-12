/** TEST ONLY: isolated restore/schema/fault controls. Never deploy. */
import { StagedActionRestore } from "../services/organization/cloudflare/action-restore.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
import { LifecycleFixture } from "./organization-cloudflare-lifecycle-worker.mjs";
import {
  initializeLedger,
  verifyLedgerSchema,
} from "../services/organization/cloudflare/schema.mjs";
import { initializeLedger as initializeV7 } from "./fixtures/cloudflare/schema-v7.mjs";
import { initializeLedger as initializeV8 } from "./fixtures/cloudflare/schema-v8.mjs";
export class ActionRestoreFixture extends LifecycleFixture {
  async fetch(request) {
    const input = await request.clone().json();
    try {
      if (
        input.operation === "restoreInitialize" ||
        input.operation === "restoreOpen"
      ) {
        this.restore?.close();
        this.restore = await StagedActionRestore[
          input.operation === "restoreInitialize" ? "initialize" : "open"
        ](this.storage, input.manifest, input.settings);
        return Response.json(await this.restore.status());
      }
      if (input.operation === "restoreApply")
        return Response.json(await this.restore.apply(input.value));
      if (input.operation === "restoreVerify")
        return Response.json(await this.restore.verify());
      if (input.operation === "restoreStatus")
        return Response.json(await this.restore.status());
      if (input.operation === "restoreClose") {
        this.restore.close();
        return Response.json({ ok: true });
      }
      if (input.operation === "regularStore") {
        const store = await DurableActionStore.open(
          this.storage,
          {
            revision: () => "",
            policy: () => ({}),
            allows: () => true,
            authorize: async () => true,
          },
          { organization: input.organization ?? "fixture-organization" },
        );
        return Response.json({ healthy: store.healthy() });
      }
      if (input.operation === "initializeNormal") {
        initializeLedger(
          this.storage,
          input.organization ?? "fixture-organization",
        );
        return Response.json({ ok: true });
      }
      if (input.operation === "verifyNormal") {
        verifyLedgerSchema(this.storage);
        return Response.json({ ok: true });
      }
      if (input.operation === "initializeV8") {
        initializeV8(this.storage, "fixture-organization");
        return Response.json({ ok: true });
      }
      if (input.operation === "initializeV7") {
        initializeV7(this.storage, "fixture-organization");
        return Response.json({ ok: true });
      }
      if (input.operation === "insertFence") {
        this.ctx.storage.sql.exec(
          "INSERT INTO xeip_action_restore(singleton,intent,sequence,head_checksum,total_bytes,phase,checksum) VALUES(1,'{}',0,?,0,'restoring',?)",
          "0".repeat(64),
          "0".repeat(64),
        );
        return Response.json({ ok: true });
      }
      return super.fetch(request);
    } catch (error) {
      return Response.json(
        { error: "unavailable" },
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
