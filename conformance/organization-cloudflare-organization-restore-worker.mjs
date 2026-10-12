/** TEST ONLY: isolated full restore controls. Never deploy. */
import { ActionRestoreFixture } from "./organization-cloudflare-action-restore-worker.mjs";
import { StagedOrganizationRestore } from "../services/organization/cloudflare/organization-restore.mjs";
import { initializeLedger as initializeV8 } from "./fixtures/cloudflare/schema-v8.mjs";
export class OrganizationRestoreFixture extends ActionRestoreFixture {
  async fetch(request) {
    const input = await request.clone().json();
    try {
      if (
        input.operation === "organizationRestoreInitialize" ||
        input.operation === "organizationRestoreOpen"
      ) {
        this.organizationRestore?.close();
        this.organizationRestore = await StagedOrganizationRestore[
          input.operation === "organizationRestoreInitialize"
            ? "initialize"
            : "open"
        ](this.storage, input.checkpoint, input.manifest, {
          organization: input.organization,
          ...input.settings,
        });
        return Response.json(await this.organizationRestore.status());
      }
      if (input.operation === "organizationRestoreApply")
        return Response.json(
          await this.organizationRestore.apply(input.sequence, input.value),
        );
      if (input.operation === "organizationRestoreVerify")
        return Response.json(await this.organizationRestore.verify());
      if (input.operation === "organizationRestoreStatus")
        return Response.json(await this.organizationRestore.status());
      if (input.operation === "organizationRestoreClose") {
        this.organizationRestore.close();
        return Response.json({ ok: true });
      }
      if (input.operation === "initializeV8") {
        initializeV8(this.storage, input.organization);
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
