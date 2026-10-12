/** TEST ONLY: real Worker lifecycle/RPC with private synthetic-history seeding. Never deploy. */
import { WorkerEntrypoint } from "cloudflare:workers";
import { OrganizationObject as ProductionObject } from "../services/organization/cloudflare/worker.mjs";
export {
  default,
  OwnerEntrypoint,
  RefreshEntrypoint,
} from "../services/organization/cloudflare/worker.mjs";
export class OrganizationObject extends ProductionObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.instanceId = crypto.randomUUID();
  }
  async manage(raw, operator) {
    let operation;
    try {
      operation = JSON.parse(raw).operation;
    } catch {
      // The production boundary owns malformed-input handling.
    }
    const observed = [
      "status",
      "organizationExportBegin",
      "organizationExportClose",
    ].includes(operation);
    if (observed)
      console.log(
        JSON.stringify({
          event: "xeip.cost-owner",
          instanceId: this.instanceId,
          operation,
          stage: "entered",
        }),
      );
    try {
      return await super.manage(raw, operator);
    } finally {
      if (observed)
        console.log(
          JSON.stringify({
            event: "xeip.cost-owner",
            instanceId: this.instanceId,
            operation,
            stage: "returned",
          }),
        );
    }
  }
  async seedCostHistory(records) {
    if (!Array.isArray(records) || records.length < 1 || records.length > 1000)
      throw Error("invalid fixture batch");
    this.ctx.storage.transactionSync(() => {
      for (const row of records)
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
    return { seeded: records.length };
  }
  async seedCostTrustRecords(records) {
    if (!Array.isArray(records) || records.length < 1 || records.length > 64)
      throw Error("invalid fixture batch");
    this.ctx.storage.transactionSync(() => {
      for (const [entity, record] of records)
        this.ctx.storage.sql.exec(
          "INSERT INTO xeip_trust_checkpoints(entity,anchor,generation,key_digest,serial,status_digest) VALUES(?,?,?,?,?,?)",
          entity,
          record.anchor,
          record.generation,
          record.keyDigest,
          record.serial,
          record.statusDigest,
        );
    });
    await this.ctx.storage.sync();
    return { seeded: records.length };
  }
  async sealCostTrust({
    revision,
    acceptedAt,
    recordsDigest,
    checksum,
    stored,
  }) {
    this.ctx.storage.sql.exec(
      "UPDATE xeip_trust_state SET revision=?,accepted_at=?,checkpoints_digest=?,checksum=?,provisioning=? WHERE singleton=1",
      revision,
      acceptedAt,
      recordsDigest,
      checksum,
      stored,
    );
    await this.ctx.storage.sync();
    return { sealed: true };
  }
  async seedCostTrustChunk(chunk) {
    this.ctx.storage.sql.exec(
      "INSERT INTO xeip_trust_chunks(revision,part,data) VALUES(?,?,?)",
      chunk.revision,
      chunk.part,
      chunk.data,
    );
    await this.ctx.storage.sync();
    return { seeded: chunk.part };
  }
  costState() {
    const rows = this.ctx.storage.sql
      .exec(
        "SELECT sequence,checksum FROM xeip_owner_events ORDER BY sequence DESC LIMIT 1",
      )
      .toArray();
    return {
      instanceId: this.instanceId,
      trustAcceptedAt: this.ctx.storage.sql
        .exec("SELECT accepted_at FROM xeip_trust_state WHERE singleton=1")
        .toArray()[0]?.accepted_at,
      headSequence: rows[0]?.sequence ?? 0,
      headChecksum: rows[0]?.checksum ?? "0".repeat(64),
    };
  }
}
export class CostProbeEntrypoint extends WorkerEntrypoint {
  async run(value) {
    const object = this.env.ORGANIZATION.get(
      this.env.ORGANIZATION.idFromName("xeip-organization-v1"),
    );
    if (value.operation === "seed")
      return object.seedCostHistory(value.records);
    if (value.operation === "state") return object.costState();
    if (value.operation === "seed-trust")
      return object.seedCostTrustRecords(value.records);
    if (value.operation === "seed-trust-chunk")
      return object.seedCostTrustChunk(value.chunk);
    if (value.operation === "seal-trust")
      return object.sealCostTrust(value.state);
    throw Error("unknown fixture operation");
  }
}
