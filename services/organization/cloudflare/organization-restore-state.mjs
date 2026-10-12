/** Historical SQL representation. Internal to isolated, permanently fenced restoration. */
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { encodeProvisioning } from "./trust-chunks.mjs";
import { verifyRecoverySchema } from "./schema.mjs";
import { hash } from "./organization-bundle-record.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {Record<string,import('./contracts.js').SqlValue>} Row */
/** @param {Storage} storage @param {string} table @param {Row} row */
export function insertRow(storage, table, row) {
  const keys = Object.keys(row);
  storage.sql.exec(
    "INSERT INTO " +
      table +
      "(" +
      keys.join(",") +
      ") VALUES(" +
      keys.map(() => "?").join(",") +
      ")",
    ...Object.values(row),
  );
}
/** Exact source control rows. All table and column names are internal constants.
 * @param {import('./organization-checkpoint.mjs').Checkpoint} checkpoint @returns {Record<string,Row[]>} */
export function controlRows(checkpoint) {
  const { lifecycle, trust, authority } = checkpoint;
  const provisioning = encodeProvisioning(
    canonicalize(trust.provisioning),
    trust.revision,
  );
  const recovery = lifecycle.runtime.recovery;
  const binding = recovery
    ? Object.fromEntries(
        Object.entries(recovery).filter(([key]) => key !== "url"),
      )
    : null;
  return {
    xeip_service_state: [
      {
        singleton: 1,
        runtime_configuration: canonicalize(lifecycle.runtime),
        initial_authority: canonicalize(lifecycle.initialAuthority),
        checksum: lifecycle.checksum,
        phase: lifecycle.phase,
      },
    ],
    xeip_trust_state: [
      {
        singleton: 1,
        configuration: canonicalize(trust.configuration),
        provisioning: provisioning.stored,
        revision: trust.revision,
        accepted_at: trust.acceptedAt,
        checkpoints_digest: hash(canonicalize(trust.records)),
        checksum: trust.checksum,
      },
    ],
    xeip_trust_checkpoints: Object.entries(trust.records)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([entity, r]) => ({
        entity,
        anchor: r.anchor,
        generation: r.generation,
        key_digest: r.keyDigest,
        serial: r.serial,
        status_digest: r.statusDigest,
      })),
    xeip_trust_chunks: provisioning.chunks,
    xeip_authority_state: [
      {
        singleton: 1,
        revision: authority.revision,
        configuration: canonicalize(authority.configuration),
        checksum: authority.checksum,
      },
    ],
    xeip_action_recovery: binding
      ? [{ singleton: 1, canonical: canonicalize(binding) }]
      : [],
  };
}
/** Must be called WITHIN a synchronous transaction. No await or user-supplied callback reaches this module.
 * Only verified original trigger SQL is restored. A throw rolls the outer transaction back, including DDL.
 * @param {Storage} storage @param {('xeip_trust_state_insert'|'xeip_authority_new'|'xeip_authority_event_new')[]} names @param {()=>void} write */
export function historicalInsert(storage, names, write) {
  verifyRecoverySchema(storage);
  const fence = storage.sql
    .exec("SELECT phase FROM xeip_organization_restore")
    .toArray();
  if (fence.length !== 1 || fence[0].phase !== "restoring")
    throw Error("restore fence required");
  const triggers = names.map((name) => {
    const rows = storage.sql
      .exec(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
        name,
      )
      .toArray();
    if (rows.length !== 1 || typeof rows[0].sql !== "string")
      throw Error("restore schema mismatch");
    return { name, sql: rows[0].sql };
  });
  for (const trigger of triggers)
    storage.sql.exec("DROP TRIGGER " + trigger.name);
  write();
  for (const trigger of triggers) storage.sql.exec(trigger.sql);
  verifyRecoverySchema(storage);
}
/** @param {Storage} storage @param {Record<string,Row[]>} rows */
export function installControls(storage, rows) {
  historicalInsert(
    storage,
    ["xeip_trust_state_insert", "xeip_authority_new"],
    () => {
      for (const [table, records] of Object.entries(rows))
        for (const row of records) {
          insertRow(
            storage,
            table,
            table === "xeip_service_state"
              ? { ...row, phase: "initializing" }
              : row,
          );
          if (table === "xeip_service_state")
            storage.sql.exec(
              "UPDATE xeip_service_state SET phase='initialized' WHERE singleton=1",
            );
        }
    },
  );
}
/** @param {Storage} storage @param {Record<string,Row[]>} expected */
export function verifyControls(storage, expected) {
  for (const [table, rows] of Object.entries(expected)) {
    const order =
      table === "xeip_trust_checkpoints"
        ? "entity"
        : table === "xeip_trust_chunks"
          ? "revision,part"
          : "singleton";
    const actual = storage.sql
      .exec(
        "SELECT * FROM " +
          table +
          " ORDER BY " +
          order +
          " LIMIT " +
          (rows.length + 1),
      )
      .toArray();
    if (canonicalize(actual) !== canonicalize(rows))
      throw Error("restore control mismatch");
  }
}
