/** Historical trust only. Validation never grants live authority or proves durability. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import {
  prepareEntityTrust,
  validateTrustRecords,
} from "../../../packages/identity/trust-state.mjs";
import { snapshot } from "../actions.mjs";
/** @typedef {import('../../../packages/identity/trust-state.mjs').TrustConfiguration} Configuration */
/** @typedef {import('../../../packages/identity/trust-state.mjs').TrustRecords} Records */
/** @typedef {{configuration:string,provisioning:string,revision:number,accepted_at:number,checkpoints_digest:string}} TrustState */
/** @typedef {{schema:'xeip.trust-checkpoint/1',organization:string,configuration:Configuration,provisioning:{keyDocuments:unknown[],statusDocuments:unknown[]},revision:number,acceptedAt:number,records:Records,checksum:string}} TrustCheckpoint */
// Only validator-owned, deeply frozen results have provenance. Weak keys do not
// retain released captures; external freezes, clones and wire values cannot opt in.
/** @type {WeakMap<TrustCheckpoint,string>} */
const encodings = new WeakMap();
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** Shared with persisted source rows: chunk descriptors must be resolved first.
 * @param {TrustState} row */
export const trustStateChecksum = (row) =>
  hash(
    "XEIP durable trust state v1\n" +
      canonicalize({
        configuration: row.configuration,
        provisioning: row.provisioning,
        revision: row.revision,
        acceptedAt: row.accepted_at,
        checkpointsDigest: row.checkpoints_digest,
      }),
  );
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
/** Validate and isolate a historical snapshot, including signed provisioning at its ORIGINAL time.
 * Each section uses its source's node/byte budget, avoiding a smaller combined node cap.
 * @param {unknown} value @param {string} organization @returns {TrustCheckpoint} */
export function validateTrustCheckpoint(value, organization) {
  try {
    if (
      typeof organization !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization)
    )
      throw Error();
    const known = /** @type {TrustCheckpoint} */ (value);
    if (encodings.has(known)) {
      if (known.organization !== organization) throw Error();
      return known;
    }
    const keys = [
      "schema",
      "organization",
      "configuration",
      "provisioning",
      "revision",
      "acceptedAt",
      "records",
      "checksum",
    ];
    if (
      !exact(value, keys) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.getOwnPropertySymbols(value).length
    )
      throw Error();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (
      Object.keys(descriptors).length !== keys.length ||
      keys.some(
        (k) =>
          !descriptors[k].enumerable || !Object.hasOwn(descriptors[k], "value"),
      )
    )
      throw Error();
    const metadata = /** @type {Record<string,unknown>} */ (
      snapshot(
        {
          schema: value.schema,
          organization: value.organization,
          revision: value.revision,
          acceptedAt: value.acceptedAt,
          checksum: value.checksum,
        },
        2048,
      )
    );
    if (
      metadata.schema !== "xeip.trust-checkpoint/1" ||
      metadata.organization !== organization ||
      !Number.isSafeInteger(metadata.revision) ||
      Number(metadata.revision) < 0 ||
      !Number.isSafeInteger(metadata.acceptedAt) ||
      Number(metadata.acceptedAt) < 0 ||
      typeof metadata.checksum !== "string" ||
      !/^[0-9a-f]{64}$/.test(metadata.checksum)
    )
      throw Error();
    const configuration = /** @type {Configuration} */ (
      snapshot(value.configuration, 65536)
    );
    const provisioning = snapshot(value.provisioning, 8388608, 262144);
    if (
      !exact(configuration, ["maxAgeSeconds", "knownExtensions"]) ||
      !exact(provisioning, ["keyDocuments", "statusDocuments"])
    )
      throw Error();
    const records = validateTrustRecords(
      snapshot(value.records, 12582912, 32768),
    );
    if (Object.keys(records).some((entity) => [...entity].length > 2048))
      throw Error();
    const prepared = prepareEntityTrust(
      configuration,
      provisioning.keyDocuments,
      provisioning.statusDocuments,
      Number(metadata.acceptedAt),
    );
    for (const [entity, record] of Object.entries(prepared.checkpoints))
      if (
        !Object.hasOwn(records, entity) ||
        canonicalize(records[entity]) !== canonicalize(record)
      )
        throw Error();
    if (
      metadata.checksum !==
      trustStateChecksum({
        configuration: canonicalize(configuration),
        provisioning: canonicalize(provisioning),
        revision: Number(metadata.revision),
        accepted_at: Number(metadata.acceptedAt),
        checkpoints_digest: hash(canonicalize(records)),
      })
    )
      throw Error();
    const result = /** @type {TrustCheckpoint} */ ({
      ...metadata,
      configuration,
      provisioning,
      records,
    });
    const encoded = canonicalize(result);
    if (Buffer.byteLength(encoded) > 16777216) throw Error();
    // Nested sections are already isolated and recursively frozen by snapshot.
    Object.freeze(result);
    encodings.set(result, encoded);
    return result;
  } catch {
    // Neither raw documents, entity identities nor validator diagnostics leave this boundary.
    throw new TypeError("invalid historical trust checkpoint");
  }
}
/** Return the existing canonical wire text after full validation or private immutable reuse.
 * No freshness, source integrity or durability claim follows from this historical encoding.
 * @param {unknown} value @param {string} organization @returns {string} */
export function encodeTrustCheckpoint(value, organization) {
  const checkpoint = validateTrustCheckpoint(value, organization);
  return /** @type {string} */ (encodings.get(checkpoint));
}
