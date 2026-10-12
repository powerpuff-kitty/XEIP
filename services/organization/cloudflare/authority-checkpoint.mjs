/** Historical authority integrity only. No network, live principal or restoration authority. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot, ActionPolicy } from "../actions.mjs";
import { KeycloakAuthenticator } from "../auth.mjs";
/** @typedef {import('./authority.mjs').Configuration} Configuration */
/** @typedef {{revision:number,configurationDigest:string,previousChecksum:string,checksum:string}} HistoryEvent */
/** @typedef {{schema:'xeip.authority-checkpoint/1',organization:string,configuration:Configuration,revision:number,previousChecksum:string,checksum:string,digest:string}} Checkpoint */
/** @typedef {{after:number,previousChecksum:string,limit:number}} Cursor */
/** @typedef {{schema:'xeip.authority-history-page/1',checkpointDigest:string,after:number,records:HistoryEvent[],next:number,complete:boolean}} Page */
const zero = "0".repeat(64);
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {unknown} value @returns {value is string} */
const digest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
/** @param {number} revision @param {string} configurationDigest @param {string} previousChecksum */
export const authorityEventChecksum = (
  revision,
  configurationDigest,
  previousChecksum,
) =>
  hash(
    "XEIP durable authority history v1\n" +
      canonicalize({ revision, configurationDigest, previousChecksum }),
  );
/** @param {Omit<Checkpoint,'digest'>} value */
export const authorityCheckpointDigest = (value) =>
  hash("XEIP authority checkpoint v1\n" + canonicalize(value));
/** Validate public configuration without real credentials or any provider request.
 * @param {unknown} value @returns {Configuration} */
export function validatePublicAuthority(value) {
  const configuration = snapshot(value, 1048576);
  if (
    !exact(configuration, ["authentication", "policy"]) ||
    configuration.authentication === null ||
    typeof configuration.authentication !== "object" ||
    Object.hasOwn(configuration.authentication, "introspectionClientSecret")
  )
    throw new TypeError("invalid public authority configuration");
  const typed = /** @type {Configuration} */ (
    /** @type {unknown} */ (configuration)
  );
  // Validation-only instance: constructors perform no fetch and this sentinel is never exported.
  new KeycloakAuthenticator({
    ...typed.authentication,
    introspectionClientSecret: "x",
  });
  new ActionPolicy(typed.policy);
  return typed;
}
/** Validate a checkpoint without credentials or a provider call; returned data is isolated/frozen.
 * @param {unknown} value @param {string} organization @returns {Checkpoint} */
export function validateAuthorityCheckpoint(value, organization) {
  try {
    const copy = snapshot(value, 1050624, 16384);
    if (
      typeof organization !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization) ||
      !exact(copy, [
        "schema",
        "organization",
        "configuration",
        "revision",
        "previousChecksum",
        "checksum",
        "digest",
      ]) ||
      copy.schema !== "xeip.authority-checkpoint/1" ||
      copy.organization !== organization ||
      !Number.isSafeInteger(copy.revision) ||
      Number(copy.revision) < 0 ||
      !digest(copy.previousChecksum) ||
      !digest(copy.checksum) ||
      !digest(copy.digest) ||
      (copy.revision === 0 && copy.previousChecksum !== zero)
    )
      throw Error();
    const configuration = validatePublicAuthority(copy.configuration);
    if (
      copy.checksum !==
      authorityEventChecksum(
        Number(copy.revision),
        hash(canonicalize(configuration)),
        copy.previousChecksum,
      )
    )
      throw Error();
    const { digest: encoded, ...body } = copy;
    if (
      encoded !==
      authorityCheckpointDigest(
        /** @type {Omit<Checkpoint,'digest'>} */ (
          /** @type {unknown} */ (body)
        ),
      )
    )
      throw Error();
    return /** @type {Checkpoint} */ (/** @type {unknown} */ (copy));
  } catch {
    throw new TypeError("invalid historical authority checkpoint");
  }
}
/** @param {unknown} value @param {number} revision @returns {Cursor} */
export function authorityHistoryCursor(value = {}, revision) {
  const copy = snapshot(value, 512);
  if (
    !copy ||
    typeof copy !== "object" ||
    Array.isArray(copy) ||
    Object.keys(copy).some(
      (k) => !["after", "previousChecksum", "limit"].includes(k),
    )
  )
    throw new TypeError("invalid authority history cursor");
  const fields = /** @type {Record<string,unknown>} */ (copy);
  const after = Object.hasOwn(fields, "after") ? fields.after : -1,
    previousChecksum = Object.hasOwn(fields, "previousChecksum")
      ? fields.previousChecksum
      : zero,
    limit = Object.hasOwn(fields, "limit") ? fields.limit : 128;
  if (
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    !Number.isSafeInteger(after) ||
    Number(after) < -1 ||
    Number(after) > revision ||
    !Number.isInteger(limit) ||
    Number(limit) < 1 ||
    Number(limit) > 256 ||
    !digest(previousChecksum) ||
    (after === -1 && previousChecksum !== zero) ||
    (after !== -1 && !Object.hasOwn(copy, "previousChecksum"))
  )
    throw new TypeError("invalid authority history cursor");
  return { after: Number(after), previousChecksum, limit: Number(limit) };
}
/** Checkpoint must first be validated for the caller's expected organization.
 * @param {unknown} value @param {Checkpoint} checkpoint @param {Cursor} options @returns {Page} */
export function validateAuthorityHistoryPage(value, checkpoint, options) {
  try {
    const cursor = authorityHistoryCursor(options, checkpoint.revision),
      page = snapshot(value, 131072);
    if (
      !exact(page, [
        "schema",
        "checkpointDigest",
        "after",
        "records",
        "next",
        "complete",
      ]) ||
      page.schema !== "xeip.authority-history-page/1" ||
      page.checkpointDigest !== checkpoint.digest ||
      page.after !== cursor.after ||
      !Array.isArray(page.records) ||
      page.records.length !==
        Math.min(cursor.limit, checkpoint.revision - cursor.after)
    )
      throw Error();
    let revision = cursor.after,
      previous = cursor.previousChecksum;
    for (const record of page.records) {
      if (
        !exact(record, [
          "revision",
          "configurationDigest",
          "previousChecksum",
          "checksum",
        ]) ||
        record.revision !== revision + 1 ||
        !digest(record.configurationDigest) ||
        record.previousChecksum !== previous ||
        record.checksum !==
          authorityEventChecksum(
            Number(record.revision),
            record.configurationDigest,
            previous,
          )
      )
        throw Error();
      revision = Number(record.revision);
      previous = String(record.checksum);
      if (
        revision === checkpoint.revision &&
        (record.configurationDigest !==
          hash(canonicalize(checkpoint.configuration)) ||
          record.previousChecksum !== checkpoint.previousChecksum)
      )
        throw Error();
    }
    const complete = revision === checkpoint.revision;
    if (
      page.next !== revision ||
      page.complete !== complete ||
      (complete && previous !== checkpoint.checksum)
    )
      throw Error();
    return /** @type {Page} */ (/** @type {unknown} */ (page));
  } catch {
    throw new TypeError("invalid authority history page");
  }
}
/** Stateful complete-history verification; failed pages cannot advance the cursor. */
export class AuthorityHistoryVerifier {
  #checkpoint;
  #cursor;
  #complete = false;
  /** @param {unknown} checkpoint @param {string} organization @param {{limit?:number}} [options] */
  constructor(checkpoint, organization, { limit = 128 } = {}) {
    this.#checkpoint = validateAuthorityCheckpoint(checkpoint, organization);
    this.#cursor = authorityHistoryCursor({ limit }, this.#checkpoint.revision);
  }
  cursor() {
    return { ...this.#cursor };
  }
  complete() {
    return this.#complete;
  }
  /** @param {unknown} value */
  accept(value) {
    if (this.#complete)
      throw new TypeError("authority history already complete");
    const page = validateAuthorityHistoryPage(
      value,
      this.#checkpoint,
      this.#cursor,
    );
    this.#cursor = {
      ...this.#cursor,
      after: page.next,
      previousChecksum:
        page.records.at(-1)?.checksum ?? this.#cursor.previousChecksum,
    };
    this.#complete = page.complete;
  }
  finish() {
    if (!this.#complete) throw new TypeError("incomplete authority history");
    return this.#checkpoint;
  }
}
