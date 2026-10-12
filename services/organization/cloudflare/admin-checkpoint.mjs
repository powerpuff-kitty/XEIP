/** Historical administrative evidence only; never command replay or live authorization. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import {
  auditEvent,
  auditChecksum,
  auditPageOptions,
} from "./admin-record.mjs";
/** @typedef {{schema:'xeip.admin-checkpoint/1',organization:string,headSequence:number,headChecksum:string,digest:string}} Checkpoint */
/** @typedef {{after:number,previousChecksum:string,limit:number}} Cursor */
/** @typedef {import('./admin-record.mjs').RecordEntry} RecordEntry */
/** @typedef {{schema:'xeip.admin-history-page/1',checkpointDigest:string,after:number,records:RecordEntry[],next:number,complete:boolean}} Page */
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
  keys.every((k) => Object.hasOwn(value, k));
/** @param {Omit<Checkpoint,'digest'>} value */
export const adminCheckpointDigest = (value) =>
  hash("XEIP admin checkpoint v1\n" + canonicalize(value));
/** @param {unknown} value @param {string} organization @returns {Checkpoint} */
export function validateAdminCheckpoint(value, organization) {
  try {
    const copy = snapshot(value, 1024);
    if (
      typeof organization !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization) ||
      !exact(copy, [
        "schema",
        "organization",
        "headSequence",
        "headChecksum",
        "digest",
      ]) ||
      copy.schema !== "xeip.admin-checkpoint/1" ||
      copy.organization !== organization ||
      !Number.isSafeInteger(copy.headSequence) ||
      Number(copy.headSequence) < 0 ||
      Number(copy.headSequence) > 100000 ||
      !digest(copy.headChecksum) ||
      !digest(copy.digest) ||
      (copy.headSequence === 0 && copy.headChecksum !== zero)
    )
      throw Error();
    const { digest: encoded, ...body } = copy;
    if (
      encoded !==
      adminCheckpointDigest(
        /** @type {Omit<Checkpoint,'digest'>} */ (
          /** @type {unknown} */ (body)
        ),
      )
    )
      throw Error();
    return /** @type {Checkpoint} */ (/** @type {unknown} */ (copy));
  } catch {
    throw new TypeError("invalid historical administrative checkpoint");
  }
}
/** @param {unknown} value @param {number} head @returns {Cursor} */
export function adminHistoryCursor(value = {}, head) {
  const copy = snapshot(value, 512);
  if (
    !copy ||
    typeof copy !== "object" ||
    Array.isArray(copy) ||
    Object.keys(copy).some(
      (k) => !["after", "previousChecksum", "limit"].includes(k),
    )
  )
    throw new TypeError("invalid administrative history cursor");
  const fields = /** @type {Record<string,unknown>} */ (copy);
  const cursor = auditPageOptions(
    {
      ...(Object.hasOwn(fields, "after") ? { after: fields.after } : {}),
      ...(Object.hasOwn(fields, "limit") ? { limit: fields.limit } : {}),
    },
    head,
  );
  const previousChecksum = Object.hasOwn(fields, "previousChecksum")
    ? fields.previousChecksum
    : zero;
  if (
    !Number.isSafeInteger(head) ||
    head < 0 ||
    head > 100000 ||
    !digest(previousChecksum) ||
    (cursor.after === 0 && previousChecksum !== zero) ||
    (cursor.after > 0 && !Object.hasOwn(fields, "previousChecksum"))
  )
    throw new TypeError("invalid administrative history cursor");
  return { ...cursor, previousChecksum };
}
/** Checkpoint must first be validated for expected organization. Does not alone prove attempt/result relationships.
 * @param {unknown} value @param {Checkpoint} checkpoint @param {Cursor} options @returns {Page} */
export function validateAdminHistoryPage(value, checkpoint, options) {
  try {
    const cursor = adminHistoryCursor(options, checkpoint.headSequence),
      page = snapshot(value, 65536);
    if (
      !exact(page, [
        "schema",
        "checkpointDigest",
        "after",
        "records",
        "next",
        "complete",
      ]) ||
      page.schema !== "xeip.admin-history-page/1" ||
      page.checkpointDigest !== checkpoint.digest ||
      page.after !== cursor.after ||
      !Array.isArray(page.records) ||
      page.records.length !==
        Math.min(cursor.limit, checkpoint.headSequence - cursor.after)
    )
      throw Error();
    let sequence = cursor.after,
      previous = cursor.previousChecksum,
      time = 0;
    for (const row of page.records) {
      if (
        !exact(row, ["sequence", "event", "previous", "checksum"]) ||
        row.sequence !== sequence + 1 ||
        row.previous !== previous
      )
        throw Error();
      const event = auditEvent(row.event);
      if (
        event.occurredAt < time ||
        row.checksum !==
          auditChecksum(Number(row.sequence), previous, canonicalize(event))
      )
        throw Error();
      sequence = Number(row.sequence);
      previous = String(row.checksum);
      time = event.occurredAt;
    }
    if (
      page.next !== sequence ||
      page.complete !== (sequence === checkpoint.headSequence) ||
      (page.complete && previous !== checkpoint.headChecksum)
    )
      throw Error();
    return /** @type {Page} */ (/** @type {unknown} */ (page));
  } catch {
    throw new TypeError("invalid administrative history page");
  }
}
/** Complete ordered verification, bounded to a digest/status per attempt; failed pages are atomic. */
export class AdminHistoryVerifier {
  #checkpoint;
  #cursor;
  #complete = false;
  #time = 0;
  #unresolved = 0;
  /** @type {Map<string,string|null>} */ #attempts = new Map();
  /** @param {unknown} checkpoint @param {string} organization @param {{limit?:number}} [options] */
  constructor(checkpoint, organization, { limit = 16 } = {}) {
    this.#checkpoint = validateAdminCheckpoint(checkpoint, organization);
    this.#cursor = adminHistoryCursor({ limit }, this.#checkpoint.headSequence);
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
      throw new TypeError("administrative history already complete");
    const page = validateAdminHistoryPage(
      value,
      this.#checkpoint,
      this.#cursor,
    );
    /** @type {Map<string,string|null>} */ const pending = new Map();
    let time = this.#time,
      unresolved = this.#unresolved;
    for (const row of page.records) {
      const { outcome, occurredAt, after, ...identity } = row.event;
      const id = row.event.attemptId,
        commitment = hash(canonicalize(identity));
      const prior = pending.has(id) ? pending.get(id) : this.#attempts.get(id);
      if (occurredAt < time)
        throw new TypeError("unordered administrative history");
      if (outcome === "started") {
        if (prior !== undefined)
          throw new TypeError("duplicate administrative attempt");
        pending.set(id, commitment);
        unresolved++;
      } else {
        if (prior !== commitment)
          throw new TypeError("unmatched administrative result");
        pending.set(id, null);
        unresolved--;
      }
      time = occurredAt;
    }
    for (const [id, value] of pending) this.#attempts.set(id, value);
    this.#time = time;
    this.#unresolved = unresolved;
    this.#cursor = {
      ...this.#cursor,
      after: page.next,
      previousChecksum:
        page.records.at(-1)?.checksum ?? this.#cursor.previousChecksum,
    };
    this.#complete = page.complete;
  }
  finish() {
    if (!this.#complete)
      throw new TypeError("incomplete administrative history");
    return {
      checkpoint: this.#checkpoint,
      attempts: this.#attempts.size,
      unresolved: this.#unresolved,
    };
  }
}
