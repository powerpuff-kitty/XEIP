/** Shared original owner audit records; checksum bytes and export rules remain unchanged. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
/** @typedef {{state:string,trustRevision:number|null,authorityRevision:number|null}} Summary */
/** @typedef {{operator:string,requestId:string,operation:string,commandDigest:string}} Metadata */
/** @typedef {Metadata & {attemptId:string,outcome:string,occurredAt:number,before:Summary,after?:Summary}} Event */
/** @typedef {{sequence:number,event:Event,previous:string,checksum:string}} RecordEntry */
const zero = "0".repeat(64);
const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
/** @param {unknown} value */
const integer = (value) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
/** @param {unknown} value @returns {Summary} */
export function auditSummary(value) {
  if (
    !exact(value, ["state", "trustRevision", "authorityRevision"]) ||
    typeof value.state !== "string" ||
    ![
      "opening",
      "uninitialized",
      "initializing",
      "initialized",
      "failed",
      "closed",
    ].includes(value.state) ||
    !(value.trustRevision === null || integer(value.trustRevision)) ||
    !(value.authorityRevision === null || integer(value.authorityRevision))
  )
    throw new TypeError("invalid audit state");
  return /** @type {Summary} */ (value);
}
/** @param {unknown} value @returns {Metadata} */
export function metadata(value) {
  if (
    !exact(value, ["operator", "requestId", "operation", "commandDigest"]) ||
    typeof value.operator !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/.test(value.operator) ||
    typeof value.requestId !== "string" ||
    !uuid.test(value.requestId) ||
    typeof value.operation !== "string" ||
    !["initialize", "refreshTrust", "updateAuthority"].includes(
      value.operation,
    ) ||
    typeof value.commandDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.commandDigest)
  )
    throw new TypeError("invalid audit metadata");
  return /** @type {Metadata} */ (value);
}
/** Validate once and retain the exact original canonical bytes for immediate use.
 * @param {unknown} value @returns {{event:Event,encoded:string}} */
export function encodeAuditEvent(value) {
  if (value === null || typeof value !== "object")
    throw new TypeError("invalid audit event");
  const event = /** @type {Record<string,unknown>} */ (value);
  const terminal = event.outcome !== "started";
  if (
    !exact(event, [
      "operator",
      "requestId",
      "operation",
      "commandDigest",
      "attemptId",
      "outcome",
      "occurredAt",
      "before",
      ...(terminal ? ["after"] : []),
    ]) ||
    typeof event.attemptId !== "string" ||
    !uuid.test(event.attemptId) ||
    !integer(event.occurredAt) ||
    typeof event.outcome !== "string" ||
    ![
      "started",
      "completed",
      "conflict",
      "invalid_request",
      "unavailable",
    ].includes(event.outcome)
  )
    throw new TypeError("invalid audit event");
  metadata({
    operator: event.operator,
    requestId: event.requestId,
    operation: event.operation,
    commandDigest: event.commandDigest,
  });
  auditSummary(event.before);
  if (terminal) auditSummary(event.after);
  const encoded = canonicalize(event);
  if (Buffer.byteLength(encoded) > 2048)
    throw new TypeError("audit event too large");
  return {
    event: /** @type {Event} */ (/** @type {unknown} */ (event)),
    encoded,
  };
}
/** @param {unknown} value @returns {Event} */
export function auditEvent(value) {
  return encodeAuditEvent(value).event;
}
/** @param {number} sequence @param {string} previous @param {string} encoded */
export const auditChecksum = (sequence, previous, encoded) =>
  createHash("sha256")
    .update(
      "XEIP owner journal v1\n" + canonicalize([sequence, previous, encoded]),
    )
    .digest("hex");
/** @param {unknown} value @param {number} head */
export function auditPageOptions(value = {}, head = Number.MAX_SAFE_INTEGER) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((k) => !["after", "limit"].includes(k))
  )
    throw new TypeError("invalid audit cursor");
  const options = /** @type {{after?:number,limit?:number}} */ (value);
  const after = options.after === undefined ? 0 : options.after,
    limit = options.limit === undefined ? 16 : options.limit;
  if (
    !integer(after) ||
    after > head ||
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 16
  )
    throw new TypeError("invalid audit cursor");
  return { after, limit };
}
/** Validate an exported page before operator output; hashes are integrity checks, not signatures.
 * @param {unknown} value @param {unknown} [options] */
export function validateAuditPage(value, options) {
  const { after, limit } = auditPageOptions(options);
  if (
    !exact(value, ["records", "next", "headSequence", "headChecksum"]) ||
    !Array.isArray(value.records) ||
    value.records.length > limit ||
    !integer(value.headSequence) ||
    Number(value.headSequence) > 100000 ||
    Number(value.headSequence) < after ||
    typeof value.headChecksum !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.headChecksum)
  )
    throw new TypeError("invalid audit page");
  let sequence = after,
    previous = after === 0 ? zero : undefined,
    time = 0;
  for (const row of value.records) {
    if (
      !exact(row, ["sequence", "event", "previous", "checksum"]) ||
      row.sequence !== sequence + 1 ||
      typeof row.previous !== "string" ||
      !/^[0-9a-f]{64}$/.test(row.previous) ||
      (previous !== undefined && row.previous !== previous)
    )
      throw new TypeError("invalid audit record");
    const event = auditEvent(row.event);
    if (
      event.occurredAt < time ||
      row.checksum !==
        auditChecksum(Number(row.sequence), row.previous, canonicalize(event))
    )
      throw new TypeError("invalid audit checksum");
    sequence = Number(row.sequence);
    previous = String(row.checksum);
    time = event.occurredAt;
  }
  if (
    value.next !== sequence ||
    sequence > Number(value.headSequence) ||
    value.records.length !==
      Math.min(limit, Number(value.headSequence) - after) ||
    (sequence === value.headSequence &&
      previous !== undefined &&
      previous !== value.headChecksum) ||
    (value.headSequence === 0 && value.headChecksum !== zero)
  )
    throw new TypeError("invalid audit head");
  return value;
}
