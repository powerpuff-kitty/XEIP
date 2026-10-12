/** Private versioned fixed-cut action evidence; no restore or retention mutation. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import {
  validateActionRow,
  validateActionHistory,
} from "./action-integrity.mjs";
/** @typedef {import('./store.mjs').Row} Row */
/** @typedef {{row:Row,history:Record<string,unknown>[]}} ActionEvidence */
/** @typedef {{schema:string,organization:string,cut:number,actions:number,digest:string}} ActionSnapshot */
export const ACTION_PAGE_BYTES = 491520;
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
/** @param {unknown} value @returns {asserts value is number} */
export function actionCursor(value) {
  if (!Number.isSafeInteger(value) || Number(value) < 0)
    throw new TypeError("invalid action cursor");
}
/** @param {unknown} value @returns {ActionSnapshot} */
export function validateActionSnapshot(value) {
  if (
    !exact(value, ["schema", "organization", "cut", "actions", "digest"]) ||
    value.schema !== "xeip.action-snapshot/1" ||
    typeof value.organization !== "string" ||
    !value.organization.length ||
    value.organization.length > 128 ||
    typeof value.digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.digest)
  )
    throw new TypeError("invalid action snapshot");
  actionCursor(value.cut);
  actionCursor(value.actions);
  if (
    value.actions > 10000 ||
    (value.cut === 0) !== (value.actions === 0) ||
    value.actions > value.cut
  )
    throw new TypeError("invalid action snapshot");
  return /** @type {ActionSnapshot} */ (/** @type {unknown} */ (value));
}
/** @param {Omit<ActionSnapshot,'digest'>} header */
export const actionSnapshotHasher = (header) =>
  createHash("sha256").update(
    "XEIP action snapshot v1\n" + canonicalize(header) + "\n",
  );
/** @param {unknown} value @param {number} cut @returns {ActionEvidence} */
export function validateActionEvidence(value, cut) {
  actionCursor(cut);
  if (
    !exact(value, ["row", "history"]) ||
    !exact(value.row, [
      "session_id",
      "request_id",
      "digest",
      "canonical",
      "expires_at",
      "state",
      "version",
      "approver",
      "approval_expires_at",
      "claim_id",
      "result_canonical",
    ]) ||
    !Array.isArray(value.history) ||
    value.history.length > 4 ||
    Buffer.byteLength(canonicalize(value)) > ACTION_PAGE_BYTES - 1024
  )
    throw new TypeError("invalid action evidence");
  const evidence = /** @type {ActionEvidence} */ (
    /** @type {unknown} */ (value)
  );
  validateActionRow(evidence.row);
  for (const event of evidence.history)
    if (
      !exact(event, [
        "sequence",
        "session_id",
        "request_id",
        "digest",
        "event",
        "actor",
        "occurred_at",
      ]) ||
      Number(event.sequence) > cut
    )
      throw new TypeError("invalid action evidence");
  validateActionHistory(evidence.row, evidence.history);
  return evidence;
}
/** @param {unknown} value @param {{cut:number,after:number}} expected */
export function validateActionPage(value, expected) {
  actionCursor(expected.cut);
  actionCursor(expected.after);
  if (
    !exact(value, ["cut", "after", "next", "record"]) ||
    value.cut !== expected.cut ||
    value.after !== expected.after ||
    Buffer.byteLength(canonicalize(value)) > ACTION_PAGE_BYTES
  )
    throw new TypeError("invalid action page");
  actionCursor(value.next);
  if (value.record === null) {
    if (value.next !== expected.after)
      throw new TypeError("invalid action page");
  } else {
    const record = validateActionEvidence(value.record, expected.cut);
    if (
      record.history[0].sequence !== value.next ||
      value.next <= expected.after
    )
      throw new TypeError("invalid action page");
  }
  return /** @type {{cut:number,after:number,next:number,record:ActionEvidence|null}} */ (
    /** @type {unknown} */ (value)
  );
}
/** @param {Row} row @param {Record<string,unknown>[]} events @param {number} cut @returns {ActionEvidence} */
export function projectAction(row, events, cut) {
  const history = events.filter((e) => Number(e.sequence) <= cut);
  if (!history.length) throw Error();
  const last = String(history.at(-1)?.event),
    decision = history.some((e) =>
      ["approved", "rejected"].includes(String(e.event)),
    ),
    claimed = history.some((e) => e.event === "claimed"),
    completed = ["succeeded", "failed"].includes(last);
  return validateActionEvidence(
    {
      row: {
        ...row,
        state:
          last === "proposed"
            ? "pending"
            : last === "claimed"
              ? "executing"
              : last,
        version: history.length - 1,
        approver: decision ? row.approver : null,
        approval_expires_at: decision ? row.approval_expires_at : null,
        claim_id: claimed ? row.claim_id : null,
        result_canonical: completed ? row.result_canonical : null,
      },
      history,
    },
    cut,
  );
}
