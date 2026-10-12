import { createHash } from "node:crypto";
/** Reconcile persisted transitions. This is consistency checking, not recovery authenticity. */
import {
  canonicalize,
  decodeKeyId,
  strictParse,
} from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
/** @param {unknown} value */
const text = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 256 &&
  !/[\u0000-\u001f\u007f]/.test(value);
/** @param {unknown} value @returns {asserts value is {subject:string,entity:string,kid:string}} */
function principal(value) {
  if (
    !exact(value, ["subject", "entity", "kid"]) ||
    !text(value.subject) ||
    !text(value.entity) ||
    !text(value.kid) ||
    !String(value.entity).startsWith("urn:xeip:entity:")
  )
    throw Error();
  decodeKeyId(String(value.entity).slice(16));
  decodeKeyId(String(value.kid));
}
const transitions = Object.freeze({
  proposed: ["approved", "rejected", "revoked"],
  approved: ["claimed", "revoked"],
  claimed: ["succeeded", "failed", "indeterminate"],
});
/** @param {import('./store.mjs').Row} row @param {Record<string,unknown>[]} events */
export function validateActionHistory(row, events) {
  if (
    events.length < 1 ||
    events.length > 4 ||
    events.length !== row.version + 1
  )
    throw Error();
  const action = JSON.parse(row.canonical),
    grant = row.approver === null ? null : JSON.parse(row.approver);
  principal(action.actor);
  if (grant !== null) {
    if (
      !exact(grant, [
        "subject",
        "entity",
        "kid",
        "clientId",
        "roles",
        "expiresAt",
      ]) ||
      typeof grant.clientId !== "string" ||
      !Array.isArray(grant.roles) ||
      grant.roles.length !== 1 ||
      grant.roles[0] !== "approver"
    )
      throw Error();
    principal({ subject: grant.subject, entity: grant.entity, kid: grant.kid });
    if (
      grant.subject === action.actor.subject ||
      grant.entity === action.actor.entity
    )
      throw Error();
  }
  let previous = "",
    sequence = 0;
  for (const event of events) {
    if (
      !Number.isSafeInteger(event.sequence) ||
      Number(event.sequence) <= sequence ||
      !Number.isSafeInteger(event.occurred_at) ||
      Number(event.occurred_at) < 0 ||
      event.session_id !== row.session_id ||
      event.request_id !== row.request_id ||
      event.digest !== row.digest ||
      typeof event.event !== "string" ||
      typeof event.actor !== "string" ||
      Buffer.byteLength(event.actor) > 4096
    )
      throw Error();
    const name = event.event,
      who = snapshot(strictParse(event.actor), 4096);
    if (canonicalize(who) !== event.actor) throw Error();
    if (
      previous === ""
        ? name !== "proposed"
        : !transitions[
            /** @type {keyof typeof transitions} */ (previous)
          ]?.includes(name)
    )
      throw Error();
    if (["succeeded", "failed", "indeterminate"].includes(name)) {
      if (
        !exact(who, ["worker", "claimId"]) ||
        who.worker !== "execution" ||
        who.claimId !== row.claim_id
      )
        throw Error();
    } else {
      principal(who);
      if (
        ["proposed", "claimed"].includes(name) &&
        canonicalize(who) !== canonicalize(action.actor)
      )
        throw Error();
      if (
        ["approved", "rejected"].includes(name) &&
        (!grant ||
          who.subject !== grant.subject ||
          who.entity !== grant.entity ||
          who.kid !== grant.kid)
      )
        throw Error();
    }
    sequence = Number(event.sequence);
    previous = name;
  }
  if (
    (previous === "proposed"
      ? "pending"
      : previous === "claimed"
        ? "executing"
        : previous) !== row.state
  )
    throw Error();
  const hasDecision = events.some(
    (e) => e.event === "approved" || e.event === "rejected",
  );
  if (hasDecision !== (grant !== null)) throw Error();
}

/** @param {unknown} value */
const id = (value) =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
/** Canonical persisted-row boundary, independent of current expiry/policy.
 * @param {import("./store.mjs").Row} row */
export function validateActionRow(row) {
  const action = /** @type {import("../contracts.js").Action} */ (
      /** @type {unknown} */ (snapshot(JSON.parse(row.canonical), 69632))
    ),
    grant =
      row.approver === null
        ? undefined
        : /** @type {import("../contracts.js").OrganizationPrincipal} */ (
            /** @type {unknown} */ (snapshot(JSON.parse(row.approver), 4096))
          );
  const consumed = [
    "executing",
    "succeeded",
    "failed",
    "indeterminate",
  ].includes(row.state);
  if (
    !id(row.session_id) ||
    !id(row.request_id) ||
    action.session !== row.session_id ||
    action.id !== row.request_id ||
    !Number.isSafeInteger(row.expires_at) ||
    row.expires_at < 0 ||
    action.expiresAt !== row.expires_at ||
    canonicalize(action) !== row.canonical ||
    createHash("sha256")
      .update("XEIP organization action v1\n" + row.canonical)
      .digest("hex") !== row.digest ||
    ![
      "pending",
      "approved",
      "rejected",
      "revoked",
      "executing",
      "succeeded",
      "failed",
      "indeterminate",
    ].includes(row.state) ||
    !Number.isInteger(row.version) ||
    row.version < 0 ||
    row.version > 7 ||
    (row.state === "pending" && row.approver !== null) ||
    ([
      "approved",
      "rejected",
      "executing",
      "succeeded",
      "failed",
      "indeterminate",
    ].includes(row.state) &&
      row.approver === null) ||
    (row.approver === null
      ? row.approval_expires_at !== null
      : !grant ||
        canonicalize(grant) !== row.approver ||
        !Number.isSafeInteger(row.approval_expires_at) ||
        /** @type {number} */ (row.approval_expires_at) < 0 ||
        /** @type {number} */ (row.approval_expires_at) > row.expires_at ||
        grant.expiresAt !== row.approval_expires_at) ||
    consumed !== (row.claim_id !== null) ||
    (row.claim_id !== null &&
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
        row.claim_id,
      )) ||
    (row.result_canonical !== null &&
      (!["succeeded", "failed"].includes(row.state) ||
        canonicalize(snapshot(JSON.parse(row.result_canonical), 131072)) !==
          row.result_canonical))
  )
    throw Error();
}
