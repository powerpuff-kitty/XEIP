/** Private export wire values. No credentials, storage writes or execution authority. */
import { snapshot } from "../actions.mjs";
import { components, limits } from "./organization-bundle-record.mjs";
import {
  validateOrganizationManifest,
  organizationPageOptions,
} from "./organization-checkpoint.mjs";
import { actionCursor, validateActionPage } from "./action-export.mjs";
import {
  authorityHistoryCursor,
  validateAuthorityHistoryPage,
} from "./authority-checkpoint.mjs";
import {
  adminHistoryCursor,
  validateAdminHistoryPage,
} from "./admin-checkpoint.mjs";
/** @typedef {import('./organization-export.mjs').Description} Description */
/** @typedef {import('./organization-checkpoint.mjs').Checkpoint} Checkpoint */
/** @typedef {{organization?:string,description?:Description,checkpoint?:Checkpoint}} ExportContext */
/** @typedef {{operation:unknown,exportId?:unknown,component?:unknown,index?:unknown,section?:unknown,cursor?:unknown,exportContext?:ExportContext}} Expected */
const fields = Object.freeze({
  organizationExportBegin: "export",
  organizationExportPart: "part",
  organizationExportPage: "page",
  organizationExportClose: "closed",
});
/** @param {unknown} operation @returns {string|undefined} */
export function exportReceiptField(operation) {
  return typeof operation === "string" && Object.hasOwn(fields, operation)
    ? fields[/** @type {keyof typeof fields} */ (operation)]
    : undefined;
}
/** @param {unknown} operation */
export const ownerResponseLimit = (operation) =>
  ["actionPage", "organizationExportPart", "organizationExportPage"].includes(
    String(operation),
  )
    ? 524288
    : 65536;
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
/** @param {unknown} value @returns {value is string} */
const digest = (value) =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
/** @param {unknown} value @returns {asserts value is string} */
export function exportIdentifier(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value,
    )
  )
    throw new TypeError("invalid organization export identifier");
}
/** @param {unknown} component @param {unknown} index */
export function exportPartRequest(component, index) {
  if (
    typeof component !== "string" ||
    !components.includes(
      /** @type {typeof components[number]} */ (component),
    ) ||
    !Number.isSafeInteger(index) ||
    Number(index) < 0
  )
    throw new TypeError("invalid organization export part");
  const name = /** @type {typeof components[number]} */ (component);
  if (Number(index) >= Math.ceil((limits[name] + 1) / 262144))
    throw new TypeError("invalid organization export part");
  return { component: name, index: Number(index) };
}
/** Validate syntax before the source applies the actual captured head.
 * @param {unknown} section @param {unknown} cursor */
export function exportPageRequest(section, cursor) {
  const request = organizationPageOptions({ section, cursor });
  if (request.section === "actions") actionCursor(request.cursor);
  else if (request.section === "authority")
    authorityHistoryCursor(request.cursor, Number.MAX_SAFE_INTEGER);
  else adminHistoryCursor(request.cursor, 100000);
  return request;
}
/** @param {unknown} value @param {string} organization @returns {Description} */
export function validateExportDescription(value, organization) {
  const copy = snapshot(value, 8192);
  if (
    !exact(copy, ["exportId", "manifest", "components"]) ||
    !exact(copy.components, [...components])
  )
    throw new TypeError("invalid export description");
  exportIdentifier(copy.exportId);
  validateOrganizationManifest(copy.manifest, organization);
  for (const component of components) {
    const descriptor = copy.components[component];
    if (
      !exact(descriptor, ["bytes", "sha256", "parts"]) ||
      !Number.isSafeInteger(descriptor.bytes) ||
      Number(descriptor.bytes) < 2 ||
      Number(descriptor.bytes) > limits[component] + 1 ||
      !digest(descriptor.sha256) ||
      descriptor.parts !== Math.ceil(Number(descriptor.bytes) / 262144)
    )
      throw new TypeError("invalid export component descriptor");
  }
  return /** @type {Description} */ (/** @type {unknown} */ (copy));
}
/** Context is trusted local capture state, never a caller-supplied source authorization.
 * @param {unknown} value @param {Expected} expected */
export function validateExportReceipt(value, expected) {
  if (expected.operation === "organizationExportBegin") {
    if (!expected.exportContext?.organization) throw Error();
    return validateExportDescription(
      value,
      expected.exportContext.organization,
    );
  }
  exportIdentifier(expected.exportId);
  if (expected.operation === "organizationExportClose") {
    const copy = snapshot(value, 256);
    if (!exact(copy, ["exportId"]) || copy.exportId !== expected.exportId)
      throw Error();
    return copy;
  }
  if (expected.operation === "organizationExportPart") {
    const context = expected.exportContext?.description;
    if (!context) throw Error();
    const description = validateExportDescription(
        context,
        context.manifest.organization,
      ),
      request = exportPartRequest(expected.component, expected.index),
      descriptor = description.components[request.component],
      copy = snapshot(value, 360448);
    if (
      !exact(copy, [
        "exportId",
        "checkpointDigest",
        "component",
        "index",
        "data",
      ]) ||
      copy.exportId !== expected.exportId ||
      copy.exportId !== description.exportId ||
      copy.checkpointDigest !== description.manifest.digest ||
      copy.component !== request.component ||
      copy.index !== request.index ||
      request.index >= descriptor.parts ||
      typeof copy.data !== "string"
    )
      throw Error();
    const bytes = Buffer.from(copy.data, "base64");
    if (
      bytes.toString("base64") !== copy.data ||
      bytes.length !==
        Math.min(262144, descriptor.bytes - request.index * 262144)
    )
      throw Error();
    return copy;
  }
  if (expected.operation === "organizationExportPage") {
    const checkpoint = expected.exportContext?.checkpoint;
    if (!checkpoint) throw Error();
    const request = exportPageRequest(expected.section, expected.cursor),
      copy = snapshot(value, 491520);
    if (
      !exact(copy, ["exportId", "checkpointDigest", "section", "page"]) ||
      copy.exportId !== expected.exportId ||
      copy.checkpointDigest !== checkpoint.manifest.digest ||
      copy.section !== request.section
    )
      throw Error();
    if (request.section === "actions") {
      actionCursor(request.cursor);
      if (request.cursor > checkpoint.manifest.actions.cut) throw Error();
      validateActionPage(copy.page, {
        cut: checkpoint.manifest.actions.cut,
        after: request.cursor,
      });
    } else if (request.section === "authority")
      validateAuthorityHistoryPage(
        copy.page,
        checkpoint.authority,
        authorityHistoryCursor(request.cursor, checkpoint.authority.revision),
      );
    else
      validateAdminHistoryPage(
        copy.page,
        checkpoint.administration,
        adminHistoryCursor(
          request.cursor,
          checkpoint.administration.headSequence,
        ),
      );
    return copy;
  }
  throw Error();
}
