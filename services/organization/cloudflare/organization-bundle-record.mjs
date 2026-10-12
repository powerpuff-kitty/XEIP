/** Portable bundle integrity contract. No filesystem, transport, credentials or activation. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { ActionArchiveVerifier } from "./action-archive-record.mjs";
import { validateLifecycleCheckpoint } from "./lifecycle-checkpoint.mjs";
import { validateTrustCheckpoint } from "./trust-checkpoint.mjs";
import {
  validateAuthorityCheckpoint,
  AuthorityHistoryVerifier,
} from "./authority-checkpoint.mjs";
import {
  validateAdminCheckpoint,
  AdminHistoryVerifier,
} from "./admin-checkpoint.mjs";
import { validateOrganizationManifest } from "./organization-checkpoint.mjs";
/** @typedef {import('./organization-checkpoint.mjs').Checkpoint} Checkpoint */
/** @typedef {import('./organization-checkpoint.mjs').Manifest} CheckpointManifest */
/** @typedef {'actions'|'authority'|'administration'} Section */
/** @typedef {{schema:'xeip.organization-bundle/1',checkpoint:CheckpointManifest,filesChecksum:string,checksum:string}} Bundle */
/** @typedef {{organization:string,expectedDigest?:string}} Expected */
/** @param {string|Uint8Array} v */
export const hash = (v) => createHash("sha256").update(v).digest("hex");
/** @param {unknown} v */
const digest = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
/** @param {Omit<Bundle,'checksum'>} value */
export const seal = (value) =>
  hash("XEIP organization bundle v1\n" + canonicalize(value));
export const filesHasher = () =>
  createHash("sha256").update("XEIP organization bundle files v1\n");
/** @param {Section} section @param {number} index */
export const filename = (section, index) =>
  section + "-" + String(index).padStart(6, "0") + ".json";
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  !!value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((k) => Object.hasOwn(value, k));
export const components = /** @type {const} */ ([
  "lifecycle",
  "trust",
  "authority",
  "administration",
]);
export const limits = {
  lifecycle: 2099200,
  trust: 16777216,
  authority: 1050624,
  administration: 1024,
};
export const validators = {
  lifecycle: validateLifecycleCheckpoint,
  trust: validateTrustCheckpoint,
  authority: validateAuthorityCheckpoint,
  administration: validateAdminCheckpoint,
};
/** @param {Checkpoint} c */
export const counts = (c) => ({
  actions: c.manifest.actions.actions,
  authority: Math.floor(c.authority.revision / 128) + 1,
  administration: Math.max(1, Math.ceil(c.administration.headSequence / 16)),
});
/** @param {unknown} value @param {Expected} expected @returns {Bundle} */
export function bundleValue(value, { organization, expectedDigest }) {
  const copy = snapshot(value, 4096);
  if (
    !exact(copy, ["schema", "checkpoint", "filesChecksum", "checksum"]) ||
    copy.schema !== "xeip.organization-bundle/1" ||
    !digest(copy.filesChecksum) ||
    !digest(copy.checksum)
  )
    throw Error();
  const checkpoint = validateOrganizationManifest(
    copy.checkpoint,
    organization,
  );
  if (
    expectedDigest !== undefined &&
    (!digest(expectedDigest) || checkpoint.digest !== expectedDigest)
  )
    throw Error();
  const { checksum, ...body } = copy;
  if (
    seal(
      /** @type {Omit<Bundle,'checksum'>} */ (/** @type {unknown} */ (body)),
    ) !== checksum
  )
    throw Error();
  return /** @type {Bundle} */ (/** @type {unknown} */ (copy));
}
/** @param {Checkpoint} checkpoint */
export function checks(checkpoint) {
  return {
    actions: new ActionArchiveVerifier(checkpoint.manifest.actions, null),
    authority: new AuthorityHistoryVerifier(
      checkpoint.authority,
      checkpoint.manifest.organization,
    ),
    administration: new AdminHistoryVerifier(
      checkpoint.administration,
      checkpoint.manifest.organization,
    ),
  };
}
/** @param {ReturnType<typeof checks>} check @param {Checkpoint} c */
export function finish(check, c) {
  check.actions.finish();
  if (check.actions.sequences.size !== c.manifest.actions.cut) throw Error();
  check.authority.finish();
  check.administration.finish();
}
