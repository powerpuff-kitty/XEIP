/** Coherent historical evidence; no independent durability or restored execution authority. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { validateLifecycleCheckpoint } from "./lifecycle-checkpoint.mjs";
import {
  validateTrustCheckpoint,
  encodeTrustCheckpoint,
} from "./trust-checkpoint.mjs";
import { validateAuthorityCheckpoint } from "./authority-checkpoint.mjs";
import { validateAdminCheckpoint } from "./admin-checkpoint.mjs";
import { validateActionSnapshot } from "./action-export.mjs";
/** @typedef {{lifecycle:import('./lifecycle-checkpoint.mjs').Checkpoint,trust:import('./trust-checkpoint.mjs').TrustCheckpoint,authority:import('./authority-checkpoint.mjs').Checkpoint,administration:import('./admin-checkpoint.mjs').Checkpoint}} Components */
/** @typedef {{schema:'xeip.organization-checkpoint/1',organization:string,lifecycleDigest:string,trustDigest:string,authorityDigest:string,administrationDigest:string,actions:import('./action-export.mjs').ActionSnapshot,digest:string}} Manifest */
/** @typedef {Components & {manifest:Manifest}} Checkpoint */
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
function exact(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.getOwnPropertySymbols(value).length
  )
    return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return (
    Object.keys(descriptors).length === keys.length &&
    keys.every(
      (k) =>
        descriptors[k]?.enumerable && Object.hasOwn(descriptors[k], "value"),
    )
  );
}
/** @param {Omit<Manifest,'digest'>} value */
export const organizationCheckpointDigest = (value) =>
  hash("XEIP organization checkpoint v1\n" + canonicalize(value));
/** @param {unknown} value @param {string} organization @returns {Manifest} */
export function validateOrganizationManifest(value, organization) {
  try {
    const copy = snapshot(value, 2048);
    if (
      typeof organization !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization) ||
      !exact(copy, [
        "schema",
        "organization",
        "lifecycleDigest",
        "trustDigest",
        "authorityDigest",
        "administrationDigest",
        "actions",
        "digest",
      ]) ||
      copy.schema !== "xeip.organization-checkpoint/1" ||
      copy.organization !== organization ||
      ![
        copy.lifecycleDigest,
        copy.trustDigest,
        copy.authorityDigest,
        copy.administrationDigest,
        copy.digest,
      ].every((v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v))
    )
      throw Error();
    const actions = validateActionSnapshot(copy.actions);
    if (
      actions.organization !== organization ||
      actions.cut > actions.actions * 4
    )
      throw Error();
    const { digest, ...body } = copy;
    if (
      digest !==
      organizationCheckpointDigest(
        /** @type {Omit<Manifest,'digest'>} */ (/** @type {unknown} */ (body)),
      )
    )
      throw Error();
    return /** @type {Manifest} */ (/** @type {unknown} */ (copy));
  } catch {
    throw new TypeError("invalid organization recovery manifest");
  }
}
/** Build a manifest from ALREADY VALIDATED component checkpoints; additionally enforce cross-component agreement.
 * @param {Components} components @param {import('./action-export.mjs').ActionSnapshot} actions @returns {Manifest} */
export function organizationManifest(
  { lifecycle, trust, authority, administration },
  actions,
) {
  const organization = lifecycle.organization,
    runtime = lifecycle.runtime;
  if (
    lifecycle.phase !== "initialized" ||
    [
      trust.organization,
      authority.organization,
      administration.organization,
      actions.organization,
    ].some((v) => v !== organization) ||
    canonicalize(trust.configuration) !==
      canonicalize({
        maxAgeSeconds: runtime.trust.maxAgeSeconds,
        knownExtensions: runtime.trust.knownExtensions ?? [],
      })
  )
    throw new TypeError("inconsistent organization recovery components");
  for (const key of /** @type {const} */ ([
    "issuer",
    "audience",
    "introspectionClientId",
  ]))
    if (
      authority.configuration.authentication[key] !==
      lifecycle.initialAuthority.authentication[key]
    )
      throw new TypeError("inconsistent recovery identity domain");
  if (
    authority.revision === 0 &&
    canonicalize(authority.configuration) !==
      canonicalize(lifecycle.initialAuthority)
  )
    throw new TypeError("inconsistent initial authority");
  for (const policy of authority.configuration.policy.targets) {
    const target = runtime.targets.find((t) => t.id === policy.id);
    if (
      !target ||
      target.revision !== policy.revision ||
      target.recipient !== policy.recipient ||
      policy.tools.some((tool) => !target.tools.includes(tool))
    )
      throw new TypeError("inconsistent recovery targets");
  }
  const body = {
    schema: /** @type {const} */ ("xeip.organization-checkpoint/1"),
    organization,
    lifecycleDigest: lifecycle.digest,
    trustDigest: hash(
      "XEIP organization trust checkpoint v1\n" +
        encodeTrustCheckpoint(trust, organization),
    ),
    authorityDigest: authority.digest,
    administrationDigest: administration.digest,
    actions,
  };
  return validateOrganizationManifest(
    { ...body, digest: organizationCheckpointDigest(body) },
    organization,
  );
}
/** Validate each body under its original limits instead of imposing a smaller aggregate cap.
 * @param {unknown} value @param {string} organization @returns {Checkpoint} */
export function validateOrganizationCheckpoint(value, organization) {
  try {
    if (
      !exact(value, [
        "manifest",
        "lifecycle",
        "trust",
        "authority",
        "administration",
      ])
    )
      throw Error();
    const manifest = validateOrganizationManifest(value.manifest, organization);
    const components = {
      lifecycle: validateLifecycleCheckpoint(value.lifecycle, organization),
      trust: Object.freeze(validateTrustCheckpoint(value.trust, organization)),
      authority: validateAuthorityCheckpoint(value.authority, organization),
      administration: validateAdminCheckpoint(
        value.administration,
        organization,
      ),
    };
    if (
      organizationManifest(components, manifest.actions).digest !==
      manifest.digest
    )
      throw Error();
    return Object.freeze({ manifest, ...components });
  } catch {
    throw new TypeError("invalid organization recovery checkpoint");
  }
}
/** @param {unknown} value @returns {{section:'actions'|'authority'|'administration',cursor:unknown}} */
export function organizationPageOptions(value) {
  const copy = snapshot(value, 1024);
  if (
    !exact(copy, ["section", "cursor"]) ||
    typeof copy.section !== "string" ||
    !["actions", "authority", "administration"].includes(copy.section)
  )
    throw new TypeError("invalid organization recovery page request");
  return /** @type {{section:'actions'|'authority'|'administration',cursor:unknown}} */ (
    copy
  );
}
