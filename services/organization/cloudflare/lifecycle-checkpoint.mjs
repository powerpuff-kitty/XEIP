/** Historical setup intent; never a live configuration loader or activation permission. */
import { createHash } from "node:crypto";
import {
  canonicalize,
  decodeKeyId,
} from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { McpConnector } from "../mcp.mjs";
import { prepareEntityTrust } from "../../../packages/identity/trust-state.mjs";
import { validatePublicAuthority } from "./authority-checkpoint.mjs";
import { validateTrustFeed } from "./refresh.mjs";
import { recoveryDescriptor } from "./action-recovery.mjs";
import { recoveryEndpoint } from "./recovery-wire.mjs";
/** @typedef {Omit<import('../mcp.mjs').Target,'clientSecret'>} PublicTarget */
/** @typedef {{organization:string,origin:string,gateway:string,trust:import('../../../packages/identity/trust-state.mjs').TrustConfiguration,targets:PublicTarget[],trustFeed?:import('./refresh.mjs').TrustFeed,recovery?:ReturnType<typeof recoveryDescriptor>&{url?:string}}} Runtime */
/** @typedef {{schema:'xeip.lifecycle-checkpoint/1',organization:string,runtime:Runtime,initialAuthority:import('./authority.mjs').Configuration,phase:'initializing'|'initialized',checksum:string,digest:string}} Checkpoint */
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  object(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((k) => Object.hasOwn(value, k));
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {string} runtime @param {string} authority */
export const lifecycleChecksum = (runtime, authority) =>
  hash("XEIP organization lifecycle v1\n" + canonicalize([runtime, authority]));
/** @param {Omit<Checkpoint,'digest'>} value */
export const lifecycleCheckpointDigest = (value) =>
  hash("XEIP lifecycle checkpoint v1\n" + canonicalize(value));
/** Public persisted runtime projection. No credentials, network calls or storage writes.
 * @param {unknown} value @param {string} organization @returns {Runtime} */
export function validatePublicRuntime(value, organization) {
  const copy = snapshot(value, 2097152, 16384);
  if (
    typeof organization !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization) ||
    !object(copy) ||
    !exact(copy, [
      "organization",
      "origin",
      "gateway",
      "trust",
      "targets",
      ...(Object.hasOwn(copy, "trustFeed") ? ["trustFeed"] : []),
      ...(Object.hasOwn(copy, "recovery") ? ["recovery"] : []),
    ]) ||
    copy.organization !== organization ||
    typeof copy.origin !== "string" ||
    typeof copy.gateway !== "string" ||
    !copy.gateway.startsWith("urn:xeip:entity:")
  )
    throw new TypeError("invalid public runtime");
  const origin = new URL(copy.origin);
  if (
    origin.origin !== copy.origin ||
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password
  )
    throw new TypeError("invalid public origin");
  decodeKeyId(copy.gateway.slice("urn:xeip:entity:".length));
  const runtime = /** @type {Runtime} */ (/** @type {unknown} */ (copy));
  prepareEntityTrust(runtime.trust, [], [], 0);
  if (
    !Array.isArray(copy.targets) ||
    copy.targets.some(
      (target) =>
        !object(target) ||
        !exact(target, [
          "id",
          "revision",
          "recipient",
          "tools",
          "endpoint",
          "resourceMetadataUrl",
          "issuer",
          "tokenEndpoint",
          "clientId",
          "scope",
          ...(Object.hasOwn(target, "allowInsecureLoopback")
            ? ["allowInsecureLoopback"]
            : []),
        ]),
    )
  )
    throw new TypeError("invalid public targets");
  // The shortest valid sentinel preserves the existing per-target byte limit.
  new McpConnector(
    runtime.targets.map((target) => ({ ...target, clientSecret: "x" })),
  );
  if (Object.hasOwn(copy, "trustFeed")) {
    validateTrustFeed(copy.trustFeed);
    if (runtime.trust.maxAgeSeconds < 180)
      throw new TypeError("trust age too short for feed");
  }
  if (Object.hasOwn(copy, "recovery")) {
    const recovery = copy.recovery;
    if (
      !object(recovery) ||
      !exact(recovery, [
        "organization",
        "stream",
        "maxEntries",
        "maxBytes",
        "genesis",
        ...(Object.hasOwn(recovery, "url") ? ["url"] : []),
      ]) ||
      recovery.organization !== organization
    )
      throw new TypeError("invalid public recovery scope");
    const { genesis, url, ...options } = recovery;
    const expected = recoveryDescriptor(options);
    if (canonicalize({ ...options, genesis }) !== canonicalize(expected))
      throw new TypeError("invalid public recovery binding");
    if (Object.hasOwn(recovery, "url")) recoveryEndpoint(url);
  }
  return runtime;
}
/** @param {unknown} value @param {string} organization @returns {Checkpoint} */
export function validateLifecycleCheckpoint(value, organization) {
  try {
    const copy = snapshot(value, 2099200, 32768);
    if (
      !exact(copy, [
        "schema",
        "organization",
        "runtime",
        "initialAuthority",
        "phase",
        "checksum",
        "digest",
      ]) ||
      copy.schema !== "xeip.lifecycle-checkpoint/1" ||
      copy.organization !== organization ||
      typeof copy.phase !== "string" ||
      !["initializing", "initialized"].includes(copy.phase) ||
      typeof copy.checksum !== "string" ||
      typeof copy.digest !== "string"
    )
      throw Error();
    const runtime = validatePublicRuntime(copy.runtime, organization),
      initialAuthority = validatePublicAuthority(copy.initialAuthority);
    for (const policy of initialAuthority.policy.targets) {
      const target = runtime.targets.find((t) => t.id === policy.id);
      if (
        !target ||
        target.revision !== policy.revision ||
        target.recipient !== policy.recipient ||
        policy.tools.some((tool) => !target.tools.includes(tool))
      )
        throw Error();
    }
    const encodedRuntime = canonicalize(runtime),
      encodedAuthority = canonicalize(initialAuthority);
    if (
      Buffer.byteLength(encodedRuntime) + Buffer.byteLength(encodedAuthority) >
        2097152 ||
      copy.checksum !== lifecycleChecksum(encodedRuntime, encodedAuthority)
    )
      throw Error();
    const { digest, ...body } = copy;
    if (
      digest !==
      lifecycleCheckpointDigest(
        /** @type {Omit<Checkpoint,'digest'>} */ (
          /** @type {unknown} */ (body)
        ),
      )
    )
      throw Error();
    return /** @type {Checkpoint} */ (/** @type {unknown} */ (copy));
  } catch {
    throw new TypeError("invalid historical lifecycle checkpoint");
  }
}
