/** Pure control-state boundary. No durability, chain-continuity or live authority claim. */
import { createHash } from "node:crypto";
import {
  canonicalize,
  strictParse,
} from "../../packages/identity/signed-envelope.mjs";
import { decodeKeyId } from "../../packages/identity/key-id.mjs";
import {
  prepareEntityTrust,
  mergeTrustRecords,
  validateTrustRecords,
} from "../../packages/identity/trust-state.mjs";
import { snapshot, ActionPolicy } from "./actions.mjs";
import { KeycloakAuthenticator } from "./auth.mjs";
import { McpConnector } from "./mcp.mjs";
import { requireUri } from "../../sdks/typescript/dist/validation.js";
/** @typedef {import('../../packages/identity/trust-state.mjs').TrustRecords} Records */
/** @typedef {Omit<import('./auth.mjs').AuthConfiguration,'introspectionClientSecret'|'allowInsecureLoopback'|'timeoutMs'|'maxTokenLifetimeSeconds'> & {maxTokenLifetimeSeconds:number}} Authentication */
/** @typedef {Omit<import('./mcp.mjs').Target,'clientSecret'|'allowInsecureLoopback'>} Target */
/** @typedef {{v:'xeip.org.authority/1',origin:string,gateway:string,authentication:Authentication,policy:import('./actions.mjs').PolicyConfiguration,targets:Target[],trust:{maxAgeSeconds:number},console?:{clientId:string}}} Authority */
/** @typedef {{value:Authority,canonical:string,digest:string}} PublicAuthority */
/** @typedef {{id:string,revision:string,digest:string}} TargetRevision */
/** @typedef {{keyDocuments:unknown[],statusDocuments:unknown[]}} Provisioning */
/** @typedef {{v:'xeip.org.control/1',authority:Authority,authorityDigest:string,provisioning:Provisioning,records:Records,targetRevisions:TargetRevision[],acceptedAt:number,operation:'enroll'|'authority'|'trust'}} State */
/** @typedef {{state:State,canonical:string,digest:string}} Prepared */
const MiB = 1024 * 1024;
const authorityKeys = [
  "v",
  "origin",
  "gateway",
  "authentication",
  "policy",
  "targets",
  "trust",
];
const authenticationKeys = [
  "issuer",
  "audience",
  "clientIds",
  "bindings",
  "introspectionClientId",
  "maxTokenLifetimeSeconds",
];
const targetKeys = [
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
];
const stateKeys = [
  "v",
  "authority",
  "authorityDigest",
  "provisioning",
  "records",
  "targetRevisions",
  "acceptedAt",
  "operation",
];
const validationSecret = "public-configuration-validation-only";
export class ControlStateError extends Error {
  constructor() {
    super("invalid organization control state");
    this.name = "ControlStateError";
  }
}
/** Inspect data properties before reading them; never invoke getters/toJSON.
 * @param {unknown} value @param {string[]} required @param {string[]} [optional]
 * @returns {Record<string,unknown>}
 */
function record(value, required, optional = []) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.getOwnPropertySymbols(value).length
  )
    throw Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    required.some((key) => !Object.hasOwn(descriptors, key)) ||
    Object.entries(descriptors).some(
      ([key, d]) =>
        (!required.includes(key) && !optional.includes(key)) ||
        !d.enumerable ||
        !Object.hasOwn(d, "value"),
    )
  )
    throw Error();
  return /** @type {Record<string,unknown>} */ (value);
}
/** @param {unknown} value @returns {unknown[]} */
function array(value) {
  if (
    !Array.isArray(value) ||
    value.length > 65536 ||
    Object.getOwnPropertySymbols(value).length
  )
    throw Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).length !== value.length + 1) throw Error();
  return Array.from({ length: value.length }, (_, i) => {
    const d = descriptors[String(i)];
    if (!d || !d.enumerable || !Object.hasOwn(d, "value")) throw Error();
    return d.value;
  });
}
/** @param {Record<string,unknown>} value @param {string[]} keys */
const pick = (value, keys) =>
  Object.fromEntries(keys.map((key) => [key, value[key]]));
/** @param {string} domain @param {string} canonical */
const digest = (domain, canonical) =>
  createHash("sha256")
    .update(domain + "\n" + canonical)
    .digest("hex");
/** @param {unknown} value */
const isDigest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
/** @param {Target} target */
const executionDigest = (target) =>
  digest(
    "XEIP organization target v1",
    canonicalize(
      pick(
        /** @type {Record<string,unknown>} */ (/** @type {unknown} */ (target)),
        targetKeys.filter((key) => !["id", "revision"].includes(key)),
      ),
    ),
  );

/** Validate public bytes independently of the protected-file loader, including offline reads.
 * @param {unknown} input @returns {PublicAuthority}
 */
function authorityValue(input) {
  const copy = snapshot(input, 4 * MiB, 262144);
  const value = /** @type {Authority} */ (
    /** @type {unknown} */ (record(copy, authorityKeys, ["console"]))
  );
  if (
    value.v !== "xeip.org.authority/1" ||
    typeof value.origin !== "string" ||
    typeof value.gateway !== "string"
  )
    throw Error();
  const origin = new URL(value.origin);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== value.origin ||
    !value.gateway.startsWith("urn:xeip:entity:")
  )
    throw Error();
  decodeKeyId(value.gateway.slice("urn:xeip:entity:".length));
  record(value.authentication, authenticationKeys);
  new KeycloakAuthenticator({
    ...value.authentication,
    introspectionClientSecret: validationSecret,
  });
  new ActionPolicy(value.policy);
  const subjects = new Set(
    value.authentication.bindings.map((binding) => binding.subject),
  );
  for (const session of value.policy.sessions) {
    requireUri(session.id, "session");
    if (
      [...session.agents, ...session.approvers].some(
        (subject) => !subjects.has(subject),
      )
    )
      throw Error();
  }
  array(value.targets).forEach((target) => record(target, targetKeys));
  new McpConnector(
    value.targets.map((target) => ({
      ...target,
      clientSecret: validationSecret,
    })),
  );
  if (
    value.targets.length !== value.policy.targets.length ||
    value.policy.targets.some((target) => {
      const actual = value.targets.find(
        (candidate) => candidate.id === target.id,
      );
      return (
        !actual ||
        actual.revision !== target.revision ||
        actual.recipient !== target.recipient ||
        canonicalize([...actual.tools].sort()) !==
          canonicalize([...target.tools].sort())
      );
    })
  )
    throw Error();
  record(value.trust, ["maxAgeSeconds"]);
  if (
    !Number.isInteger(value.trust.maxAgeSeconds) ||
    value.trust.maxAgeSeconds < 1 ||
    value.trust.maxAgeSeconds > 86400
  )
    throw Error();
  if (value.console !== undefined) {
    record(value.console, ["clientId"]);
    if (!value.authentication.clientIds.includes(value.console.clientId))
      throw Error();
  }
  const canonical = canonicalize(value);
  return Object.freeze({
    value,
    canonical,
    digest: digest("XEIP organization authority v1", canonical),
  });
}

/** Extract only public authority from a validated loadConfiguration result.
 * This does not validate excluded files, TLS or credentials; the loader still must.
 * @param {unknown} configuration @returns {PublicAuthority}
 */
export function publicAuthority(configuration) {
  try {
    const c = record(
      configuration,
      [
        "origin",
        "gateway",
        "bind",
        "tls",
        "database",
        "authentication",
        "policy",
        "targets",
        "trust",
        "provisioning",
        "management",
        "shutdownMs",
      ],
      ["console"],
    );
    const auth = record(
      c.authentication,
      authenticationKeys
        .filter((key) => key !== "maxTokenLifetimeSeconds")
        .concat("introspectionClientSecret"),
      ["maxTokenLifetimeSeconds", "timeoutMs"],
    );
    const trust = record(c.trust, [
      "directory",
      "provisioningFile",
      "maxAgeSeconds",
    ]);
    return authorityValue({
      v: "xeip.org.authority/1",
      origin: c.origin,
      gateway: c.gateway,
      authentication: {
        ...pick(
          auth,
          authenticationKeys.filter((key) => key !== "maxTokenLifetimeSeconds"),
        ),
        maxTokenLifetimeSeconds:
          auth.maxTokenLifetimeSeconds === undefined
            ? 300
            : auth.maxTokenLifetimeSeconds,
      },
      policy: c.policy,
      targets: array(c.targets).map((target) =>
        pick(record(target, [...targetKeys, "clientSecret"]), targetKeys),
      ),
      trust: { maxAgeSeconds: trust.maxAgeSeconds },
      ...(c.console === undefined ? {} : { console: c.console }),
    });
  } catch {
    throw new ControlStateError();
  }
}

/** @param {unknown} input @returns {Provisioning} */
function provision(input) {
  const p = record(snapshot(input, 8 * MiB, 262144), [
    "keyDocuments",
    "statusDocuments",
  ]);
  const keys = array(p.keyDocuments),
    statuses = array(p.statusDocuments);
  if (keys.length > 4096 || statuses.length > 4096) throw Error();
  return /** @type {Provisioning} */ (/** @type {unknown} */ (p));
}
/** @param {unknown} input @returns {Records} */
function records(input) {
  const result = validateTrustRecords(snapshot(input, 8 * MiB, 32768));
  if (
    Object.keys(result).some((entity) => [...entity].length > 2048) ||
    Buffer.byteLength(JSON.stringify({ version: 1, entities: result })) >
      8 * MiB
  )
    throw Error();
  return result;
}
/** @param {unknown} input @returns {TargetRevision[]} */
function targets(input) {
  const result = /** @type {TargetRevision[]} */ (
    /** @type {unknown} */ (snapshot(input, 8 * MiB, 262144))
  );
  const seen = new Set();
  for (const entry of array(result)) {
    const row = record(entry, ["id", "revision", "digest"]);
    if (
      typeof row.id !== "string" ||
      typeof row.revision !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(row.id) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(row.revision) ||
      !isDigest(row.digest)
    )
      throw Error();
    const key = canonicalize([row.id, row.revision]);
    if (seen.has(key)) throw Error();
    seen.add(key);
  }
  return result;
}
/** @param {State} state @returns {Prepared} */
function seal(state) {
  // Sections have their own independent node budgets; never re-snapshot the
  // combined graph with a smaller action-node cap. Every section is frozen.
  Object.freeze(state);
  const canonical = canonicalize(state);
  if (Buffer.byteLength(canonical) > 24 * MiB) throw Error();
  return Object.freeze({
    state,
    canonical,
    digest: digest("XEIP organization control state v1", canonical),
  });
}

/** Verify a historical snapshot, not its provenance, chain or current freshness.
 * @param {unknown} canonical @returns {Prepared}
 */
export function verifyControlState(canonical) {
  try {
    if (
      typeof canonical !== "string" ||
      Buffer.byteLength(canonical) > 24 * MiB
    )
      throw Error();
    const raw = record(strictParse(canonical), stateKeys);
    if (
      raw.v !== "xeip.org.control/1" ||
      !Number.isSafeInteger(raw.acceptedAt) ||
      Number(raw.acceptedAt) < 0 ||
      typeof raw.operation !== "string" ||
      !["enroll", "authority", "trust"].includes(raw.operation)
    )
      throw Error();
    const authority = authorityValue(raw.authority),
      provisioning = provision(raw.provisioning),
      retained = records(raw.records),
      history = targets(raw.targetRevisions);
    if (raw.authorityDigest !== authority.digest) throw Error();
    const prepared = prepareEntityTrust(
      authority.value.trust,
      provisioning.keyDocuments,
      provisioning.statusDocuments,
      Number(raw.acceptedAt),
    );
    for (const [entity, checkpoint] of Object.entries(prepared.checkpoints)) {
      if (
        !Object.hasOwn(retained, entity) ||
        canonicalize(retained[entity]) !== canonicalize(checkpoint)
      )
        throw Error();
    }
    for (const target of authority.value.targets) {
      const previous = history.find(
        (entry) => entry.id === target.id && entry.revision === target.revision,
      );
      if (!previous || previous.digest !== executionDigest(target))
        throw Error();
    }
    const result = seal({
      v: "xeip.org.control/1",
      authority: authority.value,
      authorityDigest: authority.digest,
      provisioning,
      records: retained,
      targetRevisions: history,
      acceptedAt: Number(raw.acceptedAt),
      operation: /** @type {State['operation']} */ (raw.operation),
    });
    if (result.canonical !== canonical) throw Error();
    return result;
  } catch {
    throw new ControlStateError();
  }
}

/** Validate a transition before any SQL writes. Previous bytes must come from the
 * authoritative store; this pure function cannot attest their provenance.
 * @param {unknown} input @returns {Prepared}
 */
export function prepareControlState(input) {
  try {
    const args = record(
      input,
      ["authority", "provisioning", "operation", "acceptedAt"],
      ["previous", "retainedRecords"],
    );
    const wrapper = record(args.authority, ["value", "canonical", "digest"]);
    const authority = authorityValue(wrapper.value);
    if (
      authority.canonical !== wrapper.canonical ||
      authority.digest !== wrapper.digest ||
      !Number.isSafeInteger(args.acceptedAt) ||
      Number(args.acceptedAt) < 0 ||
      typeof args.operation !== "string" ||
      !["enroll", "authority", "trust"].includes(args.operation)
    )
      throw Error();
    const operation = /** @type {State['operation']} */ (args.operation);
    let previous;
    if (operation === "enroll") {
      if (
        Object.hasOwn(args, "previous") ||
        !Object.hasOwn(args, "retainedRecords")
      )
        throw Error();
    } else {
      if (
        !Object.hasOwn(args, "previous") ||
        Object.hasOwn(args, "retainedRecords")
      )
        throw Error();
      previous = verifyControlState(args.previous).state;
      if (
        Number(args.acceptedAt) < previous.acceptedAt ||
        authority.value.gateway !== previous.authority.gateway ||
        (operation === "trust" && authority.digest !== previous.authorityDigest)
      )
        throw Error();
    }
    const provisioning = provision(args.provisioning);
    const prepared = prepareEntityTrust(
      authority.value.trust,
      provisioning.keyDocuments,
      provisioning.statusDocuments,
      Number(args.acceptedAt),
    );
    if (operation === "trust" && previous) {
      const prior = prepareEntityTrust(
        previous.authority.trust,
        previous.provisioning.keyDocuments,
        previous.provisioning.statusDocuments,
        previous.acceptedAt,
      );
      if (
        [...prepared.bundles.keys()].some(
          (entity) => !prior.bundles.has(entity),
        )
      )
        throw Error();
    }
    const retained = records(
      mergeTrustRecords(
        previous?.records ?? records(args.retainedRecords),
        prepared.checkpoints,
        prepared.chainDigests,
      ),
    );
    const history = [...(previous?.targetRevisions ?? [])];
    for (const target of authority.value.targets) {
      const found = history.find(
          (entry) =>
            entry.id === target.id && entry.revision === target.revision,
        ),
        hash = executionDigest(target);
      if (found && found.digest !== hash) throw Error();
      if (!found)
        history.push({
          id: target.id,
          revision: target.revision,
          digest: hash,
        });
    }
    return seal({
      v: "xeip.org.control/1",
      authority: authority.value,
      authorityDigest: authority.digest,
      provisioning,
      records: retained,
      targetRevisions: targets(history),
      acceptedAt: Number(args.acceptedAt),
      operation,
    });
  } catch {
    throw new ControlStateError();
  }
}
