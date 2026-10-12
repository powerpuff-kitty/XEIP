import { actionCursor } from "./action-export.mjs";
import {
  exportReceiptField,
  exportIdentifier,
  exportPartRequest,
  exportPageRequest,
} from "./organization-export-wire.mjs";
/** Production boundary: public profile and runtime secrets are deliberately separate. */
import {
  strictParse,
  decodeKeyId,
} from "../../../sdks/typescript/dist/identity.js";
import { snapshot, ActionPolicy } from "../actions.mjs";
import { requireUri } from "../../../sdks/typescript/dist/validation.js";
import { prepareEntityTrust } from "../../../packages/identity/trust-state.mjs";
import { McpConnector } from "../mcp.mjs";
import { KeycloakAuthenticator } from "../auth.mjs";
import { validateTrustFeed, validateFeedToken } from "./refresh.mjs";
import { auditPageOptions } from "./admin-audit.mjs";
import { recoveryConfiguration } from "./recovery-configuration.mjs";
import { recoveryToken } from "./recovery-wire.mjs";
/** @typedef {Omit<import('./service.mjs').Configuration,'targets'|'introspectionClientSecret'|'trustFeedToken'|'recoveryToken'> & {targets:Omit<import('../mcp.mjs').Target,'clientSecret'|'allowInsecureLoopback'>[]}} Profile */
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value @param {string[]} required @param {string[]} [optional] */
function fields(value, required, optional = []) {
  if (
    !object(value) ||
    required.some((k) => !Object.hasOwn(value, k)) ||
    Object.keys(value).some((k) => ![...required, ...optional].includes(k))
  )
    throw new TypeError("invalid configuration");
}
/** @param {unknown} raw @param {number} max @param {number} [maxNodes] @returns {Record<string,unknown>} */
function parse(raw, max, maxNodes = 8192) {
  if (typeof raw !== "string" || Buffer.byteLength(raw) > max)
    throw new TypeError("invalid configuration");
  const value = snapshot(strictParse(raw), max, maxNodes);
  if (!object(value)) throw new TypeError("invalid configuration");
  return value;
}
/** @param {unknown} value */
function secret(value) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 4096 ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    throw new TypeError("invalid credentials");
  return value;
}
/** @param {unknown} raw @returns {Profile} */
export function parseProfile(raw) {
  const p = parse(raw, 5120);
  fields(
    p,
    ["organization", "origin", "gateway", "trust", "targets"],
    ["timeoutMs", "trustFeed", "recovery"],
  );
  if (
    typeof p.organization !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(p.organization) ||
    typeof p.gateway !== "string" ||
    !p.gateway.startsWith("urn:xeip:entity:")
  )
    throw new TypeError("invalid profile");
  decodeKeyId(p.gateway.slice("urn:xeip:entity:".length));
  if (Object.hasOwn(p, "recovery"))
    recoveryConfiguration(p.recovery, p.organization);
  if (typeof p.origin !== "string") throw new TypeError("invalid origin");
  const origin = new URL(p.origin);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== p.origin ||
    origin.username ||
    origin.password
  )
    throw new TypeError("invalid origin");
  if (
    p.timeoutMs !== undefined &&
    (!Number.isInteger(p.timeoutMs) ||
      Number(p.timeoutMs) < 100 ||
      Number(p.timeoutMs) > 10000)
  )
    throw new TypeError("invalid timeout");
  prepareEntityTrust(
    /** @type {import('../../../packages/identity/trust-state.mjs').TrustConfiguration} */ (
      p.trust
    ),
    [],
    [],
    0,
  );
  if (Object.hasOwn(p, "trustFeed")) {
    validateTrustFeed(p.trustFeed);
    if (
      Number(/** @type {{maxAgeSeconds:number}} */ (p.trust).maxAgeSeconds) <
      180
    )
      throw new TypeError("trust age too short for feed");
  }
  if (!Array.isArray(p.targets)) throw new TypeError("invalid targets");
  for (const target of p.targets)
    fields(target, [
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
    ]);
  const profile = /** @type {Profile} */ (/** @type {unknown} */ (p));
  new McpConnector(
    profile.targets.map((t) => ({ ...t, clientSecret: "validation-only" })),
  );
  return profile;
}
/** @param {{XEIP_PROFILE?:unknown,XEIP_CREDENTIALS?:unknown}} env @returns {import('./service.mjs').Configuration} */
export function runtimeConfiguration(env) {
  const profile = parseProfile(env.XEIP_PROFILE),
    credentials = parse(env.XEIP_CREDENTIALS, 5120);
  fields(credentials, [
    "introspectionClientSecret",
    "targets",
    ...(profile.trustFeed ? ["trustFeedToken"] : []),
    ...(profile.recovery ? ["recoveryToken"] : []),
  ]);
  fields(
    credentials.targets,
    profile.targets.map((t) => t.id),
  );
  const targets = /** @type {Record<string,unknown>} */ (credentials.targets);
  return {
    ...profile,
    introspectionClientSecret: secret(credentials.introspectionClientSecret),
    ...(profile.recovery
      ? { recoveryToken: recoveryToken(credentials.recoveryToken) }
      : {}),
    ...(profile.trustFeed
      ? { trustFeedToken: validateFeedToken(credentials.trustFeedToken) }
      : {}),
    targets: profile.targets.map((t) => ({
      ...t,
      clientSecret: secret(targets[t.id]),
    })),
  };
}
/** @param {unknown} props */
export function operatorIdentity(props) {
  if (
    !object(props) ||
    typeof props.operator !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/.test(props.operator)
  )
    throw new TypeError("invalid operator binding");
  return props.operator;
}
/** @param {unknown} raw @returns {Record<string,unknown>} */
export function parseOwnerCommand(raw) {
  const c = parse(raw, 2097152, 262144);
  const operation = c.operation;
  if (
    typeof c.requestId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      c.requestId,
    )
  )
    throw new TypeError("invalid request id");
  if (exportReceiptField(operation)) {
    const keys = ["operation", "requestId"];
    if (operation !== "organizationExportBegin") {
      keys.push("exportId");
      exportIdentifier(c.exportId);
    }
    if (operation === "organizationExportPart") {
      keys.push("component", "index");
      exportPartRequest(c.component, c.index);
    } else if (operation === "organizationExportPage") {
      keys.push("section", "cursor");
      exportPageRequest(c.section, c.cursor);
    }
    fields(c, keys);
  } else if (operation === "status") fields(c, ["operation", "requestId"]);
  else if (operation === "actionSnapshot") {
    fields(c, ["operation", "requestId"], ["cut"]);
    if (c.cut !== undefined) actionCursor(c.cut);
  } else if (operation === "actionPage") {
    fields(c, ["operation", "requestId", "cut", "after"]);
    actionCursor(c.cut);
    actionCursor(c.after);
  } else if (operation === "auditExport") {
    fields(c, ["operation", "requestId"], ["after", "limit"]);
    auditPageOptions({
      ...(c.after === undefined ? {} : { after: c.after }),
      ...(c.limit === undefined ? {} : { limit: c.limit }),
    });
  } else if (operation === "initialize" || operation === "updateAuthority") {
    fields(c, [
      "operation",
      "requestId",
      "configuration",
      ...(operation === "updateAuthority" ? ["expectedRevision"] : []),
    ]);
    fields(c.configuration, ["authentication", "policy"]);
    const config = /** @type {import('./authority.mjs').Configuration} */ (
      c.configuration
    );
    if (
      !object(config.authentication) ||
      Object.hasOwn(config.authentication, "allowInsecureLoopback") ||
      Object.hasOwn(config.authentication, "introspectionClientSecret")
    )
      throw new TypeError("invalid authentication");
    new KeycloakAuthenticator({
      ...config.authentication,
      introspectionClientSecret: "validation-only",
    });
    new ActionPolicy(config.policy);
    for (const session of config.policy.sessions)
      requireUri(session.id, "policy session");
  } else if (operation === "refreshTrust")
    fields(c, ["operation", "requestId", "provisioning", "expectedRevision"]);
  else throw new TypeError("invalid operation");
  if (operation === "updateAuthority" || operation === "refreshTrust") {
    if (
      !Number.isSafeInteger(c.expectedRevision) ||
      Number(c.expectedRevision) < 0
    )
      throw new TypeError("invalid revision");
  }
  return c;
}
