/** Strict protected-file configuration for the single-organization runtime. */
import * as fs from "node:fs";
import { dirname, isAbsolute, resolve, join } from "node:path";
import { validateTrustRecords } from "../../packages/identity/trust-state.mjs";
import { isIP } from "node:net";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";
import {
  strictParse,
  decodeKeyId,
  canonicalize,
} from "../../sdks/typescript/dist/identity.js";
import { KeycloakAuthenticator } from "./auth.mjs";
import { ActionPolicy } from "./actions.mjs";
import { requireUri } from "../../sdks/typescript/dist/validation.js";
import { McpConnector } from "./mcp.mjs";
/** @typedef {import('./auth.mjs').AuthConfiguration} Auth */
/** @typedef {import('./mcp.mjs').Target} Target */
/** @typedef {{version:1,console?:{clientId:string},origin:string,gateway:string,bind:{host:string,port:number},tls:{certificateFile:string,privateKeyFile:string},database:{host:string,port:number,name:string,user:string,passwordFile:string,caFile:string,max:number},authentication:Omit<Auth,'introspectionClientSecret'|'allowInsecureLoopback'>&{introspectionClientSecretFile:string},policy:import('./actions.mjs').PolicyConfiguration,targets:(Omit<Target,'clientSecret'|'allowInsecureLoopback'>&{clientSecretFile:string})[],trust:{directory:string,provisioningFile:string,maxAgeSeconds:number},management:{host:string,port:number,tokenFile:string},shutdownMs:number}} FileConfiguration */
export class ConfigurationError extends Error {
  constructor() {
    super("invalid protected organization configuration");
    this.name = "ConfigurationError";
  }
}
/** @param {unknown} value @param {string[]} required @param {string[]} [optional]
 * @returns {asserts value is Record<string, unknown>}
 */
function exact(value, required, optional = []) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    required.some((k) => !Object.hasOwn(value, k)) ||
    Object.keys(value).some(
      (k) => !required.includes(k) && !optional.includes(k),
    )
  )
    throw new ConfigurationError();
}
/** @param {unknown} value @param {number} min @param {number} max */
function integer(value, min, max) {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  )
    throw new ConfigurationError();
}
/** @param {number} uid */
const owner = (uid) => uid === 0 || uid === process.geteuid?.();
/** Check every resolved ancestor. Root-owned sticky temporary roots are safe for owned children.
 * @param {string} directory
 */
function safeAncestors(directory) {
  let current = fs.realpathSync(directory);
  for (;;) {
    const info = fs.statSync(current);
    if (
      !info.isDirectory() ||
      !owner(info.uid) ||
      ((info.mode & 0o022) !== 0 &&
        !(info.uid === 0 && (info.mode & 0o1000) !== 0))
    )
      throw new ConfigurationError();
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
/** @param {unknown} path @param {boolean} secret @param {number} limit */
function readProtected(path, secret, limit) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path)
    throw new ConfigurationError();
  safeAncestors(dirname(path));
  const fd = fs.openSync(
    path,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  try {
    const info = fs.fstatSync(fd);
    if (
      !info.isFile() ||
      !owner(info.uid) ||
      (info.mode & (secret ? 0o077 : 0o022)) !== 0 ||
      info.size > limit
    )
      throw new ConfigurationError();
    const bytes = Buffer.alloc(limit + 1);
    let length = 0;
    for (;;) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, null);
      length += count;
      if (length > limit) throw new ConfigurationError();
      if (!count) break;
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(0, length),
    );
  } finally {
    fs.closeSync(fd);
  }
}
/** @param {string} path */
function secret(path) {
  const value = readProtected(path, true, 4096).replace(/\r?\n$/, "");
  if (!value || /[\u0000-\u001f\u007f]/.test(value))
    throw new ConfigurationError();
  return value;
}
/** @param {unknown} value */
function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
}
/** @param {string} encoded */
function json(encoded) {
  let depth = 0,
    quoted = false,
    escaped = false;
  for (const char of encoded) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "{" || char === "[") {
      if (++depth > 32) throw new ConfigurationError();
    } else if (char === "}" || char === "]") depth--;
  }
  return strictParse(encoded);
}
/** Read again for owner-driven trust reload; cryptographic validation happens before activation.
 * @param {string} path
 */
export function readProvisioning(path) {
  try {
    const value = json(readProtected(path, false, 8 * 1024 * 1024));
    exact(value, ["keyDocuments", "statusDocuments"]);
    if (
      !Array.isArray(value.keyDocuments) ||
      !Array.isArray(value.statusDocuments) ||
      value.keyDocuments.length > 4096 ||
      value.statusDocuments.length > 4096
    )
      throw new ConfigurationError();
    freeze(value);
    return {
      keyDocuments: value.keyDocuments,
      statusDocuments: value.statusDocuments,
    };
  } catch {
    throw new ConfigurationError();
  }
}
/** Validate a private checkpoint directory without creating or following it.
 * @param {string} directory @returns {boolean} whether it exists */
export function validateTrustDirectory(directory) {
  if (
    typeof directory !== "string" ||
    !isAbsolute(directory) ||
    resolve(directory) !== directory
  )
    throw new ConfigurationError();
  safeAncestors(dirname(directory));
  let info;
  try {
    info = fs.lstatSync(directory);
  } catch (error) {
    if (/** @type {NodeJS.ErrnoException} */ (error).code === "ENOENT")
      return false;
    throw new ConfigurationError();
  }
  if (!info.isDirectory() || !owner(info.uid) || (info.mode & 0o077) !== 0)
    throw new ConfigurationError();
  return true;
}
/** Caller must hold the legacy checkpoint's exclusive LOCK through use.
 * @param {string} directory */
export function readLegacyTrustRecords(directory) {
  try {
    if (!validateTrustDirectory(directory)) throw new ConfigurationError();
    const value = json(
      readProtected(join(directory, "trust.json"), false, 8 * 1024 * 1024),
    );
    exact(value, ["version", "entities"]);
    if (value.version !== 1) throw new ConfigurationError();
    const records = validateTrustRecords(value.entities);
    freeze(records);
    return records;
  } catch {
    throw new ConfigurationError();
  }
}
/** @param {FileConfiguration['database']} db @param {boolean} [owner] */
function databaseConfiguration(db, owner = false) {
  exact(db, ["host", "port", "name", "user", "passwordFile", "caFile", "max"]);
  if (
    typeof db.host !== "string" ||
    (!isIP(db.host) &&
      !/^([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(
        db.host,
      )) ||
    !/^[a-z][a-z0-9_]{0,62}$/.test(db.name) ||
    !/^[a-z][a-z0-9_]{0,62}$/.test(db.user) ||
    db.user.startsWith("pg_") ||
    (!owner && db.user === "postgres")
  )
    throw new ConfigurationError();
  integer(db.port, 1, 65535);
  integer(db.max, 1, 32);
  const ca = readProtected(db.caFile, false, 65536);
  new X509Certificate(ca);
  const database = {
    host: db.host,
    port: db.port,
    database: db.name,
    user: db.user,
    password: secret(db.passwordFile),
    ssl: { ca, rejectUnauthorized: true },
    max: db.max,
    connectionTimeoutMillis: 3000,
    query_timeout: 10000,
  };
  return database;
}
/** Explicit owner maintenance input, distinct from runtime configuration.
 * @param {string} file
 */
export function loadOwnerConfiguration(file) {
  try {
    const value = json(readProtected(file, false, 65536));
    exact(value, ["version", "database"]);
    if (value.version !== 1) throw new ConfigurationError();
    return databaseConfiguration(
      /** @type {FileConfiguration['database']} */ (value.database),
      true,
    );
  } catch {
    throw new ConfigurationError();
  }
}
/** @param {string} file */
export function loadConfiguration(file) {
  try {
    const value = /** @type {FileConfiguration} */ (
      json(readProtected(file, false, 4 * 1024 * 1024))
    );
    exact(
      value,
      [
        "version",
        "origin",
        "gateway",
        "bind",
        "tls",
        "database",
        "authentication",
        "policy",
        "targets",
        "trust",
        "management",
        "shutdownMs",
      ],
      ["console"],
    );
    if (value.version !== 1) throw new ConfigurationError();
    const origin = new URL(value.origin);
    if (
      origin.protocol !== "https:" ||
      origin.origin !== value.origin ||
      origin.username ||
      origin.password
    )
      throw new ConfigurationError();
    if (!value.gateway.startsWith("urn:xeip:entity:"))
      throw new ConfigurationError();
    decodeKeyId(value.gateway.slice("urn:xeip:entity:".length));
    exact(value.bind, ["host", "port"]);
    if (!isIP(value.bind.host)) throw new ConfigurationError();
    integer(value.bind.port, 1, 65535);
    exact(value.tls, ["certificateFile", "privateKeyFile"]);
    const tls = {
      cert: readProtected(value.tls.certificateFile, false, 65536),
      key: readProtected(value.tls.privateKeyFile, true, 16384),
    };
    const cert = new X509Certificate(tls.cert);
    if (
      !cert.checkPrivateKey(createPrivateKey(tls.key)) ||
      Date.now() < Date.parse(cert.validFrom) ||
      Date.now() >= Date.parse(cert.validTo) ||
      !(isIP(origin.hostname.replace(/^\[|\]$/g, ""))
        ? cert.checkIP(origin.hostname.replace(/^\[|\]$/g, ""))
        : cert.checkHost(origin.hostname))
    )
      throw new ConfigurationError();
    createSecureContext({ ...tls, minVersion: "TLSv1.2" });
    const database = databaseConfiguration(value.database);
    exact(
      value.authentication,
      [
        "issuer",
        "audience",
        "clientIds",
        "bindings",
        "introspectionClientId",
        "introspectionClientSecretFile",
      ],
      ["timeoutMs", "maxTokenLifetimeSeconds"],
    );
    const { introspectionClientSecretFile, ...auth } = value.authentication;
    const authentication = {
      ...auth,
      introspectionClientSecret: secret(introspectionClientSecretFile),
    };
    new KeycloakAuthenticator(authentication);
    if (value.console !== undefined) {
      exact(value.console, ["clientId"]);
      if (
        typeof value.console.clientId !== "string" ||
        !authentication.clientIds.includes(value.console.clientId)
      )
        throw new ConfigurationError();
    }
    new ActionPolicy(value.policy);
    for (const session of value.policy.sessions)
      requireUri(session.id, "policy session");
    const subjects = new Set(
      authentication.bindings.map((binding) => binding.subject),
    );
    if (
      value.policy.sessions.some((session) =>
        [...session.agents, ...session.approvers].some(
          (subject) => !subjects.has(subject),
        ),
      )
    )
      throw new ConfigurationError();
    if (!Array.isArray(value.targets)) throw new ConfigurationError();
    const targets = value.targets.map((target) => {
      exact(target, [
        "id",
        "revision",
        "recipient",
        "tools",
        "endpoint",
        "resourceMetadataUrl",
        "issuer",
        "tokenEndpoint",
        "clientId",
        "clientSecretFile",
        "scope",
      ]);
      const { clientSecretFile, ...publicTarget } = target;
      return { ...publicTarget, clientSecret: secret(clientSecretFile) };
    });
    new McpConnector(targets);
    if (
      targets.length !== value.policy.targets.length ||
      value.policy.targets.some((target) => {
        const match = targets.find((candidate) => candidate.id === target.id);
        return (
          !match ||
          target.revision !== match.revision ||
          target.recipient !== match.recipient ||
          canonicalize([...target.tools].sort()) !==
            canonicalize([...match.tools].sort())
        );
      })
    )
      throw new ConfigurationError();
    exact(value.trust, ["directory", "provisioningFile", "maxAgeSeconds"]);
    validateTrustDirectory(value.trust.directory);
    integer(value.trust.maxAgeSeconds, 1, 86400);
    const provisioning = readProvisioning(value.trust.provisioningFile);
    exact(value.management, ["host", "port", "tokenFile"]);
    if (!["127.0.0.1", "::1"].includes(value.management.host))
      throw new ConfigurationError();
    integer(value.management.port, 1, 65535);
    if (value.management.port === value.bind.port)
      throw new ConfigurationError();
    const management = {
      host: value.management.host,
      port: value.management.port,
      token: secret(value.management.tokenFile),
    };
    if (management.token.length < 32) throw new ConfigurationError();
    integer(value.shutdownMs, 1000, 120000);
    const configuration = {
      origin: value.origin,
      gateway: value.gateway,
      bind: value.bind,
      tls,
      database,
      authentication,
      policy: value.policy,
      targets,
      trust: value.trust,
      provisioning,
      management,
      shutdownMs: value.shutdownMs,
      ...(value.console ? { console: value.console } : {}),
    };
    freeze(configuration);
    return configuration;
  } catch {
    throw new ConfigurationError();
  }
}
