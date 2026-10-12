import {
  actionCursor,
  validateActionSnapshot,
  validateActionPage,
} from "./action-export.mjs";
/** Local Node operator client. No public administrator HTTP bridge or automatic retry. */
import { WireDeadline } from "./recovery-wire.mjs";
import { open, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { strictParse } from "../../../sdks/typescript/dist/identity.js";
import { parseOwnerCommand, operatorIdentity } from "./profile.mjs";
import { validateAuditPage } from "./admin-audit.mjs";
import {
  exportReceiptField,
  ownerResponseLimit,
  validateExportReceipt,
} from "./organization-export-wire.mjs";
/** @param {unknown} o @param {string[]} keys @returns {o is Record<string,unknown>} */
const exact = (o, keys) =>
  o !== null &&
  typeof o === "object" &&
  !Array.isArray(o) &&
  Object.keys(o).sort().join(",") === [...keys].sort().join(",");
/** @typedef {{name:string,compatibility_date:string,services:{binding:string,service:string,entrypoint:string,remote:boolean,props:{operator:string}}[]}} OperatorConfiguration */
/** @param {unknown} value @param {boolean} remote @returns {OperatorConfiguration} */
export function validateOperatorConfig(value, remote) {
  if (
    typeof remote !== "boolean" ||
    !exact(value, ["name", "compatibility_date", "services"]) ||
    !Array.isArray(value.services) ||
    value.services.length !== 1 ||
    typeof value.name !== "string" ||
    !/^xeip-[a-z0-9-]{1,58}$/.test(value.name) ||
    value.compatibility_date !== "2026-07-30"
  )
    throw new TypeError("invalid operator configuration");
  const binding = value.services[0];
  if (
    !exact(binding, ["binding", "service", "entrypoint", "remote", "props"]) ||
    binding.binding !== "OWNER" ||
    binding.entrypoint !== "OwnerEntrypoint" ||
    binding.remote !== remote ||
    typeof binding.service !== "string" ||
    !/^[a-z][a-z0-9-]{0,62}$/.test(binding.service) ||
    !exact(binding.props, ["operator"])
  )
    throw new TypeError("invalid owner binding");
  operatorIdentity(binding.props);
  return /** @type {OperatorConfiguration} */ (/** @type {unknown} */ (value));
}
/** @param {string} path @param {number} max */
export async function readLimited(path, max) {
  const handle = await open(path, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > max)
      throw new TypeError("invalid input file");
    const buffer = Buffer.alloc(max + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        null,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset > max) throw new TypeError("input too large");
    return new TextDecoder("utf-8", { fatal: true }).decode(
      buffer.subarray(0, offset),
    );
  } finally {
    await handle.close();
  }
}
const trustStates = [
  "opening",
  "ready",
  "empty",
  "stale",
  "updating",
  "failed",
  "closed",
];
const authorityStates = ["opening", "ready", "updating", "failed", "closed"];
/** @param {unknown} value */
const counter = (value) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
/** @param {unknown} value @param {string[]} states */
const stateIs = (value, states) =>
  typeof value === "string" && states.includes(value);
/** Validate the whole receipt before exposing any of it to operator output.
 * @param {unknown} raw
 * @param {{requestId:unknown,operation:unknown,operator:string,after?:unknown,limit?:unknown,cut?:unknown}&import('./organization-export-wire.mjs').Expected} expected
 * @returns {Record<string,unknown>}
 */
export function validateOwnerReceipt(raw, expected) {
  try {
    if (
      typeof raw !== "string" ||
      Buffer.byteLength(raw) > ownerResponseLimit(expected.operation)
    )
      throw new Error();
    const result = strictParse(raw);
    const metadata = ["operator", "requestId", "operation"];
    const correlated = (/** @type {Record<string,unknown>} */ value) =>
      value.operator === expected.operator &&
      value.requestId === expected.requestId &&
      value.operation === expected.operation;
    const exportField = exportReceiptField(expected.operation);
    if (
      exportField &&
      exact(result, ["ok", ...metadata, exportField]) &&
      result.ok === true &&
      correlated(result)
    ) {
      validateExportReceipt(result[exportField], expected);
      return result;
    }
    if (
      expected.operation === "actionSnapshot" &&
      exact(result, ["ok", ...metadata, "snapshot"]) &&
      result.ok === true &&
      correlated(result)
    ) {
      const snapshot = validateActionSnapshot(result.snapshot);
      if (expected.cut !== undefined && snapshot.cut !== expected.cut)
        throw Error();
      return result;
    }
    if (
      expected.operation === "actionPage" &&
      exact(result, ["ok", ...metadata, "page"]) &&
      result.ok === true &&
      correlated(result)
    ) {
      actionCursor(expected.cut);
      const after = expected.after ?? 0;
      actionCursor(after);
      validateActionPage(result.page, { cut: expected.cut, after });
      return result;
    }
    if (
      expected.operation === "auditExport" &&
      exact(result, ["ok", ...metadata, "audit"]) &&
      result.ok === true &&
      correlated(result)
    ) {
      validateAuditPage(result.audit, {
        ...(expected.after === undefined ? {} : { after: expected.after }),
        ...(expected.limit === undefined ? {} : { limit: expected.limit }),
      });
      return result;
    }
    if (
      ["status", "initialize", "updateAuthority", "refreshTrust"].includes(
        String(expected.operation),
      ) &&
      exact(result, ["ok", ...metadata, "status"]) &&
      result.ok === true &&
      correlated(result)
    ) {
      const status = result.status;
      if (
        !exact(status, ["state", "trust", "authority"]) ||
        !stateIs(status.state, [
          "opening",
          "uninitialized",
          "initializing",
          "initialized",
          "failed",
          "closed",
        ])
      )
        throw new Error();
      const trust = status.trust,
        authority = status.authority;
      if (
        trust !== null &&
        (!exact(trust, ["state", "entities", "revision"]) ||
          !stateIs(trust.state, trustStates) ||
          !counter(trust.entities) ||
          !(trust.revision === null || counter(trust.revision)))
      )
        throw new Error();
      if (
        authority !== null &&
        (!exact(authority, ["state", "revision", "trust"]) ||
          !stateIs(authority.state, authorityStates) ||
          !stateIs(authority.trust, trustStates) ||
          !(authority.revision === null || counter(authority.revision)))
      )
        throw new Error();
      return result;
    }
    if (
      exact(result, ["ok", "error"]) &&
      result.ok === false &&
      stateIs(result.error, ["forbidden", "invalid_request", "unavailable"])
    )
      return result;
    if (
      exact(result, ["ok", ...metadata, "error"]) &&
      result.ok === false &&
      correlated(result) &&
      stateIs(result.error, ["conflict", "invalid_request", "unavailable"])
    )
      return result;
    throw new Error();
  } catch {
    // Parser errors and target-supplied fields must not leak into logs or stdout.
    throw new Error("invalid owner response");
  }
}
/** One isolated private binding session; requests retain exact parsing and receipt checks.
 * @template T
 * @param {{configPath:string,remote?:boolean,onCleanupFailure?:()=>void}} options
 * @param {(session:{configuration:OperatorConfiguration,send:(raw:string,exportContext?:import('./organization-export-wire.mjs').ExportContext)=>Promise<Record<string,unknown>>})=>Promise<T>} run
 * @returns {Promise<T>}
 */
export async function withOwnerSession(
  { configPath, remote = false, onCleanupFailure },
  run,
) {
  const config = validateOperatorConfig(
    strictParse(await readLimited(configPath, 8192)),
    remote,
  );
  const directory = await mkdtemp(join(tmpdir(), "xeip-owner-"));
  /** @type {import("wrangler").PlatformProxy|undefined} */
  let platform;
  try {
    const isolated = join(directory, "wrangler.json");
    await writeFile(isolated, JSON.stringify(config), {
      mode: 0o600,
      flag: "wx",
    });
    // Isolate config from adjacent .env/.dev.vars and unrelated bindings. Remote mode
    // must agree with the explicit binding flag; never substitute local state.
    const { getPlatformProxy } = await import("wrangler");
    platform = await getPlatformProxy({
      configPath: isolated,
      persist: false,
      envFiles: [],
      remoteBindings: remote,
    });
    const owner = /** @type {{manage:(raw:string)=>Promise<string>}} */ (
      platform.env.OWNER
    );
    return await run({
      configuration: config,
      send: async (raw, exportContext) => {
        const command = parseOwnerCommand(raw);
        const response = await owner.manage(raw);
        return validateOwnerReceipt(response, {
          requestId: command.requestId,
          operation: command.operation,
          after: command.after,
          limit: command.limit,
          cut: command.cut,
          exportId: command.exportId,
          component: command.component,
          index: command.index,
          section: command.section,
          cursor: command.cursor,
          exportContext,
          operator: config.services[0].props.operator,
        });
      },
    });
  } finally {
    // Bound waiting, not the lifetime of a child process owned by Wrangler.
    // Export callers retain a sealed bundle while reporting unconfirmed cleanup.
    /** @param {()=>Promise<unknown>|undefined} task */
    const cleanup = async (task) => {
      try {
        await new WireDeadline().wait(Promise.resolve().then(task), 10000);
      } catch {
        if (onCleanupFailure) onCleanupFailure();
        else throw new Error("owner transport cleanup failed");
      }
    };
    try {
      await cleanup(() => platform?.dispose());
    } finally {
      await cleanup(() => rm(directory, { recursive: true, force: true }));
    }
  }
}
/** @param {{configPath:string,commandPath:string,remote?:boolean}} options */
export async function invokeOwner({ configPath, commandPath, remote = false }) {
  const raw = await readLimited(commandPath, 2097152);
  if (exportReceiptField(parseOwnerCommand(raw).operation))
    throw new TypeError("organization export requires the bundle collector");
  return withOwnerSession({ configPath, remote }, ({ send }) => send(raw));
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [configPath, commandPath, mode, ...extra] = process.argv.slice(2);
    if (
      !configPath ||
      !commandPath ||
      !["--local", "--remote"].includes(mode) ||
      extra.length
    )
      throw new Error("usage");
    const result = await invokeOwner({
      configPath,
      commandPath,
      remote: mode === "--remote",
    });
    console.log(JSON.stringify(result));
    if (!result.ok) process.exitCode = 1;
  } catch {
    console.error(
      "Owner command failed; no automatic retry. Usage: node owner.mjs OPERATOR_CONFIG.json COMMAND.json --local|--remote",
    );
    process.exitCode = 1;
  }
}
