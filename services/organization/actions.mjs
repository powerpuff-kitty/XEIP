/** Pure policy only. Callers must independently authenticate and verify live entity trust. */
import { createHash } from "node:crypto";
import {
  canonicalize,
  decodeKeyId,
} from "../../sdks/typescript/dist/identity.js";

/** @typedef {import('./types.js').Json} Json */
/** @typedef {import('./contracts.js').OrganizationPrincipal} Principal */
/** @typedef {{id: string, revision: string, recipient: string, tools: string[]}} Target */
/** @typedef {{id: string, agents: string[], approvers: string[], targets: string[]}} Session */
/** @typedef {{targets: Target[], sessions: Session[]}} PolicyConfiguration */
/** @typedef {import('./contracts.js').ActionRequest} ActionRequest */
/** @typedef {import('./contracts.js').Action} Action */
/** @typedef {import('./contracts.js').Proposal} Proposal */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
const record = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value @returns {value is string} */
const text = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 256 &&
  !/[\u0000-\u001f\u007f]/.test(value);
/** @param {unknown} value @returns {value is string} */
const id = (value) =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
/** @param {unknown} value @param {string[]} keys */
const exact = (value, keys) =>
  record(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
/** @param {string} value */
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
/** @param {unknown} value */
function entity(value) {
  if (!text(value) || !value.startsWith("urn:xeip:entity:")) return false;
  try {
    decodeKeyId(value.slice("urn:xeip:entity:".length));
    return true;
  } catch {
    return false;
  }
}
/** Copy only JSON data without invoking getters, toJSON or coercion. Reject cycles by depth/node limits.
 * @param {unknown} value @param {number} [maxBytes] @param {number} [maxNodes] @returns {Json}
 */
export function snapshot(value, maxBytes = 65536, maxNodes = 8192) {
  if (!Number.isSafeInteger(maxNodes) || maxNodes < 1 || maxNodes > 262144)
    throw new TypeError("invalid JSON node budget");
  let nodes = 0;
  /** @param {unknown} item @param {number} depth @returns {Json} */
  function visit(item, depth) {
    if (++nodes > maxNodes || depth > 32) throw new TypeError("JSON limit");
    if (item === null || typeof item === "boolean" || typeof item === "string")
      return item;
    if (typeof item === "number" && Number.isFinite(item)) return item;
    if (typeof item !== "object" || item === null)
      throw new TypeError("invalid JSON");
    const array = Array.isArray(item);
    if (
      !array &&
      ![Object.prototype, null].includes(Object.getPrototypeOf(item))
    )
      throw new TypeError("invalid JSON object");
    const descriptors = Object.getOwnPropertyDescriptors(item);
    if (Object.getOwnPropertySymbols(item).length)
      throw new TypeError("invalid JSON symbol");
    /** @type {Json[] | {[key: string]: Json}} */
    const result = array ? [] : Object.create(null);
    const keys = Object.keys(descriptors);
    if (array && (item.length > maxNodes || keys.length !== item.length + 1))
      throw new TypeError("invalid JSON array");
    for (const key of keys) {
      if (array && key === "length") continue;
      const property = descriptors[key];
      if (
        !property ||
        !Object.hasOwn(property, "value") ||
        !property.enumerable
      )
        throw new TypeError("invalid JSON property");
      if (
        array &&
        (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= item.length)
      )
        throw new TypeError("invalid JSON index");
      Object.defineProperty(result, key, {
        value: visit(property.value, depth + 1),
        enumerable: true,
      });
    }
    return Object.freeze(result);
  }
  const result = visit(value, 0);
  if (Buffer.byteLength(canonicalize(result)) > maxBytes)
    throw new TypeError("JSON byte limit");
  return result;
}
/** @param {unknown} value @param {(value: unknown) => boolean} valid */
const list = (value, valid) =>
  Array.isArray(value) &&
  value.length <= 1024 &&
  value.every(valid) &&
  new Set(value).size === value.length;

export class PolicyDenied extends Error {
  constructor() {
    super("action not permitted");
    this.name = "PolicyDenied";
  }
}

export class ActionPolicy {
  /** @type {Map<string, Target>} */
  #targets = new Map();
  /** @type {Map<string, Session>} */
  #sessions = new Map();
  #revision;
  /** @param {PolicyConfiguration} configuration */
  constructor(configuration) {
    const copy = snapshot(configuration, 262144);
    if (!exact(copy, ["targets", "sessions"]))
      throw new TypeError("invalid policy");
    const c = /** @type {PolicyConfiguration} */ (
      /** @type {unknown} */ (copy)
    );
    if (
      !Array.isArray(c.targets) ||
      !Array.isArray(c.sessions) ||
      c.targets.length > 256 ||
      c.sessions.length > 1024
    )
      throw new TypeError("invalid policy");
    for (const target of c.targets) {
      if (
        !exact(target, ["id", "revision", "recipient", "tools"]) ||
        !id(target.id) ||
        !id(target.revision) ||
        !entity(target.recipient) ||
        !list(target.tools, id) ||
        this.#targets.has(target.id)
      )
        throw new TypeError("invalid target");
      this.#targets.set(target.id, target);
    }
    for (const session of c.sessions) {
      if (
        !exact(session, ["id", "agents", "approvers", "targets"]) ||
        !id(session.id) ||
        !list(session.agents, text) ||
        !list(session.approvers, text) ||
        !list(
          session.targets,
          (value) => id(value) && this.#targets.has(value),
        ) ||
        this.#sessions.has(session.id)
      )
        throw new TypeError("invalid session");
      this.#sessions.set(session.id, session);
    }
    this.#revision = sha256(
      "XEIP organization policy v1\n" + canonicalize(copy),
    );
  }
  get revision() {
    return this.#revision;
  }
  /** Read-only recovery is independent of old action expiry or policy revision.
   * @param {Principal} principal @param {Proposal} proposal @param {number} [now]
   */
  canInspect(principal, proposal, now = Math.floor(Date.now() / 1000)) {
    try {
      this.#principal(
        principal,
        principal.roles.includes("agent") ? "agent" : "approver",
        now,
      );
      const copy = /** @type {Proposal} */ (
        /** @type {unknown} */ (snapshot(proposal, 70656))
      );
      const a = copy.action;
      if (
        !exact(copy, ["action", "digest"]) ||
        a.v !== "xeip.action/1" ||
        !id(a.session) ||
        !record(a.actor) ||
        copy.digest !==
          sha256("XEIP organization action v1\n" + canonicalize(a))
      )
        return false;
      const session = this.#sessions.get(a.session);
      return (
        !!session &&
        ((principal.roles.includes("agent") &&
          session.agents.includes(principal.subject) &&
          a.actor.subject === principal.subject &&
          a.actor.entity === principal.entity) ||
          (principal.roles.includes("approver") &&
            session.approvers.includes(principal.subject)))
      );
    } catch {
      return false;
    }
  }
  /** @param {Principal} principal @param {string} role @param {number} now */
  #principal(principal, role, now) {
    if (
      !Number.isSafeInteger(now) ||
      now < 0 ||
      !record(principal) ||
      !text(principal.subject) ||
      !entity(principal.entity) ||
      !text(principal.kid) ||
      !Array.isArray(principal.roles) ||
      !principal.roles.includes(role) ||
      !Number.isSafeInteger(principal.expiresAt) ||
      principal.expiresAt <= now
    )
      throw new PolicyDenied();
    decodeKeyId(principal.kid);
  }
  /** @param {Principal} principal @param {ActionRequest} request @param {number} [now] @returns {Proposal} */
  propose(principal, request, now = Math.floor(Date.now() / 1000)) {
    try {
      this.#principal(principal, "agent", now);
      const input = /** @type {ActionRequest} */ (
        /** @type {unknown} */ (snapshot(request, 67584))
      );
      if (
        !exact(input, [
          "id",
          "session",
          "target",
          "tool",
          "arguments",
          "expiresAt",
        ]) ||
        ![input.id, input.session, input.target, input.tool].every(id) ||
        !record(input.arguments) ||
        !Number.isSafeInteger(input.expiresAt) ||
        input.expiresAt <= now ||
        input.expiresAt > now + 300
      )
        throw new PolicyDenied();
      snapshot(input.arguments);
      const session = this.#sessions.get(input.session),
        target = this.#targets.get(input.target);
      if (
        !session?.agents.includes(principal.subject) ||
        !target ||
        !session.targets.includes(target.id) ||
        !target.tools.includes(input.tool)
      )
        throw new PolicyDenied();
      const action = /** @type {Action} */ (
        /** @type {unknown} */ (
          snapshot(
            {
              v: "xeip.action/1",
              id: input.id,
              session: input.session,
              actor: {
                subject: principal.subject,
                entity: principal.entity,
                kid: principal.kid,
              },
              target: {
                id: target.id,
                revision: target.revision,
                recipient: target.recipient,
              },
              tool: input.tool,
              arguments: input.arguments,
              expiresAt: input.expiresAt,
              policy: this.#revision,
            },
            69632,
          )
        )
      );
      return Object.freeze({
        action,
        digest: sha256("XEIP organization action v1\n" + canonicalize(action)),
      });
    } catch {
      throw new PolicyDenied();
    }
  }
  /** Reconstruct under current policy before trusting stored or caller-supplied action content.
   * @param {Proposal} proposal @param {number} now @returns {Action}
   */
  #current(proposal, now) {
    const copy = /** @type {Proposal} */ (
      /** @type {unknown} */ (snapshot(proposal, 70656))
    );
    if (!exact(copy, ["action", "digest"])) throw new PolicyDenied();
    const a = copy.action;
    const rebuilt = this.propose(
      { ...a.actor, clientId: "", roles: ["agent"], expiresAt: a.expiresAt },
      {
        id: a.id,
        session: a.session,
        target: a.target.id,
        tool: a.tool,
        arguments: a.arguments,
        expiresAt: a.expiresAt,
      },
      now,
    );
    if (
      copy.digest !== rebuilt.digest ||
      canonicalize(a) !== canonicalize(rebuilt.action)
    )
      throw new PolicyDenied();
    return rebuilt.action;
  }
  /** Policy eligibility only; does not persist approval or authenticate principal.
   * @param {Principal} principal @param {Proposal} proposal @param {number} [now]
   */
  canApprove(principal, proposal, now = Math.floor(Date.now() / 1000)) {
    try {
      this.#principal(principal, "approver", now);
      const action = this.#current(proposal, now);
      return (
        !!this.#sessions
          .get(action.session)
          ?.approvers.includes(principal.subject) &&
        principal.subject !== action.actor.subject &&
        principal.entity !== action.actor.entity
      );
    } catch {
      return false;
    }
  }
  /** Policy eligibility only; the durable store must separately consume an approved claim.
   * @param {Principal} principal @param {Proposal} proposal @param {number} [now]
   */
  canExecute(principal, proposal, now = Math.floor(Date.now() / 1000)) {
    try {
      this.#principal(principal, "agent", now);
      const action = this.#current(proposal, now);
      return (
        principal.subject === action.actor.subject &&
        principal.entity === action.actor.entity &&
        principal.kid === action.actor.kid
      );
    } catch {
      return false;
    }
  }
}
