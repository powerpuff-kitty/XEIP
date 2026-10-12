/** Signed request orchestration. Network exposure and upstream execution are separate adapters. */
import { assertEnvelope } from "../../sdks/typescript/dist/index.js";
import {
  strictParse,
  decodeKeyId,
} from "../../sdks/typescript/dist/identity.js";
import { wholeUtcSeconds } from "../../sdks/typescript/dist/entity-envelope.js";
import { PolicyDenied } from "./actions.mjs";
import { StoreConflict } from "./errors.mjs";
import { liveActionAuthorizer } from "./authorization.mjs";
/** @typedef {import('./contracts.js').OrganizationPrincipal} Principal */
/** @typedef {import('../../sdks/typescript/dist/index.js').Envelope} Envelope */
/** @typedef {import('./contracts.js').Authorizer} Authorizer */
/** @typedef {import('./contracts.js').ActionLedger} Store */
/** @typedef {{allows: (principal: {entity:string,kid:string}) => boolean, verify: (envelope: Envelope) => {valid: boolean}}} Trust */
/** @typedef {{operation: string, session: string, id: string, digest?: string, request?: import('./actions.mjs').ActionRequest}} Command */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value @param {string[]} names */
const exact = (value, names) =>
  object(value) &&
  Object.keys(value).length === names.length &&
  names.every((name) => Object.hasOwn(value, name));

export class OperationError extends Error {
  /** @param {number} status @param {string} code */
  constructor(status, code) {
    super(code);
    this.name = "OperationError";
    this.status = status;
    this.code = code;
  }
}
/** @param {unknown} value */
function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
}
/** @param {unknown} encoded @returns {Envelope} */
function parse(encoded) {
  try {
    if (typeof encoded !== "string" || Buffer.byteLength(encoded) > 98304)
      throw new Error();
    let quoted = false,
      escaped = false,
      depth = 0;
    for (const character of encoded) {
      if (quoted) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') quoted = false;
      } else if (character === '"') quoted = true;
      else if (character === "{" || character === "[") {
        if (++depth > 32) throw new Error();
      } else if (character === "}" || character === "]") depth--;
    }
    const value = strictParse(encoded);
    assertEnvelope(value);
    freeze(value);
    return value;
  } catch {
    throw new OperationError(400, "invalid_request");
  }
}
/** @param {Envelope} envelope @returns {Command} */
function commandOf(envelope) {
  const data = envelope.body.data;
  if (
    envelope.kind !== "command" ||
    envelope.body.contentType !==
      "application/vnd.xeip.organization-action+json" ||
    !object(data)
  )
    throw new OperationError(400, "invalid_request");
  const operation = data.operation;
  if (operation === "propose") {
    if (
      !exact(data, ["operation", "request"]) ||
      !object(data.request) ||
      !exact(data.request, [
        "id",
        "session",
        "target",
        "tool",
        "arguments",
        "expiresAt",
      ]) ||
      data.request.id !== envelope.id ||
      data.request.session !== envelope.session
    )
      throw new OperationError(400, "invalid_request");
    return /** @type {Command} */ (/** @type {unknown} */ (data));
  }
  if (
    !["approve", "reject", "revoke", "execute", "inspect"].includes(
      /** @type {string} */ (operation),
    ) ||
    !exact(
      data,
      operation === "inspect"
        ? ["operation", "session", "id"]
        : ["operation", "session", "id", "digest"],
    ) ||
    data.session !== envelope.session ||
    typeof data.id !== "string" ||
    data.id.length > 128 ||
    !data.id ||
    (operation !== "inspect" &&
      (typeof data.digest !== "string" || !/^[a-f0-9]{64}$/.test(data.digest)))
  )
    throw new OperationError(400, "invalid_request");
  return /** @type {Command} */ (/** @type {unknown} */ (data));
}

export class OrganizationController {
  #authentication;
  #trust;
  #gateway;
  #createStore;
  #execute;
  /** @param {{authentication: import('./contracts.js').Authentication, trust: Trust, gateway: string, createStore: (authorize: Authorizer) => Store, execute?: (principal: Principal, command: Command, context: {store:Store,authorize:Authorizer,signal?:AbortSignal,current:()=>boolean}) => Promise<import('./contracts.js').ActionInspection>}} configuration */
  constructor({ authentication, trust, gateway, createStore, execute }) {
    if (
      typeof gateway !== "string" ||
      !gateway.startsWith("urn:xeip:entity:") ||
      typeof createStore !== "function" ||
      (execute !== undefined && typeof execute !== "function")
    )
      throw new TypeError("invalid organization controller configuration");
    decodeKeyId(gateway.slice("urn:xeip:entity:".length));
    this.#authentication = authentication;
    this.#trust = trust;
    this.#gateway = gateway;
    this.#createStore = createStore;
    this.#execute = execute;
  }
  /** @param {Envelope} envelope @param {Principal} principal */
  #usable(envelope, principal) {
    const now = Math.floor(Date.now() / 1000),
      issued = wholeUtcSeconds(envelope.timestamp),
      expiry = wholeUtcSeconds(envelope.expiresAt);
    const proof = envelope.extensions?.["xeip.sig"];
    return (
      envelope.sender === principal.entity &&
      envelope.recipient === this.#gateway &&
      object(proof) &&
      proof.kid === principal.kid &&
      issued !== null &&
      expiry !== null &&
      issued <= now &&
      now - issued <= 60 &&
      expiry > now &&
      expiry <= now + 60 &&
      this.#trust.allows(principal) &&
      this.#trust.verify(envelope).valid
    );
  }
  /** Accept only a bounded, encoded JSON envelope; snapshot it before any asynchronous work.
   * @param {unknown} authorization @param {unknown} encoded @param {{signal?:AbortSignal}} [options]
   */
  async handle(authorization, encoded, { signal } = {}) {
    /** @type {Principal | null} */
    let principal = null;
    try {
      if (signal?.aborted) throw new OperationError(503, "unavailable");
      const envelope = parse(encoded),
        command = commandOf(envelope);
      principal = await this.#authentication.authenticate(authorization);
      if (!principal) throw new OperationError(401, "unauthenticated");
      if (!this.#usable(envelope, principal))
        throw new OperationError(403, "forbidden");
      const authenticated = principal;
      const live = liveActionAuthorizer(this.#authentication, this.#trust);
      /** @type {Authorizer} */
      const authorize = async (candidate, context) =>
        !signal?.aborted &&
        candidate === authenticated &&
        this.#usable(envelope, candidate) &&
        (await live(candidate, context)) &&
        !signal?.aborted &&
        this.#usable(envelope, candidate);
      const store = this.#createStore(authorize);
      /** @type {import('./contracts.js').ActionInspection} */
      let result;
      if (command.operation === "propose")
        result = await store.propose(
          principal,
          /** @type {import('./actions.mjs').ActionRequest} */ (
            command.request
          ),
        );
      else if (command.operation === "inspect")
        result = await store.inspect(principal, command.session, command.id);
      else if (
        command.operation === "approve" ||
        command.operation === "reject"
      )
        result = await store.decide(
          principal,
          command.session,
          command.id,
          /** @type {string} */ (command.digest),
          command.operation === "approve" ? "approve" : "reject",
        );
      else if (command.operation === "revoke")
        result = await store.revoke(
          principal,
          command.session,
          command.id,
          /** @type {string} */ (command.digest),
        );
      else {
        if (!this.#execute) throw new OperationError(503, "unavailable");
        result = await this.#execute(principal, command, {
          store,
          authorize,
          signal,
          current: () =>
            !signal?.aborted && this.#usable(envelope, authenticated),
        });
      }
      // The internal claim capability must never become public response authority.
      return {
        state: result.state,
        proposal: result.proposal,
        ...(Object.hasOwn(result, "result") ? { result: result.result } : {}),
      };
    } catch (error) {
      if (error instanceof OperationError) throw error;
      if (error instanceof PolicyDenied)
        throw new OperationError(403, "forbidden");
      if (error instanceof StoreConflict)
        throw new OperationError(409, "conflict");
      throw new OperationError(503, "unavailable");
    } finally {
      if (principal) this.#authentication.release(principal);
    }
  }
}
