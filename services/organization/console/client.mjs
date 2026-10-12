/** Browser action review and signed decisions. No enrollment or execution API. */
import {
  canonicalize,
  strictParse,
  decodeKeyId,
} from "../../../sdks/typescript/dist/identity.js";
import { signEntityEnvelope } from "../../../sdks/typescript/dist/entity-envelope.js";
/** @typedef {import('../contracts.js').ActionInspection} Review */
/** @typedef {{subject:string,entity:string,kid:string}} Principal */
/** @typedef {{token:string,subject:string,expiresAt:number}} Token */
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value @param {string[]} names @returns {value is Record<string,unknown>} */
const exact = (value, names) =>
  object(value) &&
  Object.keys(value).length === names.length &&
  names.every((name) => Object.hasOwn(value, name));
/** @param {unknown} value @returns {value is string} */
const id = (value) =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
/** @param {unknown} value @returns {value is string} */
const digest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
/** @param {unknown} value @returns {value is string} */
function keyId(value) {
  try {
    return typeof value === "string" && decodeKeyId(value).length === 32;
  } catch {
    return false;
  }
}
/** @param {unknown} value @returns {value is string} */
const entity = (value) =>
  typeof value === "string" &&
  value.startsWith("urn:xeip:entity:") &&
  keyId(value.slice(16));
/** @param {unknown} value @returns {value is string} */
const subject = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 256 &&
  !/[\u0000-\u001f\u007f]/.test(value);
const states = [
  "pending",
  "approved",
  "rejected",
  "revoked",
  "executing",
  "succeeded",
  "failed",
  "indeterminate",
];
const now = () => Math.floor(Date.now() / 1000);
/** @param {number} seconds */
const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
/** @param {unknown} value */
function freeze(value) {
  if (object(value) || Array.isArray(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
}

export class ApprovalClientError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "ApprovalClientError";
    this.code = code;
  }
}
/** @param {AbortSignal} signal */
function alive(signal) {
  if (signal.aborted) throw new ApprovalClientError("unavailable");
}

/** Read and parse only bounded, strict JSON; never expose raw transport errors.
 * @param {Response} response @param {AbortSignal} signal
 */
export async function readResponse(response, signal) {
  if (
    !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
      response.headers.get("content-type") ?? "",
    )
  ) {
    await response.body?.cancel();
    throw new ApprovalClientError("invalid_response");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new ApprovalClientError("invalid_response");
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  let length = 0;
  /** @type {Uint8Array[]} */ const chunks = [];
  try {
    for (;;) {
      alive(signal);
      const { done, value } = await reader.read();
      alive(signal);
      if (done) break;
      length += value.length;
      if (length > 262144) throw new ApprovalClientError("invalid_response");
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    let quoted = false,
      escaped = false,
      depth = 0;
    for (const character of text) {
      if (quoted) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') quoted = false;
      } else if (character === '"') quoted = true;
      else if (character === "{" || character === "[") {
        if (++depth > 48) throw new ApprovalClientError("invalid_response");
      } else if (character === "}" || character === "]") depth--;
    }
    return strictParse(text);
  } catch (error) {
    alive(signal);
    throw new ApprovalClientError("invalid_response");
  } finally {
    signal.removeEventListener("abort", cancel);
    await reader.cancel().catch(() => {});
  }
}

/** @param {unknown} value @param {string} session @param {string} requestId @param {string} [expectedDigest] @returns {Promise<Review>} */
async function validateReview(value, session, requestId, expectedDigest) {
  if (
    !exact(value, ["state", "proposal", "result"]) ||
    !states.includes(/** @type {string} */ (value.state)) ||
    !exact(value.proposal, ["action", "digest"]) ||
    !digest(value.proposal.digest)
  )
    throw new ApprovalClientError("invalid_response");
  const a = value.proposal.action;
  if (
    !exact(a, [
      "v",
      "id",
      "session",
      "actor",
      "target",
      "tool",
      "arguments",
      "expiresAt",
      "policy",
    ]) ||
    a.v !== "xeip.action/1" ||
    a.id !== requestId ||
    a.session !== session ||
    !id(a.tool) ||
    !object(a.arguments) ||
    !Number.isSafeInteger(a.expiresAt) ||
    /** @type {number} */ (a.expiresAt) < 0 ||
    !digest(a.policy) ||
    !exact(a.actor, ["subject", "entity", "kid"]) ||
    !subject(a.actor.subject) ||
    !entity(a.actor.entity) ||
    !keyId(a.actor.kid) ||
    !exact(a.target, ["id", "revision", "recipient"]) ||
    !id(a.target.id) ||
    !id(a.target.revision) ||
    !entity(a.target.recipient)
  )
    throw new ApprovalClientError("invalid_response");
  const hash = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        "XEIP organization action v1\n" + canonicalize(a),
      ),
    ),
  );
  const calculated = Array.from(hash, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  if (
    calculated !== value.proposal.digest ||
    (expectedDigest !== undefined && calculated !== expectedDigest)
  )
    throw new ApprovalClientError("invalid_response");
  freeze(value);
  return /** @type {Review} */ (/** @type {unknown} */ (value));
}

export class ApprovalClient {
  #origin;
  #gateway;
  #principal;
  #key;
  #token;
  #fetch;
  #timeout;
  #closed = false;
  #busy = false;
  /** @type {Review|null} */ #review = null;
  /** @type {AbortController|undefined} */ #abort;
  /** @param {{origin:string,gateway:string,principal:Principal,privateKey:CryptoKey,token:()=>Promise<Token>,fetch?:typeof fetch,timeoutMs?:number}} configuration */
  constructor({
    origin,
    gateway,
    principal,
    privateKey,
    token,
    fetch: transport = globalThis.fetch,
    timeoutMs = 15000,
  }) {
    const url = new URL(origin);
    if (
      url.protocol !== "https:" ||
      url.origin !== origin ||
      !entity(gateway) ||
      !subject(principal?.subject) ||
      !entity(principal?.entity) ||
      !keyId(principal?.kid) ||
      privateKey?.type !== "private" ||
      privateKey.algorithm.name !== "Ed25519" ||
      privateKey.extractable ||
      !privateKey.usages.includes("sign") ||
      typeof token !== "function" ||
      typeof transport !== "function" ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 60000
    )
      throw new TypeError("invalid approval client configuration");
    this.#origin = origin;
    this.#gateway = gateway;
    this.#principal = Object.freeze({
      subject: principal.subject,
      entity: principal.entity,
      kid: principal.kid,
    });
    this.#key = privateKey;
    this.#token = token;
    this.#fetch = transport.bind(globalThis);
    this.#timeout = timeoutMs;
  }

  close() {
    this.#closed = true;
    this.#review = null;
    this.#abort?.abort();
  }

  /** @param {string} session @param {string} requestId */
  async inspect(session, requestId) {
    if (!id(session) || !id(requestId))
      throw new ApprovalClientError("invalid_request");
    return this.#request("inspect", session, requestId);
  }

  /** @param {Review} review @param {'approve'|'reject'} decision */
  async decide(review, decision) {
    if (!["approve", "reject"].includes(decision))
      throw new ApprovalClientError("invalid_request");
    return this.#change(review, decision);
  }

  /** @param {Review} review */
  async revoke(review) {
    return this.#change(review, "revoke");
  }

  /** @param {Review} review @param {'approve'|'reject'|'revoke'} operation */
  async #change(review, operation) {
    if (!review || review !== this.#review)
      throw new ApprovalClientError("review_required");
    const eligible = () => {
      const a = review.proposal.action;
      if (
        a.expiresAt <= now() ||
        !(operation === "revoke"
          ? ["pending", "approved"].includes(review.state)
          : review.state === "pending") ||
        (operation !== "revoke" &&
          (a.actor.subject === this.#principal.subject ||
            a.actor.entity === this.#principal.entity))
      )
        throw new ApprovalClientError("not_actionable");
    };
    eligible();
    return this.#request(
      operation,
      review.proposal.action.session,
      review.proposal.action.id,
      review.proposal.digest,
      eligible,
    );
  }

  /** @param {string} operation @param {string} session @param {string} requestId @param {string} [expectedDigest] @param {()=>void} [eligible] */
  async #request(
    operation,
    session,
    requestId,
    expectedDigest,
    eligible = () => {},
  ) {
    if (this.#closed) throw new ApprovalClientError("unavailable");
    if (this.#busy) throw new ApprovalClientError("busy");
    this.#busy = true;
    this.#review = null;
    const abort = new AbortController();
    this.#abort = abort;
    const timer = setTimeout(() => abort.abort(), this.#timeout);
    const interrupted = new Promise((_, reject) =>
      abort.signal.addEventListener(
        "abort",
        () => reject(new ApprovalClientError("unavailable")),
        { once: true },
      ),
    );
    try {
      const work = async () => {
        const credential = await this.#token();
        alive(abort.signal);
        if (credential?.subject !== this.#principal.subject) {
          this.#closed = true;
          throw new ApprovalClientError("session_changed");
        }
        if (
          typeof credential.token !== "string" ||
          !credential.token ||
          credential.token.length > 16384 ||
          /\s|[\u0000-\u001f\u007f]/.test(credential.token) ||
          !Number.isSafeInteger(credential.expiresAt) ||
          credential.expiresAt <= now()
        )
          throw new ApprovalClientError("unauthenticated");
        eligible();
        const issued = now(),
          expires = Math.min(issued + 60, credential.expiresAt);
        const envelope = await signEntityEnvelope(
          {
            xeip: "0.1",
            id: "urn:uuid:" + crypto.randomUUID(),
            kind: "command",
            sender: this.#principal.entity,
            recipient: this.#gateway,
            session,
            timestamp: utc(issued),
            expiresAt: utc(expires),
            body: {
              contentType: "application/vnd.xeip.organization-action+json",
              data: {
                operation,
                session,
                id: requestId,
                ...(expectedDigest !== undefined
                  ? { digest: expectedDigest }
                  : {}),
              },
            },
          },
          { privateKey: this.#key, kid: this.#principal.kid },
        );
        alive(abort.signal);
        eligible();
        if (expires <= now()) throw new ApprovalClientError("unauthenticated");
        const response = await this.#fetch(this.#origin + "/v1/actions", {
          method: "POST",
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          signal: abort.signal,
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer " + credential.token,
          },
          body: JSON.stringify(envelope),
        });
        alive(abort.signal);
        if (response.status !== 200) {
          await response.body?.cancel();
          throw new ApprovalClientError(
            response.status === 401
              ? "unauthenticated"
              : response.status === 403
                ? "forbidden"
                : response.status === 409
                  ? "conflict"
                  : response.status === 429
                    ? "busy"
                    : "unavailable",
          );
        }
        const review = await validateReview(
          await readResponse(response, abort.signal),
          session,
          requestId,
          expectedDigest,
        );
        alive(abort.signal);
        const expectedState =
          operation === "approve"
            ? "approved"
            : operation === "reject"
              ? "rejected"
              : operation === "revoke"
                ? "revoked"
                : null;
        if (expectedState !== null && review.state !== expectedState)
          throw new ApprovalClientError("invalid_response");
        return review;
      };
      const review = /** @type {Review} */ (
        await Promise.race([work(), interrupted])
      );
      this.#review = review;
      return review;
    } catch (error) {
      throw error instanceof ApprovalClientError
        ? error
        : new ApprovalClientError("unavailable");
    } finally {
      clearTimeout(timer);
      abort.abort();
      this.#abort = undefined;
      this.#busy = false;
    }
  }
}
