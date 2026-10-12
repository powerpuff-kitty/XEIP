/** Shared bounded recovery HTTP records. No storage or authentication authority. */
import { strictParse } from "../../../sdks/typescript/dist/identity.js";
import {
  exact,
  integer,
  recoveryOptions,
  validateHead,
  validateEntry,
  validateAppend,
  decodePart,
  genesis,
  PART_BYTES,
} from "./recovery-record.mjs";
import { StoreUnavailable } from "../errors.mjs";
export const REQUEST_BYTES = 24 * 1024 * 1024;
export const RESPONSE_BYTES = 384 * 1024;
/** @typedef {import('./recovery-record.mjs').Options} Options */
/** @param {unknown} value @returns {string} */
export function recoveryToken(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    throw new TypeError("invalid recovery transport configuration");
  return value;
}
/** @param {unknown} value @returns {string} */
export function recoveryEndpoint(value) {
  if (typeof value !== "string" || value.length > 2048)
    throw new TypeError("invalid recovery transport configuration");
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("invalid recovery transport configuration");
  }
  if (
    url.protocol !== "https:" ||
    url.href !== value ||
    url.username ||
    url.password ||
    value.includes("?") ||
    value.includes("#")
  )
    throw new TypeError("invalid recovery transport configuration");
  return value;
}
/** @param {unknown} input */
export function transportConfiguration(input) {
  const c = exact(input, ["url", "token", "options"]);
  return {
    url: recoveryEndpoint(c.url),
    token: recoveryToken(c.token),
    options: recoveryOptions(c.options),
  };
}
/** @param {unknown} operation @param {unknown} args @param {Options} o @returns {{operation:string,args:Record<string,unknown>}} */
export function command(operation, args, o) {
  if (operation === "head") return { operation, args: exact(args, []) };
  if (operation === "entry" || operation === "part") {
    const a = exact(
      args,
      operation === "entry" ? ["sequence"] : ["sequence", "part"],
    );
    const sequence = integer(a.sequence, 1, o.maxEntries);
    return {
      operation,
      args:
        operation === "entry"
          ? { sequence }
          : { sequence, part: integer(a.part, 0, 63) },
    };
  }
  if (operation === "append")
    return { operation, args: validateAppend(args, o) };
  throw new TypeError("invalid recovery operation");
}
/** @param {unknown} input @param {Options} o */
export function parseCommand(input, o) {
  const v = exact(input, [
    "schema",
    "organization",
    "stream",
    "operation",
    "args",
  ]);
  if (
    v.schema !== "xeip.recovery-http/1" ||
    v.organization !== o.organization ||
    v.stream !== o.stream
  )
    throw new TypeError("invalid recovery scope");
  return command(v.operation, v.args, o);
}
/** @param {ReturnType<typeof command>} c @param {unknown} value @param {Options} o */
export function result(c, value, o) {
  if (c.operation === "head") {
    const h = validateHead(value, o);
    if (h.sequence === 0 && h.checksum !== genesis(o))
      throw new TypeError("invalid recovery genesis");
    return h;
  }
  if (c.operation === "part") {
    const v = exact(value, ["entry", "part", "data"]),
      e = validateEntry(v.entry, o);
    if (e.sequence !== c.args.sequence || v.part !== c.args.part)
      throw new TypeError("invalid recovery cursor");
    const index = integer(v.part, 0, e.parts - 1);
    decodePart(v.data, Math.min(PART_BYTES, e.bytes - index * PART_BYTES));
    return { entry: e, part: index, data: /** @type {string} */ (v.data) };
  }
  const e = validateEntry(value, o);
  if (c.operation === "entry") {
    if (e.sequence !== c.args.sequence)
      throw new TypeError("invalid recovery cursor");
  } else {
    const a = validateAppend(c.args, o);
    if (
      e.sequence !== a.expected.sequence + 1 ||
      e.previous !== a.expected.checksum ||
      e.id !== a.id ||
      e.bytes !== a.bytes ||
      e.payloadDigest !== a.payloadDigest ||
      e.parts !== a.chunks.length
    )
      throw new TypeError("invalid recovery receipt");
  }
  return e;
}
/** One deadline covers headers, streaming body and operation; abort is advisory. */
export class WireDeadline {
  active = true;
  expires = Infinity;
  controller = new AbortController();
  /** @type {ReadableStreamDefaultReader<Uint8Array>|undefined} */ reader;
  check() {
    if (
      !this.active ||
      this.controller.signal.aborted ||
      performance.now() >= this.expires
    )
      throw new StoreUnavailable();
  }
  async checkpoint() {
    // Deployed Workers freeze clock readings during CPU work. Let due timers
    // run before relying on elapsed time or releasing a successful result.
    await new Promise((resolve) => setTimeout(resolve, 0));
    this.check();
  }
  close() {
    this.active = false;
    this.controller.abort();
    void this.reader?.cancel().catch(() => {});
  }
  /** @template T @param {Promise<T>} task @param {number} ms @param {AbortSignal} [signal] */
  async wait(task, ms, signal) {
    this.expires = performance.now() + ms;
    /** @type {ReturnType<typeof setTimeout>|undefined} */ let timer;
    /** @type {()=>void} */ let onAbort = () => {};
    try {
      const value = await Promise.race([
        task,
        new Promise((_, reject) => {
          onAbort = () => {
            this.close();
            reject(new StoreUnavailable());
          };
          timer = setTimeout(onAbort, ms);
          if (signal?.aborted) onAbort();
          else signal?.addEventListener("abort", onAbort, { once: true });
        }),
      ]);
      // An overdue timer cannot interrupt synchronous parsing/hashing work.
      await this.checkpoint();
      return value;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      this.close();
    }
  }
}
/** @param {Request|Response} message @param {number} limit @param {WireDeadline} scope */
export async function readJson(message, limit, scope) {
  scope.check();
  const length = message.headers.get("content-length"),
    encoding = message.headers.get("content-encoding"),
    transfer = message.headers.get("transfer-encoding");
  if (
    !/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?\s*$/i.test(
      message.headers.get("content-type") ?? "",
    ) ||
    (encoding !== null && encoding !== "identity") ||
    (transfer !== null &&
      !(
        message instanceof Response &&
        transfer.toLowerCase() === "chunked" &&
        length === null
      )) ||
    (length !== null &&
      (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > limit))
  )
    throw new TypeError("invalid recovery body");
  if (!message.body) throw new TypeError("invalid recovery body");
  const reader = message.body.getReader();
  scope.reader = reader;
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let text = "",
    bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    scope.check();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > limit) throw new TypeError("invalid recovery body");
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  if (length !== null && Number(length) !== bytes)
    throw new TypeError("invalid recovery length");
  // Base64 payloads can approach24MiB. Scan structural tokens rather than
  // visiting every payload character in JavaScript; strictParse below still
  // validates all JSON syntax, duplicate keys, numbers and Unicode.
  const structural = /["\\{}\[\]]/g;
  let depth = 0,
    quoted = false,
    token;
  while ((token = structural.exec(text)) !== null) {
    const c = token[0];
    if (quoted) {
      if (c === "\\")
        structural.lastIndex++; // Escape consumes one code unit.
      else if (c === '"') quoted = false;
    } else if (c === '"') quoted = true;
    else if (c === "{" || c === "[") {
      if (++depth > 16) throw new TypeError("invalid recovery depth");
    } else if (c === "}" || c === "]") depth--;
  }
  scope.check();
  try {
    const value = strictParse(text);
    scope.check();
    return value;
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new TypeError("invalid recovery JSON");
    throw error;
  }
}
/** @param {number} status @param {unknown} value */
export function jsonResponse(status, value) {
  const body = JSON.stringify(value);
  if (Buffer.byteLength(body) > RESPONSE_BYTES) throw new StoreUnavailable();
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
