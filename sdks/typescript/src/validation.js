/** Dependency-free wire validation shared by the SDK, browser console and local relay. */
/**
 * Wire versions this implementation can read. Advertising and negotiation are
 * defined by `spec/versioning.md`; the base schema pins `xeip` to `"0.1"`. The
 * tuple is a `const` assertion so `XEIP_SUPPORTED_VERSIONS[0]` keeps the literal
 * type `"0.1"` (and therefore so does `XEIP_VERSION`) rather than widening to
 * `string`.
 * @type {readonly ["0.1"]}
 */
export const XEIP_SUPPORTED_VERSIONS = Object.freeze(/** @type {const} */ (["0.1"]));
const kinds = ["human", "agent", "machine", "service"];
const transports = ["http-sse", "http", "websocket", "local", "webrtc", "a2a", "mcp"];
/** @param {unknown} value @param {string} label @returns {Record<string, unknown>} */
const record = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(label + " must be an object");
  return /** @type {Record<string, unknown>} */ (value);
};
/** @param {Record<string, unknown>} value @param {readonly string[]} allowed */
function fields(value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new TypeError("unexpected field: " + key);
  }
}
/** @param {unknown} value @param {string} label @param {number} min @param {number} max @returns {asserts value is string} */
function string(value, label, min = 1, max = Infinity) {
  if (typeof value !== "string") throw new TypeError(label + " must be a string");
  const length = Array.from(value).length;
  if (length < min || length > max) throw new TypeError(label + " has invalid length");
}
// A version is well-formed when it is a `MAJOR.MINOR` pair of decimal integers.
// Well-formed but unsupported versions get a distinct error from malformed ones.
const versionPattern = /^\d+\.\d+$/;
/** @param {unknown} value */
function version(value) {
  if (typeof value !== "string") throw new TypeError("xeip must be a string");
  if (!versionPattern.test(value)) throw new TypeError("malformed xeip version");
  if (!XEIP_SUPPORTED_VERSIONS.some(supported => supported === value)) throw new TypeError("unsupported version");
}
/** @param {unknown} value @param {readonly string[]} allowed @param {string} label */
function member(value, allowed, label) {
  if (typeof value !== "string" || !allowed.includes(value)) throw new TypeError("invalid " + label);
}

// RFC 3986 syntax, without WHATWG URL's whitespace trimming and percent-encoding repairs.
const pchar = "(?:[a-z0-9._~!$&'()*+,;=:@-]|%[0-9a-f]{2})";
const pathPattern = new RegExp("^(?:" + pchar + "|/)*$", "i");
const queryPattern = new RegExp("^(?:" + pchar + "|[/?])*$", "i");
const userPattern = /^(?:[a-z0-9._~!$&'()*+,;=:-]|%[0-9a-f]{2})*$/i;
const hostPattern = /^(?:[a-z0-9._~!$&'()*+,;=-]|%[0-9a-f]{2})*$/i;
/** @param {string} value */
function ipLiteral(value) {
  if (/^v[0-9a-f]+\.[a-z0-9._~!$&'()*+,;=:-]+$/i.test(value)) return true;
  let address = value;
  if (address.includes(".")) {
    const at = address.lastIndexOf(":");
    const octets = address.slice(at + 1).split(".");
    if (octets.length !== 4 || octets.some(n => !/^(?:0|[1-9][0-9]{0,2})$/.test(n) || Number(n) > 255)) return false;
    address = address.slice(0, at + 1) + "0:0";
  }
  const halves = address.split("::");
  if (halves.length > 2) return false;
  const groups = halves.flatMap(half => half === "" ? [] : half.split(":"));
  if (groups.some(group => !/^[0-9a-f]{1,4}$/i.test(group))) return false;
  return halves.length === 2 ? groups.length < 8 : groups.length === 8;
}
/** @param {unknown} value @param {string} label */
export function requireUri(value, label = "URI") {
  string(value, label);
  const match = !/[^\x21-\x7e]/.test(value) && /^([a-z][a-z0-9+.-]*):(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i.exec(value);
  let valid = Boolean(match);
  if (match) {
    const [, , authority, path = "", query = "", fragment = ""] = match;
    valid = pathPattern.test(path) && queryPattern.test(query) && queryPattern.test(fragment);
    if (authority !== undefined) {
      const at = authority.lastIndexOf("@");
      const user = at < 0 ? "" : authority.slice(0, at);
      const host = /^(?:\[([^\]]+)\]|([^:]*))(?::[0-9]*)?$/.exec(authority.slice(at + 1));
      valid = valid && userPattern.test(user) && Boolean(host) &&
        (host?.[1] !== undefined ? ipLiteral(host[1]) : hostPattern.test(host?.[2] ?? ""));
    }
  }
  if (!valid) throw new TypeError(label + " must be absolute URI");
}

/** @param {unknown} value @param {string} label */
export function requireUtc(value, label = "timestamp") {
  string(value, label);
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/.exec(value);
  if (match) {
    const year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
    const hour = Number(match[4]), minute = Number(match[5]), second = Number(match[6]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [0, 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (month >= 1 && month <= 12 && day >= 1 && day <= (days[month] ?? 0) && hour < 24 && minute < 60 &&
        (second < 60 || (second === 60 && hour === 23 && minute === 59))) return;
  }
  throw new TypeError(label + " must be UTC RFC3339 date-time");
}

/** @param {unknown} value */
function jsonValue(value) {
  const ancestors = new Set();
  const stack = [{ value, exit: false }];
  while (stack.length) {
    const next = stack.pop();
    if (!next) break;
    const item = next.value;
    if (next.exit) { ancestors.delete(item); continue; }
    if (item === null || typeof item === "string" || typeof item === "boolean") continue;
    if (typeof item === "number" && Number.isFinite(item)) continue;
    if (typeof item !== "object" || ancestors.has(item) ||
        (!Array.isArray(item) && Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null)) {
      throw new TypeError("data must contain JSON values without cycles");
    }
    ancestors.add(item);
    stack.push({ value: item, exit: true });
    for (const child of Array.isArray(item) ? item : Object.values(item)) stack.push({ value: child, exit: false });
  }
}
/** @param {unknown} value */
function extensions(value) {
  if (value !== undefined) { record(value, "extensions"); jsonValue(value); }
}

/** @param {unknown} value */
export function validateEnvelope(value) {
  const e = record(value, "envelope");
  fields(e, ["xeip", "id", "kind", "sender", "recipient", "session", "timestamp", "body", "replyTo", "expiresAt", "extensions"]);
  version(e.xeip);
  requireUri(e.id, "id");
  member(e.kind, ["message", "event", "command", "receipt"], "kind");
  requireUri(e.sender, "sender"); requireUri(e.session, "session");
  if (e.recipient !== undefined) requireUri(e.recipient, "recipient");
  if (e.replyTo !== undefined) requireUri(e.replyTo, "replyTo");
  requireUtc(e.timestamp, "timestamp");
  if (e.expiresAt !== undefined) requireUtc(e.expiresAt, "expiresAt");
  const body = record(e.body, "body");
  fields(body, ["contentType", "data"]);
  string(body.contentType, "body.contentType", 1, 255);
  if (!Object.hasOwn(body, "data")) throw new TypeError("body.data missing");
  jsonValue(body.data);
  extensions(e.extensions);
}
/** @param {unknown} value */
export function validateCapability(value) {
  const cap = record(value, "capability");
  fields(cap, ["id", "description", "spec"]);
  string(cap.id, "capability.id", 1, 128);
  if (!/^[a-z][a-z0-9]*(?:[.:-][a-z0-9-]+)*$/.test(cap.id)) throw new TypeError("invalid capability id");
  if (cap.description !== undefined) string(cap.description, "capability.description", 0, 1024);
  if (cap.spec !== undefined) requireUri(cap.spec, "capability.spec");
}
/** @param {unknown} value */
export function validateEntity(value) {
  const e = record(value, "entity");
  fields(e, ["xeip", "id", "name", "kinds", "endpoints", "capabilities", "extensions"]);
  version(e.xeip); requireUri(e.id, "id");
  if (e.name !== undefined) string(e.name, "name", 1, 256);
  if (!Array.isArray(e.kinds) || !e.kinds.length || new Set(e.kinds).size !== e.kinds.length) throw new TypeError("invalid entity kinds");
  for (const kind of e.kinds) member(kind, kinds, "entity kind");
  if (e.endpoints !== undefined) {
    if (!Array.isArray(e.endpoints)) throw new TypeError("endpoints must be array");
    for (const raw of e.endpoints) {
      const endpoint = record(raw, "endpoint");
      fields(endpoint, ["transport", "url"]);
      member(endpoint.transport, transports, "endpoint transport");
      requireUri(endpoint.url, "endpoint.url");
    }
  }
  if (e.capabilities !== undefined) {
    if (!Array.isArray(e.capabilities)) throw new TypeError("capabilities must be array");
    for (const cap of e.capabilities) validateCapability(cap);
  }
  extensions(e.extensions);
}
/** @param {unknown} value */
export function validateSession(value) {
  const s = record(value, "session");
  fields(s, ["xeip", "id", "mode", "members", "createdAt", "extensions"]);
  version(s.xeip); requireUri(s.id, "id");
  member(s.mode, ["direct", "group"], "session mode");
  if (!Array.isArray(s.members) || new Set(s.members).size !== s.members.length) throw new TypeError("invalid session members");
  for (const id of s.members) requireUri(id, "members");
  requireUtc(s.createdAt, "createdAt");
  extensions(s.extensions);
}
