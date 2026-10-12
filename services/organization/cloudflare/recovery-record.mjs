/** Strict internal byte-journal records; payloads carry no execution authority. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
export { canonicalize };
export const PART_BYTES = 262144;
export const MAX_BYTES = 16777216;
/** @typedef {{organization:string,stream:string,maxEntries:number,maxBytes:number,timeoutMs:number}} Options */
/** @typedef {{organization:string,stream:string,sequence:number,checksum:string}} Head */
/** @typedef {{schema:string,organization:string,stream:string,sequence:number,id:string,previous:string,payloadDigest:string,bytes:number,parts:number,totalBytes:number,checksum:string}} Entry */
/** @param {unknown} input @param {string[]} keys @returns {Record<string,unknown>} */
export function exact(input, keys) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw new TypeError("invalid recovery record");
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (
    Reflect.ownKeys(input).length !== keys.length ||
    keys.some(
      (k) =>
        !descriptors[k] ||
        !("value" in descriptors[k]) ||
        !descriptors[k].enumerable,
    )
  )
    throw new TypeError("invalid recovery record");
  return Object.fromEntries(keys.map((k) => [k, descriptors[k].value]));
}
/** @param {unknown} n @param {number} min @param {number} max @returns {number} */
export function integer(n, min, max) {
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max)
    throw new TypeError("invalid recovery integer");
  return n;
}
/** @param {unknown} s @param {RegExp} pattern @returns {string} */
function string(s, pattern) {
  if (typeof s !== "string" || !pattern.test(s))
    throw new TypeError("invalid recovery string");
  return s;
}
const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;
/** @param {unknown} input @returns {Options} */
export function recoveryOptions(input) {
  if (!input || typeof input !== "object")
    throw new TypeError("invalid recovery options");
  const v = exact(input, Object.keys(input));
  if (
    Object.keys(v).some(
      (k) =>
        ![
          "organization",
          "stream",
          "maxEntries",
          "maxBytes",
          "timeoutMs",
        ].includes(k),
    )
  )
    throw new TypeError("invalid recovery options");
  return {
    organization: string(
      v.organization,
      /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/,
    ),
    stream: string(v.stream, uuid),
    maxEntries: integer(v.maxEntries ?? 1000000, 1, 1000000),
    maxBytes: integer(v.maxBytes ?? 1073741824, 1, 1073741824),
    timeoutMs: integer(v.timeoutMs ?? 5000, 100, 10000),
  };
}
/** @param {string} value */
export const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {Options} o */
export const genesis = (o) =>
  hash(
    "XEIP recovery genesis v1\n" +
      canonicalize({
        schemaVersion: 1,
        organization: o.organization,
        stream: o.stream,
        maxEntries: o.maxEntries,
        maxBytes: o.maxBytes,
      }),
  );
/** @param {unknown} value @param {Options} o @returns {Head} */
export function validateHead(value, o) {
  const v = exact(value, ["organization", "stream", "sequence", "checksum"]);
  if (v.organization !== o.organization || v.stream !== o.stream)
    throw new TypeError("invalid recovery scope");
  integer(v.sequence, 0, o.maxEntries);
  string(v.checksum, digest);
  return /** @type {Head} */ (v);
}
/** @param {Omit<Entry,'checksum'>} entry @returns {Entry} */
export const sealEntry = (entry) => ({
  ...entry,
  checksum: hash("XEIP recovery entry v1\n" + canonicalize(entry)),
});
/** @param {unknown} value @param {Options} o @returns {Entry} */
export function validateEntry(value, o) {
  const v = exact(value, [
    "schema",
    "organization",
    "stream",
    "sequence",
    "id",
    "previous",
    "payloadDigest",
    "bytes",
    "parts",
    "totalBytes",
    "checksum",
  ]);
  if (
    v.schema !== "xeip.recovery-entry/1" ||
    v.organization !== o.organization ||
    v.stream !== o.stream
  )
    throw new TypeError("invalid recovery scope");
  integer(v.sequence, 1, o.maxEntries);
  string(v.id, uuid);
  string(v.previous, digest);
  string(v.payloadDigest, digest);
  string(v.checksum, digest);
  const bytes = integer(v.bytes, 1, MAX_BYTES);
  integer(v.parts, 1, 64);
  integer(v.totalBytes, bytes, o.maxBytes);
  const { checksum, ...rest } = /** @type {Entry} */ (v);
  if (
    v.parts !== Math.ceil(bytes / PART_BYTES) ||
    sealEntry(rest).checksum !== checksum
  )
    throw new TypeError("invalid recovery checksum");
  return /** @type {Entry} */ (v);
}
/** @param {unknown} data @param {number} bytes */
export function decodePart(data, bytes) {
  if (
    typeof data !== "string" ||
    data.length !== 4 * Math.ceil(bytes / 3) ||
    data.length > 349528
  )
    throw new TypeError("invalid recovery part");
  const decoded = Buffer.from(data, "base64");
  if (decoded.length !== bytes || decoded.toString("base64") !== data)
    throw new TypeError("invalid recovery part");
  return decoded;
}
/** @param {unknown} value @param {Options} o */
export function validateAppend(value, o) {
  const v = exact(value, [
    "expected",
    "id",
    "bytes",
    "payloadDigest",
    "chunks",
  ]);
  const expected = validateHead(v.expected, o),
    id = string(v.id, uuid),
    bytes = integer(v.bytes, 1, MAX_BYTES),
    payloadDigest = string(v.payloadDigest, digest);
  if (
    !Array.isArray(v.chunks) ||
    Object.getPrototypeOf(v.chunks) !== Array.prototype ||
    v.chunks.length !== Math.ceil(bytes / PART_BYTES) ||
    Reflect.ownKeys(v.chunks).length !== v.chunks.length + 1
  )
    throw new TypeError("invalid recovery chunks");
  const descriptors = Object.getOwnPropertyDescriptors(v.chunks),
    chunks = [],
    h = createHash("sha256");
  for (let i = 0; i < v.chunks.length; i++) {
    if (!descriptors[i] || !("value" in descriptors[i]))
      throw new TypeError("invalid recovery chunks");
    const data = descriptors[i].value;
    h.update(decodePart(data, Math.min(PART_BYTES, bytes - i * PART_BYTES)));
    chunks.push(/** @type {string} */ (data));
  }
  if (h.digest("hex") !== payloadDigest)
    throw new TypeError("invalid recovery payload");
  return { expected, id, bytes, payloadDigest, chunks };
}
