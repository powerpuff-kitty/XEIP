/** Bounded storage representation only; the trust adapter verifies canonical signed content. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
/** @typedef {{revision:number,part:number,data:string}} Chunk */
const PART_BYTES = 262144;
const MAX_BYTES = 8388608;
const schema = "xeip.trust-chunks/1";
/** @param {string|Uint8Array} bytes */
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
/** @param {unknown} value @returns {asserts value is number} */
function revisionValue(value) {
  if (!Number.isSafeInteger(value) || Number(value) < 0)
    throw Error("invalid trust revision");
}
/** Accepts already canonical provisioning from the signed trust validator.
 * @param {string} canonical @param {number} revision
 * @returns {{stored:string,chunks:Chunk[]}}
 */
export function encodeProvisioning(canonical, revision) {
  revisionValue(revision);
  if (typeof canonical !== "string") throw Error("invalid trust content");
  const bytes = Buffer.from(canonical, "utf8");
  if (
    !bytes.length ||
    bytes.length > MAX_BYTES ||
    bytes.toString("utf8") !== canonical
  )
    throw Error("invalid trust content");
  if (bytes.length <= PART_BYTES) return { stored: canonical, chunks: [] };
  /** @type {Chunk[]} */ const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += PART_BYTES)
    chunks.push({
      revision,
      part: chunks.length,
      data: bytes.subarray(offset, offset + PART_BYTES).toString("base64"),
    });
  return {
    stored: canonicalize({
      schema,
      bytes: bytes.length,
      parts: chunks.length,
      digest: hash(bytes),
    }),
    chunks,
  };
}
/** Resolve a persisted row before canonical/signature/checkpoint checks. No repair.
 * @param {string} stored @param {number} revision @param {Record<string,unknown>[]} chunks
 * @returns {string}
 */
export function resolveProvisioning(stored, revision, chunks) {
  revisionValue(revision);
  if (
    typeof stored !== "string" ||
    Buffer.byteLength(stored) > MAX_BYTES ||
    !Array.isArray(chunks) ||
    chunks.length > 32
  )
    throw Error("invalid trust representation");
  const descriptor = JSON.parse(stored);
  if (
    !descriptor ||
    typeof descriptor !== "object" ||
    Array.isArray(descriptor) ||
    !Object.hasOwn(descriptor, "schema")
  ) {
    if (chunks.length) throw Error("orphan trust chunks");
    return stored;
  }
  if (
    Object.keys(descriptor).sort().join(",") !== "bytes,digest,parts,schema" ||
    descriptor.schema !== schema ||
    canonicalize(descriptor) !== stored ||
    !Number.isSafeInteger(descriptor.bytes) ||
    descriptor.bytes <= PART_BYTES ||
    descriptor.bytes > MAX_BYTES ||
    descriptor.parts !== Math.ceil(descriptor.bytes / PART_BYTES) ||
    chunks.length !== descriptor.parts ||
    typeof descriptor.digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(descriptor.digest)
  )
    throw Error("invalid trust descriptor");
  const buffers = chunks.map((row, part) => {
    if (
      !row ||
      typeof row !== "object" ||
      Object.keys(row).sort().join(",") !== "data,part,revision" ||
      row.revision !== revision ||
      row.part !== part ||
      typeof row.data !== "string" ||
      row.data.length > 349528
    )
      throw Error("invalid trust chunk");
    const bytes = Buffer.from(row.data, "base64");
    if (
      bytes.toString("base64") !== row.data ||
      bytes.length !==
        Math.min(PART_BYTES, descriptor.bytes - part * PART_BYTES)
    )
      throw Error("invalid trust chunk");
    return bytes;
  });
  const bytes = Buffer.concat(buffers);
  if (bytes.length !== descriptor.bytes || hash(bytes) !== descriptor.digest)
    throw Error("invalid trust content");
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
    bytes,
  );
}
