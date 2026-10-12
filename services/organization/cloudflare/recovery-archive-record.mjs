/** Platform-neutral recovery bundle format. No filesystem or activation authority. */
import { createHash } from "node:crypto";
import { recoveryEndpoint } from "./recovery-wire.mjs";
import {
  canonicalize,
  exact,
  integer,
  recoveryOptions,
  genesis,
  validateHead,
} from "./recovery-record.mjs";
/** @typedef {import('./recovery-record.mjs').Head} Head */
/** @typedef {import('./recovery-record.mjs').Entry} Entry */
/** @typedef {{url:string,options:Omit<import('./recovery-record.mjs').Options,'timeoutMs'>}} Source */
/** @typedef {{head:Head,manifestChecksum:string}} Witness */
/** @typedef {{schema:string,source:Source,head:Head,totalBytes:number,filesChecksum:string,previous:Witness|null,manifestChecksum:string}} Manifest */
export const RECOVERY_FILE_BYTES = 24 * 1024 * 1024;
/** @param {string|Uint8Array} value */
export const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {unknown} value */
const digest = (value) =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
/** @param {number} index */
export const recoveryFilename = (index) =>
  String(index).padStart(7, "0") + ".json";
export const filesHasher = () =>
  createHash("sha256").update("XEIP recovery archive files v1\n");
/** @param {Omit<Manifest,'manifestChecksum'>} value */
export const seal = (value) =>
  hash("XEIP recovery archive v1\n" + canonicalize(value));
/** @param {unknown} value @returns {Source} */
export function sourceCopy(value) {
  const v = exact(value, ["url", "options"]);
  const { timeoutMs, ...options } = recoveryOptions(v.options);
  return { url: recoveryEndpoint(v.url), options };
}
/** @param {unknown} value @returns {Manifest} */
export function manifestValue(value) {
  const v = exact(value, [
    "schema",
    "source",
    "head",
    "totalBytes",
    "filesChecksum",
    "previous",
    "manifestChecksum",
  ]);
  if (
    v.schema !== "xeip.recovery-archive/1" ||
    !digest(v.filesChecksum) ||
    !digest(v.manifestChecksum)
  )
    throw Error();
  const source = sourceCopy(v.source),
    options = recoveryOptions(source.options),
    head = validateHead(v.head, options);
  if (canonicalize(source) !== canonicalize(v.source)) throw Error();
  integer(v.totalBytes, 0, options.maxBytes);
  if (
    head.sequence === 0 &&
    (head.checksum !== genesis(options) || v.totalBytes !== 0)
  )
    throw Error();
  if (v.previous !== null) {
    const prior = exact(v.previous, ["head", "manifestChecksum"]);
    const previous = validateHead(prior.head, options);
    if (
      !digest(prior.manifestChecksum) ||
      previous.sequence > head.sequence ||
      (previous.sequence === 0 && previous.checksum !== genesis(options))
    )
      throw Error();
  }
  const m = /** @type {Manifest} */ (/** @type {unknown} */ (v)),
    { manifestChecksum, ...data } = m;
  if (seal(data) !== manifestChecksum) throw Error();
  return m;
}
