/** Public source-side recovery configuration, never credentials or namespace creation. */
import { exact, recoveryOptions } from "./recovery-record.mjs";
import { recoveryEndpoint } from "./recovery-wire.mjs";
/** @typedef {{url:string,stream:string,maxEntries?:number,maxBytes?:number,timeoutMs?:number}} RecoveryProfile */
/** @param {unknown} input @param {string} organization */
export function recoveryConfiguration(input, organization) {
  if (!input || typeof input !== "object")
    throw new TypeError("invalid recovery profile");
  const p = exact(input, Object.keys(input));
  if (
    Object.keys(p).some(
      (k) =>
        !["url", "stream", "maxEntries", "maxBytes", "timeoutMs"].includes(k),
    )
  )
    throw new TypeError("invalid recovery profile");
  for (const key of ["maxEntries", "maxBytes", "timeoutMs"])
    if (Object.hasOwn(p, key) && p[key] == null)
      throw new TypeError("invalid recovery profile");
  const { url, ...options } = p;
  return {
    url: recoveryEndpoint(url),
    options: recoveryOptions({ ...options, organization }),
  };
}
