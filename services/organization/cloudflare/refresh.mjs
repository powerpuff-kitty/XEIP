/** Bounded signed-data transport. It never initializes state or owns signing keys. */
import { strictParse } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
/** @typedef {{url:string,timeoutMs?:number}} TrustFeed */
/** @param {unknown} value @returns {TrustFeed} */
export function validateTrustFeed(value) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("invalid trust feed");
  const f = /** @type {Record<string,unknown>} */ (value);
  if (
    Object.keys(f).some((k) => !["url", "timeoutMs"].includes(k)) ||
    typeof f.url !== "string" ||
    f.url.length > 2048
  )
    throw new TypeError("invalid trust feed");
  const url = new URL(f.url);
  if (
    url.protocol !== "https:" ||
    url.href !== f.url ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    f.url.includes("?") ||
    f.url.includes("#")
  )
    throw new TypeError("invalid trust feed");
  if (
    Object.hasOwn(f, "timeoutMs") &&
    (!Number.isInteger(f.timeoutMs) ||
      Number(f.timeoutMs) < 100 ||
      Number(f.timeoutMs) > 10000)
  )
    throw new TypeError("invalid trust feed");
  return /** @type {TrustFeed} */ (f);
}
/** @param {unknown} token @returns {string} */
export function validateFeedToken(token) {
  if (
    typeof token !== "string" ||
    !/^[A-Za-z0-9._~+\/-]+=*$/.test(token) ||
    token.length > 4096
  )
    throw new TypeError("invalid feed credential");
  return token;
}
/** @param {TrustFeed} configuration @param {string} token @param {typeof fetch} [request] */
export async function fetchTrustFeed(configuration, token, request = fetch) {
  const feed = validateTrustFeed(configuration);
  validateFeedToken(token);
  const controller = new AbortController();
  /** @type {ReadableStreamDefaultReader<Uint8Array>|undefined} */ let reader;
  let active = true;
  /** @type {ReturnType<typeof setTimeout>|undefined} */ let timer;
  const unavailable = () => new Error("trust feed unavailable");
  const read = async () => {
    const response = await request(feed.url, {
      method: "GET",
      redirect: "manual",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        authorization: "Bearer " + token,
        accept: "application/json",
        "accept-encoding": "identity",
      },
    });
    if (!active) {
      void response.body?.cancel().catch(() => {});
      throw unavailable();
    }
    const length = response.headers.get("content-length");
    const type = response.headers.get("content-type") ?? "";
    const encoding = response.headers.get("content-encoding");
    if (
      response.status !== 200 ||
      (response.url && response.url !== feed.url) ||
      !/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?\s*$/i.test(type) ||
      (encoding && encoding.toLowerCase() !== "identity") ||
      (length !== null && (!/^\d+$/.test(length) || Number(length) > 2000000))
    ) {
      void response.body?.cancel().catch(() => {});
      throw unavailable();
    }
    if (!response.body) throw unavailable();
    reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let text = "",
      bytes = 0;
    while (active) {
      const chunk = await reader.read();
      if (!active) throw unavailable();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > 2000000) throw unavailable();
      text += decoder.decode(chunk.value, { stream: true });
    }
    if (!active) throw unavailable();
    text += decoder.decode();
    const value = snapshot(strictParse(text), 2000000, 262144);
    const record = /** @type {Record<string,unknown>} */ (value);
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== "keyDocuments,statusDocuments" ||
      !Array.isArray(record.keyDocuments) ||
      !Array.isArray(record.statusDocuments)
    )
      throw unavailable();
    return value;
  };
  try {
    return await Promise.race([
      read(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(unavailable()), feed.timeoutMs ?? 5000);
      }),
    ]);
  } catch {
    throw unavailable();
  } finally {
    active = false;
    clearTimeout(timer);
    controller.abort();
    void reader?.cancel().catch(() => {});
  }
}
