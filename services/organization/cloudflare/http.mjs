/** Bounded Fetch boundary. The owner supplies initialized authority and durable work. */
import { OperationError } from "../controller.mjs";
/** @typedef {{handle:(authorization:unknown,body:unknown,options:{signal:AbortSignal})=>Promise<unknown>}} Controller */
/** @typedef {{waitUntil?:(task:Promise<unknown>)=>void}} Lifetime */
/** @param {number} value @param {number} min @param {number} max */
const integer = (value, min, max) =>
  Number.isInteger(value) && value >= min && value <= max;
/** @param {number} status @param {string} code */
const failure = (status, code) => new OperationError(status, code);
const safeErrors = new Map([
  ["400:invalid_request", 400],
  ["401:unauthenticated", 401],
  ["403:forbidden", 403],
  ["404:not_found", 404],
  ["405:method_not_allowed", 405],
  ["408:request_timeout", 408],
  ["409:conflict", 409],
  ["413:body_too_large", 413],
  ["415:unsupported_media_type", 415],
  ["429:busy", 429],
  ["503:unavailable", 503],
  ["504:request_timeout", 504],
]);
/** @param {number} status @param {unknown} value @param {string} id */
function response(status, value, id) {
  const body = JSON.stringify(value);
  if (
    typeof body !== "string" ||
    new TextEncoder().encode(body).byteLength > 262144
  )
    throw failure(503, "unavailable");
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-request-id": id,
      ...(status === 429 ? { "retry-after": "1" } : {}),
    },
  });
}
/** @template T @param {Promise<T>} task @param {number} ms @param {AbortSignal} signal @param {number} status @returns {Promise<T>} */
async function deadline(task, ms, signal, status) {
  /** @type {ReturnType<typeof setTimeout> | undefined} */ let timer;
  /** @type {()=>void} */ let onAbort = () => {};
  try {
    return await Promise.race([
      task,
      new Promise((_, reject) => {
        onAbort = () => reject(failure(400, "invalid_request"));
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
        timer = setTimeout(
          () =>
            reject(
              failure(
                status,
                status === 503 ? "unavailable" : "request_timeout",
              ),
            ),
          ms,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", onAbort);
  }
}
/** @param {Request} request @param {number} ms @param {AbortSignal} signal */
async function readBody(request, ms, signal) {
  const reader = request.body?.getReader();
  /** @type {Uint8Array[]} */ const chunks = [];
  let bytes = 0;
  try {
    await deadline(
      (async () => {
        if (reader)
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            bytes += value.byteLength;
            if (bytes > 98304) throw failure(413, "body_too_large");
            chunks.push(value);
          }
      })(),
      ms,
      signal,
      408,
    );
    const length = request.headers.get("content-length");
    if (length !== null && Number(length) !== bytes)
      throw failure(400, "invalid_request");
    const joined = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(joined);
    } catch {
      throw failure(400, "invalid_request");
    }
  } finally {
    // Cancellation may itself never settle for a hostile stream; do not await it.
    void reader?.cancel().catch(() => {});
  }
}
/** @param {{controller:Controller,origin:string,ready:()=>Promise<boolean>,bodyTimeoutMs?:number,operationTimeoutMs?:number,readinessTimeoutMs?:number,maxConcurrent?:number}} configuration */
export function createWorkerHttp(configuration) {
  const {
    controller,
    origin,
    ready,
    bodyTimeoutMs = 5000,
    operationTimeoutMs = 30000,
    readinessTimeoutMs = 2000,
    maxConcurrent = 32,
  } = configuration;
  const pinned = new URL(origin);
  if (
    pinned.origin !== origin ||
    pinned.protocol !== "https:" ||
    pinned.username ||
    pinned.password ||
    !controller ||
    typeof controller.handle !== "function" ||
    typeof ready !== "function" ||
    !integer(bodyTimeoutMs, 100, 30000) ||
    !integer(operationTimeoutMs, 100, 60000) ||
    !integer(readinessTimeoutMs, 100, 10000) ||
    !integer(maxConcurrent, 1, 256)
  )
    throw new TypeError("invalid Worker HTTP configuration");
  let active = 0;
  /** @param {Request} request @param {Lifetime} [lifetime] */
  return async (request, lifetime = {}) => {
    const id = crypto.randomUUID(),
      abort = new AbortController();
    const onAbort = () => abort.abort();
    request.signal.addEventListener("abort", onAbort, { once: true });
    let counted = false,
      settled = true,
      responseDone = false,
      released = false;
    const release = () => {
      if (counted && !released) {
        released = true;
        active--;
      }
    };
    /** @template T @param {()=>Promise<T>} run */
    const track = (run) => {
      settled = false;
      const task = Promise.resolve().then(run);
      const complete = () => {
        settled = true;
        if (responseDone) release();
      };
      const completion = task.then(complete, complete);
      // Register completion before waiting for the response deadline.
      lifetime.waitUntil?.(completion);
      return task;
    };
    try {
      if (request.signal.aborted) throw failure(400, "invalid_request");
      const url = new URL(request.url),
        host = request.headers.get("host"),
        browser = request.headers.get("origin");
      if (
        url.origin !== origin ||
        (host !== null && host !== pinned.host) ||
        (browser !== null && browser !== origin)
      )
        throw failure(403, "forbidden");
      if (url.username || url.password || url.search || url.hash)
        throw failure(400, "invalid_request");
      if (!["/live", "/ready", "/v1/actions"].includes(url.pathname))
        throw failure(404, "not_found");
      if (request.method !== (url.pathname === "/v1/actions" ? "POST" : "GET"))
        throw failure(405, "method_not_allowed");
      if (request.headers.has("transfer-encoding"))
        throw failure(400, "invalid_request");
      if (
        url.pathname !== "/v1/actions" &&
        (request.body !== null ||
          Number(request.headers.get("content-length") ?? 0) !== 0)
      )
        throw failure(400, "invalid_request");
      if (url.pathname === "/live")
        return response(200, { status: "live" }, id);
      if (active >= maxConcurrent) throw failure(429, "busy");
      active++;
      counted = true;
      if (url.pathname === "/ready") {
        const healthy = await deadline(
          track(ready),
          readinessTimeoutMs,
          abort.signal,
          503,
        );
        return response(
          healthy === true ? 200 : 503,
          { status: healthy === true ? "ready" : "unavailable" },
          id,
        );
      }
      if (
        !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
          request.headers.get("content-type") ?? "",
        ) ||
        request.headers.has("content-encoding")
      )
        throw failure(415, "unsupported_media_type");
      const authorization = request.headers.get("authorization"),
        length = request.headers.get("content-length");
      if (
        authorization !== null &&
        !/^Bearer [A-Za-z0-9._~+\/-]+=*$/i.test(authorization)
      )
        throw failure(400, "invalid_request");
      if (length !== null && !/^(0|[1-9][0-9]*)$/.test(length))
        throw failure(400, "invalid_request");
      if (length !== null && Number(length) > 98304)
        throw failure(413, "body_too_large");
      const body = await readBody(request, bodyTimeoutMs, abort.signal);
      if (abort.signal.aborted) throw failure(400, "invalid_request");
      const result = await deadline(
        track(() =>
          controller.handle(authorization, body, { signal: abort.signal }),
        ),
        operationTimeoutMs,
        abort.signal,
        504,
      );
      return response(200, result, id);
    } catch (error) {
      abort.abort();
      const safe =
        error instanceof OperationError &&
        safeErrors.get(error.status + ":" + error.code) === error.status;
      return response(
        safe ? error.status : 503,
        { error: safe ? error.code : "unavailable" },
        id,
      );
    } finally {
      responseDone = true;
      request.signal.removeEventListener("abort", onAbort);
      if (settled) release();
    }
  };
}
