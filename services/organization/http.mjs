/** Bounded organization HTTP(S) boundary. Insecure mode is for literal-loopback tests only. */
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { OperationError } from "./controller.mjs";
import { randomUUID } from "node:crypto";
/** @typedef {import('node:http').IncomingMessage} Request */
/** @typedef {import('node:http').ServerResponse} Response */
/** @typedef {{handle:(authorization:unknown,body:unknown,options:{signal:AbortSignal})=>Promise<unknown>}} Controller */
/** @param {unknown} value @param {number} min @param {number} max */
const integer = (value, min, max) =>
  typeof value === "number" &&
  Number.isInteger(value) &&
  value >= min &&
  value <= max;
/** @param {Request} request @param {number} timeout @returns {Promise<string>} */
function readBody(request, timeout) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */ const chunks = [];
    let bytes = 0,
      done = false;
    const timer = setTimeout(
      () => finish(new OperationError(408, "request_timeout")),
      timeout,
    );
    /** @param {Error} [error] */
    function finish(error) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      request.removeListener("data", data);
      request.removeListener("end", end);
      request.removeListener("aborted", aborted);
      request.removeListener("error", failed);
      if (error) {
        request.pause();
        reject(error);
        return;
      }
      try {
        resolve(
          new TextDecoder("utf-8", { fatal: true }).decode(
            Buffer.concat(chunks),
          ),
        );
      } catch {
        reject(new OperationError(400, "invalid_request"));
      }
    }
    /** @param {Buffer} chunk */ function data(chunk) {
      bytes += chunk.length;
      if (bytes > 98304) {
        finish(new OperationError(413, "body_too_large"));
        return;
      }
      chunks.push(chunk);
    }
    function end() {
      finish();
    }
    function aborted() {
      finish(new OperationError(400, "invalid_request"));
    }
    /** @param {Error} _error */ function failed(_error) {
      finish(new OperationError(400, "invalid_request"));
    }
    request.on("data", data);
    request.once("end", end);
    request.once("aborted", aborted);
    request.once("error", failed);
  });
}
/** @param {Response} response @param {number} status @param {unknown} body */
function send(response, status, body) {
  if (response.destroyed || response.writableEnded) return;
  const encoded = JSON.stringify(body);
  if (Buffer.byteLength(encoded) > 262144)
    throw new OperationError(503, "unavailable");
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...(status >= 400 ? { Connection: "close" } : {}),
    ...(status === 429 ? { "Retry-After": "1" } : {}),
  });
  response.end(encoded);
}
/** @template T @param {Promise<T>} task @param {number} ms @param {()=>void} onTimeout @param {number} status @returns {Promise<T>} */
async function deadline(task, ms, onTimeout, status) {
  let timer;
  try {
    return await Promise.race([
      task,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          onTimeout();
          reject(new OperationError(status, "request_timeout"));
        }, ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
/** @param {{controller:Controller,origin:string,ready:()=>Promise<boolean>,console?:ReturnType<typeof import('./console-server.mjs').createConsole>,tls?:{key:string|Buffer,cert:string|Buffer},allowInsecureLoopback?:boolean,bodyTimeoutMs?:number,operationTimeoutMs?:number,readinessTimeoutMs?:number,maxConcurrent?:number,onRequest?:(observation:import('./telemetry.mjs').Observation)=>void}} configuration */
export function createOrganizationServer(configuration) {
  const {
    controller,
    origin,
    ready,
    tls,
    allowInsecureLoopback = false,
    bodyTimeoutMs = 5000,
    operationTimeoutMs = 30000,
    readinessTimeoutMs = 2000,
    maxConcurrent = 32,
    onRequest,
  } = configuration;
  /** @type {URL} */ let publicOrigin;
  try {
    publicOrigin = new URL(origin);
  } catch {
    throw new TypeError("valid HTTPS origin required");
  }
  if (
    publicOrigin.protocol !== "https:" ||
    publicOrigin.origin !== origin ||
    typeof ready !== "function" ||
    typeof controller?.handle !== "function" ||
    typeof allowInsecureLoopback !== "boolean" ||
    (!tls && !allowInsecureLoopback) ||
    (tls && (!tls.key || !tls.cert)) ||
    !integer(bodyTimeoutMs, 100, 30000) ||
    !integer(operationTimeoutMs, 100, 60000) ||
    !integer(readinessTimeoutMs, 100, 10000) ||
    !integer(maxConcurrent, 1, 256) ||
    (onRequest !== undefined && typeof onRequest !== "function")
  )
    throw new TypeError("invalid organization HTTP configuration");
  let active = 0;
  /** @param {Request} request @param {Response} response */
  async function handle(request, response) {
    const started = performance.now(),
      id = randomUUID();
    const route =
      request.url === "/v1/actions"
        ? "actions"
        : request.url === "/live"
          ? "live"
          : request.url === "/ready"
            ? "ready"
            : "other";
    let operation = "unknown",
      state = "unknown",
      status = 200;
    response.setHeader("X-Request-Id", id);
    const abort = new AbortController();
    response.once("close", () => {
      if (!response.writableFinished) abort.abort();
    });
    let counted = false,
      released = false,
      settled = true,
      responseDone = false;
    function release() {
      if (counted && !released) {
        released = true;
        active--;
      }
    }
    /** @template T @param {Promise<T>} task @returns {Promise<T>} */
    function track(task) {
      settled = false;
      const complete = () => {
        settled = true;
        if (responseDone) release();
      };
      task.then(complete, complete);
      return task;
    }
    try {
      const encrypted =
        "encrypted" in request.socket && request.socket.encrypted === true;
      const loopback = ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(
        request.socket.remoteAddress ?? "",
      );
      if (!encrypted && !(allowInsecureLoopback && loopback))
        throw new OperationError(403, "forbidden");
      for (const header of [
        "host",
        "authorization",
        "content-type",
        "content-length",
      ]) {
        let count = 0;
        for (let i = 0; i < request.rawHeaders.length; i += 2)
          if (request.rawHeaders[i]?.toLowerCase() === header) count++;
        if (count > 1) throw new OperationError(400, "invalid_request");
      }
      if (
        request.headers.host !== publicOrigin.host ||
        (request.headers.origin !== undefined &&
          request.headers.origin !== origin)
      )
        throw new OperationError(403, "forbidden");
      if (request.method === "GET" && request.url === "/live") {
        send(response, 200, { status: "live" });
        return;
      }
      if (active >= maxConcurrent) throw new OperationError(429, "busy");
      active++;
      counted = true;
      if (request.method === "GET" && request.url === "/ready") {
        const healthy = await deadline(
          track(Promise.resolve().then(ready)),
          readinessTimeoutMs,
          () => abort.abort(),
          503,
        );
        send(response, healthy === true ? 200 : 503, {
          status: healthy === true ? "ready" : "unavailable",
        });
        status = healthy === true ? 200 : 503;
        return;
      }
      if (request.url !== "/v1/actions") {
        const console = configuration.console;
        const asset = console?.asset(request.url ?? "");
        const profile = console && request.url === "/v1/console/profile";
        if (!asset && !profile) throw new OperationError(404, "not_found");
        if (request.method !== "GET")
          throw new OperationError(405, "method_not_allowed");
        if (
          request.headers["transfer-encoding"] !== undefined ||
          Number(request.headers["content-length"] ?? 0) !== 0
        )
          throw new OperationError(400, "invalid_request");
        if (asset) {
          response.writeHead(200, {
            "Content-Type": asset.type,
            ...asset.headers,
          });
          response.end(asset.body);
          return;
        }
        if (!console) throw new OperationError(404, "not_found");
        const result = await deadline(
          track(
            Promise.resolve().then(() =>
              console.profile(request.headers.authorization, {
                signal: abort.signal,
              }),
            ),
          ),
          operationTimeoutMs,
          () => abort.abort(),
          504,
        );
        send(response, 200, result);
        return;
      }
      if (request.method !== "POST")
        throw new OperationError(405, "method_not_allowed");
      if (
        typeof request.headers["content-type"] !== "string" ||
        !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
          request.headers["content-type"],
        ) ||
        request.headers["content-encoding"] !== undefined
      )
        throw new OperationError(415, "unsupported_media_type");
      if (
        request.headers["content-length"] !== undefined &&
        Number(request.headers["content-length"]) > 98304
      )
        throw new OperationError(413, "body_too_large");
      const body = await readBody(request, bodyTimeoutMs);
      if (onRequest) {
        try {
          const candidate = JSON.parse(body)?.body?.data?.operation;
          if (
            [
              "propose",
              "approve",
              "reject",
              "revoke",
              "execute",
              "inspect",
            ].includes(candidate)
          )
            operation = candidate;
        } catch {
          /* Malformed content is rejected by the controller. */
        }
      }
      const task = track(
        Promise.resolve().then(() =>
          controller.handle(request.headers.authorization, body, {
            signal: abort.signal,
          }),
        ),
      );
      const result = await deadline(
        task,
        operationTimeoutMs,
        () => abort.abort(),
        504,
      );
      if (
        result &&
        typeof result === "object" &&
        "state" in result &&
        typeof result.state === "string" &&
        [
          "pending",
          "approved",
          "rejected",
          "revoked",
          "executing",
          "succeeded",
          "failed",
          "indeterminate",
        ].includes(result.state)
      )
        state = result.state;
      send(response, 200, result);
    } catch (error) {
      abort.abort();
      const safe =
        error instanceof OperationError
          ? error
          : new OperationError(503, "unavailable");
      send(response, safe.status, { error: safe.code });
      status = safe.status;
    } finally {
      responseDone = true;
      // A timed-out callback still occupies its slot until it actually settles.
      if (settled) release();
      try {
        onRequest?.({
          id,
          route,
          operation,
          state,
          status:
            response.destroyed && !response.writableFinished ? 499 : status,
          elapsedMs: performance.now() - started,
        });
      } catch {
        /* Observability cannot change an already committed operation. */
      }
    }
  }
  const listener = (
    /** @type {Request} */ req,
    /** @type {Response} */ res,
  ) => {
    void handle(req, res);
  };
  const server = tls
    ? createHttpsServer(
        {
          key: tls.key,
          cert: tls.cert,
          minVersion: "TLSv1.2",
          maxHeaderSize: 8192,
        },
        listener,
      )
    : createHttpServer({ maxHeaderSize: 8192 }, listener);
  server.maxConnections = 1024;
  server.maxHeadersCount = 32;
  server.headersTimeout = Math.min(10000, bodyTimeoutMs + 1000);
  server.requestTimeout = bodyTimeoutMs + 1000;
  server.keepAliveTimeout = 5000;
  return server;
}
