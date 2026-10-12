/** Private journal transport: no namespace creation or owner operations. */
import { createHash, timingSafeEqual } from "node:crypto";
import { exact } from "./recovery-record.mjs";
import {
  transportConfiguration,
  parseCommand,
  result,
  readJson,
  WireDeadline,
  REQUEST_BYTES,
  jsonResponse,
} from "./recovery-wire.mjs";
import { StoreConflict } from "../errors.mjs";
/** @typedef {{head:()=>unknown,entry:(sequence:number)=>unknown,part:(sequence:number,index:number)=>unknown,append:(value:unknown)=>Promise<unknown>}} Journal */
/** @param {{url:string,token:string,options:unknown,journal:Journal}} configuration */
export function createRecoveryHandler(configuration) {
  const c = exact(configuration, ["url", "token", "options", "journal"]);
  const { url, token, options } = transportConfiguration({
    url: c.url,
    token: c.token,
    options: c.options,
  });
  const journal = /** @type {Journal} */ (c.journal);
  if (
    !journal ||
    ["head", "entry", "part", "append"].some(
      (key) =>
        typeof (/** @type {Record<string,unknown>} */ (c.journal)[key]) !==
        "function",
    )
  )
    throw new TypeError("invalid recovery journal");
  const pin = new URL(url),
    digest = createHash("sha256").update(token).digest();
  let busy = false;
  /** @param {Request} request @param {{waitUntil?:(task:Promise<unknown>)=>void}} [lifetime] */
  return async (request, lifetime = {}) => {
    const auth = request.headers.get("authorization");
    if (
      !auth ||
      !/^Bearer [0-9a-f]{64}$/.test(auth) ||
      !timingSafeEqual(
        digest,
        createHash("sha256").update(auth.slice(7)).digest(),
      )
    )
      return jsonResponse(401, { error: "unauthenticated" });
    if (
      request.url !== url ||
      request.method !== "POST" ||
      request.headers.has("origin") ||
      request.headers.has("cookie") ||
      (request.headers.has("host") && request.headers.get("host") !== pin.host)
    )
      return jsonResponse(400, { error: "invalid_request" });
    if (busy) return jsonResponse(429, { error: "busy" });
    busy = true;
    const scope = new WireDeadline();
    let settled = false,
      finished = false,
      invoking = false;
    const release = () => {
      if (settled && finished) busy = false;
    };
    const task = Promise.resolve().then(async () => {
      const command = parseCommand(
        await readJson(request, REQUEST_BYTES, scope),
        options,
      );
      await scope.checkpoint();
      invoking = true;
      const args = command.args;
      const value =
        command.operation === "head"
          ? await journal.head()
          : command.operation === "entry"
            ? await journal.entry(Number(args.sequence))
            : command.operation === "part"
              ? await journal.part(Number(args.sequence), Number(args.part))
              : await journal.append(args);
      scope.check();
      const response = jsonResponse(200, result(command, value, options));
      scope.check();
      return response;
    });
    const completion = task.then(
      () => {
        settled = true;
        release();
      },
      () => {
        settled = true;
        release();
      },
    );
    lifetime.waitUntil?.(completion);
    try {
      return await scope.wait(task, options.timeoutMs, request.signal);
    } catch (error) {
      const status =
        error instanceof StoreConflict
          ? 409
          : !invoking && error instanceof TypeError
            ? 400
            : 503;
      return jsonResponse(status, {
        error:
          status === 409
            ? "conflict"
            : status === 400
              ? "invalid_request"
              : "unavailable",
      });
    } finally {
      finished = true;
      release();
      if (!request.body?.locked) void request.body?.cancel().catch(() => {});
    }
  };
}
