/** Pinned, authenticated recovery transport. Never retries a journal operation. */
import {
  transportConfiguration,
  command,
  result,
  readJson,
  WireDeadline,
  REQUEST_BYTES,
  RESPONSE_BYTES,
} from "./recovery-wire.mjs";
import { StoreUnavailable } from "../errors.mjs";
/** @param {unknown} configuration @param {typeof fetch} [request] */
export function createRecoveryClient(configuration, request = fetch) {
  const { url, token, options } = transportConfiguration(configuration);
  if (typeof request !== "function")
    throw new TypeError("invalid recovery transport");
  let busy = false;
  /** @param {string} operation @param {unknown} args */
  async function run(operation, args) {
    const c = command(operation, args, options);
    if (busy) throw new StoreUnavailable();
    busy = true;
    const scope = new WireDeadline();
    let settled = false,
      finished = false;
    const release = () => {
      if (settled && finished) busy = false;
    };
    const task = Promise.resolve().then(async () => {
      scope.check();
      const body = JSON.stringify({
        schema: "xeip.recovery-http/1",
        organization: options.organization,
        stream: options.stream,
        ...c,
      });
      if (Buffer.byteLength(body) > REQUEST_BYTES) throw new StoreUnavailable();
      await scope.checkpoint();
      const response = await request(url, {
        method: "POST",
        redirect: "manual",
        cache: "no-store",
        credentials: "omit",
        signal: scope.controller.signal,
        headers: {
          authorization: "Bearer " + token,
          "content-type": "application/json",
          accept: "application/json",
          "accept-encoding": "identity",
        },
        body,
      });
      if (
        !scope.active ||
        response.status !== 200 ||
        response.redirected ||
        (response.url && response.url !== url)
      ) {
        void response.body?.cancel().catch(() => {});
        throw new StoreUnavailable();
      }
      try {
        const checked = result(
          c,
          await readJson(response, RESPONSE_BYTES, scope),
          options,
        );
        scope.check();
        return checked;
      } finally {
        if (!response.body?.locked)
          void response.body?.cancel().catch(() => {});
      }
    });
    void task.then(
      () => {
        settled = true;
        release();
      },
      () => {
        settled = true;
        release();
      },
    );
    try {
      return await scope.wait(task, options.timeoutMs);
    } catch {
      throw new StoreUnavailable();
    } finally {
      finished = true;
      release();
    }
  }
  return Object.freeze({
    head: () => run("head", {}),
    /** @param {number} sequence */ entry: (sequence) =>
      run("entry", { sequence }),
    /** @param {number} sequence @param {number} part */ part: (
      sequence,
      part,
    ) => run("part", { sequence, part }),
    /** @param {unknown} value */ append: (value) => run("append", value),
  });
}
