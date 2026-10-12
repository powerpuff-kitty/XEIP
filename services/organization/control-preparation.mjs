/** Bounded, cancellable full control validation, including all signed history. */
import { Worker } from "node:worker_threads";
import { StoreUnavailable } from "./errors.mjs";
/** @typedef {import('./control-state.mjs').Prepared} Prepared */
/** @param {unknown} value */
function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
}
/** Input must already be isolated by the store before waiting or calling this worker.
 * @param {'prepare'|'verify'} operation @param {unknown} input @param {AbortSignal} [signal]
 * @returns {Promise<Prepared>} */
export async function prepareControlInWorker(operation, input, signal) {
  if (signal?.aborted) throw new StoreUnavailable();
  const deadline = performance.now() + 8000;
  /** @type {Worker|undefined} */ let worker;
  /** @type {NodeJS.Timeout|undefined} */ let timer;
  /** @type {(()=>void)|undefined} */ let cancel;
  try {
    worker = new Worker(
      new URL("./control-preparation-worker.mjs", import.meta.url),
      {
        workerData: { operation, input },
        execArgv: [],
        env: {},
        stdout: true,
        stderr: true,
        resourceLimits: {
          maxOldGenerationSizeMb: 128,
          maxYoungGenerationSizeMb: 16,
          stackSizeMb: 4,
        },
      },
    );
    worker.stdout.resume();
    worker.stderr.resume();
    const prepared = await new Promise((resolve, reject) => {
      const fail = () => reject(new StoreUnavailable());
      cancel = fail;
      signal?.addEventListener("abort", cancel, { once: true });
      timer = setTimeout(fail, Math.max(0, deadline - performance.now()));
      worker?.once("error", fail);
      worker?.once("exit", fail);
      worker?.once("message", (message) => {
        if (
          signal?.aborted ||
          performance.now() >= deadline ||
          message.failed ||
          !message.prepared
        )
          fail();
        else resolve(/** @type {Prepared} */ (message.prepared));
      });
      if (signal?.aborted) fail();
    });
    freeze(prepared);
    if (signal?.aborted || performance.now() >= deadline)
      throw new StoreUnavailable();
    return prepared;
  } catch {
    throw new StoreUnavailable();
  } finally {
    clearTimeout(timer);
    if (cancel) signal?.removeEventListener("abort", cancel);
    if (worker) await worker.terminate();
  }
}
