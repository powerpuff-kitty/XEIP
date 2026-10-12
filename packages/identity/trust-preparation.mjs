/** Bounded Node worker lifecycle; no persistence or authority changes here. */
import { Worker } from "node:worker_threads";
export async function prepareEntityTrustInWorker(
  configuration,
  provisioning,
  nowSeconds,
  signal,
) {
  if (signal.aborted) throw new Error("entity trust preparation cancelled");
  const deadline = performance.now() + 30000;
  let worker;
  let timer;
  let cancel;
  try {
    worker = new Worker(
      new URL("./trust-preparation-worker.mjs", import.meta.url),
      {
        workerData: { configuration, provisioning, nowSeconds },
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
    return await new Promise((resolve, reject) => {
      const fail = () => reject(new Error("entity trust preparation failed"));
      cancel = () => reject(new Error("entity trust preparation cancelled"));
      signal.addEventListener("abort", cancel, { once: true });
      timer = setTimeout(fail, Math.max(0, deadline - performance.now()));
      worker.once("error", fail);
      worker.once("exit", fail);
      worker.once("message", (message) => {
        if (
          signal.aborted ||
          performance.now() >= deadline ||
          message.failed ||
          !message.prepared
        )
          fail();
        else resolve(message.prepared);
      });
      if (signal.aborted) cancel();
    });
  } finally {
    clearTimeout(timer);
    if (cancel) signal.removeEventListener("abort", cancel);
    // Keep the caller's single-worker admission occupied until termination completes.
    if (worker) await worker.terminate();
  }
}
