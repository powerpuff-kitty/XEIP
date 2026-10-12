/** Pure public control validation. No pool, files, credentials or publication. */
import { parentPort, workerData } from "node:worker_threads";
import { prepareControlState, verifyControlState } from "./control-state.mjs";
if (!parentPort) throw new Error("control worker context required");
try {
  const prepared =
    workerData.operation === "prepare"
      ? prepareControlState(workerData.input)
      : workerData.operation === "verify"
        ? verifyControlState(workerData.input)
        : undefined;
  if (!prepared) throw Error();
  parentPort.postMessage({ prepared });
} catch {
  parentPort.postMessage({ failed: true });
}
