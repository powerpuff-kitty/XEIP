/** Pure public control validation. No pool, files, credentials or publication. */
import { parentPort, workerData } from "node:worker_threads";
import { prepareControlState, verifyControlState } from "./control-state.mjs";
if (!parentPort) throw new Error("control worker context required");
try {
  let prepared;
  if (workerData.operation === "prepare") {
    prepared = prepareControlState(workerData.input);
  } else if (workerData.operation === "verify") {
    // `verify` accepts either a bare canonical string (single-snapshot check, the
    // original contract) or `{ canonical, previous }` so the caller can also verify
    // the retained-record transition against the immediate predecessor.
    const input = workerData.input;
    if (input !== null && typeof input === "object" && !Array.isArray(input)) {
      prepared = verifyControlState(input.canonical, input.previous);
    } else {
      prepared = verifyControlState(input);
    }
  }
  if (!prepared) throw Error();
  parentPort.postMessage({ prepared });
} catch {
  parentPort.postMessage({ failed: true });
}
