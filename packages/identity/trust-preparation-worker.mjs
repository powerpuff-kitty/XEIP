/** Pure public-data preparation. The parent alone owns checkpoint persistence. */
import { parentPort, workerData } from "node:worker_threads";
import { prepareEntityTrust } from "./trust-state.mjs";
try {
  const { configuration, provisioning, nowSeconds } = workerData;
  parentPort.postMessage({
    prepared: prepareEntityTrust(
      configuration,
      provisioning.keyDocuments,
      provisioning.statusDocuments,
      nowSeconds,
    ),
  });
} catch {
  // Do not send arbitrary thrown values or provisioning back as diagnostics.
  parentPort.postMessage({ failed: true });
}
