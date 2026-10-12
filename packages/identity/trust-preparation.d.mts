/** Typed boundary for the existing bounded Node worker; no storage authority. */
import type { TrustConfiguration, prepareEntityTrust } from "./trust-state.mjs";
export function prepareEntityTrustInWorker(
  configuration: TrustConfiguration,
  provisioning: { keyDocuments: unknown[]; statusDocuments: unknown[] },
  nowSeconds: number,
  signal: AbortSignal,
): Promise<ReturnType<typeof prepareEntityTrust>>;
