/** Typed boundary for the shared runtime-validated signed trust rules. */
export type TrustConfiguration = {
  maxAgeSeconds: number;
  knownExtensions?: string[];
};
export type TrustCheckpointRecord = {
  anchor: string;
  generation: number;
  keyDigest: string;
  serial: number;
  statusDigest: string;
};
export type TrustRecords = Record<string, TrustCheckpointRecord>;
export type TrustChains = Record<string, Record<number, string>>;
export type TrustBundle = {
  keyDocuments: unknown[];
  anchor: unknown;
  statusDocument: unknown;
  maxAgeSeconds: number;
  knownExtensions: string[];
  keys: Set<string>;
  revoked: Set<string>;
  issuedSeconds: number;
};
export function prepareEntityTrust(
  configuration: TrustConfiguration,
  keyDocuments: unknown,
  statusDocuments: unknown,
  nowSeconds: number,
): {
  bundles: Map<string, TrustBundle>;
  checkpoints: TrustRecords;
  chainDigests: TrustChains;
};
export function validateTrustRecords(value: unknown): TrustRecords;
export function mergeTrustRecords(
  previous: TrustRecords,
  candidates: TrustRecords,
  chainDigests?: TrustChains,
): TrustRecords;
export function verifyEntityEnvelope(
  envelope: unknown,
  options: TrustBundle & { nowSeconds: number },
): { valid: boolean; reason?: string };
