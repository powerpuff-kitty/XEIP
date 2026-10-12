/** Entity-bound 0.2 signatures with explicit pinned trust and freshness. */
import {
  canonicalize,
  strictParse,
  bytesToBase64Url,
  base64UrlToBytes,
  decodeKeyId,
  ed25519PrivateKeyFromSeed,
  isWeakEd25519PublicKey,
} from "./identity.js";
import {
  KeyDocumentTrust,
  verifyStatusDocument,
  type KeyDocumentAnchor,
} from "./keydoc.js";
export const ENTITY_SIGNATURE_PROFILE = "xeip.entity-signed-envelopes/0.2";
export const ENTITY_SIGNATURE_DOMAIN = "XEIP entity-bound envelope v0.2\n";
type Failure = { valid: false; reason: string };
export type EntityEnvelopeResult = { valid: true } | Failure;
export interface EntityTrustOptions {
  keyDocuments: unknown[];
  anchor: KeyDocumentAnchor;
  statusDocument: unknown;
  nowSeconds: number;
  maxAgeSeconds: number;
  knownExtensions?: string[];
}
interface Carrier {
  v: string;
  alg: string;
  kid: string;
  crit: string[];
  sig: string;
}
interface CurrentDocument {
  roots: string[];
  devices: string[];
}
interface CurrentStatus {
  revoked: { kid: string }[];
}
const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const fail = (reason: string): Failure => ({ valid: false, reason });
const snapshot = (value: unknown): unknown =>
  typeof value === "string"
    ? strictParse(value)
    : strictParse(canonicalize(value));
const bytes = (value: Uint8Array): ArrayBuffer => new Uint8Array(value).buffer;
export function wholeUtcSeconds(value: unknown): number | null {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
  )
    return null;
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    milliseconds < 0 ||
    new Date(milliseconds).toISOString() !== value.slice(0, -1) + ".000Z"
  )
    return null;
  return milliseconds / 1000;
}
function carrierReason(value: Record<string, unknown>): string | null {
  if (!object(value.extensions)) return "malformed signature";
  const proof = value.extensions["xeip.sig"];
  if (!object(proof)) return "malformed signature";
  if (proof.v !== "0.2" || proof.alg !== "EdDSA") return "unsupported profile";
  if (
    Object.keys(proof).sort().join(",") !== "alg,crit,kid,sig,v" ||
    typeof proof.kid !== "string" ||
    typeof proof.sig !== "string" ||
    !Array.isArray(proof.crit) ||
    proof.crit.some(
      (name) =>
        typeof name !== "string" ||
        !name ||
        name === "xeip.sig" ||
        !Object.hasOwn(value.extensions as object, name),
    ) ||
    new Set(proof.crit).size !== proof.crit.length
  )
    return "malformed signature";
  return null;
}
export function entityEnvelopeSigningInput(envelope: unknown): string {
  const value = snapshot(envelope);
  if (!object(value)) throw new TypeError("malformed envelope");
  const reason = carrierReason(value);
  if (reason) throw new TypeError(reason);
  const extensions = value.extensions as Record<string, unknown>;
  const { v, alg, kid, crit } = extensions["xeip.sig"] as Carrier;
  delete extensions["xeip.sig"];
  return (
    ENTITY_SIGNATURE_DOMAIN +
    canonicalize({ envelope: value, proof: { v, alg, kid, crit } })
  );
}
export async function signEntityEnvelope(
  envelope: unknown,
  options: {
    privateKey: CryptoKey | Uint8Array | ArrayBuffer;
    kid: string;
    criticalExtensions?: string[];
  },
): Promise<Record<string, unknown>> {
  const value = snapshot(envelope);
  if (
    !object(value) ||
    (value.extensions !== undefined && !object(value.extensions))
  )
    throw new TypeError("malformed envelope");
  const source = options.privateKey;
  const kid = options.kid;
  const criticalExtensions = snapshot(
    options.criticalExtensions ?? [],
  ) as string[];
  const key =
    source instanceof Uint8Array || source instanceof ArrayBuffer
      ? await ed25519PrivateKeyFromSeed(source)
      : source;
  if (key.type !== "private" || key.algorithm.name !== "Ed25519")
    throw new TypeError("Ed25519 private key required");
  const proof: Carrier = {
    v: "0.2",
    alg: "EdDSA",
    kid,
    crit: criticalExtensions,
    sig: "",
  };
  value.extensions = {
    ...(value.extensions as Record<string, unknown> | undefined),
    "xeip.sig": proof,
  };
  proof.sig = bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        key,
        bytes(new TextEncoder().encode(entityEnvelopeSigningInput(value))),
      ),
    ),
  );
  return value;
}
export async function validateEntityTrust(
  entity: string,
  options: EntityTrustOptions,
): Promise<
  Failure | { valid: true; current: CurrentDocument; status: CurrentStatus }
> {
  try {
    const { keyDocuments, anchor, statusDocument, nowSeconds, maxAgeSeconds } =
      snapshot(options) as EntityTrustOptions;
    if (
      !Number.isSafeInteger(nowSeconds) ||
      nowSeconds < 0 ||
      !Number.isSafeInteger(maxAgeSeconds) ||
      maxAgeSeconds < 1 ||
      maxAgeSeconds > 86400
    )
      return fail("stale status");
    if (
      !Array.isArray(keyDocuments) ||
      keyDocuments.length === 0 ||
      !object(anchor) ||
      ![anchor.genesisKid, anchor.genesisDigest].some(
        (value) => typeof value === "string" && value.length > 0,
      )
    )
      return fail("untrusted identity");
    const trust = new KeyDocumentTrust({
      entity,
      anchor: snapshot(anchor) as KeyDocumentAnchor,
    });
    let current: unknown;
    for (const document of keyDocuments) {
      current = snapshot(document);
      if (!object(current)) return fail("untrusted identity");
      const issued = wholeUtcSeconds(current.issuedAt);
      if (
        issued === null ||
        issued > nowSeconds ||
        !(await trust.ingest(current)).valid
      )
        return fail("untrusted identity");
    }
    const status = snapshot(statusDocument);
    if (!(await verifyStatusDocument(status, current)).valid || !object(status))
      return fail("untrusted identity");
    const issued = wholeUtcSeconds(status.issuedAt);
    if (
      issued === null ||
      issued > nowSeconds ||
      nowSeconds - issued > maxAgeSeconds
    )
      return fail("stale status");
    return {
      valid: true,
      current: current as CurrentDocument,
      status: status as unknown as CurrentStatus,
    };
  } catch {
    return fail("untrusted identity");
  }
}
export async function verifyEntityEnvelope(
  envelope: unknown,
  options: EntityTrustOptions,
): Promise<EntityEnvelopeResult> {
  let value: unknown;
  try {
    value = snapshot(envelope);
  } catch {
    return fail("malformed envelope");
  }
  if (!object(value) || typeof value.sender !== "string")
    return fail("malformed envelope");
  const reason = carrierReason(value);
  if (reason) return fail(reason);
  const proof = (value.extensions as Record<string, unknown>)[
    "xeip.sig"
  ] as Carrier;
  const known = options?.knownExtensions ?? [];
  if (!Array.isArray(known) || proof.crit.some((name) => !known.includes(name)))
    return fail("unsupported critical extension");
  let raw: Uint8Array;
  try {
    raw = decodeKeyId(proof.kid);
  } catch {
    return fail("malformed signature");
  }
  if (isWeakEd25519PublicKey(raw)) return fail("weak key");
  const signature = base64UrlToBytes(proof.sig);
  if (signature === null || signature.length !== 64)
    return fail("malformed signature");
  let trustOptions: EntityTrustOptions;
  try {
    trustOptions = snapshot(options) as EntityTrustOptions;
  } catch {
    return fail("untrusted identity");
  }
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      bytes(raw),
      "Ed25519",
      false,
      ["verify"],
    );
    if (
      !(await crypto.subtle.verify(
        "Ed25519",
        key,
        bytes(signature),
        bytes(new TextEncoder().encode(entityEnvelopeSigningInput(value))),
      ))
    )
      return fail("signature mismatch");
  } catch {
    return fail("signature mismatch");
  }
  const trusted = await validateEntityTrust(value.sender, trustOptions);
  if (!trusted.valid) return trusted;
  if (
    ![...trusted.current.roots, ...trusted.current.devices].includes(proof.kid)
  )
    return fail("unauthorized key");
  if (trusted.status.revoked.some((entry) => entry.kid === proof.kid))
    return fail("revoked key");
  return { valid: true };
}
