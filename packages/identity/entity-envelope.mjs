/** Experimental entity-bound signing; legacy signatures are deliberately separate. */
import { sign, verify, KeyObject } from "node:crypto";
import { decodeKeyId } from "./key-id.mjs";
import {
  canonicalize,
  strictParse,
  bytesToBase64Url,
  base64UrlToBytes,
  ed25519PrivateKeyFromSeed,
  ed25519PublicKeyFromRaw,
  isWeakEd25519PublicKey,
} from "./signed-envelope.mjs";
import { KeyDocumentTrust } from "./key-document.mjs";
import { verifyStatusDocument } from "./identity-status.mjs";

export const ENTITY_SIGNATURE_PROFILE = "xeip.entity-signed-envelopes/0.2";
export const ENTITY_SIGNATURE_DOMAIN = "XEIP entity-bound envelope v0.2\n";
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const fail = (reason) => ({ valid: false, reason });
const snapshot = (value) =>
  typeof value === "string"
    ? strictParse(value)
    : strictParse(canonicalize(value));

export function wholeUtcSeconds(value) {
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

function carrierReason(value) {
  if (!object(value) || !object(value.extensions)) return "malformed signature";
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
        name.length === 0 ||
        name === "xeip.sig" ||
        !Object.hasOwn(value.extensions, name),
    ) ||
    new Set(proof.crit).size !== proof.crit.length
  )
    return "malformed signature";
  return null;
}

/** Includes every application extension and all proof metadata except sig. */
export function entityEnvelopeSigningInput(envelope) {
  const value = snapshot(envelope);
  const reason = carrierReason(value);
  if (reason) throw new TypeError(reason);
  const { v, alg, kid, crit } = value.extensions["xeip.sig"];
  delete value.extensions["xeip.sig"];
  return (
    ENTITY_SIGNATURE_DOMAIN +
    canonicalize({ envelope: value, proof: { v, alg, kid, crit } })
  );
}

/** Seeds (32 bytes) or Ed25519 private KeyObjects; does not authorize the signer. */
export function signEntityEnvelope(
  envelope,
  { privateKey, kid, criticalExtensions = [] } = {},
) {
  const value = snapshot(envelope);
  if (
    !object(value) ||
    (value.extensions !== undefined && !object(value.extensions))
  )
    throw new TypeError("malformed envelope");
  const key =
    privateKey instanceof KeyObject
      ? privateKey
      : ed25519PrivateKeyFromSeed(privateKey);
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519")
    throw new TypeError("Ed25519 private key required");
  value.extensions = {
    ...value.extensions,
    "xeip.sig": {
      v: "0.2",
      alg: "EdDSA",
      kid,
      crit: snapshot(criticalExtensions),
      sig: "",
    },
  };
  value.extensions["xeip.sig"].sig = bytesToBase64Url(
    sign(null, Buffer.from(entityEnvelopeSigningInput(value)), key),
  );
  return value;
}

/** Validates a pinned chain and fresh status, returning isolated verified data. */
export function validateEntityTrust(entity, options) {
  try {
    const { keyDocuments, anchor, statusDocument, nowSeconds, maxAgeSeconds } =
      options;
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
    const trust = new KeyDocumentTrust({ entity, anchor: snapshot(anchor) });
    let current;
    for (const document of keyDocuments) {
      current = snapshot(document);
      const issued = wholeUtcSeconds(current.issuedAt);
      if (
        issued === null ||
        issued > nowSeconds ||
        !trust.ingest(current).valid
      )
        return fail("untrusted identity");
    }
    const status = snapshot(statusDocument);
    if (!verifyStatusDocument(status, current).valid)
      return fail("untrusted identity");
    const issued = wholeUtcSeconds(status.issuedAt);
    if (
      issued === null ||
      issued > nowSeconds ||
      nowSeconds - issued > maxAgeSeconds
    )
      return fail("stale status");
    return { valid: true, current, status };
  } catch {
    return fail("untrusted identity");
  }
}

/** Full stateless signature + anchored current-identity authorization. */
export function verifyEntityEnvelope(envelope, options) {
  let value;
  try {
    value = snapshot(envelope);
  } catch {
    return fail("malformed envelope");
  }
  if (!object(value) || typeof value.sender !== "string")
    return fail("malformed envelope");
  const reason = carrierReason(value);
  if (reason) return fail(reason);
  const proof = value.extensions["xeip.sig"];
  const known = options?.knownExtensions ?? [];
  if (!Array.isArray(known) || proof.crit.some((name) => !known.includes(name)))
    return fail("unsupported critical extension");
  let raw;
  try {
    raw = decodeKeyId(proof.kid);
  } catch {
    return fail("malformed signature");
  }
  if (isWeakEd25519PublicKey(raw)) return fail("weak key");
  const signature = base64UrlToBytes(proof.sig);
  if (signature === null || signature.length !== 64)
    return fail("malformed signature");
  if (
    !verify(
      null,
      Buffer.from(entityEnvelopeSigningInput(value)),
      ed25519PublicKeyFromRaw(raw),
      signature,
    )
  )
    return fail("signature mismatch");
  const trusted = validateEntityTrust(value.sender, options);
  if (!trusted.valid) return trusted;
  if (
    ![...trusted.current.roots, ...trusted.current.devices].includes(proof.kid)
  )
    return fail("unauthorized key");
  if (trusted.status.revoked.some((entry) => entry.kid === proof.kid))
    return fail("revoked key");
  return { valid: true };
}
