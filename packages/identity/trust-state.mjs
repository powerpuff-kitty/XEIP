/** Shared signed provisioning and monotonic checkpoint rules; no storage ownership. */
import { createHash } from "node:crypto";
import { canonicalize, strictParse } from "./signed-envelope.mjs";
import { keyDocumentChainDigest } from "./key-document.mjs";
import { statusSigningInput } from "./identity-status.mjs";
import { wholeUtcSeconds, validateEntityTrust } from "./entity-envelope.mjs";
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const snapshot = (value) =>
  typeof value === "string"
    ? strictParse(value)
    : strictParse(canonicalize(value));
const digest = (value) => createHash("sha256").update(value).digest("hex");
export function prepareEntityTrust(
  configuration,
  keyDocuments,
  statusDocuments,
  nowSeconds,
) {
  if (
    !object(configuration) ||
    Object.keys(configuration).some(
      (key) => !["maxAgeSeconds", "knownExtensions"].includes(key),
    )
  )
    throw new TypeError("invalid trust configuration");
  const { maxAgeSeconds, knownExtensions = [] } = configuration;
  if (
    !Number.isSafeInteger(nowSeconds) ||
    nowSeconds < 0 ||
    !Number.isInteger(maxAgeSeconds) ||
    maxAgeSeconds < 1 ||
    maxAgeSeconds > 86400 ||
    !Array.isArray(knownExtensions) ||
    knownExtensions.some(
      (name) => typeof name !== "string" || !name || name === "xeip.sig",
    ) ||
    new Set(knownExtensions).size !== knownExtensions.length
  )
    throw new TypeError("invalid trust configuration or time");
  if (
    !Array.isArray(keyDocuments) ||
    keyDocuments.length > 4096 ||
    !Array.isArray(statusDocuments)
  )
    throw new TypeError(
      "entity signatures require keyDocuments and statusDocuments",
    );
  const bundles = new Map();
  for (const entry of keyDocuments) {
    if (
      !object(entry) ||
      Object.keys(entry).some((key) => !["document", "anchor"].includes(key))
    )
      throw new TypeError("invalid entity key document entry");
    const document = snapshot(entry.document),
      entity = document?.entity;
    if (typeof entity !== "string")
      throw new TypeError("key document entity required");
    let bundle = bundles.get(entity);
    if (!bundle) {
      if (!object(entry.anchor))
        throw new TypeError("explicit anchor required");
      bundle = {
        keyDocuments: [],
        anchor: snapshot(entry.anchor),
        statusDocument: undefined,
        maxAgeSeconds,
        knownExtensions: [...knownExtensions],
      };
      bundles.set(entity, bundle);
    } else if (
      entry.anchor !== undefined &&
      canonicalize(entry.anchor) !== canonicalize(bundle.anchor)
    )
      throw new TypeError("conflicting anchors");
    bundle.keyDocuments.push(document);
  }
  for (const entry of statusDocuments) {
    if (
      !object(entry) ||
      Object.keys(entry).length !== 1 ||
      !Object.hasOwn(entry, "document")
    )
      throw new TypeError("entity status entry must contain only document");
    const document = snapshot(entry.document),
      bundle = bundles.get(document?.entity);
    if (!bundle || bundle.statusDocument !== undefined)
      throw new TypeError("missing entity or duplicate status");
    bundle.statusDocument = document;
  }
  const checkpoints = Object.create(null);
  const chainDigests = Object.create(null);
  for (const [entity, bundle] of bundles) {
    const verified = validateEntityTrust(entity, {
      ...bundle,
      nowSeconds: nowSeconds,
    });
    if (!verified.valid)
      throw new Error("invalid entity trust: " + verified.reason);
    bundle.keys = new Set([
      ...verified.current.roots,
      ...verified.current.devices,
    ]);
    bundle.revoked = new Set(verified.status.revoked.map((entry) => entry.kid));
    bundle.issuedSeconds = wholeUtcSeconds(verified.status.issuedAt);
    checkpoints[entity] = {
      anchor: digest(canonicalize(bundle.anchor)),
      generation: verified.current.generation,
      keyDigest: keyDocumentChainDigest(verified.current),
      serial: verified.status.serial,
      statusDigest: digest(statusSigningInput(verified.status)),
    };
    chainDigests[entity] = Object.fromEntries(
      bundle.keyDocuments.map((document) => [
        document.generation,
        keyDocumentChainDigest(document),
      ]),
    );
  }
  return { bundles, checkpoints, chainDigests };
}
const isDigest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
export function validateTrustRecords(value) {
  if (!object(value) || Object.keys(value).length > 4096)
    throw new Error("invalid trust checkpoint");
  for (const [entity, record] of Object.entries(value)) {
    if (
      !entity ||
      !object(record) ||
      Object.keys(record).sort().join(",") !==
        "anchor,generation,keyDigest,serial,statusDigest" ||
      !isDigest(record.anchor) ||
      !isDigest(record.keyDigest) ||
      !isDigest(record.statusDigest) ||
      !Number.isSafeInteger(record.generation) ||
      record.generation < 1 ||
      !Number.isSafeInteger(record.serial) ||
      record.serial < 0
    )
      throw new Error("invalid trust checkpoint");
  }
  return value;
}
/** Returns isolated history, including entities omitted from active provisioning. */
export function mergeTrustRecords(previous, candidates, chainDigests = {}) {
  const merged = Object.assign(
    Object.create(null),
    strictParse(JSON.stringify(validateTrustRecords(previous))),
  );
  const nextRecords = validateTrustRecords(
    strictParse(JSON.stringify(validateTrustRecords(candidates))),
  );
  for (const [entity, next] of Object.entries(nextRecords)) {
    const old = merged[entity];
    if (old) {
      if (old.anchor !== next.anchor)
        throw new Error("trust anchor change requires explicit recovery");
      if (next.generation < old.generation || next.serial < old.serial)
        throw new Error("trust checkpoint rollback");
      if (
        next.generation > old.generation &&
        (chainDigests[entity]?.[old.generation] !== old.keyDigest ||
          chainDigests[entity]?.[next.generation] !== next.keyDigest)
      )
        throw new Error("trust checkpoint chain continuity fork");
      if (
        (next.generation === old.generation &&
          next.keyDigest !== old.keyDigest) ||
        (next.serial === old.serial && next.statusDigest !== old.statusDigest)
      )
        throw new Error("trust checkpoint fork");
    }
    merged[entity] = next;
  }
  validateTrustRecords(merged);
  if (
    Buffer.byteLength(JSON.stringify({ version: 1, entities: merged })) >
    8 * 1024 * 1024
  )
    throw new Error("oversize trust checkpoint");
  return merged;
}
export { verifyEntityEnvelope } from "./entity-envelope.mjs";
