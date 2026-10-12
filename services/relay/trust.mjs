/** Verified provisioning and use-time trust policy for the local relay. */
import { strictParse } from "../../packages/identity/signed-envelope.mjs";
import { KeyDocumentTrust } from "../../packages/identity/key-document.mjs";
import { StatusTracker, verifyStatusDocument } from "../../packages/identity/identity-status.mjs";

// A status entry `{ kid, generation }` revokes `kid` for its recorded generation
// and later (spec/plans/identity-status.md). This slice does not model a key's
// key-document generation at the relay, so it treats any entry for a key as
// revoking that key and asks the tracker with the maximum safe generation, which
// is `>=` every recorded generation.
const STATUS_GENERATION_ANY = Number.MAX_SAFE_INTEGER;

export function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseKeyDocument(document) {
  if (typeof document === "string") {
    try {
      return strictParse(document);
    } catch {
      throw new TypeError("trusted key document is not valid JSON");
    }
  }
  return structuredClone(document);
}

function parseStatusDocument(document) {
  if (typeof document === "string") {
    try {
      return strictParse(document);
    } catch {
      throw new TypeError("status document is not valid JSON");
    }
  }
  return structuredClone(document);
}

/**
 * Verify the trusted provisioning input at construction and build a per-entity
 * view of current root/device kids. Each entity's documents are ingested, in
 * order, through a {@link KeyDocumentTrust} pinned to the anchor supplied for
 * that entity: single-document verification, chain linking and anchor checks
 * all run here. Any invalid or untrusted document throws (fail closed), so no
 * relay is ever constructed around an untrusted chain.
 */
export function buildKeyDocumentRegistry(keyDocuments) {
  if (!Array.isArray(keyDocuments) || keyDocuments.length === 0) {
    throw new TypeError("keyDocuments must be a non-empty array");
  }
  const groups = new Map();
  const entityOrder = [];
  for (const entry of keyDocuments) {
    if (!isPlainObject(entry)) throw new TypeError("each keyDocuments entry must be an object");
    for (const key of Object.keys(entry)) {
      if (key !== "document" && key !== "anchor") {
        throw new TypeError(`unknown keyDocuments entry field: ${key}`);
      }
    }
    if (!Object.hasOwn(entry, "document")) {
      throw new TypeError("keyDocuments entry requires a document");
    }
    const document = parseKeyDocument(entry.document);
    if (!isPlainObject(document) || typeof document.entity !== "string") {
      throw new TypeError("trusted key document must carry a string entity");
    }
    let group = groups.get(document.entity);
    if (group === undefined) {
      group = { anchor: entry.anchor, documents: [] };
      groups.set(document.entity, group);
      entityOrder.push(document.entity);
    } else if (group.anchor === undefined && entry.anchor !== undefined) {
      group.anchor = entry.anchor;
    }
    group.documents.push(document);
  }

  const ownerByKid = new Map();
  const kidsByEntity = new Map();
  const trustedByEntity = new Map();
  for (const entity of entityOrder) {
    const group = groups.get(entity);
    const anchor = group.anchor === undefined ? null : group.anchor;
    let trust;
    try {
      trust = new KeyDocumentTrust({ entity, anchor });
    } catch (error) {
      throw new TypeError(`invalid trusted key document anchor for ${entity}: ${error.message}`);
    }
    let current;
    for (const document of group.documents) {
      const result = trust.ingest(document);
      if (!result.valid) {
        throw new Error(`untrusted key document for ${entity}: ${result.reason}`);
      }
      current = document;
    }
    // The latest accepted generation supplies the trusted `roots` against which
    // a status document for the entity is verified.
    trustedByEntity.set(entity, current);
    const kids = new Set([...current.roots, ...current.devices]);
    kidsByEntity.set(entity, kids);
    for (const kid of kids) {
      const existing = ownerByKid.get(kid);
      if (existing !== undefined && existing !== entity) {
        throw new Error(`key ${kid} is endorsed by multiple entities`);
      }
      ownerByKid.set(kid, entity);
    }
  }
  return { ownerByKid, entityCount: kidsByEntity.size, trustedByEntity };
}

/**
 * Verify the trusted status provisioning input at construction. Each status
 * document is bound to a trusted key document for its entity (which supplies the
 * roots that must sign it) and run through a per-entity {@link StatusTracker}:
 * single-document verification plus serial-rollback and staleness rules. Any
 * invalid, rollback or stale document throws (fail closed), so a relay is never
 * constructed around an invalid revoked-key list. Status documents are
 * trusted provisioning input, not runtime wire input; runtime status refresh is
 * out of scope for this slice. Configured freshness and presence are rechecked
 * at each send; caller-owned documents are snapshotted before verification.
 */
export function buildStatusRegistry(statusDocuments, keyDocRegistry) {
  if (!Array.isArray(statusDocuments) || statusDocuments.length === 0) {
    throw new TypeError("statusDocuments must be a non-empty array");
  }
  const tracker = new StatusTracker();
  const entities = new Set();
  const validity = new Map();
  for (const entry of statusDocuments) {
    if (!isPlainObject(entry)) throw new TypeError("each statusDocuments entry must be an object");
    for (const key of Object.keys(entry)) {
      if (key !== "document" && key !== "now" && key !== "maxAgeSeconds") {
        throw new TypeError(`unknown statusDocuments entry field: ${key}`);
      }
    }
    if (!Object.hasOwn(entry, "document")) {
      throw new TypeError("statusDocuments entry requires a document");
    }
    const document = parseStatusDocument(entry.document);
    const entity = isPlainObject(document) && typeof document.entity === "string"
      ? document.entity
      : null;
    const trusted = entity === null ? undefined : keyDocRegistry.trustedByEntity.get(entity);
    if (trusted === undefined) {
      throw new Error(`status document for an entity with no trusted key document: ${entity ?? "missing"}`);
    }
    // Explicit single-document verification against the trusted key document,
    // then the stateful tracker applies serial rollback and staleness.
    const single = verifyStatusDocument(document, trusted);
    if (!single.valid) {
      throw new Error(`untrusted status document for ${entity}: ${single.reason}`);
    }
    const issuedAt = Date.parse(document.issuedAt);
    // Date.parse normalizes some impossible calendar dates. Reject those too.
    if (!Number.isFinite(issuedAt) || new Date(issuedAt).toISOString().slice(0, 19) !== document.issuedAt.slice(0, 19)) {
      throw new TypeError("invalid status issuance time");
    }
    const result = tracker.ingest(document, {
      trustedKeyDocument: trusted,
      now: entry.now,
      maxAgeSeconds: entry.maxAgeSeconds
    });
    if (!result.valid) {
      throw new Error(`untrusted status document for ${entity}: ${result.reason}`);
    }
    entities.add(entity);
    validity.set(entity, { issuedAt, maxAgeMs: entry.maxAgeSeconds === undefined ? Infinity : entry.maxAgeSeconds * 1000 });
  }
  let observedNow = Date.now();
  const allows = (entity, kid) => {
    observedNow = Math.max(observedNow, Date.now());
    const current = validity.get(entity);
    return current !== undefined && Number.isFinite(observedNow) &&
      observedNow >= current.issuedAt && observedNow - current.issuedAt <= current.maxAgeMs &&
      !tracker.isRevoked(entity, kid, STATUS_GENERATION_ANY);
  };
  return { tracker, entityCount: entities.size, allows };
}
