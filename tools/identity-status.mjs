// tools/identity-status.mjs
//
// Dependency-free reference for *signed XEIP identity status documents* (issue
// #1, the revocation/status slice of the identity key lifecycle). It is the
// third testable slice of the design in spec/identity-keys.md §9 and ADR 0010,
// after the signed envelope and the signed key document. It adds no custom
// crypto: Ed25519, RFC 8785 (JCS) canonicalization, strict parsing, the weak-key
// blacklist and the base64url codec all come from `./signed-envelope.mjs`, and
// key-ids come from `./derive-keyid.mjs`.
//
// Fixed carrier (`xeip.status/0.1`):
//
//   {
//     "xeip": "xeip.status/0.1",
//     "entity": "urn:xeip:entity:<genesis-kid>",
//     "serial": <int >= 0>,
//     "issuedAt": "<UTC>",
//     "revoked": [ { "kid": "<kid>", "generation": <int >= 1> }, ... ],
//     "signatures": [ { "kid": "<root-kid>", "sig": "<unpadded base64url 64-byte sig>" } ]
//   }
//
// Signing input = the document with `signatures` removed, RFC 8785 (JCS),
// signed with Ed25519. Verification is single-document: strict structural
// validation, then the document's `entity` must match a trusted key document's
// `entity`, then at least one valid signature by a *current root key listed in
// that trusted key document*. On top of that, a stateful StatusTracker adds the
// two lifecycle rules the design requires:
//
//   - `serial rollback`: a serial <= the highest serial already accepted for
//     the entity is rejected, so an old "clean" status cannot be replayed;
//   - `stale status`: an `issuedAt` older than a caller-supplied maximum age is
//     rejected, so a verifier fails closed rather than treating "no fresh
//     status" as "not revoked".
//
// The grammar and the stable reason strings are byte-identical to the Rust port
// in `crates/xeip-identity` and the shared vectors under
// `conformance/fixtures/identity-status/`.
//
// Deferred (see spec/plans/identity-status.md): status distribution/anchoring,
// live-stream effects, device rotation statements and durable fork evidence.

import { KeyObject, createPrivateKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { decodeKeyId, entityUrn } from "./derive-keyid.mjs";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalize,
  ed25519PrivateKeyFromSeed,
  ed25519PublicKeyFromRaw,
  isWeakEd25519PublicKey,
  strictParse,
} from "./signed-envelope.mjs";

/** The only accepted `xeip` value; anything else is `unsupported version`. */
export const STATUS_VERSION = "xeip.status/0.1";

/** Ed25519 signatures are exactly 64 bytes (RFC 8032 §5.1.6). */
export const ED25519_SIGNATURE_LENGTH = 64;

/** Largest integer that round-trips through an IEEE-754 double exactly. */
export const MAX_SAFE_INTEGER = 9007199254740991;

// The complete member set. Any other member is rejected as `unknown field`
// before `xeip` is even inspected, matching the strict pre-parse gate.
const KNOWN_FIELDS = Object.freeze([
  "xeip",
  "entity",
  "serial",
  "issuedAt",
  "revoked",
  "signatures",
]);

const KNOWN_FIELD_SET = new Set(KNOWN_FIELDS);

// `<UTC>` is an RFC 3339 instant in UTC (`Z`), optionally with a fractional
// second. Offsets are rejected: this profile fixes UTC, matching key documents.
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/**
 * Structural reasons a status document can be rejected. The first seven reasons
 * are shared with the signed key-document profile (`malformed document`,
 * `unsupported version`, `unknown field`, `entity binding`, `unknown signer`,
 * `weak key`, `signature mismatch`). `SERIAL_ROLLBACK` and `STALE` are the two
 * lifecycle rules the stateful {@link StatusTracker} adds.
 *
 * The `fmt::Display` spelling of each reason matches the Rust port
 * (`crates/xeip-identity`) so cross-language comparisons are byte-identical.
 */
export const STATUS_REASONS = Object.freeze({
  MALFORMED: "malformed document",
  VERSION: "unsupported version",
  UNKNOWN_FIELD: "unknown field",
  ENTITY_BINDING: "entity binding",
  UNKNOWN_SIGNER: "unknown signer",
  WEAK_KEY: "weak key",
  SIGNATURE_MISMATCH: "signature mismatch",
  SERIAL_ROLLBACK: "serial rollback",
  STALE: "stale status",
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function malformed() {
  return { valid: false, reason: STATUS_REASONS.MALFORMED };
}

function normalizePrivateKey(privateKey) {
  let key;
  if (privateKey instanceof KeyObject) {
    key = privateKey;
  } else if (privateKey instanceof Uint8Array) {
    if (privateKey.length !== 32) {
      throw new RangeError(`Ed25519 seed must be 32 bytes; received ${privateKey.length}`);
    }
    key = ed25519PrivateKeyFromSeed(privateKey);
  } else if (typeof privateKey === "string") {
    key = createPrivateKey(privateKey);
  } else {
    throw new TypeError("privateKey must be a KeyObject, a 32-byte seed, or a PEM/DER string");
  }
  if (key.type !== "private") throw new TypeError("privateKey must be a private key");
  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`privateKey must be Ed25519; received ${key.asymmetricKeyType}`);
  }
  return key;
}

/**
 * The exact signing input: the document with the `signatures` member removed in
 * its entirety, canonicalized with RFC 8785. Returns the canonical string (the
 * UTF-8 bytes are what is signed/verified).
 */
export function statusSigningInput(document) {
  if (!isPlainObject(document)) throw new TypeError("status document must be an object");
  const base = { ...document };
  delete base.signatures;
  return canonicalize(base);
}

/**
 * Sign a status document. The signing input is the document without
 * `signatures`, canonicalized (RFC 8785) and signed with Ed25519. Returns a new
 * document whose `signatures` array appends `{ kid, sig }` to any existing
 * signatures.
 *
 * @param {object} document Parsed status document (its `signatures` are ignored).
 * @param {{ privateKey: KeyObject|Uint8Array|string, kid: string }} options
 */
export function signStatusDocument(document, { privateKey, kid } = {}) {
  if (!isPlainObject(document)) throw new TypeError("status document must be an object");
  if (typeof kid !== "string") throw new TypeError("kid must be a string");
  decodeKeyId(kid);
  const key = normalizePrivateKey(privateKey);
  const existing = Array.isArray(document.signatures) ? document.signatures : [];
  const base = { ...document };
  delete base.signatures;
  const input = Buffer.from(canonicalize(base), "utf8");
  const signature = sign(null, input, key);
  return { ...document, signatures: [...existing, { kid, sig: bytesToBase64Url(signature) }] };
}

// Decode a key-id to its 32 raw bytes, rejecting a malformed spelling
// (`malformed document`) or a small-order key (`weak key`).
function decodeKidOrReason(kid) {
  let raw;
  try {
    raw = decodeKeyId(kid);
  } catch {
    return { reason: STATUS_REASONS.MALFORMED };
  }
  if (isWeakEd25519PublicKey(raw)) return { reason: STATUS_REASONS.WEAK_KEY };
  return { raw };
}

// The `entity` of a trusted key document, or `null` when it is not usable. The
// caller asserts the trusted document is already verified; this reads only the
// binding fields.
function trustedEntity(trusted) {
  return isPlainObject(trusted) && typeof trusted.entity === "string" ? trusted.entity : null;
}

// The set of current root key-ids listed in a trusted key document.
function trustedRoots(trusted) {
  const roots = isPlainObject(trusted) && Array.isArray(trusted.roots) ? trusted.roots : [];
  return new Set(roots.filter((kid) => typeof kid === "string"));
}

// Verify a parsed status value against a trusted key document. This is the
// single-document core (steps 1–3); {@link StatusTracker} adds rollback and
// staleness on top.
function verifyStatusValue(value, trustedKeyDocument) {
  if (!isPlainObject(value)) return malformed();

  for (const key of Object.keys(value)) {
    if (!KNOWN_FIELD_SET.has(key)) return { valid: false, reason: STATUS_REASONS.UNKNOWN_FIELD };
  }

  if (typeof value.xeip !== "string") return malformed();
  if (value.xeip !== STATUS_VERSION) {
    return { valid: false, reason: STATUS_REASONS.VERSION };
  }

  if (typeof value.entity !== "string") return malformed();
  if (
    typeof value.serial !== "number" ||
    !Number.isInteger(value.serial) ||
    value.serial < 0 ||
    value.serial > MAX_SAFE_INTEGER
  ) {
    return malformed();
  }
  if (typeof value.issuedAt !== "string" || !UTC_TIMESTAMP.test(value.issuedAt)) {
    return malformed();
  }
  if (!Array.isArray(value.revoked)) return malformed();
  for (const entry of value.revoked) {
    if (
      !isPlainObject(entry) ||
      typeof entry.kid !== "string" ||
      typeof entry.generation !== "number" ||
      !Number.isInteger(entry.generation) ||
      entry.generation < 1 ||
      entry.generation > MAX_SAFE_INTEGER
    ) {
      return malformed();
    }
    // A revoked key-id must be a canonical key-id; a malformed spelling is a
    // structural error, not `unknown signer` / `weak key`.
    try {
      decodeKeyId(entry.kid);
    } catch {
      return malformed();
    }
  }
  if (!Array.isArray(value.signatures)) return malformed();
  for (const entry of value.signatures) {
    if (!isPlainObject(entry) || typeof entry.kid !== "string" || typeof entry.sig !== "string") {
      return malformed();
    }
  }

  if (trustedEntity(trustedKeyDocument) !== value.entity) {
    return { valid: false, reason: STATUS_REASONS.ENTITY_BINDING };
  }

  if (value.signatures.length === 0) {
    return { valid: false, reason: STATUS_REASONS.UNKNOWN_SIGNER };
  }

  const roots = trustedRoots(trustedKeyDocument);
  const input = Buffer.from(statusSigningInput(value), "utf8");
  let sawRootSigner = false;
  for (const entry of value.signatures) {
    const decoded = decodeKidOrReason(entry.kid);
    if (decoded.reason) return { valid: false, reason: decoded.reason };
    const signature = base64UrlToBytes(entry.sig);
    if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) return malformed();
    if (!roots.has(entry.kid)) continue;
    sawRootSigner = true;
    const publicKey = ed25519PublicKeyFromRaw(decoded.raw);
    if (verify(null, input, publicKey, signature)) return { valid: true };
  }

  if (!sawRootSigner) return { valid: false, reason: STATUS_REASONS.UNKNOWN_SIGNER };
  return { valid: false, reason: STATUS_REASONS.SIGNATURE_MISMATCH };
}

/**
 * Verify a single signed status document against a trusted key document for the
 * entity. Accepts a JSON string (through the strict pre-parse gate) or a parsed
 * object, and returns a structured result rather than throwing:
 *
 *   { valid: true } | { valid: false, reason }
 *
 * Order, with stable reasons: strict parse / not an object (`malformed
 * document`) → unknown member (`unknown field`) → `xeip` (`unsupported
 * version`) → field types, `serial`, `issuedAt`, revoked `kid`/`generation`
 * (`malformed document` / `weak key`) → `entity == trusted.entity` (`entity
 * binding`) → at least one valid signature by a key listed in `trusted.roots`
 * (`unknown signer` / `weak key` / `signature mismatch`).
 *
 * This is the stateless single-document check. Serial rollback and staleness are
 * lifecycle rules and live in {@link StatusTracker}.
 */
export function verifyStatusDocument(document, trustedKeyDocument) {
  let value = document;
  if (typeof document === "string") {
    try {
      value = strictParse(document);
    } catch {
      return malformed();
    }
  }
  return verifyStatusValue(value, trustedKeyDocument);
}

// Parse a `YYYY-MM-DDTHH:MM:SS(.fff)Z` instant into whole epoch seconds. The
// shape is validated before this is called, so the digits are known present.
function parseUtcSeconds(text) {
  const year = Number(text.slice(0, 4));
  const month = Number(text.slice(5, 7));
  const day = Number(text.slice(8, 10));
  const hour = Number(text.slice(11, 13));
  const minute = Number(text.slice(14, 16));
  const second = Number(text.slice(17, 19));
  const milliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
  return Math.floor(milliseconds / 1000);
}

// Coerce a caller-supplied reference instant to whole epoch seconds. Accepts an
// ISO string (preferred, deterministic), a `Date`, or epoch milliseconds.
function toEpochSeconds(now) {
  if (now === undefined) return Math.floor(Date.now() / 1000);
  if (now instanceof Date) return Math.floor(now.getTime() / 1000);
  if (typeof now === "number") return Math.floor(now / 1000);
  if (typeof now === "string") {
    const parsed = Date.parse(now);
    if (Number.isNaN(parsed)) throw new TypeError("now must be an ISO instant, Date or epoch ms");
    return Math.floor(parsed / 1000);
  }
  throw new TypeError("now must be an ISO instant, Date or epoch ms");
}

/**
 * Stateful, per-`entity` status tracker for `xeip.status/0.1`.
 *
 * {@link StatusTracker.ingest} first runs the stateless verification
 * ({@link verifyStatusDocument}) and then enforces the two lifecycle rules
 * against the status already accepted for the entity:
 *
 * - **serial rollback** — a candidate whose `serial` is less than or equal to
 *   the highest serial already accepted for the entity is rejected with `serial
 *   rollback`, so a replayed old "clean" status is never accepted;
 * - **staleness** — when a caller supplies `maxAgeSeconds`, a candidate whose
 *   `issuedAt` is more than that age behind `now` is rejected with `stale
 *   status`.
 *
 * State is committed only when every check passes, so a rejected candidate
 * never advances the serial or replaces the accepted status.
 *
 * `isRevoked(entity, kid, generation)` reports whether the accepted status for
 * `entity` revokes `kid` at key-document generation `generation`. An entry
 * `{ kid, generation: G }` revokes that key for generation `G` **and later**, so
 * a rotated-but-republished key stays revoked. A missing accepted status is
 * reported as "not revoked"; callers MUST treat *no fresh status* as unknown,
 * never as proof that a key is live (`spec/identity-keys.md` §9).
 */
export class StatusTracker {
  #entities = new Map();

  /**
   * Verify and record `document` (a parsed object or JSON text) for its entity.
   *
   * @param {object|string} document Status document.
   * @param {object} options
   * @param {object} options.trustedKeyDocument Verified key document for the entity.
   * @param {string|Date|number} [options.now] Reference instant (ISO preferred).
   * @param {number} [options.maxAgeSeconds] Maximum accepted age of `issuedAt`.
   * @returns {{ valid: true } | { valid: false, reason: string }}
   */
  ingest(document, { trustedKeyDocument, now, maxAgeSeconds } = {}) {
    let value = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformed();
      }
    }

    const single = verifyStatusValue(value, trustedKeyDocument);
    if (!single.valid) return single;

    const accepted = this.#entities.get(value.entity);
    if (accepted !== undefined && value.serial <= accepted.serial) {
      return { valid: false, reason: STATUS_REASONS.SERIAL_ROLLBACK };
    }

    if (maxAgeSeconds !== undefined) {
      if (typeof maxAgeSeconds !== "number" || !Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0) {
        throw new TypeError("maxAgeSeconds must be a non-negative number");
      }
      if (toEpochSeconds(now) - parseUtcSeconds(value.issuedAt) > maxAgeSeconds) {
        return { valid: false, reason: STATUS_REASONS.STALE };
      }
    }

    this.#entities.set(value.entity, { serial: value.serial, document: value });
    return { valid: true };
  }

  /**
   * Whether the accepted status for `entity` revokes `kid` for key-document
   * generation `generation` (a revoked entry applies to its recorded generation
   * and every later one). Returns `false` when no status has been accepted.
   */
  isRevoked(entity, kid, generation) {
    const accepted = this.#entities.get(entity);
    if (accepted === undefined) return false;
    return accepted.document.revoked.some(
      (entry) => entry.kid === kid && generation >= entry.generation,
    );
  }

  /** The highest serial accepted for `entity`, or `undefined` if none. */
  acceptedSerial(entity) {
    return this.#entities.get(entity)?.serial;
  }

  /** Whether a status has been accepted for `entity`. */
  hasStatus(entity) {
    return this.#entities.has(entity);
  }
}

function printUsage() {
  return "usage:\n  node tools/identity-status.mjs verify <status.json> <trusted-keydoc.json>\n";
}

function main(argv) {
  const [command, statusPath, trustedPath] = argv;
  if (command === "verify" && statusPath !== undefined && trustedPath !== undefined) {
    try {
      const trusted = JSON.parse(readFileSync(trustedPath, "utf8"));
      const result = verifyStatusDocument(readFileSync(statusPath, "utf8"), trusted);
      process.stdout.write(JSON.stringify(result) + "\n");
      if (!result.valid) process.exitCode = 1;
    } catch (error) {
      process.stderr.write(`error: ${error.message}\n`);
      process.exitCode = 1;
    }
    return;
  }
  process.stderr.write(printUsage());
  process.exitCode = 1;
}

// Run only when invoked directly, so importing the module in tests is silent.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
