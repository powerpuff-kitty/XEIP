// tools/identity-device-rotation.mjs
//
// Dependency-free reference for *signed XEIP device-rotation statements* (issue
// #1, the device-rotation slice of the identity key lifecycle). It is the fourth
// testable slice of the design in spec/identity-keys.md §5.3/§6 and ADR 0010,
// after the signed envelope, the signed key document and the signed status
// document. It adds no custom crypto: Ed25519, RFC 8785 (JCS) canonicalization,
// strict parsing, the weak-key blacklist and the base64url codec all come from
// `./signed-envelope.mjs`, and key-ids come from `./derive-keyid.mjs`.
//
// Fixed carrier (`xeip.device-rotation/0.1`):
//
//   {
//     "xeip": "xeip.device-rotation/0.1",
//     "entity": "urn:xeip:entity:<genesis-kid>",
//     "previous_kid": "<kid>",
//     "successor_kid": "<kid>",
//     "issuedAt": "<UTC>",
//     "overlapUntil": "<UTC>",                                  // optional
//     "signatures": [ { "kid": "<root-kid>", "sig": "<unpadded base64url 64-byte sig>" } ]
//   }
//
// Signing input = the statement with `signatures` removed, RFC 8785 (JCS),
// signed with Ed25519. Verification is single-document: strict structural
// validation, then the statement's `entity` must match a trusted key document's
// `entity`, then at least one valid signature by a *current root key listed in
// that trusted key document*. On top of that, a stateful DeviceRotationTracker
// records accepted rotations per entity and adds the bounded-overlap lifecycle
// rules:
//
//   - `rotation conflict`: a second rotation of the same predecessor, or a
//     successor that is already retired (was itself a predecessor), is rejected;
//   - `overlap too long`: when the caller supplies a maximum overlap, an
//     `overlapUntil` that exceeds it is rejected;
//   - `expired predecessor`: after `overlapUntil` the previous key is no longer
//     active (`isActive`), while the successor becomes active immediately.
//
// The grammar and the stable reason strings are byte-identical to the Rust port
// in `crates/xeip-identity` and the shared vectors under
// `conformance/fixtures/identity-rotation/`.
//
// Deferred (see spec/plans/identity-device-rotation.md): root-rotation rules,
// distributing/enforcing post-overlap rejection across verifiers, and directory
// discovery.

import { KeyObject, createPrivateKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { decodeKeyId } from "./derive-keyid.mjs";
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
export const ROTATION_VERSION = "xeip.device-rotation/0.1";

/** Ed25519 signatures are exactly 64 bytes (RFC 8032 §5.1.6). */
export const ED25519_SIGNATURE_LENGTH = 64;

/** Largest integer that round-trips through an IEEE-754 double exactly. */
export const MAX_SAFE_INTEGER = 9007199254740991;

// The complete member set. Any other member is rejected as `unknown field`
// before `xeip` is even inspected, matching the strict pre-parse gate.
const KNOWN_FIELDS = Object.freeze([
  "xeip",
  "entity",
  "previous_kid",
  "successor_kid",
  "issuedAt",
  "overlapUntil",
  "signatures",
]);

const KNOWN_FIELD_SET = new Set(KNOWN_FIELDS);

// `<UTC>` is an RFC 3339 instant in UTC (`Z`), optionally with a fractional
// second. Offsets are rejected: this profile fixes UTC, matching key documents.
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/**
 * Structural and lifecycle reasons a device-rotation statement can be rejected.
 * The first seven reasons are shared with the signed key-document and status
 * profiles (`malformed document`, `unsupported version`, `unknown field`,
 * `entity binding`, `unknown signer`, `weak key`, `signature mismatch`).
 * `ROTATION_CONFLICT` and `OVERLAP_TOO_LONG` are the stateful ingest rules;
 * `EXPIRED_PREDECESSOR` and `UNKNOWN_DEVICE` are reported by
 * {@link DeviceRotationTracker.isActive}.
 *
 * The `fmt::Display` spelling of each reason matches the Rust port
 * (`crates/xeip-identity`) so cross-language comparisons are byte-identical.
 */
export const ROTATION_REASONS = Object.freeze({
  MALFORMED: "malformed document",
  VERSION: "unsupported version",
  UNKNOWN_FIELD: "unknown field",
  ENTITY_BINDING: "entity binding",
  UNKNOWN_SIGNER: "unknown signer",
  WEAK_KEY: "weak key",
  SIGNATURE_MISMATCH: "signature mismatch",
  ROTATION_CONFLICT: "rotation conflict",
  OVERLAP_TOO_LONG: "overlap too long",
  EXPIRED_PREDECESSOR: "expired predecessor",
  UNKNOWN_DEVICE: "unknown device",
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function malformed() {
  return { valid: false, reason: ROTATION_REASONS.MALFORMED };
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
 * The exact signing input: the statement with the `signatures` member removed in
 * its entirety, canonicalized with RFC 8785. Returns the canonical string (the
 * UTF-8 bytes are what is signed/verified).
 */
export function rotationSigningInput(document) {
  if (!isPlainObject(document)) throw new TypeError("rotation statement must be an object");
  const base = { ...document };
  delete base.signatures;
  return canonicalize(base);
}

/**
 * Sign a device-rotation statement. The signing input is the statement without
 * `signatures`, canonicalized (RFC 8785) and signed with Ed25519. Returns a new
 * statement whose `signatures` array appends `{ kid, sig }` to any existing
 * signatures.
 *
 * @param {object} document Parsed rotation statement (its `signatures` are ignored).
 * @param {{ privateKey: KeyObject|Uint8Array|string, kid: string }} options
 */
export function signDeviceRotation(document, { privateKey, kid } = {}) {
  if (!isPlainObject(document)) throw new TypeError("rotation statement must be an object");
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
    return { reason: ROTATION_REASONS.MALFORMED };
  }
  if (isWeakEd25519PublicKey(raw)) return { reason: ROTATION_REASONS.WEAK_KEY };
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

// Verify a parsed rotation value against a trusted key document. This is the
// single-document core; {@link DeviceRotationTracker} adds the lifecycle rules.
function verifyRotationValue(value, trustedKeyDocument) {
  if (!isPlainObject(value)) return malformed();

  for (const key of Object.keys(value)) {
    if (!KNOWN_FIELD_SET.has(key)) return { valid: false, reason: ROTATION_REASONS.UNKNOWN_FIELD };
  }

  if (typeof value.xeip !== "string") return malformed();
  if (value.xeip !== ROTATION_VERSION) {
    return { valid: false, reason: ROTATION_REASONS.VERSION };
  }

  if (typeof value.entity !== "string") return malformed();
  if (typeof value.previous_kid !== "string") return malformed();
  if (typeof value.successor_kid !== "string") return malformed();
  if (typeof value.issuedAt !== "string" || !UTC_TIMESTAMP.test(value.issuedAt)) {
    return malformed();
  }
  if (value.overlapUntil !== undefined) {
    if (typeof value.overlapUntil !== "string" || !UTC_TIMESTAMP.test(value.overlapUntil)) {
      return malformed();
    }
    if (parseUtcSeconds(value.overlapUntil) <= parseUtcSeconds(value.issuedAt)) {
      return malformed();
    }
  }

  // Both device key-ids must be canonical and non-weak. A malformed spelling is
  // a structural error; weakness is reported after the entity binding, matching
  // the single-document order.
  const previous = decodeKidOrReason(value.previous_kid);
  if (previous.reason) return { valid: false, reason: previous.reason };
  const successor = decodeKidOrReason(value.successor_kid);
  if (successor.reason) return { valid: false, reason: successor.reason };
  if (value.previous_kid === value.successor_kid) return malformed();

  if (!Array.isArray(value.signatures)) return malformed();
  for (const entry of value.signatures) {
    if (!isPlainObject(entry) || typeof entry.kid !== "string" || typeof entry.sig !== "string") {
      return malformed();
    }
  }

  if (trustedEntity(trustedKeyDocument) !== value.entity) {
    return { valid: false, reason: ROTATION_REASONS.ENTITY_BINDING };
  }

  if (isWeakEd25519PublicKey(previous.raw) || isWeakEd25519PublicKey(successor.raw)) {
    return { valid: false, reason: ROTATION_REASONS.WEAK_KEY };
  }

  if (value.signatures.length === 0) {
    return { valid: false, reason: ROTATION_REASONS.UNKNOWN_SIGNER };
  }

  const roots = trustedRoots(trustedKeyDocument);
  const input = Buffer.from(rotationSigningInput(value), "utf8");
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

  if (!sawRootSigner) return { valid: false, reason: ROTATION_REASONS.UNKNOWN_SIGNER };
  return { valid: false, reason: ROTATION_REASONS.SIGNATURE_MISMATCH };
}

/**
 * Verify a single signed device-rotation statement against a trusted key
 * document for the entity. Accepts a JSON string (through the strict pre-parse
 * gate) or a parsed object, and returns a structured result rather than
 * throwing:
 *
 *   { valid: true } | { valid: false, reason }
 *
 * Order, with stable reasons: strict parse / not an object (`malformed
 * document`) → unknown member (`unknown field`) → `xeip` (`unsupported
 * version`) → field types, kids, `issuedAt`/`overlapUntil` (`malformed
 * document` / `weak key`) → `entity == trusted.entity` (`entity binding`) →
 * weak device kids (`weak key`) → at least one valid signature by a key listed
 * in `trusted.roots` (`unknown signer` / `weak key` / `signature mismatch`).
 *
 * This is the stateless single-document check. Rotation conflict and the
 * bounded-overlap rule are lifecycle rules and live in
 * {@link DeviceRotationTracker}.
 */
export function verifyDeviceRotation(document, trustedKeyDocument) {
  let value = document;
  if (typeof document === "string") {
    try {
      value = strictParse(document);
    } catch {
      return malformed();
    }
  }
  return verifyRotationValue(value, trustedKeyDocument);
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
 * Stateful, per-`entity` device-rotation tracker for
 * `xeip.device-rotation/0.1`.
 *
 * {@link DeviceRotationTracker.ingest} first runs the stateless verification
 * ({@link verifyDeviceRotation}) and then enforces the lifecycle rules against
 * the rotations already accepted for the entity:
 *
 * - **rotation conflict** — a candidate whose `previous_kid` was already used
 *   as a predecessor (a second rotation of the same predecessor), or whose
 *   `successor_kid` is already retired (was itself a predecessor), is rejected;
 * - **overlap too long** — when the caller supplies `maxOverlapSeconds`, a
 *   candidate whose overlap (`overlapUntil - issuedAt`, or zero when
 *   `overlapUntil` is absent) exceeds it is rejected.
 *
 * State is committed only when every check passes, so a rejected candidate
 * never advances the accepted rotations.
 *
 * `isActive(entity, kid, now)` reports whether `kid` may still authenticate for
 * `entity` at `now`: the current successor is active immediately; a predecessor
 * is active through `overlapUntil` (inclusive) and then rejected with `expired
 * predecessor`; any other `kid` is `unknown device`. A missing entity is
 * `unknown device`; callers MUST treat that as "not endorsed", never as proof
 * of a key's existence.
 */
export class DeviceRotationTracker {
  // entity -> { predecessors: Map<kid, overlapUntilSeconds>, current: kid }
  #entities = new Map();

  /**
   * Verify and record `document` (a parsed object or JSON text) for its entity.
   *
   * @param {object|string} document Device-rotation statement.
   * @param {object} options
   * @param {object} options.trustedKeyDocument Verified key document for the entity.
   * @param {number} [options.maxOverlapSeconds] Maximum accepted overlap length.
   * @returns {{ valid: true } | { valid: false, reason: string }}
   */
  ingest(document, { trustedKeyDocument, maxOverlapSeconds } = {}) {
    let value = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformed();
      }
    }

    const single = verifyRotationValue(value, trustedKeyDocument);
    if (!single.valid) return single;

    const state = this.#entities.get(value.entity) ?? {
      predecessors: new Map(),
      current: null,
    };

    if (
      state.predecessors.has(value.previous_kid) ||
      state.predecessors.has(value.successor_kid)
    ) {
      return { valid: false, reason: ROTATION_REASONS.ROTATION_CONFLICT };
    }

    const issuedAt = parseUtcSeconds(value.issuedAt);
    const overlapUntil =
      value.overlapUntil === undefined ? issuedAt : parseUtcSeconds(value.overlapUntil);
    if (maxOverlapSeconds !== undefined) {
      if (
        typeof maxOverlapSeconds !== "number" ||
        !Number.isFinite(maxOverlapSeconds) ||
        maxOverlapSeconds < 0
      ) {
        throw new TypeError("maxOverlapSeconds must be a non-negative number");
      }
      if (overlapUntil - issuedAt > maxOverlapSeconds) {
        return { valid: false, reason: ROTATION_REASONS.OVERLAP_TOO_LONG };
      }
    }

    state.predecessors.set(value.previous_kid, overlapUntil);
    state.current = value.successor_kid;
    this.#entities.set(value.entity, state);
    return { valid: true };
  }

  /**
   * Whether `kid` may authenticate for `entity` at `now`. Returns
   * `{ active: true }`, or `{ active: false, reason }` with `expired
   * predecessor` (a predecessor past its overlap) or `unknown device` (no
   * accepted rotation names the key). `now` is required.
   */
  isActive(entity, kid, now) {
    const state = this.#entities.get(entity);
    if (state === undefined) return { active: false, reason: ROTATION_REASONS.UNKNOWN_DEVICE };
    if (state.current === kid) return { active: true };
    const overlapUntil = state.predecessors.get(kid);
    if (overlapUntil === undefined) {
      return { active: false, reason: ROTATION_REASONS.UNKNOWN_DEVICE };
    }
    if (toEpochSeconds(now) <= overlapUntil) return { active: true };
    return { active: false, reason: ROTATION_REASONS.EXPIRED_PREDECESSOR };
  }

  /** Whether any rotation has been accepted for `entity`. */
  hasRotations(entity) {
    return this.#entities.has(entity);
  }
}

function printUsage() {
  return "usage:\n  node tools/identity-device-rotation.mjs verify <rotation.json> <trusted-keydoc.json>\n";
}

function main(argv) {
  const [command, rotationPath, trustedPath] = argv;
  if (command === "verify" && rotationPath !== undefined && trustedPath !== undefined) {
    try {
      const trusted = JSON.parse(readFileSync(trustedPath, "utf8"));
      const result = verifyDeviceRotation(readFileSync(rotationPath, "utf8"), trusted);
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
