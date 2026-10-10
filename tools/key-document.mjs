// tools/key-document.mjs
//
// Dependency-free reference for *signed XEIP key documents* (issue #1, first
// key-lifecycle slice). This is the first testable slice of the design in
// spec/identity-keys.md and ADR 0010: a single signed key document and
// single-document verification. Chain, rollback and trust-store resolution are
// deliberately out of scope (see spec/plans/identity-keydoc.md).
//
// Fixed carrier (`xeip.keydoc/0.1`):
//
//   {
//     "xeip": "xeip.keydoc/0.1",
//     "entity": "urn:xeip:entity:<genesis-kid>",
//     "genesis": "<genesis-kid>",
//     "generation": <int >= 1>,
//     "issuedAt": "<UTC>",
//     "previous": "<sha256-hex of previous canonical doc>",   // optional
//     "roots":   ["<kid>", ...],
//     "devices": ["<kid>", ...],
//     "signatures": [ { "kid": "<root-kid>", "sig": "<unpadded base64url 64-byte sig>" } ]
//   }
//
// Signing input = the document with `signatures` removed, RFC 8785 (JCS),
// signed with Ed25519. Verification is single-document only: strict structural
// validation, then at least one valid signature by a key listed in `roots`.
// `previous` is recorded but never chased.
//
// Ed25519, JCS and base64url come from the existing audited/reference modules
// (`./signed-envelope.mjs`); this file only adds the document grammar and its
// verification order. See spec/local-signed-envelopes.md for the sibling
// profile and spec/decisions/0007-crypto-dependencies.md for the dependency
// policy ("no custom crypto").

import { KeyObject, createHash, createPrivateKey, sign, verify } from "node:crypto";
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
export const KEYDOC_VERSION = "xeip.keydoc/0.1";

/** Ed25519 signatures are exactly 64 bytes (RFC 8032 §5.1.6). */
export const ED25519_SIGNATURE_LENGTH = 64;

/** Largest integer that round-trips through an IEEE-754 double exactly. */
export const MAX_SAFE_INTEGER = 9007199254740991;

// The complete member set. Any other member is rejected as `unknown field`
// before `xeip` is even inspected, matching the strict pre-parse gate.
const KNOWN_FIELDS = Object.freeze([
  "xeip",
  "entity",
  "genesis",
  "generation",
  "issuedAt",
  "previous",
  "roots",
  "devices",
  "signatures",
]);

const KNOWN_FIELD_SET = new Set(KNOWN_FIELDS);

// `<UTC>` is an RFC 3339 instant in UTC (`Z`), optionally with a fractional
// second. Offsets are rejected: this profile fixes UTC, matching the design.
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

// `previous` is a lowercase hex SHA-256 digest of the previous document.
const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * Structural reasons a key document can be rejected. The `reason` strings are
 * the stable cross-language contract shared with `crates/xeip-identity`.
 */
export const KEYDOC_REASONS = Object.freeze({
  MALFORMED: "malformed document",
  VERSION: "unsupported version",
  UNKNOWN_FIELD: "unknown field",
  ENTITY_BINDING: "entity binding",
  UNKNOWN_SIGNER: "unknown signer",
  WEAK_KEY: "weak key",
  SIGNATURE_MISMATCH: "signature mismatch",
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function malformed() {
  return { valid: false, reason: KEYDOC_REASONS.MALFORMED };
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
 * its entirety, canonicalized with RFC 8785 and encoded as UTF-8 by the caller.
 * Returns the canonical string (UTF-8 bytes when signed/verified).
 */
export function keyDocumentSigningInput(document) {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
  const base = { ...document };
  delete base.signatures;
  return canonicalize(base);
}

/**
 * `previous` digest: lowercase hex SHA-256 of the canonical signing input of
 * `document` (the document without `signatures`). Chain verification is out of
 * scope for this slice; this helper exists so a caller can produce the
 * `previous` link a later generation would carry.
 */
export function keyDocumentDigest(document) {
  return createHash("sha256").update(keyDocumentSigningInput(document), "utf8").digest("hex");
}

/**
 * Sign a key document. The signing input is the document without `signatures`,
 * canonicalized (RFC 8785) and signed with Ed25519. Returns a new document
 * whose `signatures` array appends `{ kid, sig }` to any existing signatures,
 * so a dual-signed rotation is produced by signing twice.
 *
 * @param {object} document Parsed key document (its `signatures`, if any, are ignored).
 * @param {{ privateKey: KeyObject|Uint8Array|string, kid: string }} options
 */
export function signKeyDocument(document, { privateKey, kid } = {}) {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
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
    return { reason: KEYDOC_REASONS.MALFORMED };
  }
  if (isWeakEd25519PublicKey(raw)) return { reason: KEYDOC_REASONS.WEAK_KEY };
  return { raw };
}

/**
 * Verify a single signed key document. Accepts a JSON string (through the
 * strict pre-parse gate) or a parsed object, and returns a structured result
 * rather than throwing:
 *
 *   { valid: true } | { valid: false, reason }
 *
 * Order, with stable reasons: strict parse (`malformed document`) → unknown
 * member (`unknown field`) → `xeip` (`unsupported version`) → field types
 * (`malformed document`) → genesis decode (`malformed document` / `weak key`)
 * → `entity == entityUrn(genesis)` (`entity binding`) → every root/device kid
 * decodes non-weak (`malformed document` / `weak key`) → at least one valid
 * signature by a key in `roots` (`unknown signer` / `signature mismatch`).
 *
 * `previous` is shape-checked but never chased: chain/rollback verification is
 * out of scope. Weak or unknown signers never satisfy the root-signature
 * requirement; extra non-root signatures are ignored.
 */
export function verifyKeyDocument(document) {
  let value = document;
  if (typeof document === "string") {
    try {
      value = strictParse(document);
    } catch {
      return malformed();
    }
  }
  if (!isPlainObject(value)) return malformed();

  for (const key of Object.keys(value)) {
    if (!KNOWN_FIELD_SET.has(key)) return { valid: false, reason: KEYDOC_REASONS.UNKNOWN_FIELD };
  }

  if (typeof value.xeip !== "string") return malformed();
  if (value.xeip !== KEYDOC_VERSION) {
    return { valid: false, reason: KEYDOC_REASONS.VERSION };
  }

  if (typeof value.entity !== "string") return malformed();
  if (typeof value.genesis !== "string") return malformed();
  if (
    typeof value.generation !== "number" ||
    !Number.isInteger(value.generation) ||
    value.generation < 1 ||
    value.generation > MAX_SAFE_INTEGER
  ) {
    return malformed();
  }
  if (typeof value.issuedAt !== "string" || !UTC_TIMESTAMP.test(value.issuedAt)) {
    return malformed();
  }
  if (
    value.previous !== undefined &&
    (typeof value.previous !== "string" || !SHA256_HEX.test(value.previous))
  ) {
    return malformed();
  }
  if (!Array.isArray(value.roots) || !value.roots.every((kid) => typeof kid === "string")) {
    return malformed();
  }
  if (!Array.isArray(value.devices) || !value.devices.every((kid) => typeof kid === "string")) {
    return malformed();
  }
  if (!Array.isArray(value.signatures)) return malformed();
  for (const entry of value.signatures) {
    if (!isPlainObject(entry) || typeof entry.kid !== "string" || typeof entry.sig !== "string") {
      return malformed();
    }
  }

  const genesis = decodeKidOrReason(value.genesis);
  if (genesis.reason) return { valid: false, reason: genesis.reason };
  if (value.entity !== entityUrn(value.genesis)) {
    return { valid: false, reason: KEYDOC_REASONS.ENTITY_BINDING };
  }

  const rootKids = new Set();
  for (const kid of value.roots) {
    const decoded = decodeKidOrReason(kid);
    if (decoded.reason) return { valid: false, reason: decoded.reason };
    rootKids.add(kid);
  }
  for (const kid of value.devices) {
    const decoded = decodeKidOrReason(kid);
    if (decoded.reason) return { valid: false, reason: decoded.reason };
  }

  if (value.signatures.length === 0) {
    return { valid: false, reason: KEYDOC_REASONS.UNKNOWN_SIGNER };
  }

  const input = Buffer.from(keyDocumentSigningInput(value), "utf8");
  let sawRootSigner = false;
  for (const entry of value.signatures) {
    const decoded = decodeKidOrReason(entry.kid);
    if (decoded.reason) return { valid: false, reason: decoded.reason };
    const signature = base64UrlToBytes(entry.sig);
    if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) return malformed();
    if (!rootKids.has(entry.kid)) continue;
    sawRootSigner = true;
    const publicKey = ed25519PublicKeyFromRaw(decoded.raw);
    if (verify(null, input, publicKey, signature)) return { valid: true };
  }

  if (!sawRootSigner) return { valid: false, reason: KEYDOC_REASONS.UNKNOWN_SIGNER };
  return { valid: false, reason: KEYDOC_REASONS.SIGNATURE_MISMATCH };
}

function printUsage() {
  return "usage:\n  node tools/key-document.mjs verify <file.json>\n";
}

function main(argv) {
  const [command, argument] = argv;
  if (command === "verify" && argument !== undefined) {
    try {
      const result = verifyKeyDocument(readFileSync(argument, "utf8"));
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
