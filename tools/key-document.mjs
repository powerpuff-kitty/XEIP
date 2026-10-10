// tools/key-document.mjs
//
// Dependency-free reference for *signed XEIP key documents* (issue #1, first
// key-lifecycle slice). This is the first testable slice of the design in
// spec/identity-keys.md and ADR 0010: a single signed key document,
// single-document verification, per-entity chain verification (generation
// linking, rollback and fork detection) and trust-store anchor resolution
// (pinned anchor and bounded TOFU). Revocation/status documents, bounded
// overlap, directory discovery and durable fork evidence are deliberately out
// of scope (see spec/plans/identity-keydoc.md).
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
 *
 * The first seven reasons are single-document reasons. `ROLLBACK`, `FORK`,
 * `CHAIN_GAP` and `ROOT_ROTATION_NOT_DUAL_SIGNED` are produced only by chain
 * verification ({@link KeyDocumentChain}); `NO_ANCHOR`, `UNTRUSTED_ANCHOR` and
 * `GENERATION_EXCEEDS_MAX` are produced only by trust-store resolution
 * ({@link KeyDocumentTrust}). Every document must first pass single-document
 * verification and chain linking, so a chain or trust reason is only ever
 * returned after the structural reasons above have been cleared.
 */
export const KEYDOC_REASONS = Object.freeze({
  MALFORMED: "malformed document",
  VERSION: "unsupported version",
  UNKNOWN_FIELD: "unknown field",
  ENTITY_BINDING: "entity binding",
  UNKNOWN_SIGNER: "unknown signer",
  WEAK_KEY: "weak key",
  SIGNATURE_MISMATCH: "signature mismatch",
  ROLLBACK: "rollback",
  FORK: "fork",
  CHAIN_GAP: "chain gap",
  ROOT_ROTATION_NOT_DUAL_SIGNED: "root rotation not dual-signed",
  NO_ANCHOR: "no anchor",
  UNTRUSTED_ANCHOR: "untrusted anchor",
  GENERATION_EXCEEDS_MAX: "generation exceeds maximum",
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
 * Signing-input digest: lowercase hex SHA-256 of the canonical signing input of
 * `document` (the document **without** `signatures`). This is the digest used by
 * the standalone single-document rotation vector; it deliberately excludes the
 * signatures so a dual-signed document and an unsigned draft share a digest.
 *
 * Chain verification commits to the *signed* predecessor instead: use
 * {@link keyDocumentChainDigest}, which hashes the whole document including
 * `signatures`. A `previous` link in a verified chain is a
 * {@link keyDocumentChainDigest} value, never this one.
 */
export function keyDocumentDigest(document) {
  return createHash("sha256").update(keyDocumentSigningInput(document), "utf8").digest("hex");
}

/**
 * `previous` link digest for chain verification: lowercase hex SHA-256 of the
 * RFC 8785 canonical form of `document` **including** its `signatures` member.
 *
 * A successor document carries this value in `previous`, so each generation
 * commits to the exact signed predecessor (including its signature set). This is
 * the definition of `previous` in [`KeyDocumentChain`] and in
 * `spec/plans/identity-keydoc.md`.
 */
export function keyDocumentChainDigest(document) {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
  return createHash("sha256").update(canonicalize(document), "utf8").digest("hex");
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

// Whether any key in `kids` has a signature entry that verifies over the
// document's canonical signing input. Chain verification uses this to require a
// signature by a key drawn from the *predecessor's* root set (the retiry
// authorization); it deliberately re-checks the bytes rather than trusting the
// single-document result, which only records that *some* current root signed.
//
// The single-document check runs first and guarantees every entry is
// well-formed and non-weak, but each step stays defensive so a malformed entry
// simply does not count.
function signsWithAnyKid(document, kids) {
  if (kids.size === 0) return false;
  const input = Buffer.from(keyDocumentSigningInput(document), "utf8");
  for (const entry of document.signatures) {
    if (!kids.has(entry.kid)) continue;
    let raw;
    try {
      raw = decodeKeyId(entry.kid);
    } catch {
      continue;
    }
    const signature = base64UrlToBytes(entry.sig);
    if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) continue;
    if (verify(null, input, ed25519PublicKeyFromRaw(raw), signature)) return true;
  }
  return false;
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

/**
 * Stateful, per-`entity` chain verifier for `xeip.keydoc/0.1`.
 *
 * `ingest` first runs {@link verifyKeyDocument} on the candidate (so every
 * structural and signature rule still applies) and only then enforces the chain
 * rules against the highest document already accepted for that entity. It never
 * throws for a well-formed call and returns `{ valid: true }` or
 * `{ valid: false, reason }`:
 *
 * - a genesis document (`generation == 1`, no `previous`) starts the chain;
 * - a successor must have `generation == prev.generation + 1` and
 *   `previous == keyDocumentChainDigest(prev)` (the full signed predecessor);
 * - a successor must additionally carry a valid signature by at least one key
 *   in `prev.roots` (the **retiry authorization**) — the *successor* root is
 *   already required by single-document verification, and the pre-endorsed case
 *   (a successor already listed in `prev.roots`) is satisfied by that same
 *   retiring-root signature; a successor with no old-root signature is
 *   `root rotation not dual-signed`;
 * - a candidate whose `generation <=` the accepted generation is `rollback`,
 *   except that a *distinct* document at the accepted generation is `fork`
 *   (equivocation);
 * - a generation jump (`generation > prev.generation + 1`) or a `previous` that
 *   does not match the accepted document is `chain gap`.
 *
 * Acceptance is idempotent only in the sense that re-ingesting the exact accepted
 * document is rejected as `rollback` (it is not newer): a caller that needs
 * at-least-once delivery must treat `rollback` as "already known", not as an
 * error. Trust-store resolution and revocation stay out of scope.
 */
export class KeyDocumentChain {
  #accepted = new Map();

  /**
   * Verify and add `document` (a parsed object or JSON text) to the chain for
   * its `entity`.
   *
   * @returns {{ valid: true } | { valid: false, reason: string }}
   */
  ingest(document) {
    let value = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformed();
      }
    }

    const single = verifyKeyDocument(value);
    if (!single.valid) return single;

    const accepted = this.#accepted.get(value.entity);
    if (accepted === undefined) {
      if (value.generation !== 1 || value.previous !== undefined) {
        return { valid: false, reason: KEYDOC_REASONS.CHAIN_GAP };
      }
      this.#accept(value);
      return { valid: true };
    }

    if (value.generation < accepted.generation) {
      return { valid: false, reason: KEYDOC_REASONS.ROLLBACK };
    }
    if (value.generation === accepted.generation) {
      if (keyDocumentChainDigest(value) === accepted.digest) {
        return { valid: false, reason: KEYDOC_REASONS.ROLLBACK };
      }
      return { valid: false, reason: KEYDOC_REASONS.FORK };
    }
    if (value.generation !== accepted.generation + 1) {
      return { valid: false, reason: KEYDOC_REASONS.CHAIN_GAP };
    }
    if (value.previous !== accepted.digest) {
      return { valid: false, reason: KEYDOC_REASONS.CHAIN_GAP };
    }
    // Root-rotation authorization: the successor is already known to carry a
    // valid signature by one of its own roots (single-document verification);
    // the chain adds the retiry requirement that a key from the predecessor's
    // root set also signed. A pre-endorsed successor root is itself in that old
    // set, so its signature satisfies both at once (retiry-only case).
    if (!signsWithAnyKid(value, new Set(accepted.roots))) {
      return { valid: false, reason: KEYDOC_REASONS.ROOT_ROTATION_NOT_DUAL_SIGNED };
    }
    this.#accept(value);
    return { valid: true };
  }

  #accept(value) {
    this.#accepted.set(value.entity, {
      generation: value.generation,
      digest: keyDocumentChainDigest(value),
      roots: [...value.roots],
    });
  }

  /**
   * Return an independent copy of the accepted per-entity state. Used by
   * {@link KeyDocumentTrust} to evaluate a candidate without committing it, so
   * an untrusted document is never recorded. Cloning does not change the
   * behavior of `ingest`.
   *
   * @returns {KeyDocumentChain}
   */
  clone() {
    const copy = new KeyDocumentChain();
    for (const [entity, state] of this.#accepted) {
      copy.#accepted.set(entity, { ...state });
    }
    return copy;
  }
}

/**
 * Trust-store anchor resolution for `xeip.keydoc/0.1`.
 *
 * A {@link KeyDocumentChain} only links generations; it deliberately has no
 * notion of *which* genesis to start from. `KeyDocumentTrust` adds that
 * out-of-band anchor: it wraps a chain and, for a single configured `entity`,
 * accepts a document only when it passes single-document verification and the
 * chain rules *and* is reached from the configured anchor. It never throws for
 * a well-formed call.
 *
 * Anchor enforcement runs after the wrapped chain has accepted the candidate on
 * a private trial copy (so a rejected document is never recorded). A candidate
 * is rejected with:
 *
 * - **No anchor** — when no anchor is configured (and TOFU is off) every
 *   document is rejected with `no anchor`. This is the default: a trust store
 *   fails closed rather than trusting on first use.
 * - **Wrong anchor** — a document whose `entity`, `genesis` key-id or (for the
 *   genesis document) chain digest does not match the pinned anchor is rejected
 *   with `untrusted anchor`.
 * - **Generation bound** — a document whose `generation > maxGeneration`
 *   (when configured) is rejected with `generation exceeds maximum`.
 *
 * **Bounded TOFU (opt-in, not verified).** With `{ tofu: true }` and no pinned
 * anchor, the first document accepted for the entity records its
 * `(entity, genesis-kid, genesis-digest)` as the effective anchor, and every
 * later document must chain from it (a different genesis is `untrusted
 * anchor`). The recorded anchor is bounded by the same `maxGeneration`. TOFU is
 * **not verified identity**: callers MUST present a successful `tofu` result as
 * unverified and MUST NOT conflate it with a pinned anchor
 * (`spec/identity-keys.md` §7.2), which a pinned result signals.
 *
 * @example
 * const trust = new KeyDocumentTrust({
 *   entity: entityUrn(genesisKid),
 *   anchor: { genesisKid, genesisDigest },
 *   maxGeneration: 3,
 * });
 * trust.ingest(genesis); // { valid: true, trust: "pinned" }
 */
export class KeyDocumentTrust {
  #entity;
  #anchor;
  #maxGeneration;
  #tofu;
  #chain = new KeyDocumentChain();
  #tofuAnchors = new Map();

  /**
   * @param {object} options
   * @param {string} options.entity Entity URN this trust store is pinned to.
   * @param {{ genesisKid?: string, genesisDigest?: string }|null} [options.anchor]
   *   Pinned genesis key-id and/or genesis chain digest. `null`/omitted means no
   *   anchor is configured (fail closed unless TOFU is enabled).
   * @param {number} [options.maxGeneration] Reject `generation` above this.
   * @param {boolean} [options.tofu] Opt in to bounded, *unverified* TOFU.
   */
  constructor({ entity, anchor = null, maxGeneration, tofu = false } = {}) {
    if (typeof entity !== "string") throw new TypeError("entity must be a string");
    if (anchor !== null) {
      if (!isPlainObject(anchor)) throw new TypeError("anchor must be an object or null");
      for (const key of Object.keys(anchor)) {
        if (key !== "genesisKid" && key !== "genesisDigest") {
          throw new TypeError(`unknown anchor field: ${key}`);
        }
      }
      if (anchor.genesisKid !== undefined && typeof anchor.genesisKid !== "string") {
        throw new TypeError("anchor.genesisKid must be a string");
      }
      if (anchor.genesisDigest !== undefined && typeof anchor.genesisDigest !== "string") {
        throw new TypeError("anchor.genesisDigest must be a string");
      }
    }
    if (
      maxGeneration !== undefined &&
      (!Number.isInteger(maxGeneration) || maxGeneration < 1)
    ) {
      throw new TypeError("maxGeneration must be an integer >= 1");
    }
    if (typeof tofu !== "boolean") throw new TypeError("tofu must be a boolean");
    this.#entity = entity;
    this.#anchor = anchor;
    this.#maxGeneration = maxGeneration;
    this.#tofu = tofu;
  }

  /**
   * Verify and anchor `document` (a parsed object or JSON text).
   *
   * @returns {{ valid: true, trust: "pinned"|"tofu" } | { valid: false, reason: string }}
   */
  ingest(document) {
    let value = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformed();
      }
    }

    // Run the existing single-document and chain rules on an independent copy.
    // Nothing is committed unless every trust check below also passes.
    const trial = this.#chain.clone();
    const chained = trial.ingest(value);
    if (!chained.valid) return chained;

    let anchor;
    let trust;
    if (this.#anchor !== null) {
      anchor = this.#anchor;
      trust = "pinned";
    } else if (this.#tofu) {
      const recorded = this.#tofuAnchors.get(value.entity);
      if (recorded !== undefined) {
        anchor = recorded;
        trust = "tofu";
      } else if (value.generation === 1 && value.previous === undefined) {
        anchor = {
          genesisKid: value.genesis,
          genesisDigest: keyDocumentChainDigest(value),
        };
        trust = "tofu";
      } else {
        return { valid: false, reason: KEYDOC_REASONS.NO_ANCHOR };
      }
    } else {
      return { valid: false, reason: KEYDOC_REASONS.NO_ANCHOR };
    }

    if (value.entity !== this.#entity) {
      return { valid: false, reason: KEYDOC_REASONS.UNTRUSTED_ANCHOR };
    }
    if (this.#maxGeneration !== undefined && value.generation > this.#maxGeneration) {
      return { valid: false, reason: KEYDOC_REASONS.GENERATION_EXCEEDS_MAX };
    }
    if (anchor.genesisKid !== undefined && value.genesis !== anchor.genesisKid) {
      return { valid: false, reason: KEYDOC_REASONS.UNTRUSTED_ANCHOR };
    }
    if (
      anchor.genesisDigest !== undefined &&
      value.generation === 1 &&
      keyDocumentChainDigest(value) !== anchor.genesisDigest
    ) {
      return { valid: false, reason: KEYDOC_REASONS.UNTRUSTED_ANCHOR };
    }

    if (trust === "tofu" && !this.#tofuAnchors.has(value.entity)) {
      this.#tofuAnchors.set(value.entity, anchor);
    }
    this.#chain = trial;
    return { valid: true, trust };
  }
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
