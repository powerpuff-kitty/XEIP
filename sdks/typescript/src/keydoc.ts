/**
 * Portable, dependency-free implementation of the XEIP identity key lifecycle
 * for the TypeScript SDK: signed key documents (`xeip.keydoc/0.1`), signed
 * identity status documents (`xeip.status/0.1`), per-entity chain verification
 * and trust-store anchor resolution.
 *
 * It reproduces the grammar, verification order and stable reason strings of
 * `tools/key-document.mjs` and `tools/identity-status.mjs` using only WebCrypto
 * (`crypto.subtle`) and plain JavaScript, so JS/Node, Rust (`crates/xeip-identity`)
 * and TypeScript consume the same conformance vectors under
 * `conformance/fixtures/identity-keydoc/` and `identity-status/`.
 *
 * JCS canonicalization, the key-id codec, the strict pre-parse gate, the
 * weak-key blacklist and the Ed25519 primitive are reused from `./identity.js`;
 * this module adds only the document grammar, SHA-256 linking and verification
 * order. Ed25519 is always the platform's WebCrypto implementation, never a
 * hand-written primitive. The one asynchronous wrinkle relative to the Node
 * reference is that every operation that hashes or verifies returns a promise.
 */

import {
  ED25519_SIGNATURE_LENGTH,
  MAX_SAFE_INTEGER,
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalize,
  decodeKeyId,
  ed25519PrivateKeyFromSeed,
  entityUrn,
  isWeakEd25519PublicKey,
  strictParse,
} from "./identity.js";

/** The only accepted key-document `xeip`; anything else is `unsupported version`. */
export const KEYDOC_VERSION = "xeip.keydoc/0.1";

/** The only accepted status-document `xeip`; anything else is `unsupported version`. */
export const STATUS_VERSION = "xeip.status/0.1";

/** The complete key-document member set; any other member is `unknown field`. */
const KEYDOC_FIELDS: readonly string[] = Object.freeze([
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

/** The complete status-document member set; any other member is `unknown field`. */
const STATUS_FIELDS: readonly string[] = Object.freeze([
  "xeip",
  "entity",
  "serial",
  "issuedAt",
  "revoked",
  "signatures",
]);

const KEYDOC_FIELD_SET = new Set(KEYDOC_FIELDS);
const STATUS_FIELD_SET = new Set(STATUS_FIELDS);

// UTF-8 UTC instant (`Z`), optionally with a fractional second. Offsets are
// rejected: both profiles fix UTC.
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

// A `previous` link is a lowercase hex SHA-256 digest.
const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Stable key-document reasons, shared with the JS/Rust references. */
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
} as const);

/** Stable status-document reasons, shared with the JS/Rust references. */
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
} as const);

/** Reason returned by single-document and chain key-document verification. */
export type KeyDocumentReason = (typeof KEYDOC_REASONS)[keyof typeof KEYDOC_REASONS];

/** Reason returned by status-document verification. */
export type StatusReason = (typeof STATUS_REASONS)[keyof typeof STATUS_REASONS];

/** Failure shape shared by key-document results. */
export type KeyDocumentFailure = { valid: false; reason: KeyDocumentReason };

/** Structured result of {@link verifyKeyDocument} / {@link KeyDocumentChain.ingest}. */
export type KeyDocumentResult = { valid: true } | KeyDocumentFailure;

/** Structured result of {@link KeyDocumentTrust.ingest}. */
export type KeyDocumentTrustResult =
  | { valid: true; trust: "pinned" | "tofu" }
  | KeyDocumentFailure;

/** Failure shape shared by status-document results. */
export type StatusFailure = { valid: false; reason: StatusReason };

/** Structured result of {@link verifyStatusDocument} / {@link StatusTracker.ingest}. */
export type StatusResult = { valid: true } | StatusFailure;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function malformedKeyDoc(): KeyDocumentFailure {
  return { valid: false, reason: KEYDOC_REASONS.MALFORMED };
}

function malformedStatus(): StatusFailure {
  return { valid: false, reason: STATUS_REASONS.MALFORMED };
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return typeof CryptoKey !== "undefined" && value instanceof CryptoKey;
}

// WebCrypto `BufferSource` needs an `ArrayBuffer`-backed view; copy so callers
// may pass any Uint8Array view.
function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

async function sha256Hex(text: string): Promise<string> {
  const input = toBufferSource(new TextEncoder().encode(text));
  const digest = await crypto.subtle.digest("SHA-256", input);
  return bytesToHex(new Uint8Array(digest));
}

async function normalizeSigningKey(
  privateKey: CryptoKey | Uint8Array | ArrayBuffer,
): Promise<CryptoKey> {
  if (isCryptoKey(privateKey)) {
    if (privateKey.type !== "private" || privateKey.algorithm.name !== "Ed25519") {
      throw new TypeError("privateKey must be an Ed25519 private CryptoKey");
    }
    return privateKey;
  }
  if (privateKey instanceof Uint8Array || privateKey instanceof ArrayBuffer) {
    return ed25519PrivateKeyFromSeed(privateKey);
  }
  throw new TypeError("privateKey must be a CryptoKey, a Uint8Array or an ArrayBuffer");
}

function isValidGeneration(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= MAX_SAFE_INTEGER
  );
}

function isValidSerial(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= MAX_SAFE_INTEGER
  );
}

// Decode a key-id to raw bytes, mapping a malformed spelling to `malformed
// document` and a small-order key to `weak key`.
function decodeKidOrReason(
  kid: unknown,
): { raw: Uint8Array } | { reason: KeyDocumentReason } {
  if (typeof kid !== "string") return { reason: KEYDOC_REASONS.MALFORMED };
  let raw: Uint8Array;
  try {
    raw = decodeKeyId(kid);
  } catch {
    return { reason: KEYDOC_REASONS.MALFORMED };
  }
  if (isWeakEd25519PublicKey(raw)) return { reason: KEYDOC_REASONS.WEAK_KEY };
  return { raw };
}

async function verifyEd25519(
  rawPublicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    toBufferSource(rawPublicKey),
    "Ed25519",
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "Ed25519",
    publicKey,
    toBufferSource(signature),
    toBufferSource(message),
  );
}

/* -------------------------------------------------------------------------- */
/* Signed key documents (`xeip.keydoc/0.1`)                                   */
/* -------------------------------------------------------------------------- */

/** The exact signing input: the document with `signatures` removed, RFC 8785. */
export function keyDocumentSigningInput(document: unknown): string {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
  const base: Record<string, unknown> = { ...document };
  delete base.signatures;
  return canonicalize(base);
}

/**
 * Lowercase hex SHA-256 of the canonical signing input (the document **without**
 * `signatures`). This is the single-document rotation digest, not the `previous`
 * chain link; a chain link is {@link keyDocumentChainDigest}.
 */
export async function keyDocumentDigest(document: unknown): Promise<string> {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
  return sha256Hex(keyDocumentSigningInput(document));
}

/**
 * `previous` chain-link digest: lowercase hex SHA-256 of the RFC 8785 canonical
 * form of `document` **including** its `signatures` member. Each generation
 * commits to the exact signed predecessor.
 */
export async function keyDocumentChainDigest(document: unknown): Promise<string> {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
  return sha256Hex(canonicalize(document));
}

/** Options accepted by {@link signKeyDocument} and {@link signStatusDocument}. */
export interface SignDocumentOptions {
  privateKey: CryptoKey | Uint8Array | ArrayBuffer;
  kid: string;
}

/**
 * Ed25519-sign a key document with WebCrypto and return a shallow copy whose
 * `signatures` array appends `{ kid, sig }` (so a dual-signed rotation is
 * produced by signing twice). The signing input is the document without
 * `signatures`, canonicalized per RFC 8785.
 */
export async function signKeyDocument(
  document: unknown,
  options: SignDocumentOptions,
): Promise<Record<string, unknown>> {
  if (!isPlainObject(document)) throw new TypeError("key document must be an object");
  if (!isPlainObject(options) || typeof options.kid !== "string") {
    throw new TypeError("kid must be a string");
  }
  decodeKeyId(options.kid);
  const key = await normalizeSigningKey(options.privateKey);
  const existing = Array.isArray(document.signatures) ? document.signatures : [];
  const input = new TextEncoder().encode(keyDocumentSigningInput(document));
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, toBufferSource(input)),
  );
  return {
    ...document,
    signatures: [...existing, { kid: options.kid, sig: bytesToBase64Url(signature) }],
  };
}

/**
 * Verify a single signed key document. Accepts a JSON string (through the strict
 * pre-parse gate) or a parsed object and returns a structured result rather than
 * throwing.
 *
 * Order, with stable reasons: strict parse (`malformed document`) → unknown
 * member (`unknown field`) → `xeip` (`unsupported version`) → field types
 * (`malformed document`) → genesis decode (`malformed document` / `weak key`) →
 * `entity == entityUrn(genesis)` (`entity binding`) → every root/device kid
 * decodes non-weak (`malformed document` / `weak key`) → at least one valid
 * signature by a key in `roots` (`unknown signer` / `signature mismatch`).
 */
export async function verifyKeyDocument(document: unknown): Promise<KeyDocumentResult> {
  let value: unknown = document;
  if (typeof document === "string") {
    try {
      value = strictParse(document);
    } catch {
      return malformedKeyDoc();
    }
  }
  if (!isPlainObject(value)) return malformedKeyDoc();

  for (const key of Object.keys(value)) {
    if (!KEYDOC_FIELD_SET.has(key)) {
      return { valid: false, reason: KEYDOC_REASONS.UNKNOWN_FIELD };
    }
  }

  if (typeof value.xeip !== "string") return malformedKeyDoc();
  if (value.xeip !== KEYDOC_VERSION) {
    return { valid: false, reason: KEYDOC_REASONS.VERSION };
  }

  if (typeof value.entity !== "string") return malformedKeyDoc();
  if (typeof value.genesis !== "string") return malformedKeyDoc();
  if (!isValidGeneration(value.generation)) return malformedKeyDoc();
  if (typeof value.issuedAt !== "string" || !UTC_TIMESTAMP.test(value.issuedAt)) {
    return malformedKeyDoc();
  }
  if (
    value.previous !== undefined &&
    (typeof value.previous !== "string" || !SHA256_HEX.test(value.previous))
  ) {
    return malformedKeyDoc();
  }
  if (!Array.isArray(value.roots) || !value.roots.every((kid) => typeof kid === "string")) {
    return malformedKeyDoc();
  }
  if (!Array.isArray(value.devices) || !value.devices.every((kid) => typeof kid === "string")) {
    return malformedKeyDoc();
  }
  if (!Array.isArray(value.signatures)) return malformedKeyDoc();
  for (const entry of value.signatures) {
    if (!isPlainObject(entry) || typeof entry.kid !== "string" || typeof entry.sig !== "string") {
      return malformedKeyDoc();
    }
  }

  const genesis = decodeKidOrReason(value.genesis);
  if ("reason" in genesis) return { valid: false, reason: genesis.reason };
  if (value.entity !== entityUrn(value.genesis)) {
    return { valid: false, reason: KEYDOC_REASONS.ENTITY_BINDING };
  }

  const rootKids = new Set<string>();
  for (const kid of value.roots as string[]) {
    const decoded = decodeKidOrReason(kid);
    if ("reason" in decoded) return { valid: false, reason: decoded.reason };
    rootKids.add(kid);
  }
  for (const kid of value.devices as string[]) {
    const decoded = decodeKidOrReason(kid);
    if ("reason" in decoded) return { valid: false, reason: decoded.reason };
  }

  const signatures = value.signatures as Array<{ kid: string; sig: string }>;
  if (signatures.length === 0) {
    return { valid: false, reason: KEYDOC_REASONS.UNKNOWN_SIGNER };
  }

  const input = new TextEncoder().encode(keyDocumentSigningInput(value));
  let sawRootSigner = false;
  for (const entry of signatures) {
    const decoded = decodeKidOrReason(entry.kid);
    if ("reason" in decoded) return { valid: false, reason: decoded.reason };
    const signature = base64UrlToBytes(entry.sig);
    if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) {
      return malformedKeyDoc();
    }
    if (!rootKids.has(entry.kid)) continue;
    sawRootSigner = true;
    if (await verifyEd25519(decoded.raw, input, signature)) return { valid: true };
  }

  if (!sawRootSigner) return { valid: false, reason: KEYDOC_REASONS.UNKNOWN_SIGNER };
  return { valid: false, reason: KEYDOC_REASONS.SIGNATURE_MISMATCH };
}

/* -------------------------------------------------------------------------- */
/* Per-entity chain verification                                              */
/* -------------------------------------------------------------------------- */

interface AcceptedState {
  generation: number;
  digest: string;
  roots: string[];
}

// Whether any key in `kids` has a signature entry that verifies over the
// document's canonical signing input. Chain verification uses this to require a
// signature by a key drawn from the *predecessor's* root set (the retiry
// authorization), re-checking the bytes rather than trusting the single-document
// result, which only records that *some* current root signed. The single-document
// check has already run, so every entry is well-formed and non-weak; each step
// stays defensive so a malformed entry simply does not count.
async function signsWithAnyKid(
  document: Record<string, unknown>,
  kids: Set<string>,
): Promise<boolean> {
  if (kids.size === 0) return false;
  const signatures = document.signatures as Array<{ kid: string; sig: string }>;
  const input = new TextEncoder().encode(keyDocumentSigningInput(document));
  for (const entry of signatures) {
    if (!kids.has(entry.kid)) continue;
    let raw: Uint8Array;
    try {
      raw = decodeKeyId(entry.kid);
    } catch {
      continue;
    }
    const signature = base64UrlToBytes(entry.sig);
    if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) continue;
    if (await verifyEd25519(raw, input, signature)) return true;
  }
  return false;
}

/**
 * Stateful, per-`entity` chain verifier for `xeip.keydoc/0.1`.
 *
 * `ingest` first runs {@link verifyKeyDocument} and only then enforces the chain
 * rules against the highest document accepted for that entity:
 *
 * - a genesis document (`generation == 1`, no `previous`) starts the chain;
 * - a successor must have `generation == prev.generation + 1` and
 *   `previous == keyDocumentChainDigest(prev)` (the full signed predecessor);
 * - a successor must additionally carry a valid signature by at least one key in
 *   `prev.roots` (the **retiry authorization**): the successor's own root is
 *   already required by single-document verification, so a successor with no
 *   old-root signature is `root rotation not dual-signed`;
 * - a candidate at or below the accepted generation is `rollback`, except a
 *   *distinct* document at the accepted generation, which is `fork`;
 * - a generation jump or a mismatched `previous` is `chain gap`.
 *
 * Re-ingesting the exact accepted document is a `rollback`: callers that need
 * at-least-once delivery must treat `rollback` as "already known".
 */
export class KeyDocumentChain {
  private accepted = new Map<string, AcceptedState>();

  async ingest(document: unknown): Promise<KeyDocumentResult> {
    let value: unknown = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformedKeyDoc();
      }
    }

    const single = await verifyKeyDocument(value);
    if (!single.valid) return single;

    const doc = value as Record<string, unknown> & {
      entity: string;
      generation: number;
      previous?: string;
      roots: string[];
    };
    const accepted = this.accepted.get(doc.entity);
    if (accepted === undefined) {
      if (doc.generation !== 1 || doc.previous !== undefined) {
        return { valid: false, reason: KEYDOC_REASONS.CHAIN_GAP };
      }
      await this.accept(doc);
      return { valid: true };
    }

    if (doc.generation < accepted.generation) {
      return { valid: false, reason: KEYDOC_REASONS.ROLLBACK };
    }
    if (doc.generation === accepted.generation) {
      if ((await keyDocumentChainDigest(doc)) === accepted.digest) {
        return { valid: false, reason: KEYDOC_REASONS.ROLLBACK };
      }
      return { valid: false, reason: KEYDOC_REASONS.FORK };
    }
    if (doc.generation !== accepted.generation + 1) {
      return { valid: false, reason: KEYDOC_REASONS.CHAIN_GAP };
    }
    if (doc.previous !== accepted.digest) {
      return { valid: false, reason: KEYDOC_REASONS.CHAIN_GAP };
    }
    // Retiry authorization: the successor is known to carry a valid signature by
    // one of its own roots; the chain additionally requires a signature by a key
    // from the predecessor's root set. A pre-endorsed successor root is itself in
    // that old set, so its signature satisfies both at once.
    if (!(await signsWithAnyKid(doc, new Set(accepted.roots)))) {
      return { valid: false, reason: KEYDOC_REASONS.ROOT_ROTATION_NOT_DUAL_SIGNED };
    }
    await this.accept(doc);
    return { valid: true };
  }

  private async accept(doc: Record<string, unknown>): Promise<void> {
    this.accepted.set(doc.entity as string, {
      generation: doc.generation as number,
      digest: await keyDocumentChainDigest(doc),
      roots: [...(doc.roots as string[])],
    });
  }

  /**
   * Independent copy of the accepted state. {@link KeyDocumentTrust} uses it to
   * evaluate a candidate without committing it.
   */
  clone(): KeyDocumentChain {
    const copy = new KeyDocumentChain();
    for (const [entity, state] of this.accepted) {
      copy.accepted.set(entity, { ...state });
    }
    return copy;
  }
}

/* -------------------------------------------------------------------------- */
/* Trust-store anchor resolution                                              */
/* -------------------------------------------------------------------------- */

/** Pinned genesis anchor: a key-id and/or a genesis chain digest. */
export interface KeyDocumentAnchor {
  genesisKid?: string;
  genesisDigest?: string;
}

/** Options accepted by the {@link KeyDocumentTrust} constructor. */
export interface KeyDocumentTrustOptions {
  entity: string;
  anchor?: KeyDocumentAnchor | null;
  maxGeneration?: number;
  tofu?: boolean;
}

/**
 * Trust-store anchor resolution for `xeip.keydoc/0.1`.
 *
 * Wraps a {@link KeyDocumentChain} and accepts a document only when it passes
 * single-document and chain verification *and* is reached from the configured
 * anchor. It fails closed: with no pinned anchor and TOFU off, every document is
 * `no anchor`. Bounded, opt-in TOFU records the first-seen genesis as an
 * effective anchor; it is **not verified identity** and callers MUST present a
 * `tofu` result as unverified.
 */
export class KeyDocumentTrust {
  private readonly entity: string;
  private readonly anchor: KeyDocumentAnchor | null;
  private readonly maxGeneration: number | undefined;
  private readonly tofu: boolean;
  private chain = new KeyDocumentChain();
  private readonly tofuAnchors = new Map<string, KeyDocumentAnchor>();

  constructor(options: KeyDocumentTrustOptions) {
    const { entity, anchor = null, maxGeneration, tofu = false } = options ?? {};
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
    if (maxGeneration !== undefined && (!Number.isInteger(maxGeneration) || maxGeneration < 1)) {
      throw new TypeError("maxGeneration must be an integer >= 1");
    }
    if (typeof tofu !== "boolean") throw new TypeError("tofu must be a boolean");
    this.entity = entity;
    this.anchor = anchor;
    this.maxGeneration = maxGeneration;
    this.tofu = tofu;
  }

  async ingest(document: unknown): Promise<KeyDocumentTrustResult> {
    let value: unknown = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformedKeyDoc();
      }
    }

    // Evaluate on an independent copy; commit only after every trust check.
    const trial = this.chain.clone();
    const chained = await trial.ingest(value);
    if (!chained.valid) return chained;

    const doc = value as Record<string, unknown> & {
      entity: string;
      genesis: string;
      generation: number;
      previous?: string;
    };

    let anchor: KeyDocumentAnchor;
    let trust: "pinned" | "tofu";
    if (this.anchor !== null) {
      anchor = this.anchor;
      trust = "pinned";
    } else if (this.tofu) {
      const recorded = this.tofuAnchors.get(doc.entity);
      if (recorded !== undefined) {
        anchor = recorded;
        trust = "tofu";
      } else if (doc.generation === 1 && doc.previous === undefined) {
        anchor = {
          genesisKid: doc.genesis,
          genesisDigest: await keyDocumentChainDigest(doc),
        };
        trust = "tofu";
      } else {
        return { valid: false, reason: KEYDOC_REASONS.NO_ANCHOR };
      }
    } else {
      return { valid: false, reason: KEYDOC_REASONS.NO_ANCHOR };
    }

    if (doc.entity !== this.entity) {
      return { valid: false, reason: KEYDOC_REASONS.UNTRUSTED_ANCHOR };
    }
    if (this.maxGeneration !== undefined && doc.generation > this.maxGeneration) {
      return { valid: false, reason: KEYDOC_REASONS.GENERATION_EXCEEDS_MAX };
    }
    if (anchor.genesisKid !== undefined && doc.genesis !== anchor.genesisKid) {
      return { valid: false, reason: KEYDOC_REASONS.UNTRUSTED_ANCHOR };
    }
    if (
      anchor.genesisDigest !== undefined &&
      doc.generation === 1 &&
      (await keyDocumentChainDigest(doc)) !== anchor.genesisDigest
    ) {
      return { valid: false, reason: KEYDOC_REASONS.UNTRUSTED_ANCHOR };
    }

    if (trust === "tofu" && !this.tofuAnchors.has(doc.entity)) {
      this.tofuAnchors.set(doc.entity, anchor);
    }
    this.chain = trial;
    return { valid: true, trust };
  }
}

/* -------------------------------------------------------------------------- */
/* Signed status documents (`xeip.status/0.1`)                                */
/* -------------------------------------------------------------------------- */

/** The exact signing input: the status document with `signatures` removed. */
export function statusSigningInput(document: unknown): string {
  if (!isPlainObject(document)) throw new TypeError("status document must be an object");
  const base: Record<string, unknown> = { ...document };
  delete base.signatures;
  return canonicalize(base);
}

/**
 * Ed25519-sign a status document with WebCrypto and return a shallow copy whose
 * `signatures` array appends `{ kid, sig }`. The signing input is the document
 * without `signatures`, canonicalized per RFC 8785.
 */
export async function signStatusDocument(
  document: unknown,
  options: SignDocumentOptions,
): Promise<Record<string, unknown>> {
  if (!isPlainObject(document)) throw new TypeError("status document must be an object");
  if (!isPlainObject(options) || typeof options.kid !== "string") {
    throw new TypeError("kid must be a string");
  }
  decodeKeyId(options.kid);
  const key = await normalizeSigningKey(options.privateKey);
  const existing = Array.isArray(document.signatures) ? document.signatures : [];
  const input = new TextEncoder().encode(statusSigningInput(document));
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, toBufferSource(input)),
  );
  return {
    ...document,
    signatures: [...existing, { kid: options.kid, sig: bytesToBase64Url(signature) }],
  };
}

function trustedEntity(trusted: unknown): string | null {
  return isPlainObject(trusted) && typeof trusted.entity === "string" ? trusted.entity : null;
}

function trustedRoots(trusted: unknown): Set<string> {
  const roots = isPlainObject(trusted) && Array.isArray(trusted.roots) ? trusted.roots : [];
  return new Set(roots.filter((kid): kid is string => typeof kid === "string"));
}

async function verifyStatusValue(value: unknown, trustedKeyDocument: unknown): Promise<StatusResult> {
  if (!isPlainObject(value)) return malformedStatus();

  for (const key of Object.keys(value)) {
    if (!STATUS_FIELD_SET.has(key)) {
      return { valid: false, reason: STATUS_REASONS.UNKNOWN_FIELD };
    }
  }

  if (typeof value.xeip !== "string") return malformedStatus();
  if (value.xeip !== STATUS_VERSION) {
    return { valid: false, reason: STATUS_REASONS.VERSION };
  }

  if (typeof value.entity !== "string") return malformedStatus();
  if (!isValidSerial(value.serial)) return malformedStatus();
  if (typeof value.issuedAt !== "string" || !UTC_TIMESTAMP.test(value.issuedAt)) {
    return malformedStatus();
  }
  if (!Array.isArray(value.revoked)) return malformedStatus();
  for (const entry of value.revoked) {
    if (
      !isPlainObject(entry) ||
      typeof entry.kid !== "string" ||
      !isValidGeneration(entry.generation)
    ) {
      return malformedStatus();
    }
    try {
      decodeKeyId(entry.kid);
    } catch {
      return malformedStatus();
    }
  }
  if (!Array.isArray(value.signatures)) return malformedStatus();
  for (const entry of value.signatures) {
    if (!isPlainObject(entry) || typeof entry.kid !== "string" || typeof entry.sig !== "string") {
      return malformedStatus();
    }
  }

  if (trustedEntity(trustedKeyDocument) !== value.entity) {
    return { valid: false, reason: STATUS_REASONS.ENTITY_BINDING };
  }

  const signatures = value.signatures as Array<{ kid: string; sig: string }>;
  if (signatures.length === 0) {
    return { valid: false, reason: STATUS_REASONS.UNKNOWN_SIGNER };
  }

  const roots = trustedRoots(trustedKeyDocument);
  const input = new TextEncoder().encode(statusSigningInput(value));
  let sawRootSigner = false;
  for (const entry of signatures) {
    const decoded = decodeKidOrReason(entry.kid);
    if ("reason" in decoded) {
      return { valid: false, reason: decoded.reason as StatusReason };
    }
    const signature = base64UrlToBytes(entry.sig);
    if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) {
      return malformedStatus();
    }
    if (!roots.has(entry.kid)) continue;
    sawRootSigner = true;
    if (await verifyEd25519(decoded.raw, input, signature)) return { valid: true };
  }

  if (!sawRootSigner) return { valid: false, reason: STATUS_REASONS.UNKNOWN_SIGNER };
  return { valid: false, reason: STATUS_REASONS.SIGNATURE_MISMATCH };
}

/** Reserved options for {@link verifyStatusDocument}; stateless checks ignore them. */
export interface StatusVerifyOptions {
  [key: string]: never;
}

/**
 * Verify a single signed status document against a trusted key document for the
 * entity. Accepts a JSON string (strict pre-parse gate) or a parsed object and
 * returns a structured result rather than throwing.
 *
 * Order, with stable reasons: strict parse / not an object (`malformed
 * document`) → unknown member (`unknown field`) → `xeip` (`unsupported version`)
 * → field types, `serial`, `issuedAt`, revoked `kid`/`generation`
 * (`malformed document`) → `entity == trusted.entity` (`entity binding`) → at
 * least one valid signature by a key listed in `trusted.roots` (`unknown signer`
 * / `weak key` / `signature mismatch`). Serial rollback and staleness are
 * lifecycle rules and live in {@link StatusTracker}.
 */
export async function verifyStatusDocument(
  document: unknown,
  trustedKeyDocument: unknown,
  _options?: StatusVerifyOptions,
): Promise<StatusResult> {
  let value: unknown = document;
  if (typeof document === "string") {
    try {
      value = strictParse(document);
    } catch {
      return malformedStatus();
    }
  }
  return verifyStatusValue(value, trustedKeyDocument);
}

// Parse a `YYYY-MM-DDTHH:MM:SS(.fff)Z` instant into whole epoch seconds. The
// shape is validated before this is called, so the digits are known present.
function parseUtcSeconds(text: string): number {
  const year = Number(text.slice(0, 4));
  const month = Number(text.slice(5, 7));
  const day = Number(text.slice(8, 10));
  const hour = Number(text.slice(11, 13));
  const minute = Number(text.slice(14, 16));
  const second = Number(text.slice(17, 19));
  return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
}

// Coerce a caller-supplied reference instant to whole epoch seconds.
function toEpochSeconds(now: string | Date | number | undefined): number {
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

/** Options accepted by {@link StatusTracker.ingest}. */
export interface StatusIngestOptions {
  trustedKeyDocument: unknown;
  now?: string | Date | number;
  maxAgeSeconds?: number;
}

interface AcceptedStatusDocument {
  entity: string;
  serial: number;
  issuedAt: string;
  revoked: Array<{ kid: string; generation: number }>;
}

interface AcceptedStatus {
  serial: number;
  document: AcceptedStatusDocument;
}

/**
 * Stateful, per-`entity` status tracker for `xeip.status/0.1`.
 *
 * {@link StatusTracker.ingest} runs the stateless verification
 * ({@link verifyStatusDocument}) and then enforces:
 *
 * - **serial rollback** — a `serial` less than or equal to the highest accepted
 *   is rejected, so a replayed old "clean" status is never accepted;
 * - **staleness** — when `maxAgeSeconds` is supplied, an `issuedAt` older than
 *   that age behind `now` is `stale status`.
 *
 * State is committed only when every check passes. `isRevoked` reports whether
 * the accepted status revokes `kid` at generation `generation` or later; a
 * missing status is reported as not revoked (unknown), never as proof of life.
 */
export class StatusTracker {
  private readonly entities = new Map<string, AcceptedStatus>();

  async ingest(document: unknown, options: StatusIngestOptions): Promise<StatusResult> {
    const { trustedKeyDocument, now, maxAgeSeconds } = options ?? {};
    let value: unknown = document;
    if (typeof document === "string") {
      try {
        value = strictParse(document);
      } catch {
        return malformedStatus();
      }
    }

    const single = await verifyStatusValue(value, trustedKeyDocument);
    if (!single.valid) return single;

    const doc = value as AcceptedStatusDocument;

    const accepted = this.entities.get(doc.entity);
    if (accepted !== undefined && doc.serial <= accepted.serial) {
      return { valid: false, reason: STATUS_REASONS.SERIAL_ROLLBACK };
    }

    if (maxAgeSeconds !== undefined) {
      if (
        typeof maxAgeSeconds !== "number" ||
        !Number.isFinite(maxAgeSeconds) ||
        maxAgeSeconds < 0
      ) {
        throw new TypeError("maxAgeSeconds must be a non-negative number");
      }
      if (toEpochSeconds(now) - parseUtcSeconds(doc.issuedAt) > maxAgeSeconds) {
        return { valid: false, reason: STATUS_REASONS.STALE };
      }
    }

    this.entities.set(doc.entity, { serial: doc.serial, document: doc });
    return { valid: true };
  }

  /**
   * Whether the accepted status for `entity` revokes `kid` for key-document
   * generation `generation` (an entry applies to its recorded generation and
   * every later one). `false` when no status has been accepted.
   */
  isRevoked(entity: string, kid: string, generation: number): boolean {
    const accepted = this.entities.get(entity);
    if (accepted === undefined) return false;
    return accepted.document.revoked.some(
      (entry) => entry.kid === kid && generation >= entry.generation,
    );
  }

  /** The highest serial accepted for `entity`, or `undefined` if none. */
  acceptedSerial(entity: string): number | undefined {
    return this.entities.get(entity)?.serial;
  }

  /** Whether a status has been accepted for `entity`. */
  hasStatus(entity: string): boolean {
    return this.entities.has(entity);
  }
}
