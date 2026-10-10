// tools/signed-envelope.mjs
//
// Dependency-free reference for *signed XEIP envelopes* (issue #1, first
// verification slice). It implements exactly three things:
//
//   1. RFC 8785 (JCS) canonicalization of a parsed JSON value.
//   2. A strict JSON parser that rejects, before canonicalization, duplicate
//      object names, lone surrogate escapes, non-finite numbers and integers
//      outside the interoperable ±(2^53-1) range (ADR 0007).
//   3. Ed25519 sign/verify of the canonical UTF-8 bytes via `node:crypto`,
//      with the signature carried in `envelope.extensions["xeip.sig"]` and the
//      signer's key-id bound to `envelope.sender`.
//
// SCOPE / BOUNDARY: this is a reference implementation and conformance
// consumer, not yet wired into the relay. It adds no dependency and no
// hand-written primitive: Ed25519 comes from Node's audited OpenSSL-backed
// `node:crypto` (ADR 0007). The hand-written code here is deterministic
// serialization (JCS) and parsing, which ADR 0007 explicitly permits to
// complement a canonicalizer. See spec/local-signed-envelopes.md for the
// profile contract and spec/decisions/0009-local-signed-envelopes.md for the
// decision.
//
// Exports: canonicalize, strictParse, signEnvelope, verifySignedEnvelope, and
// the carrier/limit constants and key-encoding helpers used by tests and the
// CLI. `verifySignedEnvelope` returns a structured result and never throws for
// a well-formed call; each malformed input maps to a stable `reason`.

import {
  KeyObject,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { decodeKeyId, encodeKeyId, entityUrn } from "./derive-keyid.mjs";

/** Extensions member that carries the detached signature. */
export const SIG_EXTENSION = "xeip.sig";

/** Version of the signature carrier. */
export const SIG_VERSION = "0.1";

/** Fixed algorithm identifier; EdDSA is the only accepted value. */
export const SIG_ALG = "EdDSA";

/** Largest integer that round-trips through an IEEE-754 double exactly. */
export const MAX_SAFE_INTEGER = 9007199254740991;

/** Ed25519 signatures are exactly 64 bytes (RFC 8032 §5.1.6). */
export const ED25519_SIGNATURE_LENGTH = 64;

// The eight canonical encodings of the small-order (torsion) points of the
// Ed25519 curve, including the identity `01 00…00` and the all-zero encoding.
// A verifying key that is small-order is a *weak key*: for the identity key,
// `R = [S]B` with `S = 1` forges a signature that verifies for *every* message.
// Node's OpenSSL-backed verifier happens to reject most of these, but WebCrypto
// implementations differ, so the encodings are pinned here and checked before
// any platform import. Source: the canonical small-order point blacklist.
export const ED25519_SMALL_ORDER_POINTS = Object.freeze([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

const ED25519_SMALL_ORDER_POINT_SET = new Set(ED25519_SMALL_ORDER_POINTS);

/**
 * Whether 32 raw Ed25519 public-key bytes are one of the canonical small-order
 * (weak) points. Independent of `node:crypto`/WebCrypto so every runtime
 * rejects the same keys with reason `"weak key"`.
 */
export function isWeakEd25519PublicKey(raw) {
  const bytes = raw instanceof Uint8Array ? raw : Uint8Array.from(raw);
  if (bytes.length !== 32) return false;
  return ED25519_SMALL_ORDER_POINT_SET.has(Buffer.from(bytes).toString("hex"));
}

// DER prefixes for the two `node:crypto` key forms we convert to and from raw
// bytes. These are fixed ASN.1 wrappers around the raw key, not a primitive.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Reject a string that contains a lone (unpaired) surrogate code unit, in
 * either direction. RFC 8785 operates on well-formed Unicode; a lone surrogate
 * cannot be represented in UTF-8 and must not reach canonicalization.
 */
function assertNoLoneSurrogates(text) {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new SyntaxError("string contains a lone high surrogate");
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new SyntaxError("string contains a lone low surrogate");
    }
  }
  return text;
}

// UTF-16 code-unit ordering, the RFC 8785 §3.2.3 object-key order.
function compareUtf16(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function serialize(value, out) {
  if (value === null) {
    out.push("null");
    return;
  }
  const type = typeof value;
  if (type === "boolean") {
    out.push(value ? "true" : "false");
    return;
  }
  if (type === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("cannot canonicalize a non-finite number");
    }
    // ECMAScript Number::toString, exactly what RFC 8785 §3.2.2.3 requires
    // (including mapping -0 to 0 and the 1e+21 / 1e-7 thresholds).
    out.push(JSON.stringify(value));
    return;
  }
  if (type === "string") {
    assertNoLoneSurrogates(value);
    out.push(JSON.stringify(value));
    return;
  }
  if (Array.isArray(value)) {
    out.push("[");
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out.push(",");
      serialize(value[i], out);
    }
    out.push("]");
    return;
  }
  if (type === "object") {
    const keys = Object.keys(value).sort(compareUtf16);
    out.push("{");
    for (let i = 0; i < keys.length; i++) {
      if (i > 0) out.push(",");
      assertNoLoneSurrogates(keys[i]);
      out.push(JSON.stringify(keys[i]), ":");
      serialize(value[keys[i]], out);
    }
    out.push("}");
    return;
  }
  throw new TypeError(`cannot canonicalize a value of type ${type}`);
}

/**
 * RFC 8785 JSON Canonicalization Scheme. Produces the deterministic UTF-8
 * envelope bytes that are signed: object keys sorted by UTF-16 code units, no
 * whitespace, ECMAScript number formatting, strings escaped as JSON, arrays in
 * order. Rejects values that have no canonical JSON form (non-finite numbers,
 * `undefined`, functions, symbols, bigints, lone surrogates).
 */
export function canonicalize(value) {
  const out = [];
  serialize(value, out);
  return out.join("");
}

/**
 * Strict JSON parser. Unlike `JSON.parse`, this rejects the ambiguity that
 * would let two different wire byte sequences share one signature:
 *
 *   - duplicate object member names,
 *   - lone surrogate escapes or raw lone surrogates,
 *   - numbers that are non-finite (`1e999`),
 *   - integer values outside ±(2^53-1).
 *
 * Objects are built with a null prototype so a `"__proto__"` member is an
 * ordinary own property rather than a prototype mutation. Whitespace is the
 * four JSON characters only.
 */
class StrictJsonParser {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  error(message) {
    return new SyntaxError(`${message} at position ${this.index}`);
  }

  atEnd() {
    return this.index >= this.text.length;
  }

  peek() {
    return this.text[this.index];
  }

  skipWhitespace() {
    while (this.index < this.text.length) {
      const char = this.text[this.index];
      if (char === " " || char === "\t" || char === "\n" || char === "\r") {
        this.index++;
      } else {
        break;
      }
    }
  }

  expect(char) {
    if (this.text[this.index] !== char) {
      throw this.error(`expected ${JSON.stringify(char)}`);
    }
    this.index++;
  }

  parseValue() {
    this.skipWhitespace();
    if (this.atEnd()) throw this.error("unexpected end of input");
    const char = this.peek();
    if (char === "{") return this.parseObject();
    if (char === "[") return this.parseArray();
    if (char === '"') return this.parseString();
    if (char === "-" || (char >= "0" && char <= "9")) return this.parseNumber();
    if (this.text.startsWith("true", this.index)) {
      this.index += 4;
      return true;
    }
    if (this.text.startsWith("false", this.index)) {
      this.index += 5;
      return false;
    }
    if (this.text.startsWith("null", this.index)) {
      this.index += 4;
      return null;
    }
    throw this.error(`unexpected character ${JSON.stringify(char)}`);
  }

  parseObject() {
    this.expect("{");
    this.skipWhitespace();
    const object = Object.create(null);
    const seen = new Set();
    if (this.peek() === "}") {
      this.index++;
      return object;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.peek() !== '"') throw this.error("expected a string object key");
      const key = this.parseString();
      if (seen.has(key)) {
        throw this.error(`duplicate object member name ${JSON.stringify(key)}`);
      }
      seen.add(key);
      this.skipWhitespace();
      this.expect(":");
      object[key] = this.parseValue();
      this.skipWhitespace();
      const char = this.text[this.index];
      if (char === ",") {
        this.index++;
        continue;
      }
      if (char === "}") {
        this.index++;
        return object;
      }
      throw this.error("expected ',' or '}'");
    }
  }

  parseArray() {
    this.expect("[");
    this.skipWhitespace();
    const array = [];
    if (this.peek() === "]") {
      this.index++;
      return array;
    }
    for (;;) {
      array.push(this.parseValue());
      this.skipWhitespace();
      const char = this.text[this.index];
      if (char === ",") {
        this.index++;
        continue;
      }
      if (char === "]") {
        this.index++;
        return array;
      }
      throw this.error("expected ',' or ']'");
    }
  }

  parseString() {
    this.expect('"');
    let out = "";
    for (;;) {
      if (this.atEnd()) throw this.error("unterminated string");
      const char = this.text[this.index++];
      if (char === '"') break;
      if (char === "\\") {
        if (this.atEnd()) throw this.error("unterminated escape");
        const escape = this.text[this.index++];
        if (escape === '"') out += '"';
        else if (escape === "\\") out += "\\";
        else if (escape === "/") out += "/";
        else if (escape === "b") out += "\b";
        else if (escape === "f") out += "\f";
        else if (escape === "n") out += "\n";
        else if (escape === "r") out += "\r";
        else if (escape === "t") out += "\t";
        else if (escape === "u") {
          const hex = this.text.slice(this.index, this.index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw this.error("invalid \\u escape");
          out += String.fromCharCode(Number.parseInt(hex, 16));
          this.index += 4;
        } else {
          throw this.error(`invalid escape ${JSON.stringify(escape)}`);
        }
        continue;
      }
      if (char.charCodeAt(0) < 0x20) {
        throw this.error("unescaped control character in string");
      }
      out += char;
    }
    return assertNoLoneSurrogates(out);
  }

  parseNumber() {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      this.text.slice(this.index),
    );
    if (!match || match[0].length === 0) throw this.error("invalid number");
    const token = match[0];
    this.index += token.length;
    const value = Number(token);
    if (!Number.isFinite(value)) {
      throw this.error("non-finite number");
    }
    if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER) {
      throw this.error("integer outside the safe range");
    }
    return value;
  }
}

/** Parse JSON text with the strict rules documented on `StrictJsonParser`. */
export function strictParse(jsonText) {
  if (typeof jsonText !== "string") {
    throw new TypeError("strictParse expects a JSON string");
  }
  const parser = new StrictJsonParser(jsonText);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.atEnd()) throw parser.error("unexpected trailing content");
  return value;
}

/** Canonical, unpadded base64url for bytes. */
export function bytesToBase64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Decode canonical, unpadded base64url. Returns `null` for padding, invalid
 * characters, the length ≡ 1 (mod 4) case, or any non-canonical spelling.
 */
export function base64UrlToBytes(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) return null;
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) return null;
  return bytes;
}

/** Build a Node public `KeyObject` from 32 raw Ed25519 public-key bytes. */
export function ed25519PublicKeyFromRaw(raw) {
  const bytes = Buffer.from(raw);
  if (bytes.length !== 32) {
    throw new RangeError(`Ed25519 public key must be 32 bytes; received ${bytes.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]),
    format: "der",
    type: "spki",
  });
}

/** Build a Node private `KeyObject` from a 32-byte Ed25519 seed. */
export function ed25519PrivateKeyFromSeed(seed) {
  const bytes = Buffer.from(seed);
  if (bytes.length !== 32) {
    throw new RangeError(`Ed25519 seed must be 32 bytes; received ${bytes.length}`);
  }
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, bytes]),
    format: "der",
    type: "pkcs8",
  });
}

function normalizePrivateKey(privateKey) {
  let key;
  if (privateKey instanceof KeyObject) {
    key = privateKey;
  } else if (typeof privateKey === "string") {
    key = createPrivateKey(privateKey);
  } else if (privateKey instanceof Uint8Array) {
    key = privateKey.length === 32
      ? ed25519PrivateKeyFromSeed(privateKey)
      : createPrivateKey({ key: Buffer.from(privateKey), format: "der", type: "pkcs8" });
  } else if (isPlainObject(privateKey) && "key" in privateKey) {
    key = createPrivateKey(privateKey);
  } else {
    throw new TypeError("privateKey must be a KeyObject, seed, PEM/DER, or createPrivateKey options");
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`privateKey must be Ed25519; received ${key.asymmetricKeyType}`);
  }
  if (key.type !== "private") {
    throw new TypeError("privateKey must be a private key");
  }
  return key;
}

/**
 * Sign an envelope. The signing input is the envelope with `extensions`
 * removed, canonicalized per RFC 8785 and encoded as UTF-8. Returns a shallow
 * copy of the envelope with `extensions["xeip.sig"]` set to the carrier.
 *
 * Sender binding is not enforced here: signing is a primitive that must also be
 * able to produce deliberately unbound vectors. `verifySignedEnvelope` is what
 * enforces `entityUrn(kid) === sender`.
 *
 * @param {object} envelope Parsed envelope object.
 * @param {{ privateKey: KeyObject|Uint8Array|string|object, kid: string }} options
 */
export function signEnvelope(envelope, { privateKey, kid } = {}) {
  if (!isPlainObject(envelope)) throw new TypeError("envelope must be an object");
  if (typeof kid !== "string") throw new TypeError("kid must be a string");
  const key = normalizePrivateKey(privateKey);
  const base = { ...envelope };
  delete base.extensions;
  const input = Buffer.from(canonicalize(base), "utf8");
  const signature = sign(null, input, key);
  const extensions = isPlainObject(envelope.extensions) ? { ...envelope.extensions } : {};
  extensions[SIG_EXTENSION] = {
    v: SIG_VERSION,
    alg: SIG_ALG,
    kid,
    sig: bytesToBase64Url(signature),
  };
  return { ...envelope, extensions };
}

/**
 * Verify a signed envelope. Accepts either a JSON string or a parsed envelope
 * object, and returns a structured result rather than throwing:
 *
 *   { valid: true } | { valid: false, reason, error? }
 *
 * Steps: strict-parse (when given text) → check the carrier (including the
 * `v` version) → reject small-order/identity keys ("weak key") → sender binding
 * (`entityUrn(kid) === sender`) → canonicalize the envelope without
 * `extensions` → Ed25519 verify. Reasons: "malformed envelope",
 * "missing signature", "malformed signature", "unsupported algorithm",
 * "weak key", "sender binding", "signature mismatch".
 *
 * NOTE: passing a pre-parsed object skips the strict-parse gate; only a JSON
 * string is protected against duplicate keys and out-of-range numbers.
 */
export function verifySignedEnvelope(envelope) {
  let value = envelope;
  if (typeof envelope === "string") {
    try {
      value = strictParse(envelope);
    } catch (error) {
      return { valid: false, reason: "malformed envelope", error: error.message };
    }
  }
  if (!isPlainObject(value)) {
    return { valid: false, reason: "malformed envelope" };
  }

  const carrier = isPlainObject(value.extensions) ? value.extensions[SIG_EXTENSION] : undefined;
  if (carrier === undefined || carrier === null) {
    return { valid: false, reason: "missing signature" };
  }
  if (!isPlainObject(carrier)) {
    return { valid: false, reason: "malformed signature" };
  }
  const { alg, kid, sig } = carrier;
  if (typeof kid !== "string" || typeof sig !== "string") {
    return { valid: false, reason: "malformed signature" };
  }
  if (alg !== SIG_ALG) {
    return { valid: false, reason: "unsupported algorithm" };
  }
  if (carrier.v !== SIG_VERSION) {
    return { valid: false, reason: "malformed signature" };
  }

  let publicKey;
  try {
    const raw = decodeKeyId(kid);
    if (isWeakEd25519PublicKey(raw)) {
      return { valid: false, reason: "weak key" };
    }
    publicKey = ed25519PublicKeyFromRaw(raw);
    if (entityUrn(kid) !== value.sender) {
      return { valid: false, reason: "sender binding" };
    }
  } catch (error) {
    return { valid: false, reason: "sender binding", error: error.message };
  }

  const signature = base64UrlToBytes(sig);
  if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) {
    return { valid: false, reason: "malformed signature" };
  }

  const base = { ...value };
  delete base.extensions;
  let input;
  try {
    input = Buffer.from(canonicalize(base), "utf8");
  } catch (error) {
    return { valid: false, reason: "malformed envelope", error: error.message };
  }

  return verify(null, input, publicKey, signature)
    ? { valid: true }
    : { valid: false, reason: "signature mismatch" };
}

function printUsage() {
  return (
    "usage:\n" +
    "  node tools/signed-envelope.mjs verify <file.json>\n" +
    "  node tools/signed-envelope.mjs keygen\n"
  );
}

function main(argv) {
  const [command, argument] = argv;
  if (command === "verify") {
    if (argument === undefined) {
      process.stderr.write(printUsage());
      process.exitCode = 1;
      return;
    }
    try {
      const result = verifySignedEnvelope(readFileSync(argument, "utf8"));
      process.stdout.write(JSON.stringify(result) + "\n");
      if (!result.valid) process.exitCode = 1;
    } catch (error) {
      process.stderr.write(`error: ${error.message}\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (command === "keygen") {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const seed = Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url");
    const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const kid = encodeKeyId(raw);
    process.stdout.write(
      JSON.stringify({
        seedHex: seed.toString("hex"),
        publicKeyHex: raw.toString("hex"),
        keyId: kid,
        entityUrn: entityUrn(kid),
      }) + "\n",
    );
    return;
  }
  process.stderr.write(printUsage());
  process.exitCode = 1;
}

// Local base58btc encoding is imported lazily to keep keygen self-contained;
// `encodeKeyId` is re-exported here so callers need not import two modules.
// Run only when invoked directly, so importing the module in tests is silent.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
