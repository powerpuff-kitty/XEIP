/**
 * Portable, dependency-free implementation of the detached signed-envelope
 * profile (`xeip.local-signed-envelopes/0.1`) for the TypeScript SDK.
 *
 * It reproduces byte-for-byte the framing of `tools/signed-envelope.mjs` and
 * `tools/derive-keyid.mjs` using only WebCrypto (`crypto.subtle`) and plain
 * JavaScript, so JS/Node, Rust and TypeScript share the same conformance
 * vectors:
 *
 *   - RFC 8785 (JCS) canonicalization of a parsed JSON value,
 *   - a strict JSON parser mirroring the reference pre-parse gate,
 *   - canonical key-id encode/decode and `entityUrn`/`deviceUrn`,
 *   - Ed25519 sign/verify over `UTF-8(RFC8785(envelope without extensions))`
 *     with the signature in `extensions["xeip.sig"]` and `entityUrn(kid)`
 *     bound to `envelope.sender`.
 *
 * Ed25519 is provided by the platform's WebCrypto implementation, never a
 * hand-written primitive. See `spec/local-signed-envelopes.md`.
 */

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

/** Raw Ed25519 public keys are exactly 32 bytes (RFC 8032 §5.1.3). */
export const ED25519_PUBLIC_KEY_LENGTH = 32;

/** Multicodec code 0xed01 (`ed25519-pub`) as an unsigned LEB128 varint. */
export const ED25519_MULTICODEC = [0xed, 0x01] as const;

/** Multibase prefix for base58btc. */
export const MULTIBASE_BASE58BTC = "z";

/** The Bitcoin base58btc alphabet: no 0, O, I or l. */
export const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// DER (PKCS#8) wrapper around a raw 32-byte Ed25519 seed, used to import a
// private key into WebCrypto. This is a fixed ASN.1 prefix, not a primitive.
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

/** The reason strings shared with the JavaScript reference implementation. */
export type VerifyFailureReason =
  | "malformed envelope"
  | "missing signature"
  | "malformed signature"
  | "unsupported algorithm"
  | "sender binding"
  | "signature mismatch";

/** Structured result of {@link verifySignedEnvelope}. */
export type VerifyResult =
  | { valid: true }
  | { valid: false; reason: VerifyFailureReason; error?: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/* -------------------------------------------------------------------------- */
/* RFC 8785 JSON Canonicalization Scheme                                      */
/* -------------------------------------------------------------------------- */

function assertNoLoneSurrogates(text: string): string {
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
function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function serialize(value: unknown, out: string[]): void {
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("cannot canonicalize a non-finite number");
      }
      out.push(JSON.stringify(value));
      return;
    case "string":
      assertNoLoneSurrogates(value);
      out.push(JSON.stringify(value));
      return;
    case "object": {
      if (Array.isArray(value)) {
        out.push("[");
        for (let i = 0; i < value.length; i++) {
          if (i > 0) out.push(",");
          serialize(value[i], out);
        }
        out.push("]");
        return;
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort(compareUtf16);
      out.push("{");
      for (let i = 0; i < keys.length; i++) {
        if (i > 0) out.push(",");
        const key = keys[i]!;
        assertNoLoneSurrogates(key);
        out.push(JSON.stringify(key), ":");
        serialize(record[key], out);
      }
      out.push("}");
      return;
    }
    default:
      throw new TypeError(`cannot canonicalize a value of type ${typeof value}`);
  }
}

/**
 * RFC 8785 JSON Canonicalization Scheme. Produces the deterministic UTF-8
 * envelope bytes that are signed: object keys sorted by UTF-16 code units, no
 * whitespace, ECMAScript number formatting, strings escaped as JSON, arrays in
 * order. Rejects values that have no canonical JSON form.
 */
export function canonicalize(value: unknown): string {
  const out: string[] = [];
  serialize(value, out);
  return out.join("");
}

/* -------------------------------------------------------------------------- */
/* Strict JSON pre-parse gate                                                 */
/* -------------------------------------------------------------------------- */

class StrictJsonParser {
  private readonly text: string;
  private index: number;

  constructor(text: string) {
    this.text = text;
    this.index = 0;
  }

  error(message: string): SyntaxError {
    return new SyntaxError(`${message} at position ${this.index}`);
  }

  atEnd(): boolean {
    return this.index >= this.text.length;
  }

  private peek(): string {
    return this.text.charAt(this.index);
  }

  skipWhitespace(): void {
    while (this.index < this.text.length) {
      const char = this.text.charAt(this.index);
      if (char === " " || char === "\t" || char === "\n" || char === "\r") {
        this.index++;
      } else {
        break;
      }
    }
  }

  private expect(char: string): void {
    if (this.text.charAt(this.index) !== char) {
      throw this.error(`expected ${JSON.stringify(char)}`);
    }
    this.index++;
  }

  parseValue(): unknown {
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

  private parseObject(): Record<string, unknown> {
    this.expect("{");
    this.skipWhitespace();
    const object: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
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
      const char = this.text.charAt(this.index);
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

  private parseArray(): unknown[] {
    this.expect("[");
    this.skipWhitespace();
    const array: unknown[] = [];
    if (this.peek() === "]") {
      this.index++;
      return array;
    }
    for (;;) {
      array.push(this.parseValue());
      this.skipWhitespace();
      const char = this.text.charAt(this.index);
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

  private parseString(): string {
    this.expect('"');
    let out = "";
    for (;;) {
      if (this.atEnd()) throw this.error("unterminated string");
      const char = this.text.charAt(this.index);
      this.index++;
      if (char === '"') break;
      if (char === "\\") {
        if (this.atEnd()) throw this.error("unterminated escape");
        const escape = this.text.charAt(this.index);
        this.index++;
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

  private parseNumber(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      this.text.slice(this.index),
    );
    const token = match?.[0];
    if (token === undefined || token.length === 0) throw this.error("invalid number");
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

/**
 * Strict JSON parser. Unlike `JSON.parse`, this rejects duplicate object member
 * names, lone surrogate escapes, non-finite numbers and integers outside
 * ±(2^53-1), so two different wire byte sequences cannot share one signature.
 */
export function strictParse(jsonText: string): unknown {
  if (typeof jsonText !== "string") {
    throw new TypeError("strictParse expects a JSON string");
  }
  const parser = new StrictJsonParser(jsonText);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.atEnd()) throw parser.error("unexpected trailing content");
  return value;
}

/* -------------------------------------------------------------------------- */
/* Base64url (canonical, unpadded) and base58btc                              */
/* -------------------------------------------------------------------------- */

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64URL_INDEX = new Map<string, number>(
  [...BASE64URL_ALPHABET].map((char, index) => [char, index]),
);

/** Canonical, unpadded base64url for bytes. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += BASE64URL_ALPHABET.charAt(b0 >> 2);
    out += BASE64URL_ALPHABET.charAt(((b0 & 3) << 4) | ((b1 ?? 0) >> 4));
    if (b1 !== undefined) {
      out += BASE64URL_ALPHABET.charAt(((b1 & 15) << 2) | ((b2 ?? 0) >> 6));
    }
    if (b2 !== undefined) {
      out += BASE64URL_ALPHABET.charAt(b2 & 63);
    }
  }
  return out;
}

/**
 * Decode canonical, unpadded base64url. Returns `null` for padding, invalid
 * characters, the length ≡ 1 (mod 4) case, or any non-canonical spelling.
 */
export function base64UrlToBytes(text: string): Uint8Array | null {
  if (typeof text !== "string" || text.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of text) {
    const digit = BASE64URL_INDEX.get(char);
    if (digit === undefined) return null;
    value = (value << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  const bytes = Uint8Array.from(out);
  if (bytesToBase64Url(bytes) !== text) return null;
  return bytes;
}

function toBytes(input: Uint8Array | readonly number[]): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (Array.isArray(input)) {
    for (const value of input) {
      if (!Number.isInteger(value) || value < 0 || value > 255) {
        throw new TypeError("byte array values must be integers in [0, 255]");
      }
    }
    return Uint8Array.from(input);
  }
  throw new TypeError("expected a Uint8Array or an array of byte values");
}

/** Base58btc encode (Bitcoin alphabet). Leading zero bytes become leading '1'. */
export function base58btcEncode(input: Uint8Array | readonly number[]): string {
  const bytes = toBytes(input);
  if (bytes.length === 0) return "";

  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    leadingZeros++;
  }

  let value = 0n;
  for (let i = leadingZeros; i < bytes.length; i++) {
    value = (value << 8n) | BigInt(bytes[i]!);
  }

  let encoded = "";
  while (value > 0n) {
    encoded = BASE58BTC_ALPHABET.charAt(Number(value % 58n)) + encoded;
    value /= 58n;
  }

  return "1".repeat(leadingZeros) + encoded;
}

const BASE58BTC_INDEX = new Map<string, number>(
  [...BASE58BTC_ALPHABET].map((char, index) => [char, index]),
);

/** Base58btc decode, the inverse of {@link base58btcEncode}. */
export function base58btcDecode(text: string): Uint8Array {
  if (typeof text !== "string") throw new TypeError("base58btc input must be a string");

  let leadingOnes = 0;
  while (leadingOnes < text.length && text.charAt(leadingOnes) === "1") leadingOnes++;

  let value = 0n;
  for (let i = leadingOnes; i < text.length; i++) {
    const digit = BASE58BTC_INDEX.get(text.charAt(i));
    if (digit === undefined) {
      throw new Error(`invalid base58btc character: ${JSON.stringify(text.charAt(i))}`);
    }
    value = value * 58n + BigInt(digit);
  }

  const body: number[] = [];
  while (value > 0n) {
    body.unshift(Number(value & 0xffn));
    value >>= 8n;
  }

  const out = new Uint8Array(leadingOnes + body.length);
  out.set(body, leadingOnes);
  return out;
}

function assertEd25519PublicKey(input: Uint8Array | readonly number[]): Uint8Array {
  const bytes = toBytes(input);
  if (bytes.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new RangeError(
      `Ed25519 public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes; received ${bytes.length}`,
    );
  }
  return bytes;
}

/**
 * Encode a 32-byte raw Ed25519 public key as the identity-profile key-id:
 * base58btc of the `ed25519-pub` multicodec prefix followed by the key bytes,
 * with the 'z' multibase prefix. This is the exact value embedded in URNs.
 */
export function encodeKeyId(publicKeyBytes: Uint8Array | readonly number[]): string {
  const key = assertEd25519PublicKey(publicKeyBytes);
  const payload = new Uint8Array(ED25519_MULTICODEC.length + key.length);
  payload.set(ED25519_MULTICODEC as unknown as ArrayLike<number>, 0);
  payload.set(key, ED25519_MULTICODEC.length);
  return MULTIBASE_BASE58BTC + base58btcEncode(payload);
}

/**
 * Decode and canonical-validate a key-id produced by {@link encodeKeyId}.
 * Returns the 32 raw public-key bytes, or throws for a missing 'z' prefix,
 * wrong length, wrong multicodec, invalid base58btc or non-canonical spelling.
 */
export function decodeKeyId(keyId: string): Uint8Array {
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new TypeError("key-id must be a non-empty string");
  }
  if (keyId.charAt(0) !== MULTIBASE_BASE58BTC) {
    throw new Error("key-id must start with the base58btc multibase prefix 'z'");
  }
  const payload = base58btcDecode(keyId.slice(1));
  const expectedLength = ED25519_MULTICODEC.length + ED25519_PUBLIC_KEY_LENGTH;
  if (payload.length !== expectedLength) {
    throw new Error(`key-id payload must be ${expectedLength} bytes; received ${payload.length}`);
  }
  if (payload[0] !== ED25519_MULTICODEC[0] || payload[1] !== ED25519_MULTICODEC[1]) {
    throw new Error("key-id does not carry the ed25519-pub multicodec prefix");
  }
  if (MULTIBASE_BASE58BTC + base58btcEncode(payload) !== keyId) {
    throw new Error("key-id is not in canonical form");
  }
  return payload.slice(ED25519_MULTICODEC.length);
}

function assertKeyId(keyId: string): string {
  decodeKeyId(keyId);
  return keyId;
}

/** `urn:xeip:entity:<key-id>` for a canonical key-id produced by {@link encodeKeyId}. */
export function entityUrn(keyId: string): string {
  return `urn:xeip:entity:${assertKeyId(keyId)}`;
}

/** `urn:xeip:device:<key-id>` for a canonical key-id produced by {@link encodeKeyId}. */
export function deviceUrn(keyId: string): string {
  return `urn:xeip:device:${assertKeyId(keyId)}`;
}

/* -------------------------------------------------------------------------- */
/* Ed25519 via WebCrypto                                                      */
/* -------------------------------------------------------------------------- */

function concatBytes(prefix: Uint8Array, suffix: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + suffix.length);
  out.set(prefix, 0);
  out.set(suffix, prefix.length);
  return out;
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return typeof CryptoKey !== "undefined" && value instanceof CryptoKey;
}

function bytesFromSource(source: Uint8Array | ArrayBuffer): Uint8Array {
  if (source instanceof Uint8Array) return source;
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  throw new TypeError("privateKey must be a CryptoKey, a Uint8Array or an ArrayBuffer");
}

// WebCrypto `BufferSource` requires an `ArrayBuffer`-backed view; copy into a
// fresh ArrayBuffer so callers may pass any Uint8Array view.
function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Import a 32-byte Ed25519 seed (or an already DER-encoded PKCS#8 private key)
 * into WebCrypto as a non-extractable signing key.
 */
export async function ed25519PrivateKeyFromSeed(
  seed: Uint8Array | ArrayBuffer,
): Promise<CryptoKey> {
  const bytes = bytesFromSource(seed);
  const der = bytes.length === 32 ? concatBytes(ED25519_PKCS8_PREFIX, bytes) : bytes;
  const key = await crypto.subtle.importKey("pkcs8", toBufferSource(der), "Ed25519", false, ["sign"]);
  if (key.algorithm.name !== "Ed25519") {
    throw new TypeError("privateKey must be Ed25519");
  }
  return key;
}

async function normalizePrivateKey(
  privateKey: CryptoKey | Uint8Array | ArrayBuffer,
): Promise<CryptoKey> {
  if (isCryptoKey(privateKey)) {
    if (privateKey.type !== "private" || privateKey.algorithm.name !== "Ed25519") {
      throw new TypeError("privateKey must be an Ed25519 private CryptoKey");
    }
    return privateKey;
  }
  return ed25519PrivateKeyFromSeed(privateKey);
}

/** Options accepted by {@link signEnvelope}. */
export interface SignEnvelopeOptions {
  privateKey: CryptoKey | Uint8Array | ArrayBuffer;
  kid: string;
}

/**
 * Sign an envelope with Ed25519 via WebCrypto. The signing input is the
 * envelope with `extensions` removed, canonicalized per RFC 8785 and encoded as
 * UTF-8. Returns a shallow copy of the envelope with
 * `extensions["xeip.sig"]` set to the carrier. Sender binding is not enforced
 * here; {@link verifySignedEnvelope} enforces `entityUrn(kid) === sender`.
 */
export async function signEnvelope(
  envelope: unknown,
  options: SignEnvelopeOptions,
): Promise<Record<string, unknown>> {
  if (!isPlainObject(envelope)) throw new TypeError("envelope must be an object");
  if (!isPlainObject(options) || typeof options.kid !== "string") {
    throw new TypeError("kid must be a string");
  }
  const key = await normalizePrivateKey(options.privateKey);
  const base: Record<string, unknown> = { ...envelope };
  delete base.extensions;
  const input = new TextEncoder().encode(canonicalize(base));
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, toBufferSource(input)),
  );
  const existing = isPlainObject(envelope.extensions) ? envelope.extensions : {};
  const extensions: Record<string, unknown> = { ...existing };
  extensions[SIG_EXTENSION] = {
    v: SIG_VERSION,
    alg: SIG_ALG,
    kid: options.kid,
    sig: bytesToBase64Url(signature),
  };
  return { ...envelope, extensions };
}

/**
 * Verify a signed envelope via WebCrypto. Accepts either a JSON string or a
 * parsed envelope object and returns a structured result rather than throwing:
 *
 *   `{ valid: true } | { valid: false, reason, error? }`
 *
 * Steps: strict-parse (when given text) → carrier → sender binding → canonical
 * bytes without `extensions` → Ed25519 verify. The reason strings match the JS
 * reference: `malformed envelope`, `missing signature`, `malformed signature`,
 * `unsupported algorithm`, `sender binding`, `signature mismatch`.
 */
export async function verifySignedEnvelope(envelope: unknown): Promise<VerifyResult> {
  let value: unknown = envelope;
  if (typeof envelope === "string") {
    try {
      value = strictParse(envelope);
    } catch (error) {
      return { valid: false, reason: "malformed envelope", error: errorMessage(error) };
    }
  }
  if (!isPlainObject(value)) {
    return { valid: false, reason: "malformed envelope" };
  }

  const carrier =
    isPlainObject(value.extensions) ? value.extensions[SIG_EXTENSION] : undefined;
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

  let publicKey: CryptoKey;
  try {
    const raw = decodeKeyId(kid);
    publicKey = await crypto.subtle.importKey(
      "raw",
      toBufferSource(raw),
      "Ed25519",
      false,
      ["verify"],
    );
    if (entityUrn(kid) !== value.sender) {
      return { valid: false, reason: "sender binding" };
    }
  } catch (error) {
    return { valid: false, reason: "sender binding", error: errorMessage(error) };
  }

  const signature = base64UrlToBytes(sig);
  if (signature === null || signature.length !== ED25519_SIGNATURE_LENGTH) {
    return { valid: false, reason: "malformed signature" };
  }

  const base: Record<string, unknown> = { ...value };
  delete base.extensions;
  let input: Uint8Array;
  try {
    input = new TextEncoder().encode(canonicalize(base));
  } catch (error) {
    return { valid: false, reason: "malformed envelope", error: errorMessage(error) };
  }

  const valid = await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    toBufferSource(signature),
    toBufferSource(input),
  );
  return valid ? { valid: true } : { valid: false, reason: "signature mismatch" };
}
