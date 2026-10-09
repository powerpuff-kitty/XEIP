// tools/derive-keyid.mjs
//
// Dependency-free key-ID encoding for the *proposed* XEIP identity profile
// (spec/identity.md §2). It implements the encoding step only:
//
//   key-id = "z" + base58btc(0xed 0x01 || raw-ed25519-public-key-bytes)
//            \_/   \_______/ \_________/    \_________________________/
//         multibase   multicodec   raw public key
//         base58btc  ed25519-pub  (exactly 32 bytes)
//
// This is a `did:key`-style multibase(MULTICODEC(public-key-type, bytes))
// construction. It is a *multicodec*, not a multihash: the two-byte prefix
// names the key type and is not a hash of the key.
//
// SCOPE / BOUNDARY: base58btc is a plain, well-defined base conversion, not a
// cryptographic primitive, so it is safe to hand-write and auditable here.
// This module deliberately does NOT generate keys, sign, verify, or validate
// that the bytes are a canonical curve point. Those steps require the audited
// libraries selected in ADR 0007 and are out of scope for the encoding layer.
//
// Exports: encodeKeyId, entityUrn, deviceUrn. Also exports the base58btc
// helpers and input parser for tests and inspection.

import { pathToFileURL } from "node:url";

// Multicodec code 0xed01 (`ed25519-pub`) written as an unsigned LEB128 varint.
// 0xed01 is > 0x7f, so the varint needs two bytes: [0xed, 0x01].
export const ED25519_MULTICODEC = Object.freeze([0xed, 0x01]);

// Raw Ed25519 public keys are exactly 32 bytes (RFC 8032 §5.1.3).
export const ED25519_PUBLIC_KEY_LENGTH = 32;

// Multibase prefix for base58btc (https://github.com/multiformats/multibase).
export const MULTIBASE_BASE58BTC = "z";

// The Bitcoin base58btc alphabet: no 0, O, I or l to avoid visual ambiguity.
export const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Coerce a byte source to Uint8Array without copying through a dependency.
 * Accepts Uint8Array (and its Node Buffer subclass) or a plain byte array.
 */
function toBytes(input) {
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

/**
 * Base58btc encode (Bitcoin alphabet). Leading zero bytes are encoded as
 * leading '1' characters, exactly like the reference implementation.
 */
export function base58btcEncode(input) {
  const bytes = toBytes(input);
  if (bytes.length === 0) return "";

  // Each leading 0x00 byte becomes one leading '1' and is not part of the
  // big-integer value, so count it first and exclude it from the conversion.
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    leadingZeros++;
  }

  let value = 0n;
  for (let i = leadingZeros; i < bytes.length; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }

  let encoded = "";
  while (value > 0n) {
    encoded = BASE58BTC_ALPHABET[Number(value % 58n)] + encoded;
    value /= 58n;
  }

  return "1".repeat(leadingZeros) + encoded;
}

// Reverse lookup for base58btcDecode; built once from the alphabet.
const BASE58BTC_INDEX = new Map(
  [...BASE58BTC_ALPHABET].map((char, index) => [char, index]),
);

/**
 * Base58btc decode. Used for round-trip tests and for consuming key-ids; it is
 * not needed to produce an identifier from key bytes.
 */
export function base58btcDecode(text) {
  if (typeof text !== "string") throw new TypeError("base58btc input must be a string");

  let leadingOnes = 0;
  while (leadingOnes < text.length && text[leadingOnes] === "1") leadingOnes++;

  let value = 0n;
  for (let i = leadingOnes; i < text.length; i++) {
    const digit = BASE58BTC_INDEX.get(text[i]);
    if (digit === undefined) {
      throw new Error(`invalid base58btc character: ${JSON.stringify(text[i])}`);
    }
    value = value * 58n + BigInt(digit);
  }

  const body = [];
  while (value > 0n) {
    body.unshift(Number(value & 0xffn));
    value >>= 8n;
  }

  const out = new Uint8Array(leadingOnes + body.length);
  out.set(body, leadingOnes);
  return out;
}

/**
 * Validate and return a raw Ed25519 public key as bytes.
 * Rejects any length other than 32 bytes. Note that point validation (curve
 * membership, canonical encoding, small-order rejection per RFC 8032 §5.1.3)
 * is intentionally not performed here; see the module header.
 */
function assertEd25519PublicKey(input) {
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
 * base58btc of the multicodec type prefix followed by the key bytes, with the
 * 'z' multibase prefix. This is the exact value embedded in entity/device URNs.
 *
 * @param {Uint8Array|number[]} publicKeyBytes 32 raw public-key bytes.
 * @returns {string} multibase/multicodec key-id, e.g. "z6Mk...".
 */
export function encodeKeyId(publicKeyBytes) {
  const key = assertEd25519PublicKey(publicKeyBytes);
  const payload = new Uint8Array(ED25519_MULTICODEC.length + key.length);
  payload.set(ED25519_MULTICODEC, 0);
  payload.set(key, ED25519_MULTICODEC.length);
  return MULTIBASE_BASE58BTC + base58btcEncode(payload);
}

/**
 * Decode and canonical-validate a key-id produced by `encodeKeyId`. Returns the
 * 32 raw public-key bytes. Rejects a missing `z` multibase prefix, a wrong total
 * payload length, a missing `ed25519-pub` multicodec prefix, invalid base58btc
 * characters, and any non-canonical spelling (compared by re-encoding).
 */
export function decodeKeyId(keyId) {
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new TypeError("key-id must be a non-empty string");
  }
  if (keyId[0] !== MULTIBASE_BASE58BTC) {
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

function assertKeyId(keyId) {
  decodeKeyId(keyId);
  return keyId;
}

/** `urn:xeip:entity:<key-id>` for a canonical key-id produced by encodeKeyId. */
export function entityUrn(keyId) {
  return `urn:xeip:entity:${assertKeyId(keyId)}`;
}

/** `urn:xeip:device:<key-id>` for a canonical key-id produced by encodeKeyId. */
export function deviceUrn(keyId) {
  return `urn:xeip:device:${assertKeyId(keyId)}`;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hex input");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Parse a user-supplied 32-byte Ed25519 public key from hex (64 characters) or
 * unpadded/padded base64url. Hex wins when the input is exactly 64 hex digits;
 * everything else is treated as base64url. Length is checked downstream.
 */
export function parsePublicKey(text) {
  if (typeof text !== "string") throw new TypeError("public key input must be a string");
  if (text !== text.trim()) throw new Error("public key must not contain surrounding whitespace");
  if (/^[0-9a-fA-F]{64}$/.test(text)) return hexToBytes(text);
  // Canonical, unpadded base64url only: reject padding, invalid characters and
  // the length ≡ 1 (mod 4) case that cannot represent whole bytes.
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) {
    throw new Error("public key must be 64 hex characters or base64url");
  }
  const bytes = Uint8Array.from(Buffer.from(text, "base64url"));
  if (Buffer.from(bytes).toString("base64url") !== text) {
    throw new Error("public key base64url is not canonical");
  }
  return bytes;
}

function main(argv) {
  const [input] = argv;
  if (input === undefined) {
    process.stderr.write(
      "usage: node tools/derive-keyid.mjs <32-byte-ed25519-public-key (hex or base64url)>\n",
    );
    process.exitCode = 1;
    return;
  }
  try {
    const keyId = encodeKeyId(parsePublicKey(input));
    const output = {
      keyId,
      entityUrn: entityUrn(keyId),
      deviceUrn: deviceUrn(keyId),
    };
    process.stdout.write(JSON.stringify(output) + "\n");
  } catch (error) {
    process.stderr.write(`error: ${error.message}\n`);
    process.exitCode = 1;
  }
}

// Run only when invoked directly, so importing the module in tests is silent.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
