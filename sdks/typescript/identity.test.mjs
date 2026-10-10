// sdks/typescript/identity.test.mjs
//
// Conformance consumer for the portable TypeScript signed-envelope profile.
// Imports only the built SDK (`./dist/index.js`) and the shared vectors, and
// checks that the TypeScript port returns the exact same results and signing
// bytes as `tools/signed-envelope.mjs`.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  canonicalize,
  strictParse,
  bytesToBase64Url,
  base64UrlToBytes,
  base58btcEncode,
  base58btcDecode,
  encodeKeyId,
  decodeKeyId,
  entityUrn,
  deviceUrn,
  ed25519PrivateKeyFromSeed,
  signEnvelope,
  verifySignedEnvelope,
  SIG_EXTENSION,
  SIG_VERSION,
  SIG_ALG,
} from "./dist/index.js";

const VECTORS_URL = new URL(
  "../../conformance/fixtures/identity-signed/signed.vectors.json",
  import.meta.url,
);
const vectors = JSON.parse(readFileSync(VECTORS_URL, "utf8"));
const positive = vectors.find((vector) => vector.valid === true);
const positiveSignature = positive.envelope.extensions[SIG_EXTENSION].sig;

// Standard Ed25519 keypair for seed 000102…1f, pinned independently of this
// implementation so a wrong seed conversion fails loudly.
const SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const EXPECTED_PUBLIC_KEY_HEX =
  "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const EXPECTED_KEY_ID = "z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";

const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const toHex = (bytes) => Buffer.from(bytes).toString("hex");

function unsignedEnvelope() {
  const copy = structuredClone(positive.envelope);
  delete copy.extensions;
  return copy;
}

test("conformance fixture: every vector yields its documented result", async () => {
  assert.equal(vectors.length, 6, "one positive and five negative vectors are required");
  const names = new Set();
  for (const vector of vectors) {
    names.add(vector.name);
    const result = await verifySignedEnvelope(vector.envelope);
    if (vector.valid === true) {
      assert.deepEqual(result, { valid: true }, vector.name);
    } else {
      assert.equal(result.valid, false, vector.name);
      assert.equal(result.reason, vector.reason, vector.name);
    }
  }
  assert.equal(names.size, vectors.length, "vector names must be unique");
});

test("the positive vector verifies from JSON text through the strict gate", async () => {
  assert.deepEqual(await verifySignedEnvelope(JSON.stringify(positive.envelope)), { valid: true });
});

test("verifySignedEnvelope returns structured results and never throws", async () => {
  assert.deepEqual(await verifySignedEnvelope(null), { valid: false, reason: "malformed envelope" });
  assert.deepEqual(await verifySignedEnvelope(42), { valid: false, reason: "malformed envelope" });
  assert.deepEqual(await verifySignedEnvelope({}), { valid: false, reason: "missing signature" });
  assert.deepEqual(await verifySignedEnvelope({ extensions: {} }), {
    valid: false,
    reason: "missing signature",
  });
  assert.equal((await verifySignedEnvelope("{ not json")).reason, "malformed envelope");
  assert.equal((await verifySignedEnvelope('{"a":1,"a":2}')).reason, "malformed envelope");

  const unsigned = unsignedEnvelope();
  assert.deepEqual(await verifySignedEnvelope(unsigned), {
    valid: false,
    reason: "missing signature",
  });

  assert.deepEqual(await verifySignedEnvelope({ ...unsigned, extensions: { [SIG_EXTENSION]: "nope" } }), {
    valid: false,
    reason: "malformed signature",
  });

  const { kid, sig } = positive.envelope.extensions[SIG_EXTENSION];
  assert.deepEqual(
    await verifySignedEnvelope({
      ...unsigned,
      extensions: { [SIG_EXTENSION]: { v: "0.1", alg: "none", kid, sig } },
    }),
    { valid: false, reason: "unsupported algorithm" },
  );
  assert.deepEqual(
    await verifySignedEnvelope({
      ...unsigned,
      extensions: { [SIG_EXTENSION]: { v: "0.1", alg: "EdDSA", kid, sig: "!!!" } },
    }),
    { valid: false, reason: "malformed signature" },
  );
  assert.equal(
    (await verifySignedEnvelope({
      ...unsigned,
      extensions: { [SIG_EXTENSION]: { v: "0.1", alg: "EdDSA", kid: "not-a-kid", sig } },
    })).reason,
    "sender binding",
  );
});

test("deterministic seed derives the pinned public key and key-id via WebCrypto", async () => {
  const seed = hexBytes(SEED_HEX);
  const key = await ed25519PrivateKeyFromSeed(seed);
  // WebCrypto cannot derive a public key from an Ed25519 private key directly,
  // but a JWK export carries the public `x` coordinate.
  const jwkKey = await crypto.subtle.importKey(
    "pkcs8",
    Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    "Ed25519",
    true,
    ["sign"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", jwkKey);
  const publicKey = base64UrlToBytes(jwk.x);
  assert.equal(toHex(publicKey), EXPECTED_PUBLIC_KEY_HEX);

  const kid = encodeKeyId(publicKey);
  assert.equal(kid, EXPECTED_KEY_ID);
  assert.deepEqual(Array.from(decodeKeyId(kid)), Array.from(publicKey));
  assert.equal(entityUrn(kid), positive.envelope.sender);
  assert.equal(deviceUrn(kid), "urn:xeip:device:" + kid);

  // The CryptoKey signs the same bytes as the raw seed.
  const payload = new TextEncoder().encode("deterministic");
  const fromCryptoKey = new Uint8Array(await crypto.subtle.sign("Ed25519", key, payload));
  const fromRawKey = await ed25519PrivateKeyFromSeed(seed);
  const again = new Uint8Array(await crypto.subtle.sign("Ed25519", fromRawKey, payload));
  assert.deepEqual(Array.from(fromCryptoKey), Array.from(again));
});

test("signEnvelope reproduces the committed signature byte-for-byte and round-trips", async () => {
  const seed = hexBytes(SEED_HEX);
  const kid = EXPECTED_KEY_ID;

  // A raw 32-byte seed is accepted in place of a CryptoKey.
  const signed = await signEnvelope(unsignedEnvelope(), { privateKey: seed, kid });
  const carrier = signed.extensions[SIG_EXTENSION];
  assert.equal(carrier.v, SIG_VERSION);
  assert.equal(carrier.alg, SIG_ALG);
  assert.equal(carrier.kid, kid);
  // Ed25519 is deterministic: the signature must equal the committed vector.
  assert.equal(carrier.sig, positiveSignature);
  assert.deepEqual(await verifySignedEnvelope(signed), { valid: true });
  assert.deepEqual(await verifySignedEnvelope(JSON.stringify(signed)), { valid: true });

  // A CryptoKey and an ArrayBuffer seed also sign identically.
  const cryptoKey = await ed25519PrivateKeyFromSeed(seed);
  const fromCryptoKey = await signEnvelope(unsignedEnvelope(), { privateKey: cryptoKey, kid });
  assert.equal(fromCryptoKey.extensions[SIG_EXTENSION].sig, positiveSignature);

  const arrayBufferSeed = seed.buffer.slice(seed.byteOffset, seed.byteOffset + seed.byteLength);
  const fromArrayBuffer = await signEnvelope(unsignedEnvelope(), {
    privateKey: arrayBufferSeed,
    kid,
  });
  assert.equal(fromArrayBuffer.extensions[SIG_EXTENSION].sig, positiveSignature);
});

test("signEnvelope preserves unrelated extensions but never signs them", async () => {
  const envelope = unsignedEnvelope();
  envelope.extensions = { "x.note": "kept" };
  const signed = await signEnvelope(envelope, { privateKey: hexBytes(SEED_HEX), kid: EXPECTED_KEY_ID });
  assert.equal(signed.extensions["x.note"], "kept");
  assert.equal(signed.extensions[SIG_EXTENSION].sig, positiveSignature);
  assert.deepEqual(await verifySignedEnvelope(signed), { valid: true });
});

test("a tampered body under a valid signature is rejected", async () => {
  const signed = await signEnvelope(unsignedEnvelope(), {
    privateKey: hexBytes(SEED_HEX),
    kid: EXPECTED_KEY_ID,
  });
  signed.body.data.text = "tampered";
  assert.deepEqual(await verifySignedEnvelope(signed), {
    valid: false,
    reason: "signature mismatch",
  });
});

test("canonicalize matches RFC 8785 and the reference vectors", () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ z: 1, a: 2, A: 3 }), '{"A":3,"a":2,"z":1}');
  assert.equal(canonicalize({ a: -0 }), '{"a":0}');
  assert.equal(canonicalize({ a: 1e21 }), '{"a":1e+21}');
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
  assert.throws(() => canonicalize({ a: Infinity }), TypeError);
  assert.throws(() => canonicalize("\ud800"), SyntaxError);
});

test("base64url helpers are canonical and unpadded", () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  assert.equal(bytesToBase64Url(bytes), "AAEC_f7_");
  assert.deepEqual(Array.from(base64UrlToBytes("AAEC_f7_")), Array.from(bytes));
  assert.equal(base64UrlToBytes("AAEC_f7_="), null);
  assert.equal(base64UrlToBytes("A"), null);
  assert.equal(base64UrlToBytes("not base64!"), null);
  assert.equal(base64UrlToBytes(""), null);
});

test("key-id encode/decode round-trips through base58btc", () => {
  const bytes = hexBytes(EXPECTED_PUBLIC_KEY_HEX);
  const kid = encodeKeyId(bytes);
  assert.equal(kid, EXPECTED_KEY_ID);
  assert.equal(base58btcEncode(decodeKeyId(kid)), base58btcEncode(bytes));
  assert.deepEqual(Array.from(base58btcDecode(base58btcEncode(bytes))), Array.from(bytes));
  assert.throws(() => encodeKeyId(new Uint8Array(31)), RangeError);
  assert.throws(() => decodeKeyId("6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"), /prefix/);
  assert.throws(() => decodeKeyId(kid + "1"), /canonical|payload|prefix/);
});

test("strictParse mirrors the reference pre-parse gate", () => {
  assert.throws(() => strictParse('{"a":1,"a":2}'), /duplicate/);
  assert.throws(() => strictParse('"\\uD800"'), /lone high surrogate/);
  assert.throws(() => strictParse("1e999"), /non-finite number/);
  assert.throws(() => strictParse("9007199254740992"), /outside the safe range/);
  assert.deepEqual({ ...strictParse('{"a":1}') }, { a: 1 });
});
