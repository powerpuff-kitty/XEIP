import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeKeyId } from "./derive-keyid.mjs";
import {
  canonicalize,
  strictParse,
  signEnvelope,
  verifySignedEnvelope,
  ed25519PrivateKeyFromSeed,
  ed25519PublicKeyFromRaw,
  bytesToBase64Url,
  base64UrlToBytes,
  isWeakEd25519PublicKey,
} from "./signed-envelope.mjs";

const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));

// Standard Ed25519 keypair for seed 000102…1f. These values are independent of
// this implementation; the test pins them so a wrong key conversion fails loudly.
const SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const EXPECTED_PUBLIC_KEY_HEX =
  "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

const VECTORS_URL = new URL(
  "../conformance/fixtures/identity-signed/signed.vectors.json",
  import.meta.url,
);
const vectors = JSON.parse(readFileSync(VECTORS_URL, "utf8"));
const positive = vectors.find((vector) => vector.valid === true);
const positiveSignature = positive.envelope.extensions["xeip.sig"].sig;

const CANONICAL_VECTORS_URL = new URL(
  "../conformance/fixtures/identity-canonical/canonical.vectors.json",
  import.meta.url,
);
const canonicalVectors = JSON.parse(readFileSync(CANONICAL_VECTORS_URL, "utf8"));

// A copy of the positive envelope with the signature carrier removed; this is
// the exact object that gets signed.
function unsignedEnvelope() {
  const copy = structuredClone(positive.envelope);
  delete copy.extensions;
  return copy;
}

test("canonicalize implements RFC 8785 JSON Canonicalization", () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  // UTF-16 code-unit order: uppercase before lowercase, code points by value.
  assert.equal(canonicalize({ z: 1, a: 2, A: 3 }), '{"A":3,"a":2,"z":1}');
  assert.equal(canonicalize({ "\u00e9": 1, z: 2 }), '{"z":2,"\u00e9":1}');
  assert.equal(canonicalize({ "": 1, a: 2 }), '{"":1,"a":2}');
  // Arrays keep their order; nested objects are sorted recursively.
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
  assert.equal(canonicalize({ a: [1, { y: 1, x: 2 }] }), '{"a":[1,{"x":2,"y":1}]}');
  // No insignificant whitespace, ever.
  assert.equal(canonicalize({ a: { b: [1, 2] } }), '{"a":{"b":[1,2]}}');
});

test("canonicalize uses ECMAScript number formatting and maps -0 to 0", () => {
  assert.equal(canonicalize({ a: -0 }), '{"a":0}');
  assert.equal(canonicalize({ a: 0 }), '{"a":0}');
  assert.equal(canonicalize({ a: 100.0 }), '{"a":100}');
  assert.equal(canonicalize({ a: 1e21 }), '{"a":1e+21}');
  assert.equal(canonicalize({ a: 1e-7 }), '{"a":1e-7}');
  assert.equal(canonicalize({ a: 0.1 }), '{"a":0.1}');
  assert.equal(canonicalize({ a: 9007199254740991 }), '{"a":9007199254740991}');
});

test("canonicalize escapes strings as JSON without over-escaping", () => {
  assert.equal(canonicalize({ a: "a/b\n" }), '{"a":"a/b\\n"}');
  assert.equal(canonicalize({ a: "\u0000\u001f" }), '{"a":"\\u0000\\u001f"}');
  // U+2028/U+2029 and other non-ASCII are literal, per JCS.
  assert.equal(canonicalize({ a: "\u2028\u2029" }), '{"a":"\u2028\u2029"}');
  assert.equal(canonicalize({ a: "\u00e9" }), '{"a":"\u00e9"}');
});

test("canonicalize matches the shared RFC 8785 known-answer vectors", () => {
  assert.ok(
    canonicalVectors.length >= 20,
    "at least twenty canonicalization vectors are required",
  );
  const names = new Set();
  for (const vector of canonicalVectors) {
    assert.ok(!names.has(vector.name), `duplicate vector name: ${vector.name}`);
    names.add(vector.name);
    assert.equal(
      canonicalize(JSON.parse(vector.json)),
      vector.canonical,
      `canonicalization mismatch: ${vector.name}`,
    );
  }
});

test("canonicalize rejects values with no canonical JSON form", () => {
  assert.throws(() => canonicalize(undefined), TypeError);
  assert.throws(() => canonicalize({ a: undefined }), TypeError);
  assert.throws(() => canonicalize({ a: Infinity }), TypeError);
  assert.throws(() => canonicalize({ a: -Infinity }), TypeError);
  assert.throws(() => canonicalize({ a: NaN }), TypeError);
  assert.throws(() => canonicalize({ a: 1n }), TypeError);
  assert.throws(() => canonicalize({ a: () => {} }), TypeError);
  assert.throws(() => canonicalize({ a: Symbol("x") }), TypeError);
  assert.throws(() => canonicalize("\ud800"), SyntaxError);
});

test("strictParse rejects duplicate object member names", () => {
  assert.throws(() => strictParse('{"a":1,"a":2}'), /duplicate object member name/);
  assert.throws(() => strictParse('{"a":1,"b":2,"a":3}'), /duplicate/);
  assert.throws(() => strictParse('{"__proto__":1,"__proto__":2}'), /duplicate/);
  // Different names are fine.
  assert.deepEqual({ ...strictParse('{"a":1,"b":2}') }, { a: 1, b: 2 });
});

test("strictParse rejects lone surrogate escapes", () => {
  assert.throws(() => strictParse('"\\uD800"'), /lone high surrogate/);
  assert.throws(() => strictParse('"\\uDC00"'), /lone low surrogate/);
  assert.throws(() => strictParse('"a\\uD800b"'), /lone high surrogate/);
  assert.throws(() => strictParse('["\\uDBFF"]'), /lone high surrogate/);
  // A correctly paired surrogate is one code point.
  assert.equal(strictParse('"\\uD83D\\uDE00"'), "\u{1f600}");
  // A raw (unescaped) lone surrogate is rejected the same way.
  assert.throws(() => strictParse('"a\ud800b"'), /lone high surrogate/);
});

test("strictParse rejects non-finite numbers and unsafe integers", () => {
  assert.throws(() => strictParse("1e999"), /non-finite number/);
  assert.throws(() => strictParse("-1e999"), /non-finite number/);
  assert.throws(() => strictParse("9007199254740992"), /outside the safe range/);
  assert.throws(() => strictParse("-9007199254740992"), /outside the safe range/);
  // 2^53+1 is not representable and parses to 2^53, which is already rejected.
  assert.throws(() => strictParse("9007199254740993"), /outside the safe range/);
  assert.equal(strictParse("9007199254740991"), 9007199254740991);
  assert.equal(strictParse("-9007199254740991"), -9007199254740991);
  assert.equal(strictParse("1e15"), 1e15);
  assert.equal(strictParse("0.1"), 0.1);
  assert.equal(strictParse("-0"), -0);
});

test("strictParse rejects malformed input and never mutates prototypes", () => {
  assert.throws(() => strictParse('{"a":1}x'), /trailing content/);
  assert.throws(() => strictParse("01"), /trailing content/);
  assert.throws(() => strictParse("{"), /end of input|expected/);
  assert.throws(() => strictParse('"a\nb"'), /control character/);
  assert.throws(() => strictParse("'a'"), SyntaxError);
  assert.throws(() => strictParse(42), TypeError);
  // Objects have a null prototype, so "__proto__" is an ordinary member.
  const parsed = strictParse('{"__proto__":1}');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.deepEqual(Object.keys(parsed), ["__proto__"]);
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
});

test("ed25519 key conversion matches the standard seed/public-key pair", () => {
  const privateKey = ed25519PrivateKeyFromSeed(hexBytes(SEED_HEX));
  const raw = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  assert.equal(raw.toString("hex"), EXPECTED_PUBLIC_KEY_HEX);

  // The derived key-id is the sender/key-id used throughout the vectors.
  const kid = encodeKeyId(hexBytes(EXPECTED_PUBLIC_KEY_HEX));
  assert.equal(kid, positive.envelope.extensions["xeip.sig"].kid);
});

test("signEnvelope round-trips deterministically against the fixture", () => {
  const privateKey = ed25519PrivateKeyFromSeed(hexBytes(SEED_HEX));
  const kid = encodeKeyId(hexBytes(EXPECTED_PUBLIC_KEY_HEX));
  const signed = signEnvelope(unsignedEnvelope(), { privateKey, kid });

  assert.equal(signed.extensions["xeip.sig"].v, "0.1");
  assert.equal(signed.extensions["xeip.sig"].alg, "EdDSA");
  assert.equal(signed.extensions["xeip.sig"].kid, kid);
  // Ed25519 is deterministic: the signature must equal the committed vector.
  assert.equal(signed.extensions["xeip.sig"].sig, positiveSignature);
  assert.deepEqual(verifySignedEnvelope(signed), { valid: true });
  // The same envelope as JSON text also verifies (strict parse path).
  assert.deepEqual(verifySignedEnvelope(JSON.stringify(signed)), { valid: true });
  // A raw 32-byte seed is accepted in place of a KeyObject.
  const fromSeed = signEnvelope(unsignedEnvelope(), { privateKey: hexBytes(SEED_HEX), kid });
  assert.equal(fromSeed.extensions["xeip.sig"].sig, positiveSignature);
});

test("verifySignedEnvelope detects a modified body under a valid signature", () => {
  const privateKey = ed25519PrivateKeyFromSeed(hexBytes(SEED_HEX));
  const kid = encodeKeyId(hexBytes(EXPECTED_PUBLIC_KEY_HEX));
  const signed = signEnvelope(unsignedEnvelope(), { privateKey, kid });
  signed.body.data.text = "tampered";
  assert.deepEqual(verifySignedEnvelope(signed), { valid: false, reason: "signature mismatch" });
});

test("verifySignedEnvelope returns structured results and never throws", () => {
  assert.deepEqual(verifySignedEnvelope(null), { valid: false, reason: "malformed envelope" });
  assert.deepEqual(verifySignedEnvelope(42), { valid: false, reason: "malformed envelope" });
  assert.deepEqual(verifySignedEnvelope({}), { valid: false, reason: "missing signature" });
  assert.deepEqual(verifySignedEnvelope({ extensions: {} }), { valid: false, reason: "missing signature" });
  assert.equal(verifySignedEnvelope("{ not json").reason, "malformed envelope");
  assert.equal(verifySignedEnvelope('{"a":1,"a":2}').reason, "malformed envelope");

  const unsigned = unsignedEnvelope();
  assert.deepEqual(verifySignedEnvelope(unsigned), { valid: false, reason: "missing signature" });

  const carrier = { ...unsigned, extensions: { "xeip.sig": "nope" } };
  assert.deepEqual(verifySignedEnvelope(carrier), { valid: false, reason: "malformed signature" });

  const { kid, sig } = positive.envelope.extensions["xeip.sig"];
  const wrongAlg = { ...unsigned, extensions: { "xeip.sig": { v: "0.1", alg: "none", kid, sig } } };
  assert.deepEqual(verifySignedEnvelope(wrongAlg), { valid: false, reason: "unsupported algorithm" });

  const badSig = { ...unsigned, extensions: { "xeip.sig": { v: "0.1", alg: "EdDSA", kid, sig: "!!!" } } };
  assert.deepEqual(verifySignedEnvelope(badSig), { valid: false, reason: "malformed signature" });

  // A well-formed envelope whose claimed kid is not a canonical key-id.
  const badKid = { ...unsigned, extensions: { "xeip.sig": { v: "0.1", alg: "EdDSA", kid: "not-a-kid", sig } } };
  assert.deepEqual(verifySignedEnvelope(badKid).reason, "sender binding");
});

test("base64url helpers are canonical and unpadded", () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const text = bytesToBase64Url(bytes);
  assert.equal(text, "AAEC_f7_");
  assert.deepEqual(Array.from(base64UrlToBytes(text)), Array.from(bytes));
  assert.equal(base64UrlToBytes("AAEC_f7_="), null);
  assert.equal(base64UrlToBytes("A"), null);
  assert.equal(base64UrlToBytes("not base64!"), null);
  assert.equal(base64UrlToBytes(""), null);
});

test("ed25519PublicKeyFromRaw enforces a 32-byte key", () => {
  const key = ed25519PublicKeyFromRaw(hexBytes(EXPECTED_PUBLIC_KEY_HEX));
  assert.equal(key.asymmetricKeyType, "ed25519");
  assert.throws(() => ed25519PublicKeyFromRaw(new Uint8Array(31)), RangeError);
  assert.throws(() => ed25519PrivateKeyFromSeed(new Uint8Array(31)), RangeError);
});

test("conformance fixture: every vector yields its documented result", () => {
  assert.equal(vectors.length, 17, "one positive and sixteen negative vectors are required");
  const names = new Set();
  for (const vector of vectors) {
    names.add(vector.name);
    const input = vector.text !== undefined ? vector.text : vector.envelope;
    const result = verifySignedEnvelope(input);
    if (vector.valid === true) {
      assert.deepEqual(result, { valid: true }, vector.name);
    } else {
      assert.equal(result.valid, false, vector.name);
      assert.equal(result.reason, vector.reason, vector.name);
    }
  }
  assert.equal(names.size, vectors.length, "vector names must be unique");
  assert.ok(vectors.some((vector) => vector.valid === true), "a positive vector is required");
  assert.ok(
    vectors.some((vector) => vector.reason === "sender binding"),
    "a sender-binding vector is required",
  );
  assert.ok(
    vectors.some((vector) => vector.reason === "signature mismatch"),
    "a signature-mismatch vector is required",
  );
  assert.ok(vectors.some((vector) => vector.reason === "weak key"), "a weak-key vector is required");
  assert.ok(
    vectors.some((vector) => vector.reason === "malformed envelope" && vector.text !== undefined),
    "a strict-parse text vector is required",
  );
});

test("verifySignedEnvelope rejects weak (small-order) keys independently of the platform", () => {
  // The identity key with R = [S]B, S = 1 forges a signature valid for every
  // message under a non-strict verifier. It must be rejected as a weak key.
  const identityKid = encodeKeyId(
    hexBytes("0100000000000000000000000000000000000000000000000000000000000000"),
  );
  const forgedSig = "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const envelope = {
    ...unsignedEnvelope(),
    sender: `urn:xeip:entity:${identityKid}`,
    extensions: {
      "xeip.sig": { v: "0.1", alg: "EdDSA", kid: identityKid, sig: forgedSig },
    },
  };
  assert.deepEqual(verifySignedEnvelope(envelope), { valid: false, reason: "weak key" });
  assert.equal(isWeakEd25519PublicKey(hexBytes("0100000000000000000000000000000000000000000000000000000000000000")), true);
  assert.equal(isWeakEd25519PublicKey(hexBytes(EXPECTED_PUBLIC_KEY_HEX)), false);
});

test("verifySignedEnvelope validates the carrier version", () => {
  const { kid, sig } = positive.envelope.extensions["xeip.sig"];
  const versioned = (v) => ({
    ...unsignedEnvelope(),
    extensions: { "xeip.sig": { v, alg: "EdDSA", kid, sig } },
  });
  assert.deepEqual(verifySignedEnvelope(versioned("0.1")), { valid: true });
  assert.deepEqual(verifySignedEnvelope(versioned("0.2")), {
    valid: false,
    reason: "malformed signature",
  });
  const noVersion = unsignedEnvelope();
  noVersion.extensions = { "xeip.sig": { alg: "EdDSA", kid, sig } };
  assert.deepEqual(verifySignedEnvelope(noVersion), {
    valid: false,
    reason: "malformed signature",
  });
});

test("CLI verify reports the structured result and exits by validity", () => {
  const cli = new URL("./signed-envelope.mjs", import.meta.url).pathname;
  const directory = mkdtempSync(join(tmpdir(), "xeip-signed-"));
  const goodPath = join(directory, "good.json");
  const badPath = join(directory, "bad.json");
  writeFileSync(goodPath, JSON.stringify(positive.envelope));
  writeFileSync(badPath, JSON.stringify(vectors.find((v) => v.reason === "signature mismatch").envelope));

  const good = spawnSync(process.execPath, [cli, "verify", goodPath], { encoding: "utf8" });
  assert.equal(good.status, 0);
  assert.deepEqual(JSON.parse(good.stdout), { valid: true });

  const bad = spawnSync(process.execPath, [cli, "verify", badPath], { encoding: "utf8" });
  assert.notEqual(bad.status, 0);
  assert.deepEqual(JSON.parse(bad.stdout), { valid: false, reason: "signature mismatch" });

  const missing = spawnSync(process.execPath, [cli, "verify"], { encoding: "utf8" });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /usage:/);
});

test("CLI keygen emits a usable deterministic-format keypair", () => {
  const cli = new URL("./signed-envelope.mjs", import.meta.url).pathname;
  const generated = spawnSync(process.execPath, [cli, "keygen"], { encoding: "utf8" });
  assert.equal(generated.status, 0);
  const output = JSON.parse(generated.stdout);
  assert.match(output.seedHex, /^[0-9a-f]{64}$/);
  assert.match(output.publicKeyHex, /^[0-9a-f]{64}$/);
  assert.ok(output.keyId.startsWith("z"));
  assert.equal(output.entityUrn, `urn:xeip:entity:${output.keyId}`);

  // The emitted keypair actually signs and verifies.
  const privateKey = ed25519PrivateKeyFromSeed(hexBytes(output.seedHex));
  const raw = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  assert.equal(raw.toString("hex"), output.publicKeyHex);
  assert.equal(bytesToBase64Url(raw), bytesToBase64Url(hexBytes(output.publicKeyHex)));
  // Signing a body whose sender is the generated entity verifies...
  const bound = signEnvelope({ ...unsignedEnvelope(), sender: output.entityUrn }, { privateKey, kid: output.keyId });
  assert.deepEqual(verifySignedEnvelope(bound), { valid: true });
  // ...but the same signature over the original sender is rejected as unbound.
  const unbound = signEnvelope(unsignedEnvelope(), { privateKey, kid: output.keyId });
  assert.deepEqual(verifySignedEnvelope(unbound), { valid: false, reason: "sender binding" });

  const noCommand = spawnSync(process.execPath, [cli], { encoding: "utf8" });
  assert.notEqual(noCommand.status, 0);
  assert.match(noCommand.stderr, /usage:/);
});
