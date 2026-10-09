import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import {
  BASE58BTC_ALPHABET,
  ED25519_MULTICODEC,
  base58btcDecode,
  base58btcEncode,
  decodeKeyId,
  deviceUrn,
  encodeKeyId,
  entityUrn,
  parsePublicKey,
} from "./derive-keyid.mjs";

const utf8 = (text) => new TextEncoder().encode(text);
const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const bytesToArray = (value) => Array.from(value);

// RFC 8032 §7.1 test vector 1 public key (also used in the fixtures below).
const RFC8032_PUBLIC_KEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_KEY_ID = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

test("base58btc known-answer vectors", () => {
  // Canonical multibase/base58btc KAT: ASCII "Hello World!".
  assert.equal(base58btcEncode(utf8("Hello World!")), "2NEpo7TZRRrLZSi2U");
  // Empty input and the leading-zero (0x00-heavy) special cases.
  assert.equal(base58btcEncode(new Uint8Array(0)), "");
  assert.equal(base58btcEncode(new Uint8Array([0])), "1");
  assert.equal(base58btcEncode(new Uint8Array([0, 0])), "11");
  assert.equal(base58btcEncode(new Uint8Array([0, 0, 0])), "111");
  assert.equal(base58btcEncode(new Uint8Array([0, 0, 1])), "112");
  // A high byte and a leading-zero-plus-high-byte case.
  assert.equal(base58btcEncode(new Uint8Array([0xff])), "5Q");
  assert.equal(base58btcEncode(new Uint8Array([0, 0xff])), "15Q");
  // Every alphabet character is reachable and unambiguous.
  assert.equal(BASE58BTC_ALPHABET.length, 58);
  assert.equal(new Set(BASE58BTC_ALPHABET).size, 58);
});

test("base58btc round-trips arbitrary bytes including leading zeros", () => {
  const samples = [
    new Uint8Array(0),
    new Uint8Array([0]),
    new Uint8Array([0, 0, 0, 4]),
    new Uint8Array([0, 0, 1, 2, 3]),
    utf8("Hello World!"),
    Uint8Array.from({ length: 64 }, (_, i) => (i * 37) & 0xff),
  ];
  for (const sample of samples) {
    const encoded = base58btcEncode(sample);
    assert.deepEqual(bytesToArray(base58btcDecode(encoded)), bytesToArray(sample));
  }
  assert.throws(() => base58btcDecode("0"), /invalid base58btc character/);
  assert.throws(() => base58btcDecode("O"), /invalid base58btc character/);
});

test("key-id is multibase base58btc of the ed25519-pub multicodec", () => {
  const key = new Uint8Array(32);
  const keyId = encodeKeyId(key);
  assert.ok(keyId.startsWith("z"));
  assert.deepEqual(ED25519_MULTICODEC, [0xed, 0x01]);

  const decoded = base58btcDecode(keyId.slice(1));
  assert.equal(decoded.length, ED25519_MULTICODEC.length + key.length);
  assert.deepEqual(bytesToArray(decoded.slice(0, ED25519_MULTICODEC.length)), [0xed, 0x01]);
  assert.deepEqual(bytesToArray(decoded.slice(ED25519_MULTICODEC.length)), bytesToArray(key));

  // The multicodec prefix is type metadata, not a hash: distinct keys keep it.
  const other = base58btcDecode(encodeKeyId(Uint8Array.from({ length: 32 }, () => 1)).slice(1));
  assert.deepEqual(bytesToArray(other.slice(0, 2)), [0xed, 0x01]);
});

test("interoperates with the W3C did:key z6Mk reference example", () => {
  const referenceKeyId = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  const payload = base58btcDecode(referenceKeyId.slice(1));
  assert.deepEqual(bytesToArray(payload.slice(0, 2)), [0xed, 0x01]);
  assert.equal(encodeKeyId(payload.slice(2)), referenceKeyId);
});

test("rejects public keys that are not exactly 32 bytes", () => {
  for (const length of [0, 1, 31, 33, 64]) {
    assert.throws(() => encodeKeyId(new Uint8Array(length)), RangeError);
  }
  assert.throws(() => encodeKeyId("00"), TypeError);
});

test("encoding is deterministic and matches a stable known-answer value", () => {
  const key = hexBytes(RFC8032_PUBLIC_KEY_HEX);
  assert.equal(encodeKeyId(key), RFC8032_KEY_ID);
  assert.equal(encodeKeyId(Uint8Array.from(key)), RFC8032_KEY_ID);
  assert.equal(encodeKeyId(key), encodeKeyId(key));
});

test("entity and device URNs differ only by the entity/device segment", () => {
  const keyId = encodeKeyId(hexBytes(RFC8032_PUBLIC_KEY_HEX));
  const entity = entityUrn(keyId);
  const device = deviceUrn(keyId);

  assert.notEqual(entity, device);
  assert.equal(entity, `urn:xeip:entity:${keyId}`);
  assert.equal(device, `urn:xeip:device:${keyId}`);
  assert.equal(entity.replace("entity", "device"), device);
  assert.equal(
    entity.slice("urn:xeip:entity:".length),
    device.slice("urn:xeip:device:".length),
  );
  assert.throws(() => entityUrn(""), TypeError);
  assert.throws(() => deviceUrn(""), TypeError);
});

test("parses the same key from hex and base64url", () => {
  const key = hexBytes(RFC8032_PUBLIC_KEY_HEX);
  const fromHex = parsePublicKey(RFC8032_PUBLIC_KEY_HEX);
  const fromHexUpper = parsePublicKey(RFC8032_PUBLIC_KEY_HEX.toUpperCase());
  const fromBase64Url = parsePublicKey(Buffer.from(key).toString("base64url"));
  assert.deepEqual(bytesToArray(fromHex), bytesToArray(key));
  assert.deepEqual(bytesToArray(fromHexUpper), bytesToArray(key));
  assert.deepEqual(bytesToArray(fromBase64Url), bytesToArray(key));
  assert.throws(() => parsePublicKey("not a key!"), /hex characters or base64url/);
});

test("decodeKeyId round-trips canonical key-ids and rejects non-canonical input", () => {
  const key = hexBytes(RFC8032_PUBLIC_KEY_HEX);
  const keyId = encodeKeyId(key);
  assert.deepEqual(bytesToArray(decodeKeyId(keyId)), bytesToArray(key));

  assert.throws(() => decodeKeyId(""), TypeError);
  assert.throws(() => decodeKeyId(keyId.slice(1)), /multibase prefix 'z'/);
  assert.throws(() => decodeKeyId("z1" + keyId.slice(1)), /payload must be/);
  assert.throws(() => decodeKeyId("1" + keyId), /multibase prefix 'z'/);
  assert.throws(() => decodeKeyId(keyId + "0"), /invalid base58btc character/);
  assert.throws(() => decodeKeyId(keyId.slice(0, -2)), /payload must be/);

  const wrongPrefix =
    "z" + base58btcEncode(Uint8Array.from([0x00, 0x00, ...new Uint8Array(32)]));
  assert.throws(() => decodeKeyId(wrongPrefix), /multicodec prefix/);
});

test("entity and device URNs require a canonical key-id", () => {
  const keyId = encodeKeyId(hexBytes(RFC8032_PUBLIC_KEY_HEX));
  assert.throws(() => entityUrn("z1" + keyId.slice(1)), /payload must be/);
  assert.throws(() => deviceUrn(keyId + " "), /invalid base58btc character/);
  assert.throws(() => entityUrn("urn:xeip:entity:%61"), /multibase prefix 'z'/);
});

test("parsePublicKey rejects non-canonical encodings", () => {
  assert.throws(() => parsePublicKey(" " + RFC8032_PUBLIC_KEY_HEX), /whitespace/);
  const base64url = Buffer.from(hexBytes(RFC8032_PUBLIC_KEY_HEX)).toString("base64url");
  assert.throws(() => parsePublicKey(base64url + "="), /64 hex characters or base64url/);
  assert.throws(() => parsePublicKey("AAAAA"), /64 hex characters or base64url/);
});

test("byte coercion rejects out-of-range array values", () => {
  assert.throws(() => base58btcEncode([256]), /integers in \[0, 255\]/);
  assert.throws(() => base58btcEncode([-1]), /integers in \[0, 255\]/);
  assert.throws(() => base58btcEncode([1.5]), /integers in \[0, 255\]/);
});

test("conformance fixtures reproduce every vector", () => {
  const path = new URL(
    "../conformance/fixtures/identity-keyid/identity-keyid.vectors.json",
    import.meta.url,
  );
  const vectors = JSON.parse(readFileSync(path, "utf8"));
  assert.ok(vectors.length >= 5, "at least five vectors are required");

  const names = new Set();
  for (const vector of vectors) {
    names.add(vector.name);
    if (vector.valid === false) {
      assert.throws(() => decodeKeyId(vector.keyId), vector.name);
      continue;
    }
    const keyId = encodeKeyId(hexBytes(vector.publicKeyHex));
    assert.equal(keyId, vector.keyId, vector.name);
    assert.equal(entityUrn(keyId), vector.entityUrn, vector.name);
    assert.equal(deviceUrn(keyId), vector.deviceUrn, vector.name);
  }
  assert.equal(names.size, vectors.length, "vector names must be unique");
  assert.ok(
    vectors.some((vector) => vector.publicKeyHex === "0".repeat(64)),
    "an all-zero key vector is required",
  );
  assert.ok(
    vectors.some((vector) => vector.publicKeyHex === "f".repeat(64)),
    "an all-0xff key vector is required",
  );
});

test("CLI emits the key-id and both URNs", () => {
  const cli = new URL("./derive-keyid.mjs", import.meta.url).pathname;
  const result = spawnSync(process.execPath, [cli, RFC8032_PUBLIC_KEY_HEX], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout), {
    keyId: RFC8032_KEY_ID,
    entityUrn: `urn:xeip:entity:${RFC8032_KEY_ID}`,
    deviceUrn: `urn:xeip:device:${RFC8032_KEY_ID}`,
  });
});

test("CLI rejects missing and wrong-length input", () => {
  const cli = new URL("./derive-keyid.mjs", import.meta.url).pathname;
  const missing = spawnSync(process.execPath, [cli], { encoding: "utf8" });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /usage:/);

  const short = spawnSync(process.execPath, [cli, "aabb"], { encoding: "utf8" });
  assert.notEqual(short.status, 0);
  assert.match(short.stderr, /32 bytes/);
});
