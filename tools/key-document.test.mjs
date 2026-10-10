import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeKeyId, entityUrn } from "./derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed } from "./signed-envelope.mjs";
import {
  KEYDOC_VERSION,
  keyDocumentDigest,
  keyDocumentSigningInput,
  signKeyDocument,
  verifyKeyDocument,
} from "./key-document.mjs";

const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));

// Deterministic RFC 8032 seeds shared with the committed vectors. Seed A is the
// fixed seed from the task; its public key is pinned so a wrong conversion
// fails loudly.
const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SEED_B = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const SEED_C = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const PUBLIC_A_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

const VECTORS_URL = new URL(
  "../conformance/fixtures/identity-keydoc/keydoc.vectors.json",
  import.meta.url,
);
const vectors = JSON.parse(readFileSync(VECTORS_URL, "utf8"));

const byName = (name) => {
  const vector = vectors.find((candidate) => candidate.name === name);
  assert.ok(vector, `missing vector ${name}`);
  return vector;
};

const kidA = encodeKeyId(hexBytes(PUBLIC_A_HEX));
const kidB = encodeKeyId(
  createPublicKey(ed25519PrivateKeyFromSeed(hexBytes(SEED_B)))
    .export({ format: "der", type: "spki" })
    .subarray(-32),
);
const kidC = encodeKeyId(
  createPublicKey(ed25519PrivateKeyFromSeed(hexBytes(SEED_C)))
    .export({ format: "der", type: "spki" })
    .subarray(-32),
);

test("seed A derives the pinned reference public key and key-id", () => {
  const raw = createPublicKey(ed25519PrivateKeyFromSeed(hexBytes(SEED_A)))
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  assert.equal(raw.toString("hex"), PUBLIC_A_HEX);
  assert.equal(kidA, "z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd");
});

test("signing input is the document with signatures removed", () => {
  const document = byName("genesis.valid").document;
  const unsigned = structuredClone(document);
  delete unsigned.signatures;
  assert.equal(keyDocumentSigningInput(document), keyDocumentSigningInput(unsigned));
  assert.ok(!keyDocumentSigningInput(document).includes("signatures"));
});

test("signing reproduces the committed genesis vector byte for byte", () => {
  const expected = byName("genesis.valid").document;
  const unsigned = structuredClone(expected);
  delete unsigned.signatures;
  const signed = signKeyDocument(unsigned, { privateKey: hexBytes(SEED_A), kid: kidA });
  assert.deepEqual(signed, expected);
  assert.deepEqual(verifyKeyDocument(signed), { valid: true });
});

test("dual-signing reproduces the committed rotation vector and its previous digest", () => {
  const genesis = byName("genesis.valid").document;
  const rotation = byName("rotation.dual-signed").document;

  const unsignedRotation = structuredClone(rotation);
  delete unsignedRotation.signatures;
  const signed = signKeyDocument(
    signKeyDocument(unsignedRotation, { privateKey: hexBytes(SEED_A), kid: kidA }),
    { privateKey: hexBytes(SEED_B), kid: kidB },
  );
  assert.deepEqual(signed, rotation);

  // `previous` commits to the genesis document's canonical signing input.
  assert.equal(rotation.previous, keyDocumentDigest(genesis));
  assert.deepEqual(verifyKeyDocument(rotation), { valid: true });
});

test("every committed vector yields its documented result", () => {
  assert.ok(vectors.length >= 9, "at least nine key-document vectors are required");
  const names = new Set();
  for (const vector of vectors) {
    assert.ok(!names.has(vector.name), `duplicate vector name: ${vector.name}`);
    names.add(vector.name);
    assert.ok(
      (vector.document === undefined) !== (vector.text === undefined),
      `${vector.name}: exactly one of document/text is required`,
    );
    const input = vector.text !== undefined ? vector.text : vector.document;
    const result = verifyKeyDocument(input);
    if (vector.valid === true) {
      assert.deepEqual(result, { valid: true }, vector.name);
    } else {
      assert.equal(result.valid, false, vector.name);
      assert.equal(result.reason, vector.reason, vector.name);
    }
  }

  assert.ok(vectors.some((vector) => vector.valid === true), "a positive vector is required");
  for (const reason of [
    "signature mismatch",
    "entity binding",
    "weak key",
    "unsupported version",
    "unknown field",
    "unknown signer",
    "malformed document",
  ]) {
    assert.ok(
      vectors.some((vector) => vector.valid === false && vector.reason === reason),
      `a negative vector with reason ${reason} is required`,
    );
  }
  assert.ok(
    vectors.some((vector) => vector.reason === "malformed document" && vector.text !== undefined),
    "a strict-parse text vector is required",
  );
});

test("verifyKeyDocument reports stable reasons for malformed documents", () => {
  assert.deepEqual(verifyKeyDocument(null), { valid: false, reason: "malformed document" });
  assert.deepEqual(verifyKeyDocument(42), { valid: false, reason: "malformed document" });
  assert.deepEqual(verifyKeyDocument({}), { valid: false, reason: "malformed document" });
  assert.equal(verifyKeyDocument("{ not json").reason, "malformed document");

  const genesis = byName("genesis.valid").document;

  // Wrong type for generation.
  assert.equal(
    verifyKeyDocument({ ...genesis, generation: "1" }).reason,
    "malformed document",
  );
  // Generation below the minimum.
  assert.equal(verifyKeyDocument({ ...genesis, generation: 0 }).reason, "malformed document");
  // A non-UTC issuedAt.
  assert.equal(
    verifyKeyDocument({ ...genesis, issuedAt: "2026-10-10T00:00:00+00:00" }).reason,
    "malformed document",
  );
  // A `previous` that is not a SHA-256 hex digest.
  assert.equal(
    verifyKeyDocument({ ...genesis, previous: "sha256:not-hex" }).reason,
    "malformed document",
  );
  // A root kid that does not decode.
  assert.equal(
    verifyKeyDocument({ ...genesis, roots: ["not-a-kid"] }).reason,
    "malformed document",
  );
  // A device kid that is small-order.
  assert.equal(
    verifyKeyDocument({
      ...genesis,
      devices: [encodeKeyId(hexBytes("0100000000000000000000000000000000000000000000000000000000000000"))],
    }).reason,
    "weak key",
  );
  // An unknown member anywhere in the document.
  assert.equal(
    verifyKeyDocument({ ...genesis, extensions: {} }).reason,
    "unknown field",
  );
  assert.equal(
    verifyKeyDocument({ ...genesis, xeip: KEYDOC_VERSION.toUpperCase() }).reason,
    "unsupported version",
  );
});

test("verification requires a valid signature from a key listed in roots", () => {
  const unsigned = structuredClone(byName("genesis.valid").document);
  delete unsigned.signatures;

  // Signed by B, but B is not a root: unknown signer.
  const signedByB = signKeyDocument(unsigned, { privateKey: hexBytes(SEED_B), kid: kidB });
  assert.deepEqual(verifyKeyDocument(signedByB), {
    valid: false,
    reason: "unknown signer",
  });

  // Signed by A after A is removed from roots: unknown signer.
  const withoutRoot = signKeyDocument(
    { ...unsigned, roots: [kidC] },
    { privateKey: hexBytes(SEED_A), kid: kidA },
  );
  assert.deepEqual(verifyKeyDocument(withoutRoot), {
    valid: false,
    reason: "unknown signer",
  });

  // A valid root signature plus an ignored non-root signature still verifies.
  const mixed = signKeyDocument(
    signKeyDocument(unsigned, { privateKey: hexBytes(SEED_A), kid: kidA }),
    { privateKey: hexBytes(SEED_B), kid: kidB },
  );
  assert.deepEqual(verifyKeyDocument(mixed), { valid: true });
});

test("a device kid is accepted structurally but devices do not sign", () => {
  const unsigned = structuredClone(byName("genesis.valid").document);
  delete unsigned.signatures;
  // The device key C signs, but C is not in roots: unknown signer.
  const signedByDevice = signKeyDocument(unsigned, {
    privateKey: hexBytes(SEED_C),
    kid: kidC,
  });
  assert.deepEqual(verifyKeyDocument(signedByDevice), {
    valid: false,
    reason: "unknown signer",
  });
});

test("entity binding ties the document to the genesis key", () => {
  const unsigned = structuredClone(byName("genesis.valid").document);
  delete unsigned.signatures;
  const moved = signKeyDocument(
    { ...unsigned, entity: entityUrn(kidB) },
    { privateKey: hexBytes(SEED_A), kid: kidA },
  );
  assert.deepEqual(verifyKeyDocument(moved), {
    valid: false,
    reason: "entity binding",
  });
});

test("signKeyDocument rejects a malformed signer kid", () => {
  assert.throws(() => signKeyDocument({}, { privateKey: hexBytes(SEED_A), kid: "not-a-kid" }));
});

test("CLI verify reports the structured result and exits by validity", () => {
  const cli = new URL("./key-document.mjs", import.meta.url).pathname;
  const directory = mkdtempSync(join(tmpdir(), "xeip-keydoc-"));
  const goodPath = join(directory, "good.json");
  const badPath = join(directory, "bad.json");
  writeFileSync(goodPath, JSON.stringify(byName("genesis.valid").document));
  writeFileSync(badPath, JSON.stringify(byName("doc.bad-signature").document));

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
