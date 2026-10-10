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
  KEYDOC_REASONS,
  KEYDOC_VERSION,
  KeyDocumentChain,
  KeyDocumentTrust,
  keyDocumentChainDigest,
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

const CHAIN_VECTORS_URL = new URL(
  "../conformance/fixtures/identity-keydoc/keydoc-chain.vectors.json",
  import.meta.url,
);
const chainVectors = JSON.parse(readFileSync(CHAIN_VECTORS_URL, "utf8"));

const TRUST_VECTORS_URL = new URL(
  "../conformance/fixtures/identity-keydoc/keydoc-trust.vectors.json",
  import.meta.url,
);
const trustVectors = JSON.parse(readFileSync(TRUST_VECTORS_URL, "utf8"));

const ROOT_ROTATION_VECTORS_URL = new URL(
  "../conformance/fixtures/identity-keydoc/keydoc-root-rotation.vectors.json",
  import.meta.url,
);
const rootRotationVectors = JSON.parse(readFileSync(ROOT_ROTATION_VECTORS_URL, "utf8"));

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

test("keyDocumentChainDigest commits to the full signed document", () => {
  const genesis = byName("genesis.valid").document;
  const digest = keyDocumentChainDigest(genesis);
  assert.match(digest, /^[0-9a-f]{64}$/);
  // Unlike the signing-input digest, the chain digest includes `signatures`.
  assert.notEqual(digest, keyDocumentDigest(genesis));
  const withoutSignatures = structuredClone(genesis);
  delete withoutSignatures.signatures;
  assert.notEqual(digest, keyDocumentChainDigest(withoutSignatures));
  assert.equal(digest, keyDocumentChainDigest(structuredClone(genesis)));
});

test("every chain vector yields its documented per-step result", () => {
  assert.ok(chainVectors.documents, "the chain file carries a documents registry");
  assert.ok(Array.isArray(chainVectors.chains), "the chain file carries chains");
  assert.ok(chainVectors.chains.length >= 4, "at least four chains are required");

  const names = new Set();
  const reasons = new Set();
  let validSteps = 0;
  for (const chain of chainVectors.chains) {
    assert.ok(!names.has(chain.name), `duplicate chain name: ${chain.name}`);
    names.add(chain.name);
    const verifier = new KeyDocumentChain();
    for (const step of chain.steps) {
      assert.ok(
        Object.hasOwn(chainVectors.documents, step.document),
        `${chain.name}/${step.name}: unknown document ${step.document}`,
      );
      const document = chainVectors.documents[step.document];
      const result = verifier.ingest(document);
      if (step.valid === true) {
        assert.deepEqual(result, { valid: true }, `${chain.name}/${step.name}`);
        validSteps += 1;
      } else {
        assert.equal(result.valid, false, `${chain.name}/${step.name}`);
        assert.equal(result.reason, step.reason, `${chain.name}/${step.name}`);
        reasons.add(result.reason);
      }
    }
  }

  assert.ok(validSteps >= 3, "the valid chain must accept its genesis and rotations");
  for (const reason of ["rollback", "fork", "chain gap"]) {
    assert.ok(reasons.has(reason), `a chain vector with reason ${reason} is required`);
  }
});

test("the chain commits to the signed predecessor", () => {
  const genesis = chainVectors.documents["genesis.gen1"];
  const rotation = chainVectors.documents["rotation.gen2"];
  assert.equal(rotation.previous, keyDocumentChainDigest(genesis));
  const verifier = new KeyDocumentChain();
  assert.deepEqual(verifier.ingest(genesis), { valid: true });
  assert.deepEqual(verifier.ingest(rotation), { valid: true });
});

test("KeyDocumentChain rejects a non-genesis first document as a gap", () => {
  const rotation = chainVectors.documents["rotation.gen2"];
  const verifier = new KeyDocumentChain();
  assert.deepEqual(verifier.ingest(rotation), { valid: false, reason: "chain gap" });
});

test("KeyDocumentChain tracks per-entity state independently", () => {
  const genesisA = chainVectors.documents["genesis.gen1"];
  const rotationA = chainVectors.documents["rotation.gen2"];
  const genesisB = signKeyDocument(
    {
      xeip: KEYDOC_VERSION,
      entity: entityUrn(kidB),
      genesis: kidB,
      generation: 1,
      issuedAt: "2026-10-10T00:00:00Z",
      roots: [kidB],
      devices: [],
    },
    { privateKey: hexBytes(SEED_B), kid: kidB },
  );
  const verifier = new KeyDocumentChain();
  assert.deepEqual(verifier.ingest(genesisA), { valid: true });
  assert.deepEqual(verifier.ingest(rotationA), { valid: true });
  assert.deepEqual(verifier.ingest(genesisB), { valid: true });
  // B's genesis does not advance or reset A's chain.
  assert.deepEqual(verifier.ingest(rotationA), { valid: false, reason: "rollback" });
});

test("KeyDocumentChain reuses single-document verification first", () => {
  const verifier = new KeyDocumentChain();
  const bad = byName("doc.bad-signature").document;
  assert.deepEqual(verifier.ingest(bad), { valid: false, reason: "signature mismatch" });
  assert.deepEqual(verifier.ingest("{ not json"), {
    valid: false,
    reason: KEYDOC_REASONS.MALFORMED,
  });
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

// ---------------------------------------------------------------------------
// Root rotation: retiry authorization in the chain
// ---------------------------------------------------------------------------

test("every root-rotation vector yields its documented per-step result", () => {
  assert.ok(rootRotationVectors.documents, "the root-rotation file carries a documents registry");
  assert.ok(Array.isArray(rootRotationVectors.chains), "the root-rotation file carries chains");
  assert.ok(rootRotationVectors.chains.length >= 4, "at least four root-rotation chains are required");

  const names = new Set();
  const reasons = new Set();
  let validSteps = 0;
  for (const chain of rootRotationVectors.chains) {
    assert.ok(!names.has(chain.name), `duplicate chain name: ${chain.name}`);
    names.add(chain.name);
    const verifier = new KeyDocumentChain();
    for (const step of chain.steps) {
      assert.ok(
        Object.hasOwn(rootRotationVectors.documents, step.document),
        `${chain.name}/${step.name}: unknown document ${step.document}`,
      );
      const document = rootRotationVectors.documents[step.document];
      const result = verifier.ingest(document);
      if (step.valid === true) {
        assert.deepEqual(result, { valid: true }, `${chain.name}/${step.name}`);
        validSteps += 1;
      } else {
        assert.equal(result.valid, false, `${chain.name}/${step.name}`);
        assert.equal(result.reason, step.reason, `${chain.name}/${step.name}`);
        reasons.add(result.reason);
      }
    }
  }

  assert.ok(validSteps >= 2, "a dual-signed and a pre-endorsed rotation must be accepted");
  assert.ok(
    reasons.has("root rotation not dual-signed"),
    "a root-rotation vector with reason `root rotation not dual-signed` is required",
  );
  assert.ok(
    rootRotationVectors.chains.some(
      (chain) =>
        chain.name === "root-rotation.successor-preendorsed" &&
        chain.steps.every((step) => step.valid === true),
    ),
    "the pre-endorsed successor vector must be accepted",
  );
});

test("root-rotation dual-signed document is reproducible from the reference seeds", () => {
  const genesis = rootRotationVectors.documents["genesis.gen1"];
  const rotation = rootRotationVectors.documents["rotation.dual-signed.gen2"];
  assert.equal(rotation.previous, keyDocumentChainDigest(genesis));

  const unsigned = structuredClone(rotation);
  delete unsigned.signatures;
  const signed = signKeyDocument(
    signKeyDocument(unsigned, { privateKey: hexBytes(SEED_A), kid: kidA }),
    { privateKey: hexBytes(SEED_B), kid: kidB },
  );
  assert.deepEqual(signed, rotation);
});

test("a successor must be authorized by the predecessor's root set", () => {
  // The pre-endorsed successor root B was already listed by the predecessor, so
  // a single signature by B satisfies both the retiry and successor checks.
  const verifier = new KeyDocumentChain();
  assert.deepEqual(verifier.ingest(rootRotationVectors.documents["genesis.preendorsed.gen1"]), {
    valid: true,
  });
  assert.deepEqual(verifier.ingest(rootRotationVectors.documents["rotation.preendorsed.gen2"]), {
    valid: true,
  });

  // A rotation signed only by the new root, with no old-root signature, is
  // rejected with the new stable reason.
  const rejected = new KeyDocumentChain();
  assert.deepEqual(rejected.ingest(rootRotationVectors.documents["genesis.gen1"]), {
    valid: true,
  });
  assert.deepEqual(
    rejected.ingest(rootRotationVectors.documents["rotation.successor-only.gen2"]),
    { valid: false, reason: KEYDOC_REASONS.ROOT_ROTATION_NOT_DUAL_SIGNED },
  );
});

// ---------------------------------------------------------------------------
// KeyDocumentTrust: trust-store anchor resolution
// ---------------------------------------------------------------------------

const trustDocument = (name) => {
  const document = trustVectors.documents[name];
  assert.ok(document, `missing trust document ${name}`);
  return document;
};

const trustVerifier = (vector) =>
  new KeyDocumentTrust({
    entity: vector.entity,
    anchor: vector.anchor ?? null,
    maxGeneration: vector.maxGeneration,
    tofu: vector.tofu ?? false,
  });

test("KeyDocumentTrust.clone leaves the committed chain independent", () => {
  const chain = new KeyDocumentChain();
  const copy = chain.clone();
  assert.deepEqual(copy.ingest(chainVectors.documents["genesis.gen1"]), { valid: true });
  // The original chain never saw the genesis.
  assert.deepEqual(chain.ingest(chainVectors.documents["rotation.gen2"]), {
    valid: false,
    reason: "chain gap",
  });
});

test("every trust vector yields its documented per-step result", () => {
  assert.ok(trustVectors.documents, "the trust file carries a documents registry");
  assert.ok(Array.isArray(trustVectors.trusts), "the trust file carries trusts");
  assert.ok(trustVectors.trusts.length >= 4, "at least four trusts are required");

  const names = new Set();
  const reasons = new Set();
  const trustLevels = new Set();
  let validSteps = 0;
  for (const vector of trustVectors.trusts) {
    assert.ok(!names.has(vector.name), `duplicate trust name: ${vector.name}`);
    names.add(vector.name);
    const verifier = trustVerifier(vector);
    for (const step of vector.steps) {
      assert.ok(
        Object.hasOwn(trustVectors.documents, step.document),
        `${vector.name}/${step.name}: unknown document ${step.document}`,
      );
      const document = trustDocument(step.document);
      const result = verifier.ingest(document);
      if (step.valid === true) {
        assert.deepEqual(result, { valid: true, trust: step.trust }, `${vector.name}/${step.name}`);
        trustLevels.add(result.trust);
        validSteps += 1;
      } else {
        assert.equal(result.valid, false, `${vector.name}/${step.name}`);
        assert.equal(result.reason, step.reason, `${vector.name}/${step.name}`);
        reasons.add(result.reason);
      }
    }
  }

  assert.ok(validSteps >= 3, "the trusted chain must accept its generations");
  for (const reason of ["no anchor", "untrusted anchor", "generation exceeds maximum"]) {
    assert.ok(reasons.has(reason), `a trust vector with reason ${reason} is required`);
  }
  assert.ok(trustLevels.has("pinned"), "a pinned trust level is required");
});

test("a wrong anchor rejects the chain without polluting trust state", () => {
  const genesis = trustDocument("genesis.gen1");
  const rotation = trustDocument("rotation.gen2");
  const entity = genesis.entity;
  const kidB = rotation.roots[1];
  const verifier = new KeyDocumentTrust({ entity, anchor: { genesisKid: kidB } });
  // The foreign genesis is untrusted...
  assert.deepEqual(verifier.ingest(genesis), {
    valid: false,
    reason: "untrusted anchor",
  });
  // ...and was never recorded, so the correctly anchored genesis still starts.
  const correct = new KeyDocumentTrust({ entity, anchor: { genesisKid: genesis.genesis } });
  assert.deepEqual(correct.ingest(genesis), { valid: true, trust: "pinned" });
  assert.deepEqual(correct.ingest(rotation), { valid: true, trust: "pinned" });
});

test("no anchor fails closed and never trusts on first use", () => {
  const genesis = trustDocument("genesis.gen1");
  const verifier = new KeyDocumentTrust({ entity: genesis.entity });
  assert.deepEqual(verifier.ingest(genesis), { valid: false, reason: "no anchor" });
  assert.deepEqual(verifier.ingest(genesis), { valid: false, reason: "no anchor" });
});

test("generation beyond maxGeneration is rejected after the chain links", () => {
  const genesis = trustDocument("genesis.gen1");
  const rotation = trustDocument("rotation.gen2");
  const beyond = trustDocument("rotation.gen3");
  const entity = genesis.entity;
  const verifier = new KeyDocumentTrust({
    entity,
    anchor: { genesisKid: genesis.genesis },
    maxGeneration: 2,
  });
  assert.deepEqual(verifier.ingest(genesis), { valid: true, trust: "pinned" });
  assert.deepEqual(verifier.ingest(rotation), { valid: true, trust: "pinned" });
  assert.deepEqual(verifier.ingest(beyond), {
    valid: false,
    reason: "generation exceeds maximum",
  });
});

test("bounded TOFU records the first-seen anchor and stays bounded", () => {
  const genesis = trustDocument("genesis.gen1");
  const rotation = trustDocument("rotation.gen2");
  const beyond = trustDocument("rotation.gen3");
  const entity = genesis.entity;
  const verifier = new KeyDocumentTrust({
    entity,
    maxGeneration: 2,
    tofu: true,
  });
  // First use is recorded and explicitly marked unverified.
  assert.deepEqual(verifier.ingest(genesis), { valid: true, trust: "tofu" });
  assert.deepEqual(verifier.ingest(rotation), { valid: true, trust: "tofu" });
  // The recorded anchor is bounded by maxGeneration.
  assert.deepEqual(verifier.ingest(beyond), {
    valid: false,
    reason: "generation exceeds maximum",
  });
  // A non-genesis first document is never a TOFU anchor.
  const empty = new KeyDocumentTrust({ entity, tofu: true });
  assert.deepEqual(empty.ingest(rotation), { valid: false, reason: "chain gap" });
  const fresh = new KeyDocumentTrust({ entity, tofu: true });
  assert.deepEqual(fresh.ingest(beyond), { valid: false, reason: "chain gap" });
});

test("trust verification reuses single-document and chain reasons first", () => {
  const genesis = trustDocument("genesis.gen1");
  const verifier = new KeyDocumentTrust({
    entity: genesis.entity,
    anchor: { genesisKid: genesis.genesis },
  });
  // A malformed document reports its single-document reason, not "no anchor".
  assert.deepEqual(verifier.ingest("{ not json"), {
    valid: false,
    reason: "malformed document",
  });
  const bad = byName("doc.bad-signature").document;
  assert.deepEqual(verifier.ingest(bad), { valid: false, reason: "signature mismatch" });
  // A non-genesis first document is a chain gap, not an anchor failure.
  const noAnchor = new KeyDocumentTrust({ entity: genesis.entity });
  assert.deepEqual(noAnchor.ingest(trustDocument("rotation.gen2")), {
    valid: false,
    reason: "chain gap",
  });
});

test("KeyDocumentTrust validates its configuration", () => {
  assert.throws(() => new KeyDocumentTrust({}), TypeError);
  assert.throws(() => new KeyDocumentTrust({ entity: "e", anchor: { extra: 1 } }), TypeError);
  assert.throws(
    () => new KeyDocumentTrust({ entity: "e", anchor: { genesisKid: 7 } }),
    TypeError,
  );
  assert.throws(() => new KeyDocumentTrust({ entity: "e", maxGeneration: 0 }), TypeError);
  assert.throws(() => new KeyDocumentTrust({ entity: "e", tofu: "yes" }), TypeError);
});
