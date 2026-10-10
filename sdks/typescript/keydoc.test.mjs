// sdks/typescript/keydoc.test.mjs
//
// Conformance consumer for the portable TypeScript identity key lifecycle:
// signed key documents (`xeip.keydoc/0.1`), signed status documents
// (`xeip.status/0.1`), per-entity chain verification and trust-store anchor
// resolution. Imports only the built SDK (`./dist/index.js`) and the shared
// vectors under `conformance/fixtures/`, so JS/Node, Rust and TypeScript must
// agree on every positive and every documented reason string.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import {
  KEYDOC_REASONS,
  KEYDOC_VERSION,
  STATUS_REASONS,
  STATUS_VERSION,
  KeyDocumentChain,
  KeyDocumentTrust,
  StatusTracker,
  base64UrlToBytes,
  encodeKeyId,
  entityUrn,
  keyDocumentChainDigest,
  keyDocumentDigest,
  keyDocumentSigningInput,
  signKeyDocument,
  signStatusDocument,
  statusSigningInput,
  verifyKeyDocument,
  verifyStatusDocument,
} from "./dist/index.js";

const read = (relative) =>
  JSON.parse(readFileSync(new URL(relative, import.meta.url), "utf8"));

const keydocVectors = read(
  "../../conformance/fixtures/identity-keydoc/keydoc.vectors.json",
);
const chainVectors = read(
  "../../conformance/fixtures/identity-keydoc/keydoc-chain.vectors.json",
);
const trustVectors = read(
  "../../conformance/fixtures/identity-keydoc/keydoc-trust.vectors.json",
);
const statusFile = read(
  "../../conformance/fixtures/identity-status/status.vectors.json",
);
// Root-rotation retiry vectors were added after the first key-lifecycle slice;
// consume them when present so TS tracks the reference as it evolves.
const rootRotationUrl = new URL(
  "../../conformance/fixtures/identity-keydoc/keydoc-root-rotation.vectors.json",
  import.meta.url,
);
const rootRotationVectors = existsSync(rootRotationUrl)
  ? JSON.parse(readFileSync(rootRotationUrl, "utf8"))
  : null;

const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SEED_B = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const SEED_C = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const PUBLIC_A_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

const PKCS8_PREFIX = "302e020100300506032b657004220420";

// Derive a raw Ed25519 public key from a seed through WebCrypto, independently
// of the SDK, so a wrong seed conversion fails loudly.
async function publicKeyFromSeed(seed) {
  const der = Buffer.concat([Buffer.from(PKCS8_PREFIX, "hex"), seed]);
  const key = await crypto.subtle.importKey("pkcs8", der, "Ed25519", true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return base64UrlToBytes(jwk.x);
}

const kidA = encodeKeyId(await publicKeyFromSeed(hexBytes(SEED_A)));
const kidB = encodeKeyId(await publicKeyFromSeed(hexBytes(SEED_B)));
const kidC = encodeKeyId(await publicKeyFromSeed(hexBytes(SEED_C)));

const keydocByName = (name) => {
  const vector = keydocVectors.find((candidate) => candidate.name === name);
  assert.ok(vector, `missing keydoc vector ${name}`);
  return vector;
};
const statusByName = (name) => {
  const document = statusFile.statuses[name];
  assert.ok(document, `missing status ${name}`);
  return document;
};
const trustedKeydoc = () => statusFile.trusted["keydoc.entity"];

test("deterministic seeds derive the committed key-ids", () => {
  assert.equal(kidA, "z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd");
  assert.equal(
    kidA,
    keydocByName("genesis.valid").document.genesis,
  );
  assert.equal(kidB, chainVectors.documents["rotation.gen2"].roots[1]);
  assert.equal(kidA, chainVectors.documents["genesis.gen1"].genesis);
});

test("signing reproduces the committed genesis key-document byte for byte", async () => {
  const expected = keydocByName("genesis.valid").document;
  const unsigned = structuredClone(expected);
  delete unsigned.signatures;
  assert.equal(
    keyDocumentSigningInput(expected),
    keyDocumentSigningInput(unsigned),
  );
  assert.ok(!keyDocumentSigningInput(expected).includes("signatures"));

  const signed = await signKeyDocument(unsigned, {
    privateKey: hexBytes(SEED_A),
    kid: kidA,
  });
  assert.deepEqual(signed, expected);
  assert.deepEqual(await verifyKeyDocument(signed), { valid: true });
});

test("dual-signing reproduces the committed rotation and its chain link", async () => {
  const genesis = keydocByName("genesis.valid").document;
  const rotation = keydocByName("rotation.dual-signed").document;
  const unsignedRotation = structuredClone(rotation);
  delete unsignedRotation.signatures;

  const signed = await signKeyDocument(
    await signKeyDocument(unsignedRotation, { privateKey: hexBytes(SEED_A), kid: kidA }),
    { privateKey: hexBytes(SEED_B), kid: kidB },
  );
  assert.deepEqual(signed, rotation);
  assert.equal(rotation.previous, await keyDocumentDigest(genesis));
  assert.deepEqual(await verifyKeyDocument(rotation), { valid: true });

  // The chain link commits to the full signed document, not the signing input.
  assert.notEqual(await keyDocumentDigest(genesis), await keyDocumentChainDigest(genesis));
});

test("every keydoc vector yields its documented result", async () => {
  assert.equal(keydocVectors.length, 11, "eleven key-document vectors are required");
  const names = new Set();
  for (const vector of keydocVectors) {
    assert.ok(!names.has(vector.name), `duplicate vector name: ${vector.name}`);
    names.add(vector.name);
    assert.ok(
      (vector.document === undefined) !== (vector.text === undefined),
      `${vector.name}: exactly one of document/text is required`,
    );
    const input = vector.text !== undefined ? vector.text : vector.document;
    const result = await verifyKeyDocument(input);
    if (vector.valid === true) {
      assert.deepEqual(result, { valid: true }, vector.name);
    } else {
      assert.equal(result.valid, false, vector.name);
      assert.equal(result.reason, vector.reason, vector.name);
    }
  }

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
      keydocVectors.some((vector) => vector.valid === false && vector.reason === reason),
      `a negative keydoc vector with reason ${reason} is required`,
    );
  }
  assert.ok(
    keydocVectors.some(
      (vector) => vector.reason === "malformed document" && vector.text !== undefined,
    ),
    "a strict-parse text vector is required",
  );
});

test("verifyKeyDocument reports stable reasons for malformed documents", async () => {
  assert.deepEqual(await verifyKeyDocument(null), {
    valid: false,
    reason: KEYDOC_REASONS.MALFORMED,
  });
  assert.deepEqual(await verifyKeyDocument(42), {
    valid: false,
    reason: KEYDOC_REASONS.MALFORMED,
  });
  assert.deepEqual(await verifyKeyDocument({}), {
    valid: false,
    reason: KEYDOC_REASONS.MALFORMED,
  });
  assert.equal((await verifyKeyDocument("{ not json")).reason, "malformed document");

  const genesis = keydocByName("genesis.valid").document;
  assert.equal(
    (await verifyKeyDocument({ ...genesis, generation: "1" })).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyKeyDocument({ ...genesis, generation: 0 })).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyKeyDocument({ ...genesis, issuedAt: "2026-10-10T00:00:00+00:00" })).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyKeyDocument({ ...genesis, previous: "sha256:not-hex" })).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyKeyDocument({ ...genesis, roots: ["not-a-kid"] })).reason,
    "malformed document",
  );
  assert.equal(
    (
      await verifyKeyDocument({
        ...genesis,
        devices: [
          encodeKeyId(
            hexBytes("0100000000000000000000000000000000000000000000000000000000000000"),
          ),
        ],
      })
    ).reason,
    "weak key",
  );
  assert.equal((await verifyKeyDocument({ ...genesis, extensions: {} })).reason, "unknown field");
  assert.equal(
    (await verifyKeyDocument({ ...genesis, xeip: KEYDOC_VERSION.toUpperCase() })).reason,
    "unsupported version",
  );
});

test("verification requires a valid signature from a key listed in roots", async () => {
  const unsigned = structuredClone(keydocByName("genesis.valid").document);
  delete unsigned.signatures;

  const signedByB = await signKeyDocument(unsigned, {
    privateKey: hexBytes(SEED_B),
    kid: kidB,
  });
  assert.deepEqual(await verifyKeyDocument(signedByB), {
    valid: false,
    reason: "unknown signer",
  });

  const withoutRoot = await signKeyDocument(
    { ...unsigned, roots: [kidC] },
    { privateKey: hexBytes(SEED_A), kid: kidA },
  );
  assert.deepEqual(await verifyKeyDocument(withoutRoot), {
    valid: false,
    reason: "unknown signer",
  });

  const mixed = await signKeyDocument(
    await signKeyDocument(unsigned, { privateKey: hexBytes(SEED_A), kid: kidA }),
    { privateKey: hexBytes(SEED_B), kid: kidB },
  );
  assert.deepEqual(await verifyKeyDocument(mixed), { valid: true });
});

test("entity binding ties the document to the genesis key", async () => {
  const unsigned = structuredClone(keydocByName("genesis.valid").document);
  delete unsigned.signatures;
  const moved = await signKeyDocument(
    { ...unsigned, entity: entityUrn(kidB) },
    { privateKey: hexBytes(SEED_A), kid: kidA },
  );
  assert.deepEqual(await verifyKeyDocument(moved), {
    valid: false,
    reason: "entity binding",
  });
});

test("signKeyDocument / signStatusDocument reject a malformed signer kid", async () => {
  await assert.rejects(
    signKeyDocument({}, { privateKey: hexBytes(SEED_A), kid: "not-a-kid" }),
  );
  await assert.rejects(
    signStatusDocument({}, { privateKey: hexBytes(SEED_A), kid: "not-a-kid" }),
  );
});

// ---------------------------------------------------------------------------
// KeyDocumentChain
// ---------------------------------------------------------------------------

test("every chain vector yields its documented per-step result", async () => {
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
      const result = await verifier.ingest(chainVectors.documents[step.document]);
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

test("the chain commits to the signed predecessor", async () => {
  const genesis = chainVectors.documents["genesis.gen1"];
  const rotation = chainVectors.documents["rotation.gen2"];
  assert.equal(rotation.previous, await keyDocumentChainDigest(genesis));
  const verifier = new KeyDocumentChain();
  assert.deepEqual(await verifier.ingest(genesis), { valid: true });
  assert.deepEqual(await verifier.ingest(rotation), { valid: true });
});

test("KeyDocumentChain.clone leaves the committed chain independent", async () => {
  const chain = new KeyDocumentChain();
  const copy = chain.clone();
  assert.deepEqual(await copy.ingest(chainVectors.documents["genesis.gen1"]), {
    valid: true,
  });
  assert.deepEqual(await chain.ingest(chainVectors.documents["rotation.gen2"]), {
    valid: false,
    reason: "chain gap",
  });
});

test("KeyDocumentChain reuses single-document verification first", async () => {
  const verifier = new KeyDocumentChain();
  const bad = keydocByName("doc.bad-signature").document;
  assert.deepEqual(await verifier.ingest(bad), {
    valid: false,
    reason: "signature mismatch",
  });
  assert.deepEqual(await verifier.ingest("{ not json"), {
    valid: false,
    reason: KEYDOC_REASONS.MALFORMED,
  });
});

test(
  "every root-rotation vector yields its documented per-step result",
  { skip: rootRotationVectors === null },
  async () => {
    assert.ok(rootRotationVectors.documents, "the root-rotation file carries a documents registry");
    assert.ok(Array.isArray(rootRotationVectors.chains), "the root-rotation file carries chains");
    assert.equal(rootRotationVectors.chains.length, 5, "five root-rotation chains are required");

    const reasons = new Set();
    let validSteps = 0;
    for (const chain of rootRotationVectors.chains) {
      const verifier = new KeyDocumentChain();
      for (const step of chain.steps) {
        assert.ok(
          Object.hasOwn(rootRotationVectors.documents, step.document),
          `${chain.name}/${step.name}: unknown document ${step.document}`,
        );
        const result = await verifier.ingest(rootRotationVectors.documents[step.document]);
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

    assert.ok(validSteps >= 2, "the valid root rotations must be accepted");
    assert.ok(
      reasons.has("root rotation not dual-signed"),
      "a retiry negative vector is required",
    );
  },
);

// ---------------------------------------------------------------------------
// KeyDocumentTrust
// ---------------------------------------------------------------------------

const trustVerifier = (vector) =>
  new KeyDocumentTrust({
    entity: vector.entity,
    anchor: vector.anchor ?? null,
    maxGeneration: vector.maxGeneration,
    tofu: vector.tofu ?? false,
  });

test("every trust vector yields its documented per-step result", async () => {
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
      const result = await verifier.ingest(trustVectors.documents[step.document]);
      if (step.valid === true) {
        assert.deepEqual(
          result,
          { valid: true, trust: step.trust },
          `${vector.name}/${step.name}`,
        );
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

test("a wrong anchor rejects the chain without polluting trust state", async () => {
  const genesis = trustVectors.documents["genesis.gen1"];
  const rotation = trustVectors.documents["rotation.gen2"];
  const entity = genesis.entity;
  const verifier = new KeyDocumentTrust({
    entity,
    anchor: { genesisKid: rotation.roots[1] },
  });
  assert.deepEqual(await verifier.ingest(genesis), {
    valid: false,
    reason: "untrusted anchor",
  });
  const correct = new KeyDocumentTrust({ entity, anchor: { genesisKid: genesis.genesis } });
  assert.deepEqual(await correct.ingest(genesis), { valid: true, trust: "pinned" });
  assert.deepEqual(await correct.ingest(rotation), { valid: true, trust: "pinned" });
});

test("no anchor fails closed and never trusts on first use", async () => {
  const genesis = trustVectors.documents["genesis.gen1"];
  const verifier = new KeyDocumentTrust({ entity: genesis.entity });
  assert.deepEqual(await verifier.ingest(genesis), { valid: false, reason: "no anchor" });
  assert.deepEqual(await verifier.ingest(genesis), { valid: false, reason: "no anchor" });
});

test("bounded TOFU records the first-seen anchor and stays bounded", async () => {
  const genesis = trustVectors.documents["genesis.gen1"];
  const rotation = trustVectors.documents["rotation.gen2"];
  const beyond = trustVectors.documents["rotation.gen3"];
  const entity = genesis.entity;
  const verifier = new KeyDocumentTrust({ entity, maxGeneration: 2, tofu: true });
  assert.deepEqual(await verifier.ingest(genesis), { valid: true, trust: "tofu" });
  assert.deepEqual(await verifier.ingest(rotation), { valid: true, trust: "tofu" });
  assert.deepEqual(await verifier.ingest(beyond), {
    valid: false,
    reason: "generation exceeds maximum",
  });
  const fresh = new KeyDocumentTrust({ entity, tofu: true });
  assert.deepEqual(await fresh.ingest(beyond), { valid: false, reason: "chain gap" });
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

// ---------------------------------------------------------------------------
// Signed status documents
// ---------------------------------------------------------------------------

test("signing reproduces the committed status vector byte for byte", async () => {
  const expected = statusByName("status.revoke.1");
  const unsigned = structuredClone(expected);
  delete unsigned.signatures;
  assert.equal(statusSigningInput(expected), statusSigningInput(unsigned));
  assert.ok(!statusSigningInput(expected).includes("signatures"));

  const signed = await signStatusDocument(unsigned, {
    privateKey: hexBytes(SEED_A),
    kid: kidA,
  });
  assert.deepEqual(signed, expected);
  assert.deepEqual(await verifyStatusDocument(signed, trustedKeydoc()), { valid: true });
});

test("verifyStatusDocument reports stable single-document reasons", async () => {
  const trusted = trustedKeydoc();
  assert.deepEqual(await verifyStatusDocument(statusByName("status.revoke.1"), trusted), {
    valid: true,
  });
  assert.deepEqual(await verifyStatusDocument(null, trusted), {
    valid: false,
    reason: STATUS_REASONS.MALFORMED,
  });
  assert.deepEqual(await verifyStatusDocument("{ not json", trusted), {
    valid: false,
    reason: STATUS_REASONS.MALFORMED,
  });

  const valid = statusByName("status.revoke.1");
  assert.equal(
    (await verifyStatusDocument({ ...valid, serial: "1" }, trusted)).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyStatusDocument({ ...valid, serial: -1 }, trusted)).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyStatusDocument({ ...valid, issuedAt: "2026-10-10T00:00:00+00:00" }, trusted))
      .reason,
    "malformed document",
  );
  assert.equal(
    (await verifyStatusDocument({ ...valid, revoked: [{ kid: kidA, generation: 0 }] }, trusted))
      .reason,
    "malformed document",
  );
  assert.equal(
    (
      await verifyStatusDocument(
        { ...valid, revoked: [{ kid: "not-a-kid", generation: 1 }] },
        trusted,
      )
    ).reason,
    "malformed document",
  );
  assert.equal(
    (await verifyStatusDocument({ ...valid, extra: 1 }, trusted)).reason,
    "unknown field",
  );
  assert.equal(
    (await verifyStatusDocument({ ...valid, xeip: STATUS_VERSION.toUpperCase() }, trusted))
      .reason,
    "unsupported version",
  );
  assert.equal(
    (await verifyStatusDocument(statusByName("status.entity-mismatch"), trusted)).reason,
    "entity binding",
  );
  assert.equal(
    (await verifyStatusDocument(statusByName("status.nonroot"), trusted)).reason,
    "unknown signer",
  );
  assert.equal(
    (await verifyStatusDocument(statusByName("status.empty-sigs"), trusted)).reason,
    "unknown signer",
  );
  assert.equal(
    (await verifyStatusDocument(statusByName("status.weak"), trusted)).reason,
    "weak key",
  );
  assert.equal(
    (await verifyStatusDocument(statusByName("status.tampered"), trusted)).reason,
    "signature mismatch",
  );
});

test("every status tracker step yields its documented result", async () => {
  assert.ok(statusFile.trackers.length >= 6, "at least six trackers are required");

  const names = new Set();
  const reasons = new Set();
  let validSteps = 0;
  let sawRevoked = false;

  for (const tracker of statusFile.trackers) {
    assert.ok(!names.has(tracker.name), `duplicate tracker name: ${tracker.name}`);
    names.add(tracker.name);
    const trusted = trustedKeydoc();
    const instance = new StatusTracker();
    for (const step of tracker.steps) {
      assert.ok(
        (step.status === undefined) !== (step.text === undefined),
        `${tracker.name}/${step.name}: exactly one of status/text is required`,
      );
      const input = step.text !== undefined ? step.text : statusByName(step.status);
      const result = await instance.ingest(input, {
        trustedKeyDocument: trusted,
        now: tracker.now,
        maxAgeSeconds: tracker.maxAgeSeconds,
      });
      if (step.valid === true) {
        assert.deepEqual(result, { valid: true }, `${tracker.name}/${step.name}`);
        for (const check of step.revoked ?? []) {
          assert.equal(
            instance.isRevoked(trusted.entity, check.kid, check.generation),
            check.expected,
            `${tracker.name}/${step.name}: isRevoked(${check.kid}, ${check.generation})`,
          );
          sawRevoked = true;
        }
        validSteps += 1;
      } else {
        assert.equal(result.valid, false, `${tracker.name}/${step.name}`);
        assert.equal(result.reason, step.reason, `${tracker.name}/${step.name}`);
        reasons.add(result.reason);
      }
    }
  }

  assert.ok(validSteps >= 2, "the valid trackers must accept their status");
  assert.ok(sawRevoked, "a revoked-key assertion is required");
  for (const reason of [
    "serial rollback",
    "stale status",
    "unknown signer",
    "weak key",
    "signature mismatch",
    "entity binding",
    "unknown field",
    "unsupported version",
    "malformed document",
  ]) {
    assert.ok(reasons.has(reason), `a negative status vector with reason ${reason} is required`);
  }
});

test("isRevoked applies an entry to its generation and later", async () => {
  const instance = new StatusTracker();
  const entity = trustedKeydoc().entity;
  const deviceKid = statusByName("status.revoke.1").revoked[0].kid;
  assert.deepEqual(
    await instance.ingest(statusByName("status.revoke.1"), {
      trustedKeyDocument: trustedKeydoc(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: true },
  );
  assert.ok(instance.isRevoked(entity, deviceKid, 1));
  assert.ok(instance.isRevoked(entity, deviceKid, 5));
  assert.ok(!instance.isRevoked(entity, deviceKid, 0));
  assert.ok(!instance.isRevoked(entity, kidA, 1));
  assert.ok(!instance.isRevoked("urn:xeip:entity:unknown", kidA, 1));
  assert.equal(instance.acceptedSerial(entity), 1);
  assert.ok(instance.hasStatus(entity));
});

test("StatusTracker commits state only on a fully valid candidate", async () => {
  const entity = trustedKeydoc().entity;
  const instance = new StatusTracker();

  assert.deepEqual(
    await instance.ingest(statusByName("status.stale"), {
      trustedKeyDocument: trustedKeydoc(),
      now: "2026-10-12T00:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: false, reason: "stale status" },
  );
  assert.ok(!instance.hasStatus(entity));

  assert.deepEqual(
    await instance.ingest(statusByName("status.revoke.1"), {
      trustedKeyDocument: trustedKeydoc(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: true },
  );
  assert.equal(instance.acceptedSerial(entity), 1);

  assert.deepEqual(
    await instance.ingest(statusByName("status.clean.1"), {
      trustedKeyDocument: trustedKeydoc(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: false, reason: "serial rollback" },
  );
  assert.equal(instance.acceptedSerial(entity), 1);
});

test("StatusTracker validates maxAgeSeconds", async () => {
  const instance = new StatusTracker();
  await assert.rejects(
    instance.ingest(statusByName("status.revoke.1"), {
      trustedKeyDocument: trustedKeydoc(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: -1,
    }),
    TypeError,
  );
  assert.equal(
    (
      await instance.ingest(statusByName("status.revoke.1"), {
        trustedKeyDocument: trustedKeydoc(),
        now: "2026-10-10T12:00:00Z",
      })
    ).valid,
    true,
  );
});

test("STATUS_REASONS exposes the stable cross-language strings", () => {
  assert.equal(STATUS_REASONS.SERIAL_ROLLBACK, "serial rollback");
  assert.equal(STATUS_REASONS.STALE, "stale status");
});
