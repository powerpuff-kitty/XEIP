import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeKeyId } from "./derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed } from "./signed-envelope.mjs";
import {
  DeviceRotationTracker,
  ROTATION_REASONS,
  ROTATION_VERSION,
  rotationSigningInput,
  signDeviceRotation,
  verifyDeviceRotation,
} from "./identity-device-rotation.mjs";

const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));

const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PUBLIC_A_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

const VECTORS_URL = new URL(
  "../conformance/fixtures/identity-rotation/rotation.vectors.json",
  import.meta.url,
);
const file = JSON.parse(readFileSync(VECTORS_URL, "utf8"));

const trusted = () => file.trusted["keydoc.entity"];
const rotation = (name) => {
  const document = file.rotations[name];
  assert.ok(document, `missing rotation ${name}`);
  return document;
};
const kidA = encodeKeyId(hexBytes(PUBLIC_A_HEX));

test("seed A derives the pinned reference public key and key-id", () => {
  const raw = createPublicKey(ed25519PrivateKeyFromSeed(hexBytes(SEED_A)))
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  assert.equal(raw.toString("hex"), PUBLIC_A_HEX);
  assert.equal(kidA, "z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd");
});

test("signing input is the statement with signatures removed", () => {
  const document = rotation("rotation.valid");
  const unsigned = structuredClone(document);
  delete unsigned.signatures;
  assert.equal(rotationSigningInput(document), rotationSigningInput(unsigned));
  assert.ok(!rotationSigningInput(document).includes("signatures"));
});

test("signing reproduces the committed rotation vector byte for byte", () => {
  const expected = rotation("rotation.valid");
  const unsigned = structuredClone(expected);
  delete unsigned.signatures;
  const signed = signDeviceRotation(unsigned, { privateKey: hexBytes(SEED_A), kid: kidA });
  assert.deepEqual(signed, expected);
  assert.deepEqual(verifyDeviceRotation(signed, trusted()), { valid: true });
});

test("every tracker step yields its documented result", () => {
  assert.ok(file.trackers.length >= 6, "at least six trackers are required");

  const names = new Set();
  const reasons = new Set();
  let validSteps = 0;

  for (const tracker of file.trackers) {
    assert.ok(!names.has(tracker.name), `duplicate tracker name: ${tracker.name}`);
    names.add(tracker.name);
    const trustedDocument = trusted();
    const instance = new DeviceRotationTracker();
    for (const step of tracker.steps) {
      if (step.kind === "ingest") {
        assert.ok(
          (step.rotation === undefined) !== (step.text === undefined),
          `${tracker.name}/${step.name}: exactly one of rotation/text is required`,
        );
        const input = step.text !== undefined ? step.text : rotation(step.rotation);
        const result = instance.ingest(input, {
          trustedKeyDocument: trustedDocument,
          maxOverlapSeconds: tracker.maxOverlapSeconds,
        });
        if (step.valid === true) {
          assert.deepEqual(result, { valid: true }, `${tracker.name}/${step.name}`);
          validSteps += 1;
        } else {
          assert.equal(result.valid, false, `${tracker.name}/${step.name}`);
          assert.equal(result.reason, step.reason, `${tracker.name}/${step.name}`);
          reasons.add(result.reason);
        }
      } else {
        assert.equal(step.kind, "active", `${tracker.name}/${step.name}: unknown step kind`);
        const result = instance.isActive(trustedDocument.entity, step.kid, step.now);
        if (step.active === true) {
          assert.deepEqual(result, { active: true }, `${tracker.name}/${step.name}`);
        } else {
          assert.equal(result.active, false, `${tracker.name}/${step.name}`);
          assert.equal(result.reason, step.reason, `${tracker.name}/${step.name}`);
          reasons.add(result.reason);
        }
      }
    }
  }

  assert.ok(validSteps >= 2, "the valid trackers must accept their rotations");
  for (const reason of [
    "rotation conflict",
    "overlap too long",
    "expired predecessor",
    "unknown device",
    "unknown signer",
    "weak key",
    "signature mismatch",
    "entity binding",
    "unknown field",
    "unsupported version",
    "malformed document",
  ]) {
    assert.ok(reasons.has(reason), `a negative vector with reason ${reason} is required`);
  }
});

test("verifyDeviceRotation reports stable single-document reasons", () => {
  assert.deepEqual(verifyDeviceRotation(rotation("rotation.valid"), trusted()), { valid: true });
  assert.deepEqual(verifyDeviceRotation(null, trusted()), {
    valid: false,
    reason: "malformed document",
  });
  assert.deepEqual(verifyDeviceRotation("{ not json", trusted()), {
    valid: false,
    reason: "malformed document",
  });

  const valid = rotation("rotation.valid");
  assert.equal(
    verifyDeviceRotation({ ...valid, issuedAt: "2026-10-10T00:00:00+00:00" }, trusted()).reason,
    "malformed document",
  );
  assert.equal(
    verifyDeviceRotation({ ...valid, previous_kid: "not-a-kid" }, trusted()).reason,
    "malformed document",
  );
  assert.equal(
    verifyDeviceRotation({ ...valid, successor_kid: valid.previous_kid }, trusted()).reason,
    "malformed document",
  );
  assert.equal(verifyDeviceRotation({ ...valid, extra: 1 }, trusted()).reason, "unknown field");
  assert.equal(
    verifyDeviceRotation({ ...valid, xeip: ROTATION_VERSION.toUpperCase() }, trusted()).reason,
    "unsupported version",
  );
  assert.equal(
    verifyDeviceRotation(rotation("rotation.entity-mismatch"), trusted()).reason,
    "entity binding",
  );
  assert.equal(verifyDeviceRotation(rotation("rotation.nonroot"), trusted()).reason, "unknown signer");
  assert.equal(
    verifyDeviceRotation(rotation("rotation.weak-successor"), trusted()).reason,
    "weak key",
  );
  assert.equal(
    verifyDeviceRotation(rotation("rotation.tampered"), trusted()).reason,
    "signature mismatch",
  );
});

test("isActive tracks the successor and bounded predecessor overlap", () => {
  const instance = new DeviceRotationTracker();
  const entity = trusted().entity;
  const predecessor = rotation("rotation.valid").previous_kid;
  const successor = rotation("rotation.valid").successor_kid;

  // Nothing accepted yet: every key is an unknown device.
  assert.deepEqual(instance.isActive(entity, successor, "2026-10-10T00:00:00Z"), {
    active: false,
    reason: "unknown device",
  });

  assert.deepEqual(
    instance.ingest(rotation("rotation.valid"), {
      trustedKeyDocument: trusted(),
      maxOverlapSeconds: 2592000,
    }),
    { valid: true },
  );
  // The successor is active immediately.
  assert.deepEqual(instance.isActive(entity, successor, "2026-10-10T00:00:00Z"), { active: true });
  // The predecessor is active through the end of the overlap (inclusive).
  assert.deepEqual(instance.isActive(entity, predecessor, "2026-10-10T00:00:00Z"), { active: true });
  assert.deepEqual(instance.isActive(entity, predecessor, "2026-11-09T00:00:00Z"), { active: true });
  // After the overlap it is an expired predecessor.
  assert.deepEqual(instance.isActive(entity, predecessor, "2026-11-09T00:00:01Z"), {
    active: false,
    reason: "expired predecessor",
  });
});

test("DeviceRotationTracker commits state only on a fully valid candidate", () => {
  const entity = trusted().entity;
  const instance = new DeviceRotationTracker();

  // A rejected rotation records nothing.
  assert.deepEqual(
    instance.ingest(rotation("rotation.tampered"), {
      trustedKeyDocument: trusted(),
      maxOverlapSeconds: 2592000,
    }),
    { valid: false, reason: "signature mismatch" },
  );
  assert.ok(!instance.hasRotations(entity));

  assert.deepEqual(
    instance.ingest(rotation("rotation.valid"), {
      trustedKeyDocument: trusted(),
      maxOverlapSeconds: 2592000,
    }),
    { valid: true },
  );

  // A second rotation of the same predecessor is a conflict and does not advance.
  assert.deepEqual(
    instance.ingest(rotation("rotation.second-rotation"), {
      trustedKeyDocument: trusted(),
      maxOverlapSeconds: 2592000,
    }),
    { valid: false, reason: "rotation conflict" },
  );
  assert.deepEqual(
    instance.isActive(entity, rotation("rotation.second-rotation").successor_kid, "2026-10-25T00:00:00Z"),
    { active: false, reason: "unknown device" },
  );

  // A valid extension of the current successor is accepted.
  assert.deepEqual(
    instance.ingest(rotation("rotation.extend"), {
      trustedKeyDocument: trusted(),
      maxOverlapSeconds: 2592000,
    }),
    { valid: true },
  );
});

test("DeviceRotationTracker enforces the caller-supplied maximum overlap", () => {
  const instance = new DeviceRotationTracker();
  assert.deepEqual(
    instance.ingest(rotation("rotation.valid"), {
      trustedKeyDocument: trusted(),
      maxOverlapSeconds: 86400,
    }),
    { valid: false, reason: "overlap too long" },
  );
  assert.throws(
    () =>
      instance.ingest(rotation("rotation.valid"), {
        trustedKeyDocument: trusted(),
        maxOverlapSeconds: -1,
      }),
    TypeError,
  );
  // No bound configured: the overlap is accepted.
  assert.deepEqual(
    instance.ingest(rotation("rotation.valid"), {
      trustedKeyDocument: trusted(),
    }),
    { valid: true },
  );
});

test("CLI verify reports the structured result and exits by validity", () => {
  const cli = new URL("./identity-device-rotation.mjs", import.meta.url).pathname;
  const directory = mkdtempSync(join(tmpdir(), "xeip-rotation-"));
  const rotationPath = join(directory, "rotation.json");
  const trustedPath = join(directory, "trusted.json");
  writeFileSync(rotationPath, JSON.stringify(rotation("rotation.valid")));
  writeFileSync(trustedPath, JSON.stringify(trusted()));

  const good = spawnSync(process.execPath, [cli, "verify", rotationPath, trustedPath], {
    encoding: "utf8",
  });
  assert.equal(good.status, 0);
  assert.deepEqual(JSON.parse(good.stdout), { valid: true });

  writeFileSync(rotationPath, JSON.stringify(rotation("rotation.tampered")));
  const bad = spawnSync(process.execPath, [cli, "verify", rotationPath, trustedPath], {
    encoding: "utf8",
  });
  assert.notEqual(bad.status, 0);
  assert.deepEqual(JSON.parse(bad.stdout), { valid: false, reason: "signature mismatch" });

  const missing = spawnSync(process.execPath, [cli, "verify"], { encoding: "utf8" });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /usage:/);
});

test("ROTATION_REASONS exposes the stable cross-language strings", () => {
  assert.equal(ROTATION_REASONS.ROTATION_CONFLICT, "rotation conflict");
  assert.equal(ROTATION_REASONS.OVERLAP_TOO_LONG, "overlap too long");
  assert.equal(ROTATION_REASONS.EXPIRED_PREDECESSOR, "expired predecessor");
});
