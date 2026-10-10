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
  STATUS_REASONS,
  STATUS_VERSION,
  StatusTracker,
  statusSigningInput,
  signStatusDocument,
  verifyStatusDocument,
} from "./identity-status.mjs";

const hexBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));

const SEED_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PUBLIC_A_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";

const VECTORS_URL = new URL(
  "../conformance/fixtures/identity-status/status.vectors.json",
  import.meta.url,
);
const file = JSON.parse(readFileSync(VECTORS_URL, "utf8"));

const trusted = () => file.trusted["keydoc.entity"];
const status = (name) => {
  const document = file.statuses[name];
  assert.ok(document, `missing status ${name}`);
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

test("signing input is the document with signatures removed", () => {
  const document = status("status.revoke.1");
  const unsigned = structuredClone(document);
  delete unsigned.signatures;
  assert.equal(statusSigningInput(document), statusSigningInput(unsigned));
  assert.ok(!statusSigningInput(document).includes("signatures"));
});

test("signing reproduces the committed status vector byte for byte", () => {
  const expected = status("status.revoke.1");
  const unsigned = structuredClone(expected);
  delete unsigned.signatures;
  const signed = signStatusDocument(unsigned, { privateKey: hexBytes(SEED_A), kid: kidA });
  assert.deepEqual(signed, expected);
  assert.deepEqual(verifyStatusDocument(signed, trusted()), { valid: true });
});

test("every tracker step yields its documented result", () => {
  assert.ok(file.trackers.length >= 6, "at least six trackers are required");

  const names = new Set();
  const reasons = new Set();
  let validSteps = 0;
  let sawRevoked = false;

  for (const tracker of file.trackers) {
    assert.ok(!names.has(tracker.name), `duplicate tracker name: ${tracker.name}`);
    names.add(tracker.name);
    const trustedDocument = trusted();
    const instance = new StatusTracker();
    for (const step of tracker.steps) {
      assert.ok(
        (step.status === undefined) !== (step.text === undefined),
        `${tracker.name}/${step.name}: exactly one of status/text is required`,
      );
      const input = step.text !== undefined ? step.text : status(step.status);
      const result = instance.ingest(input, {
        trustedKeyDocument: trustedDocument,
        now: tracker.now,
        maxAgeSeconds: tracker.maxAgeSeconds,
      });
      if (step.valid === true) {
        assert.deepEqual(result, { valid: true }, `${tracker.name}/${step.name}`);
        for (const check of step.revoked ?? []) {
          assert.equal(
            instance.isRevoked(trustedDocument.entity, check.kid, check.generation),
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
    assert.ok(reasons.has(reason), `a negative vector with reason ${reason} is required`);
  }
});

test("verifyStatusDocument reports stable single-document reasons", () => {
  assert.deepEqual(verifyStatusDocument(status("status.revoke.1"), trusted()), { valid: true });
  assert.deepEqual(verifyStatusDocument(null, trusted()), {
    valid: false,
    reason: "malformed document",
  });
  assert.deepEqual(verifyStatusDocument("{ not json", trusted()), {
    valid: false,
    reason: "malformed document",
  });

  const valid = status("status.revoke.1");
  assert.equal(verifyStatusDocument({ ...valid, serial: "1" }, trusted()).reason, "malformed document");
  assert.equal(verifyStatusDocument({ ...valid, serial: -1 }, trusted()).reason, "malformed document");
  assert.equal(
    verifyStatusDocument({ ...valid, issuedAt: "2026-10-10T00:00:00+00:00" }, trusted()).reason,
    "malformed document",
  );
  assert.equal(
    verifyStatusDocument({ ...valid, revoked: [{ kid: kidA, generation: 0 }] }, trusted()).reason,
    "malformed document",
  );
  assert.equal(
    verifyStatusDocument({ ...valid, revoked: [{ kid: "not-a-kid", generation: 1 }] }, trusted()).reason,
    "malformed document",
  );
  assert.equal(verifyStatusDocument({ ...valid, extra: 1 }, trusted()).reason, "unknown field");
  assert.equal(
    verifyStatusDocument({ ...valid, xeip: STATUS_VERSION.toUpperCase() }, trusted()).reason,
    "unsupported version",
  );
  assert.equal(
    verifyStatusDocument(status("status.entity-mismatch"), trusted()).reason,
    "entity binding",
  );
  assert.equal(verifyStatusDocument(status("status.nonroot"), trusted()).reason, "unknown signer");
  assert.equal(verifyStatusDocument(status("status.empty-sigs"), trusted()).reason, "unknown signer");
  assert.equal(verifyStatusDocument(status("status.weak"), trusted()).reason, "weak key");
  assert.equal(verifyStatusDocument(status("status.tampered"), trusted()).reason, "signature mismatch");
});

test("isRevoked applies an entry to its generation and later", () => {
  const instance = new StatusTracker();
  const entity = trusted().entity;
  const deviceKid = status("status.revoke.1").revoked[0].kid;
  assert.deepEqual(
    instance.ingest(status("status.revoke.1"), {
      trustedKeyDocument: trusted(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: true },
  );
  assert.ok(instance.isRevoked(entity, deviceKid, 1));
  assert.ok(instance.isRevoked(entity, deviceKid, 5));
  assert.ok(!instance.isRevoked(entity, deviceKid, 0));
  assert.ok(!instance.isRevoked(entity, kidA, 1));
  // An entity with no accepted status is reported as not revoked (unknown).
  assert.ok(!instance.isRevoked("urn:xeip:entity:unknown", kidA, 1));
  assert.equal(instance.acceptedSerial(entity), 1);
  assert.ok(instance.hasStatus(entity));
});

test("StatusTracker commits state only on a fully valid candidate", () => {
  const entity = trusted().entity;
  const instance = new StatusTracker();

  // Stale is rejected on a fresh tracker and records nothing.
  assert.deepEqual(
    instance.ingest(status("status.stale"), {
      trustedKeyDocument: trusted(),
      now: "2026-10-12T00:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: false, reason: "stale status" },
  );
  assert.ok(!instance.hasStatus(entity));

  assert.deepEqual(
    instance.ingest(status("status.revoke.1"), {
      trustedKeyDocument: trusted(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: true },
  );
  assert.equal(instance.acceptedSerial(entity), 1);

  // An older or equal serial is a rollback, even if distinct.
  assert.deepEqual(
    instance.ingest(status("status.clean.1"), {
      trustedKeyDocument: trusted(),
      now: "2026-10-10T12:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: false, reason: "serial rollback" },
  );
  assert.equal(instance.acceptedSerial(entity), 1);

  // A newer serial is accepted and replaces the accepted status.
  assert.deepEqual(
    instance.ingest(status("status.revoke.2"), {
      trustedKeyDocument: trusted(),
      now: "2026-10-12T00:00:00Z",
      maxAgeSeconds: 604800,
    }),
    { valid: true },
  );
  assert.equal(instance.acceptedSerial(entity), 2);
});

test("StatusTracker validates maxAgeSeconds and tracks entities independently", () => {
  const instance = new StatusTracker();
  assert.throws(
    () =>
      instance.ingest(status("status.revoke.1"), {
        trustedKeyDocument: trusted(),
        now: "2026-10-10T12:00:00Z",
        maxAgeSeconds: -1,
      }),
    TypeError,
  );
  assert.equal(
    instance.ingest(status("status.revoke.1"), {
      trustedKeyDocument: trusted(),
      now: "2026-10-10T12:00:00Z",
    }).valid,
    true,
  );
  assert.equal(instance.acceptedSerial(trusted().entity), 1);
});

test("CLI verify reports the structured result and exits by validity", () => {
  const cli = new URL("./identity-status.mjs", import.meta.url).pathname;
  const directory = mkdtempSync(join(tmpdir(), "xeip-status-"));
  const statusPath = join(directory, "status.json");
  const trustedPath = join(directory, "trusted.json");
  writeFileSync(statusPath, JSON.stringify(status("status.revoke.1")));
  writeFileSync(trustedPath, JSON.stringify(trusted()));

  const good = spawnSync(process.execPath, [cli, "verify", statusPath, trustedPath], {
    encoding: "utf8",
  });
  assert.equal(good.status, 0);
  assert.deepEqual(JSON.parse(good.stdout), { valid: true });

  writeFileSync(statusPath, JSON.stringify(status("status.tampered")));
  const bad = spawnSync(process.execPath, [cli, "verify", statusPath, trustedPath], {
    encoding: "utf8",
  });
  assert.notEqual(bad.status, 0);
  assert.deepEqual(JSON.parse(bad.stdout), { valid: false, reason: "signature mismatch" });

  const missing = spawnSync(process.execPath, [cli, "verify"], { encoding: "utf8" });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /usage:/);
});

test("STATUS_REASONS exposes the stable cross-language strings", () => {
  assert.equal(STATUS_REASONS.SERIAL_ROLLBACK, "serial rollback");
  assert.equal(STATUS_REASONS.STALE, "stale status");
});
