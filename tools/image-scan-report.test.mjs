import assert from "node:assert/strict";
import { test } from "node:test";
import { assessImageScan, imageScanEvidence } from "./image-scan-report.mjs";

function report(severities = []) {
  return {
    descriptor: {
      name: "grype",
      db: { status: { valid: true, built: "2026-10-11T06:30:42Z" } },
      configuration: {
        db: { "validate-by-hash-on-start": true, "validate-age": true },
      },
    },
    source: { type: "image" },
    matches: severities.map((severity) => ({ vulnerability: { severity } })),
  };
}

test("scan errors cannot become a successful empty report", () => {
  for (const status of [1, 2, 125, 137, null, undefined]) {
    assert.notEqual(assessImageScan(report(), status).exitCode, 0);
  }
});

test("High and Critical findings fail even if the scanner returns success", () => {
  for (const severity of ["High", "Critical"]) {
    assert.equal(assessImageScan(report([severity]), 0).exitCode, 2);
  }
});

test("successful lower-severity reports retain counts without claiming no findings", () => {
  assert.deepEqual(assessImageScan(report(["Medium", "Medium", "Low"]), 0), {
    exitCode: 0,
    counts: { Medium: 2, Low: 1 },
  });
  assert.deepEqual(assessImageScan(report(), 0), { exitCode: 0, counts: {} });
});

test("missing report fields, invalid databases and disabled validation fail closed", () => {
  const invalid = [null, {}, { matches: [] }];
  for (const mutate of [
    (r) => delete r.matches,
    (r) => (r.matches = {}),
    (r) => (r.descriptor.db.status.valid = false),
    (r) => delete r.descriptor.db,
    (r) => (r.descriptor.configuration.db["validate-age"] = false),
    (r) => (r.descriptor.configuration.db["validate-by-hash-on-start"] = false),
    (r) => (r.source.type = "directory"),
    (r) => (r.descriptor.name = "other"),
  ]) {
    const value = report();
    mutate(value);
    invalid.push(value);
  }
  for (const value of invalid) assert.throws(() => assessImageScan(value, 0));
});

test("unknown or malformed severity cannot bypass the gate", () => {
  for (const severity of [undefined, null, "Unknown", "high", "__proto__"]) {
    assert.throws(() => assessImageScan(report([severity]), 0));
  }
});

test("retained reports exclude image configuration, manifests, history and arbitrary source fields", () => {
  const value = report(["Medium"]);
  value.source = {
    type: "image",
    privateField: "synthetic-private-marker",
    target: {
      imageID: "sha256:" + "a".repeat(64),
      manifestDigest: "sha256:" + "b".repeat(64),
      config: "synthetic-private-marker",
      manifest: "synthetic-private-marker",
      history: "synthetic-private-marker",
      labels: { secret: "synthetic-private-marker" },
    },
  };
  const evidence = imageScanEvidence(value);
  assert.equal(
    JSON.stringify(evidence).includes("synthetic-private-marker"),
    false,
  );
  assert.deepEqual(evidence.source, {
    type: "image",
    target: {
      imageID: "sha256:" + "a".repeat(64),
      manifestDigest: "sha256:" + "b".repeat(64),
    },
  });
  assert.equal(evidence.matches.length, 1);
  assert.equal(evidence.descriptor.db.status.valid, true);
});
