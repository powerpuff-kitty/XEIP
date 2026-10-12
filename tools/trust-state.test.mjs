import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  prepareEntityTrust,
  mergeTrustRecords,
  validateTrustRecords,
} from "../packages/identity/trust-state.mjs";
const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
const base = vectors.vectors[0].options;
const config = { maxAgeSeconds: 60, knownExtensions: ["app.action"] };
const documents = () => ({
  keyDocuments: base.keyDocuments.map((document) => ({
    document: structuredClone(document),
    anchor: structuredClone(base.anchor),
  })),
  statusDocuments: [{ document: structuredClone(base.statusDocument) }],
});
test("shared preparation verifies signed provisioning and isolates caller data", () => {
  const p = documents(),
    prepared = prepareEntityTrust(
      config,
      p.keyDocuments,
      p.statusDocuments,
      base.nowSeconds,
    );
  const bundle = prepared.bundles.get(vectors.envelope.sender);
  assert.ok(bundle.keys.has(vectors.kid));
  assert.equal(bundle.revoked.has(vectors.kid), false);
  assert.equal(prepared.checkpoints[vectors.envelope.sender].generation, 1);
  assert.equal(
    prepared.chainDigests[vectors.envelope.sender][1],
    prepared.checkpoints[vectors.envelope.sender].keyDigest,
  );
  p.keyDocuments[0].document.devices = [];
  p.statusDocuments[0].document.revoked.push({
    kid: vectors.kid,
    generation: 1,
  });
  assert.ok(bundle.keys.has(vectors.kid));
  assert.equal(bundle.statusDocument.revoked.length, 0);
});
test("shared preparation refuses invalid signatures, duplicate status, absent anchors and stale trust", () => {
  for (const mutate of [
    (p) => (p.statusDocuments[0].document.signatures[0].sig = "A".repeat(86)),
    (p) => p.statusDocuments.push(p.statusDocuments[0]),
    (p) => delete p.keyDocuments[0].anchor,
  ]) {
    const p = documents();
    mutate(p);
    assert.throws(() =>
      prepareEntityTrust(
        config,
        p.keyDocuments,
        p.statusDocuments,
        base.nowSeconds,
      ),
    );
  }
  const p = documents();
  assert.throws(() =>
    prepareEntityTrust(
      config,
      p.keyDocuments,
      p.statusDocuments,
      base.nowSeconds + 61,
    ),
  );
  assert.throws(() =>
    prepareEntityTrust(
      { ...config, maxAgeSeconds: 0 },
      p.keyDocuments,
      p.statusDocuments,
      base.nowSeconds,
    ),
  );
  assert.throws(() =>
    prepareEntityTrust(
      { ...config, knownExtensions: ["xeip.sig"] },
      p.keyDocuments,
      p.statusDocuments,
      base.nowSeconds,
    ),
  );
});
const entity = "urn:test:entity";
const record = {
  anchor: "a".repeat(64),
  generation: 1,
  keyDigest: "b".repeat(64),
  serial: 1,
  statusDigest: "c".repeat(64),
};
const state = (patch = {}) => ({ [entity]: { ...record, ...patch } });
test("checkpoint merge retains omitted history and isolates all input records", () => {
  const previous = state(),
    candidate = state({ serial: 2, statusDigest: "d".repeat(64) });
  const merged = mergeTrustRecords(previous, candidate);
  previous[entity].anchor = "e".repeat(64);
  candidate[entity].serial = 3;
  assert.equal(merged[entity].anchor, record.anchor);
  assert.equal(merged[entity].serial, 2);
  const retained = mergeTrustRecords(merged, {});
  merged[entity].serial = 4;
  assert.equal(retained[entity].serial, 2);
});
test("checkpoint merge rejects counter, same-counter content, anchor and historical-chain rollback", () => {
  for (const candidate of [
    state({ serial: 0 }),
    state({ keyDigest: "d".repeat(64) }),
    state({ statusDigest: "d".repeat(64) }),
    state({ anchor: "d".repeat(64) }),
    state({ generation: 2, keyDigest: "d".repeat(64) }),
  ])
    assert.throws(() => mergeTrustRecords(state(), candidate));
  const next = state({
    generation: 2,
    keyDigest: "d".repeat(64),
    serial: 2,
    statusDigest: "e".repeat(64),
  });
  assert.deepEqual(
    JSON.parse(
      JSON.stringify(
        mergeTrustRecords(state(), next, {
          [entity]: { 1: record.keyDigest, 2: "d".repeat(64) },
        }),
      ),
    ),
    next,
  );
  assert.throws(() =>
    mergeTrustRecords(state(), next, {
      [entity]: { 1: "f".repeat(64), 2: "d".repeat(64) },
    }),
  );
});
test("checkpoint records reject malformed, oversized and extra-field records", () => {
  for (const value of [
    null,
    [],
    state({ generation: 0 }),
    state({ serial: -1 }),
    state({ anchor: "x" }),
    state({ extra: true }),
    Object.fromEntries(
      Array.from({ length: 4097 }, (_, i) => ["entity" + i, { ...record }]),
    ),
  ])
    assert.throws(() => validateTrustRecords(value));
});
