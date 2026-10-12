import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  signEntityEnvelope,
  verifyEntityEnvelope,
  entityEnvelopeSigningInput,
} from "../packages/identity/entity-envelope.mjs";
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
for (const vector of fixture.vectors)
  test("entity profile: " + vector.name, () => {
    assert.deepEqual(
      verifyEntityEnvelope(vector.envelope, vector.options),
      vector.valid ? { valid: true } : { valid: false, reason: vector.reason },
    );
  });
test("entity profile reproduces committed bytes and device signature", () => {
  const signed = signEntityEnvelope(fixture.envelope, {
    privateKey: Buffer.from(fixture.seed, "hex"),
    kid: fixture.kid,
    criticalExtensions: fixture.criticalExtensions,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(signed)), fixture.signed);
  assert.equal(entityEnvelopeSigningInput(signed), fixture.signingInput);
});
test("entity profile strict-parses duplicate wire keys", () => {
  assert.deepEqual(
    verifyEntityEnvelope(
      '{"sender":"a","sender":"b"}',
      fixture.vectors[0].options,
    ),
    { valid: false, reason: "malformed envelope" },
  );
});

test("signing isolates critical extensions from caller mutation", () => {
  const criticalExtensions = [...fixture.criticalExtensions];
  const signed = signEntityEnvelope(fixture.envelope, {
    privateKey: Buffer.from(fixture.seed, "hex"),
    kid: fixture.kid,
    criticalExtensions,
  });
  criticalExtensions.length = 0;
  assert.deepEqual(verifyEntityEnvelope(signed, fixture.vectors[0].options), {
    valid: true,
  });
});
