import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  signEntityEnvelope,
  verifyEntityEnvelope,
  entityEnvelopeSigningInput,
} from "./dist/entity-envelope.js";
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../conformance/fixtures/entity-envelope/vectors.json",
      import.meta.url,
    ),
  ),
);
for (const vector of fixture.vectors)
  test("entity profile: " + vector.name, async () => {
    assert.deepEqual(
      await verifyEntityEnvelope(vector.envelope, vector.options),
      vector.valid ? { valid: true } : { valid: false, reason: vector.reason },
    );
  });
test("entity profile reproduces committed bytes and device signature", async () => {
  const signed = await signEntityEnvelope(fixture.envelope, {
    privateKey: Buffer.from(fixture.seed, "hex"),
    kid: fixture.kid,
    criticalExtensions: fixture.criticalExtensions,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(signed)), fixture.signed);
  assert.equal(entityEnvelopeSigningInput(signed), fixture.signingInput);
});
test("entity profile strict-parses duplicate wire keys", async () => {
  assert.deepEqual(
    await verifyEntityEnvelope(
      '{"sender":"a","sender":"b"}',
      fixture.vectors[0].options,
    ),
    { valid: false, reason: "malformed envelope" },
  );
});

test("signing snapshots metadata before asynchronous crypto", async () => {
  const criticalExtensions = [...fixture.criticalExtensions];
  const promise = signEntityEnvelope(fixture.envelope, {
    privateKey: Buffer.from(fixture.seed, "hex"),
    kid: fixture.kid,
    criticalExtensions,
  });
  criticalExtensions.length = 0;
  const signed = await promise;
  assert.deepEqual(
    signed.extensions["xeip.sig"].crit,
    fixture.criticalExtensions,
  );
  assert.deepEqual(
    await verifyEntityEnvelope(signed, fixture.vectors[0].options),
    { valid: true },
  );
});

test("verification snapshots trust before asynchronous crypto", async () => {
  const options = structuredClone(fixture.vectors[0].options);
  const promise = verifyEntityEnvelope(fixture.signed, options);
  options.keyDocuments.length = 0;
  options.statusDocument.revoked.push({ kid: fixture.kid, generation: 1 });
  assert.deepEqual(await promise, { valid: true });
});
