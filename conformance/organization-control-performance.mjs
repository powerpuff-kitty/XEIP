// Local actual-PG responsiveness evidence, not a hosted latency acceptance test.
import assert from "node:assert/strict";
import { createHash, createPublicKey } from "node:crypto";
import { withPostgres } from "./postgres.mjs";
import { ControlStore } from "../services/organization/control-store.mjs";
import { publicAuthority } from "../services/organization/control-state.mjs";
import { configuration } from "../services/organization/test-fixtures/control.mjs";
import { encodeKeyId } from "../packages/identity/key-id.mjs";
import { ed25519PrivateKeyFromSeed } from "../packages/identity/signed-envelope.mjs";
import { signKeyDocument } from "../packages/identity/key-document.mjs";
import { signStatusDocument } from "../packages/identity/identity-status.mjs";
const keyDocuments = [],
  statusDocuments = [];
const issuedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
for (let i = 0; i < 700; i++) {
  const seed = createHash("sha256")
    .update("xeip synthetic refresh probe " + i)
    .digest();
  const kid = encodeKeyId(
    createPublicKey(ed25519PrivateKeyFromSeed(seed))
      .export({ format: "der", type: "spki" })
      .subarray(-32),
  );
  const entity = "urn:xeip:entity:" + kid;
  keyDocuments.push({
    document: signKeyDocument(
      {
        xeip: "xeip.keydoc/0.1",
        entity,
        genesis: kid,
        generation: 1,
        issuedAt,
        roots: [kid],
        devices: [],
        signatures: [],
      },
      { privateKey: seed, kid },
    ),
    anchor: { genesisKid: kid },
  });
  statusDocuments.push({
    document: signStatusDocument(
      {
        xeip: "xeip.status/0.1",
        entity,
        serial: 1,
        issuedAt,
        revoked: [],
        signatures: [],
      },
      { privateKey: seed, kid },
    ),
  });
}

const config = configuration();
config.trust.maxAgeSeconds = 86400;
const input = {
  authority: publicAuthority(config),
  provisioning: { keyDocuments, statusDocuments },
  acceptedAt: Math.floor(Date.now() / 1000),
};
await withPostgres(
  async ({ pool }) => {
    const store = new ControlStore(pool);
    const initial = await store.enroll({ ...input, retainedRecords: {} });
    for (const operation of ["open", "publishTrust"]) {
      let ticks = 0,
        maxGapMs = 0,
        last = performance.now();
      const timer = setInterval(() => {
        const now = performance.now();
        ticks++;
        maxGapMs = Math.max(maxGapMs, now - last);
        last = now;
      }, 10);
      const started = performance.now();
      try {
        const result =
          operation === "open"
            ? await store.open(input)
            : await store.publishTrust(initial, input);
        maxGapMs = Math.max(maxGapMs, performance.now() - last);
        assert.ok(
          ticks > 0,
          "actual store must keep timers responsive during signed validation",
        );
        console.log(
          JSON.stringify({
            operation,
            result: "pass",
            entities: keyDocuments.length,
            canonicalBytes: Buffer.byteLength(result.snapshot.canonical),
            elapsedMs: performance.now() - started,
            ticks,
            maxMainThreadGapMs: maxGapMs,
            scope:
              "local actual PostgreSQL control validation; no hosted SLO or maximum-input acceptance",
          }),
        );
      } finally {
        clearInterval(timer);
      }
    }
  },
  { baselineChecks: false },
);
