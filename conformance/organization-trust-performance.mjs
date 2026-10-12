// Local CPU/responsiveness probe, not a hosted capacity acceptance test.
import { createHash, createPublicKey } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setImmediate as yieldTurn } from "node:timers/promises";
import { EntityTrustPolicy } from "../services/relay/entity-trust.mjs";
import { encodeKeyId } from "../packages/identity/key-id.mjs";
import { ed25519PrivateKeyFromSeed } from "../packages/identity/signed-envelope.mjs";
import { signKeyDocument } from "../packages/identity/key-document.mjs";
import { signStatusDocument } from "../packages/identity/identity-status.mjs";
const mode = process.argv[2] ?? "sync";
if (!["sync", "async"].includes(mode))
  throw new Error("expected sync or async");
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
const directory = mkdtempSync(join(tmpdir(), "xeip-refresh-probe-"));
let policy;
try {
  policy = new EntityTrustPolicy(
    { trustDir: join(directory, "trust"), maxAgeSeconds: 86400 },
    keyDocuments,
    statusDocuments,
  );
  await yieldTurn();
  let ticks = 0,
    maxGapMs = 0,
    last = performance.now();
  const interval = setInterval(() => {
    const now = performance.now();
    maxGapMs = Math.max(maxGapMs, now - last);
    last = now;
    ticks++;
  }, 10);
  const cpu = process.cpuUsage(),
    start = performance.now();
  try {
    await policy[mode === "async" ? "updateAsync" : "update"]({
      keyDocuments,
      statusDocuments,
    });
    maxGapMs = Math.max(maxGapMs, performance.now() - last);
    const elapsedMs = performance.now() - start,
      usage = process.cpuUsage(cpu);
    console.log(
      JSON.stringify({
        mode,
        entities: 700,
        elapsedMs,
        cpuMs: (usage.user + usage.system) / 1000,
        ticksDuringPreparation: ticks,
        maxMainThreadGapMs: maxGapMs,
        note: "Process CPU includes worker; shared-host timings do not certify the rollout SLO.",
      }),
    );
  } finally {
    clearInterval(interval);
  }
} finally {
  policy?.close();
  rmSync(directory, { recursive: true, force: true });
}
