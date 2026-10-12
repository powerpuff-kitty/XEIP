/** TEST ONLY: private local worker controls and freshly generated signing identities. */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createPublicKey, randomUUID } from "node:crypto";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { encodeKeyId } from "../../../tools/derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed } from "../../../tools/signed-envelope.mjs";
import { signKeyDocument } from "../../../tools/key-document.mjs";
import { signStatusDocument } from "../../../tools/identity-status.mjs";
import { signEntityEnvelope } from "../../../packages/identity/entity-envelope.mjs";
export const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
export const now = () => Math.floor(Date.now() / 1000);
export function identity(subject) {
  const seed = randomBytes(32),
    kid = encodeKeyId(
      createPublicKey(ed25519PrivateKeyFromSeed(seed))
        .export({ format: "der", type: "spki" })
        .subarray(-32),
    ),
    entity = "urn:xeip:entity:" + kid;
  const document = signKeyDocument(
    {
      xeip: "xeip.keydoc/0.1",
      entity,
      genesis: kid,
      generation: 1,
      issuedAt: utc(now()),
      roots: [kid],
      devices: [],
      signatures: [],
    },
    { privateKey: seed, kid },
  );
  return {
    subject,
    entity,
    kid,
    seed,
    keyDocument: { document, anchor: { genesisKid: kid } },
    status: (serial = 1, revoked = []) => ({
      document: signStatusDocument(
        {
          xeip: "xeip.status/0.1",
          entity,
          serial,
          issuedAt: utc(now()),
          revoked,
          signatures: [],
        },
        { privateKey: seed, kid },
      ),
    }),
  };
}
export function configuration(provider, actors) {
  const { introspectionClientSecret, ...authentication } = provider.config;
  authentication.bindings = actors.map(({ subject, entity, kid }) => ({
    subject,
    entity,
    kid,
  }));
  return {
    authentication,
    policy: {
      targets: [
        {
          id: "internal",
          revision: "1",
          recipient: actors[0].entity,
          tools: ["lookup"],
        },
      ],
      sessions: [
        {
          id: "urn:test:operations",
          agents: [actors[0].subject],
          approvers: [actors[1].subject],
          targets: ["internal"],
        },
      ],
    },
  };
}
export function provisioning(actors, serial = 1, revokedSubject) {
  return {
    keyDocuments: actors.map((a) => a.keyDocument),
    statusDocuments: actors.map((a) =>
      a.status(
        serial,
        a.subject === revokedSubject ? [{ kid: a.kid, generation: 1 }] : [],
      ),
    ),
  };
}
export function command(
  actor,
  gateway,
  operation,
  id,
  digest,
  args = { value: "sample" },
) {
  id = "urn:test:" + id;
  const data =
    operation === "propose"
      ? {
          operation,
          request: {
            id,
            session: "urn:test:operations",
            target: "internal",
            tool: "lookup",
            arguments: args,
            expiresAt: now() + 120,
          },
        }
      : {
          operation,
          session: "urn:test:operations",
          id,
          ...(digest ? { digest } : {}),
        };
  return JSON.stringify(
    signEntityEnvelope(
      {
        xeip: "0.1",
        id: operation === "propose" ? id : "urn:uuid:" + randomUUID(),
        kind: "command",
        sender: actor.entity,
        recipient: gateway,
        session: "urn:test:operations",
        timestamp: utc(now()),
        expiresAt: utc(now() + 60),
        body: {
          contentType: "application/vnd.xeip.organization-action+json",
          data,
        },
      },
      { privateKey: actor.seed, kid: actor.kid },
    ),
  );
}
export async function harness() {
  const directory = await mkdtemp(join(tmpdir(), "xeip-authority-")),
    scriptPath = join(directory, "worker.mjs");
  let mf,
    sequence = 0;
  const start = async () => {
    mf = new Miniflare({
      host: "127.0.0.1",
      port: 0,
      modules: true,
      modulesRoot: directory,
      scriptPath,
      compatibilityDate: "2026-07-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: {
        AUTHORITY: { className: "AuthorityFixture", useSQLite: true },
      },
      durableObjectsPersist: join(directory, "storage"),
    });
    await mf.ready;
  };
  try {
    await build({
      entryPoints: [
        new URL(
          "../../organization-cloudflare-authority-worker.mjs",
          import.meta.url,
        ).pathname,
      ],
      outfile: scriptPath,
      bundle: true,
      format: "esm",
      platform: "neutral",
      external: ["cloudflare:workers", "node:*"],
      logLevel: "silent",
    });
    await start();
  } catch (error) {
    await mf?.dispose();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
  return {
    async fixture(name = "case-" + ++sequence) {
      const namespace = await mf.getDurableObjectNamespace("AUTHORITY"),
        stub = namespace.get(namespace.idFromName(name));
      const send = async (input) => {
        const response = await stub.fetch("https://fixture.invalid/", {
          method: "POST",
          body: JSON.stringify(input),
        });
        return { status: response.status, body: await response.json() };
      };
      return {
        name,
        send,
        sql: (query, ...bindings) =>
          send({ operation: "sql", query, bindings }),
      };
    },
    async restart() {
      await mf.dispose();
      await start();
    },
    async close() {
      await mf?.dispose();
      await rm(directory, { recursive: true, force: true });
    },
    async publicStatus() {
      return (await mf.dispatchFetch("http://localhost/")).status;
    },
  };
}
