/** TEST ONLY: authenticated Fetch transport between separate native SQLite objects. */
import { DurableObject } from "cloudflare:workers";
import { createHash, randomUUID } from "node:crypto";
import { RecoveryFixture } from "./organization-cloudflare-recovery-worker.mjs";
import { LedgerFixture } from "./organization-cloudflare-worker.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
import { createRecoveryClient } from "../services/organization/cloudflare/recovery-client.mjs";
import { RecoveryJournal } from "../services/organization/cloudflare/recovery-journal.mjs";
import { createRecoveryHandler } from "../services/organization/cloudflare/recovery-http.mjs";
const endpoint = "https://journal.example/v1/recovery",
  token = "a1".repeat(32);
export class RecoveryHttpJournalFixture extends RecoveryFixture {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      // TEST ONLY synthetic settings. A deployed host must obtain credentials
      // from its own secret custody, not from journal data.
      const configuration = await ctx.storage.get("fixture-http-configuration");
      if (configuration) {
        this.journal = await RecoveryJournal.open(
          this.storage,
          configuration.options,
        );
        this.handler = createRecoveryHandler({
          ...configuration,
          journal: this.journal,
        });
      }
    });
  }
  async fetch(request) {
    if (request.url === endpoint)
      return this.handler
        ? this.handler(request, this.ctx)
        : new Response(null, { status: 503 });
    const input = await request.clone().json();
    if (input.operation === "forwardHttp") {
      // Node's Miniflare proxy rewrites Host. Reconstruct the original Fetch
      // request inside this TEST ONLY bridge; production checks remain intact.
      const response = await this.handler(
        new Request(input.request.url, input.request),
      );
      return Response.json({
        status: response.status,
        headers: [...response.headers],
        body: await response.text(),
      });
    }
    if (input.operation === "configureHttp") {
      const configuration = {
        url: endpoint,
        token: input.token ?? token,
        options: input.options,
      };
      const handler = createRecoveryHandler({
        ...configuration,
        journal: this.journal,
      });
      await this.ctx.storage.put("fixture-http-configuration", configuration);
      await this.ctx.storage.sync();
      this.handler = handler;
      return Response.json({ ok: true });
    }
    return super.fetch(request);
  }
}
function clientFor(f, input) {
  const stub = f.env.JOURNAL.get(f.env.JOURNAL.idFromName(input.name));
  return createRecoveryClient(
    { url: endpoint, token: input.token ?? token, options: input.options },
    async (url, init) => {
      const response = await stub.fetch(url, init);
      if (f.lostReceipt && JSON.parse(init.body).operation === "append") {
        void response.body?.cancel();
        throw Error("lost receipt");
      }
      return response;
    },
  );
}
export class RecoveryHttpClientFixture extends DurableObject {
  async fetch(request) {
    const input = await request.json();
    try {
      if (input.operation === "configure") {
        this.client = clientFor(this, input);
        return Response.json({ ok: true });
      }
      if (input.operation === "lostReceipt") {
        this.lostReceipt = input.value;
        return Response.json({ ok: true });
      }
      if (input.operation === "head")
        return Response.json(await this.client.head());
      if (input.operation === "entry")
        return Response.json(await this.client.entry(input.sequence));
      if (input.operation === "part")
        return Response.json(
          await this.client.part(input.sequence, input.part),
        );
      if (input.operation === "append") {
        const bytes = input.bytes ?? 1,
          data = Buffer.alloc(bytes, 97),
          chunks = [];
        for (let i = 0; i < bytes; i += 262144)
          chunks.push(data.subarray(i, i + 262144).toString("base64"));
        return Response.json(
          await this.client.append({
            expected: input.expected ?? (await this.client.head()),
            id: input.id ?? randomUUID(),
            bytes,
            payloadDigest: createHash("sha256").update(data).digest("hex"),
            chunks,
          }),
        );
      }
      return new Response(null, { status: 404 });
    } catch (error) {
      return Response.json({ error: error.name }, { status: 503 });
    }
  }
}
export class RecoveryHttpActionFixture extends LedgerFixture {
  openStore() {}
  async fetch(request) {
    const input = await request.clone().json();
    try {
      if (input.operation === "configure") {
        this.store?.close();
        this.store = await DurableActionStore.open(
          this.storage,
          this.authority,
          {
            organization: "fixture-organization",
            recovery: {
              options: input.options,
              client: clientFor(this, input),
              initialize: input.initialize === true,
            },
          },
        );
        return Response.json({ healthy: this.store.healthy() });
      }
      if (input.operation === "lostReceipt") {
        this.lostReceipt = input.value;
        return Response.json({ ok: true });
      }
      return super.fetch(request);
    } catch (error) {
      return Response.json({ error: error.name }, { status: 503 });
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
};
