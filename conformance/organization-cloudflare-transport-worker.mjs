/** TEST ONLY: private controls. Never deploy this fixture. */
import { DurableObject } from "cloudflare:workers";
import { createWorkerHttp } from "../services/organization/cloudflare/http.mjs";
import {
  OperationError,
  OrganizationController,
} from "../services/organization/controller.mjs";
import { DurableEntityTrust } from "../services/organization/cloudflare/trust.mjs";
import { DurableOrganizationAuthority } from "../services/organization/cloudflare/authority.mjs";
import { DurableActionStore } from "../services/organization/cloudflare/store.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { McpConnector } from "../services/organization/mcp.mjs";
export class TransportFixture extends DurableObject {
  async fetch(request) {
    if (new URL(request.url).origin !== "https://fixture.invalid")
      return this.http
        ? this.http(request, { waitUntil: (p) => this.ctx.waitUntil(p) })
        : Response.json({ error: "unavailable" }, { status: 503 });
    const input = await request.json();
    if (input.operation === "route") {
      const response = await publicRoute(
        new Request(input.url, input.init),
        this.env,
      );
      return Response.json({
        status: response.status,
        body: await response.json(),
      });
    }
    if (input.operation === "open") {
      this.authority?.close();
      this.trust?.close();
      this.trust = await DurableEntityTrust.open(this.ctx.storage, {
        organization: "transport-fixture",
        configuration: { maxAgeSeconds: 300 },
        initialize: input.initialize ?? false,
      });
      if (input.provisioning) await this.trust.update(input.provisioning);
      this.authority = await DurableOrganizationAuthority.open(
        this.ctx.storage,
        {
          organization: "transport-fixture",
          trust: this.trust,
          introspectionClientSecret: input.secret,
          initialize: input.configuration,
        },
      );
      this.ledger = new DurableActionStore(this.ctx.storage, this.authority, {
        organization: "transport-fixture",
      });
      const connector = new McpConnector([input.target], { timeoutMs: 3000 });
      this.controller = new OrganizationController({
        authentication: this.authority,
        trust: this.trust,
        gateway: input.gateway,
        createStore: (guard) => this.ledger.withAuthorization(guard),
        execute: (p, c, context) =>
          createActionExecutor(this.authority.policy(), connector)(p, c, {
            ...context,
            authorize: async (p, c) =>
              (await this.authority.authorize(p, c)) &&
              (await context.authorize(p, c)),
          }),
      });
      this.control = { pending: 0 };
      this.http = createWorkerHttp({
        controller: this.controller,
        origin: "https://xeip.example",
        ready: async () => this.authority.status().state === "ready",
        ...input.httpOptions,
      });
      return Response.json({ ok: true });
    }
    if (input.operation === "trust-update")
      return Response.json(await this.trust.update(input.provisioning));
    if (input.operation === "sql")
      return Response.json({
        rows: this.ctx.storage.sql
          .exec(input.query, ...(input.bindings ?? []))
          .toArray(),
      });
    if (input.operation === "http-init") {
      this.control = {
        calls: 0,
        readyCalls: 0,
        hold: false,
        holdReady: false,
        settled: 0,
        aborted: 0,
        pending: 0,
        ...input.controls,
      };
      this.http = createWorkerHttp({
        origin: "https://xeip.example",
        ...input.options,
        ready: async () => {
          this.control.readyCalls++;
          while (this.control.holdReady)
            await new Promise((r) => setTimeout(r, 5));
          return this.control.ready !== false;
        },
        controller: {
          handle: async (header, body, { signal }) => {
            this.control.calls++;
            while (this.control.hold)
              await new Promise((r) => setTimeout(r, 5));
            if (signal.aborted) this.control.aborted++;
            this.control.settled++;
            if (this.control.error === "safe")
              throw new OperationError(403, "forbidden");
            if (this.control.error)
              throw new OperationError(418, "secret-credential");
            return {
              header,
              body,
              value: this.control.large ? "x".repeat(270000) : "ok",
            };
          },
        },
      });
      return Response.json({ ok: true });
    }
    if (input.operation === "controls") {
      Object.assign(this.control, input.controls);
      return Response.json(this.control);
    }
    if (input.operation === "http") {
      const abort = new AbortController();
      const timer =
        input.abortMs === undefined
          ? undefined
          : setTimeout(() => abort.abort(), input.abortMs);
      if (input.aborted) abort.abort();
      let body = input.body ?? "{}";
      if (input.chunks || input.stallBody) {
        body = new ReadableStream({
          start(c) {
            for (const chunk of input.chunks ?? [])
              c.enqueue(new Uint8Array(chunk));
            if (!input.stallBody) c.close();
          },
        });
      }
      try {
        const method = input.method ?? "POST";
        const request = new Request(
          input.url ?? "https://xeip.example/v1/actions",
          {
            method,
            headers: input.headers ?? {
              "content-type": "application/json",
              authorization: "Bearer fixture",
            },
            signal: abort.signal,
            ...(!["GET", "HEAD"].includes(method) ? { body } : {}),
          },
        );
        const response = await this.http(request, {
          waitUntil: (p) => {
            this.control.pending++;
            const done = () => {
              this.control.pending--;
            };
            this.ctx.waitUntil(p.then(done, done));
          },
        });
        return Response.json({
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body: await response.json(),
        });
      } finally {
        clearTimeout(timer);
      }
    }
    if (input.operation === "mcp") {
      const abort = new AbortController();
      let checks = 0;
      try {
        const result = await new McpConnector([input.target], {
          timeoutMs: input.timeoutMs ?? 3000,
        }).call(input.action, {
          signal: abort.signal,
          beforeSend: async () => {
            checks++;
            if (input.abort) abort.abort();
            if (input.stall)
              await new Promise((r) => setTimeout(r, input.stall));
            return input.allow !== false;
          },
        });
        return Response.json({ result, checks });
      } catch (error) {
        return Response.json({ error: error.name, sent: error.sent, checks });
      }
    }
    return new Response(null, { status: 404 });
  }
}
function publicRoute(request, env) {
  if (new URL(request.url).origin !== "https://xeip.example")
    return Response.json({ error: "forbidden" }, { status: 403 });
  return env.TRANSPORT.get(env.TRANSPORT.idFromName("public")).fetch(request);
}
export default { fetch: publicRoute };
