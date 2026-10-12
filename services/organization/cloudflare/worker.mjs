/** Deployable experimental entrypoints. Never add an HTTP owner dispatcher. */
import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { OrganizationService } from "./service.mjs";
import {
  runtimeConfiguration,
  parseOwnerCommand,
  operatorIdentity,
} from "./profile.mjs";
import { StoreConflict } from "../errors.mjs";
import {
  exportReceiptField,
  ownerResponseLimit,
} from "./organization-export-wire.mjs";
/** @typedef {{XEIP_PROFILE:string,XEIP_CREDENTIALS:string,ORGANIZATION:DurableObjectNamespace<OrganizationObject>}} Env */
const objectName = "xeip-organization-v1";
/** @param {Env} env */
const stub = (env) =>
  env.ORGANIZATION.get(env.ORGANIZATION.idFromName(objectName));
/** @param {number} status @param {string} error */
const failure = (status, error) =>
  Response.json(
    { error },
    {
      status,
      headers: {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    },
  );
/** @param {unknown} value @param {number} [maximum] */
function encoded(value, maximum = 65536) {
  const result = JSON.stringify(value);
  if (Buffer.byteLength(result) > maximum)
    return JSON.stringify({ ok: false, error: "unavailable" });
  return result;
}
/** @extends {DurableObject<Env>} */
export class OrganizationObject extends DurableObject {
  /** @type {OrganizationService|undefined} */ #service;
  /** @param {DurableObjectState} ctx @param {Env} env */
  constructor(ctx, env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      try {
        this.#service = await OrganizationService.open(
          ctx.storage,
          runtimeConfiguration(env),
        );
      } catch {
        this.#service = undefined;
      }
    });
  }
  /** @param {Request} request */
  async fetch(request) {
    try {
      if (!this.#service)
        return request.method === "GET" &&
          new URL(request.url).pathname === "/live"
          ? Response.json(
              { live: true },
              { headers: { "cache-control": "no-store" } },
            )
          : failure(503, "unavailable");
      return await this.#service.fetch(request, {
        waitUntil: (p) => this.ctx.waitUntil(p),
      });
    } catch {
      return failure(503, "unavailable");
    }
  }
  /** Only namespace holders can invoke the fixed configured refresh. */
  async refresh() {
    let outcome;
    try {
      outcome = this.#service ? await this.#service.pollTrustFeed() : "failed";
    } catch (error) {
      outcome = error instanceof StoreConflict ? "busy" : "failed";
    }
    console.log(JSON.stringify({ event: "xeip.trust-refresh", outcome }));
    return outcome;
  }
  /** Only namespace/binding holders may call this. @param {unknown} raw @param {unknown} operator */
  async manage(raw, operator) {
    /** @type {Record<string,unknown>} */ let command;
    let actor;
    try {
      actor = operatorIdentity({ operator });
      command = parseOwnerCommand(raw);
    } catch {
      return encoded({ ok: false, error: "invalid_request" });
    }
    const metadata = {
      operator: actor,
      requestId: command.requestId,
      operation: command.operation,
    };
    console.log(
      JSON.stringify({ event: "xeip.owner", ...metadata, outcome: "started" }),
    );
    try {
      if (!this.#service) throw new Error("unavailable");
      const value = await this.#service.manage(raw, actor);
      const exportField = exportReceiptField(command.operation);
      console.log(
        JSON.stringify({
          event: "xeip.owner",
          ...metadata,
          outcome: "completed",
        }),
      );
      return encoded(
        {
          ok: true,
          ...metadata,
          ...(exportField
            ? { [exportField]: value }
            : command.operation === "auditExport"
              ? { audit: value }
              : command.operation === "actionSnapshot"
                ? { snapshot: value }
                : command.operation === "actionPage"
                  ? { page: value }
                  : { status: value }),
        },
        ownerResponseLimit(command.operation),
      );
    } catch (error) {
      const code =
        error instanceof StoreConflict
          ? "conflict"
          : error instanceof TypeError
            ? "invalid_request"
            : "unavailable";
      console.log(
        JSON.stringify({ event: "xeip.owner", ...metadata, outcome: code }),
      );
      return encoded({ ok: false, ...metadata, error: code });
    }
  }
}
/** @extends {WorkerEntrypoint<Env,{operator:string}>} */
export class OwnerEntrypoint extends WorkerEntrypoint {
  fetch() {
    return failure(404, "not_found");
  }
  /** @param {unknown} raw */
  async manage(raw) {
    let operator;
    try {
      operator = operatorIdentity(this.ctx.props);
    } catch {
      return encoded({ ok: false, error: "forbidden" });
    }
    try {
      parseOwnerCommand(raw);
    } catch {
      return encoded({ ok: false, error: "invalid_request" });
    }
    try {
      return await stub(this.env).manage(raw, operator);
    } catch {
      return encoded({ ok: false, error: "unavailable" });
    }
  }
}
/** Private capability granted only to the dedicated scheduler Worker.
 * @extends {WorkerEntrypoint<Env,{purpose:string}>} */
export class RefreshEntrypoint extends WorkerEntrypoint {
  fetch() {
    return failure(404, "not_found");
  }
  async refresh() {
    if (this.ctx.props?.purpose !== "trust-refresh")
      throw new Error("forbidden");
    try {
      return await stub(this.env).refresh();
    } catch {
      throw new Error("trust refresh unavailable");
    }
  }
}
/** @extends {WorkerEntrypoint<Env>} */
export default class PublicEntrypoint extends WorkerEntrypoint {
  /** @param {Request} request */
  async fetch(request) {
    try {
      return await stub(this.env).fetch(request);
    } catch {
      return failure(503, "unavailable");
    }
  }
}
