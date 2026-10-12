/** Fixed startup assets and an authenticated, non-authorizing enrollment profile. */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { OperationError } from "./controller.mjs";
/** @typedef {{type:string,body:Buffer}} Asset */
/** @typedef {import('./console/session.mjs').Bootstrap} Bootstrap */
/** Load only explicitly named build outputs; request URLs never become paths. */
export function loadConsoleAssets() {
  const directory = new URL("../../dist/console/", import.meta.url);
  const manifest = JSON.parse(
    readFileSync(new URL("manifest.json", directory), "utf8"),
  );
  /** @type {Map<string,Asset>} */ const assets = new Map();
  for (const [name, type, limit] of /** @type {[string,string,number][]} */ ([
    ["index.html", "text/html; charset=utf-8", 32768],
    ["app.js", "text/javascript; charset=utf-8", 524288],
    ["app.css", "text/css; charset=utf-8", 32768],
    ["THIRD_PARTY_LICENSES.txt", "text/plain; charset=utf-8", 65536],
  ])) {
    const body = readFileSync(new URL(name, directory));
    if (
      body.length > limit ||
      manifest.files?.[name] !== createHash("sha256").update(body).digest("hex")
    )
      throw new Error("console assets unavailable");
    assets.set(name === "index.html" ? "/console/" : "/console/" + name, {
      type,
      body,
    });
  }
  return assets;
}
/** @param {{configuration:Bootstrap,authentication:import('./contracts.js').Authentication,assets:Map<string,Asset>}} options */
export function createConsole({ configuration, authentication, assets }) {
  const headers = Object.freeze({
    "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ${new URL(configuration.issuer).origin}; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' ${new URL(configuration.issuer).origin}`,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  const published = new Map(assets);
  published.set("/console/config", {
    type: "application/json; charset=utf-8",
    body: Buffer.from(
      JSON.stringify({
        issuer: configuration.issuer,
        clientId: configuration.clientId,
        gateway: configuration.gateway,
        audience: configuration.audience,
      }),
    ),
  });
  return {
    /** @param {string} path */
    asset(path) {
      const asset = published.get(path);
      return asset ? { ...asset, headers } : undefined;
    },
    /** @param {unknown} authorization @param {{signal:AbortSignal}} options */
    async profile(authorization, { signal }) {
      /** @type {import('./contracts.js').OrganizationPrincipal|null} */ let principal =
        null;
      try {
        if (signal.aborted) throw new OperationError(503, "unavailable");
        principal = await authentication.authenticate(authorization);
        if (signal.aborted) throw new OperationError(503, "unavailable");
        if (!principal) throw new OperationError(401, "unauthenticated");
        if (
          principal.clientId !== configuration.clientId ||
          !principal.roles.includes("approver") ||
          principal.expiresAt <= Math.floor(Date.now() / 1000)
        )
          throw new OperationError(403, "forbidden");
        return {
          subject: principal.subject,
          entity: principal.entity,
          kid: principal.kid,
          expiresAt: principal.expiresAt,
        };
      } finally {
        if (principal) authentication.release(principal);
      }
    },
  };
}
