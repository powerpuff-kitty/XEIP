/** One bounded, non-retrying MCP effect using target-scoped OAuth credentials. */
import {
  Client,
  StreamableHTTPClientTransport,
  ClientCredentialsProvider,
  auth,
  buildDiscoveryUrls,
  discoverOAuthProtectedResourceMetadata,
  discoverAuthorizationServerMetadata,
} from "@modelcontextprotocol/client";
import { snapshot } from "./actions.mjs";
import { decodeKeyId } from "../../sdks/typescript/dist/identity.js";
import { ConnectorFailure } from "./errors.mjs";
export { ConnectorFailure } from "./errors.mjs";
/** @typedef {{id:string,revision:string,recipient:string,tools:readonly string[],endpoint:string,resourceMetadataUrl:string,issuer:string,tokenEndpoint:string,clientId:string,clientSecret:string,scope:string,allowInsecureLoopback?:boolean}} Target */
/** @typedef {Pick<import('./actions.mjs').Action,'target'|'tool'|'arguments'>} Action */
/** @param {string} value @param {boolean} loopback */
function endpoint(value, loopback) {
  const url = new URL(value);
  if (
    url.href !== value ||
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    !(
      url.protocol === "https:" ||
      (loopback &&
        url.protocol === "http:" &&
        ["127.0.0.1", "[::1]"].includes(url.hostname))
    )
  )
    throw new TypeError("pinned HTTPS endpoint required");
  return url;
}
/** @param {Response} response @param {number} limit */
async function boundedResponse(response, limit) {
  const reader = response.body?.getReader();
  /** @type {Uint8Array[]} */ const parts = [];
  let bytes = 0;
  try {
    if (reader)
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > limit) throw new Error("response limit");
        parts.push(value);
      }
  } finally {
    await reader?.cancel().catch(() => {});
  }
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.delete("content-encoding");
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
    Buffer.concat(parts),
  );
  return new Response(
    [204, 205, 304].includes(response.status) ? null : decoded,
    { status: response.status, headers },
  );
}
/** @typedef {import('./contracts.js').EffectConnector} EffectConnector */
/** @implements {EffectConnector} */
export class McpConnector {
  /** @type {Map<string,Target>} */ #targets = new Map();
  #timeout;
  /** @param {Target[]} targets @param {{timeoutMs?:number}} [options] */
  constructor(targets, { timeoutMs = 15000 } = {}) {
    if (
      !Array.isArray(targets) ||
      targets.length === 0 ||
      targets.length > 256 ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 30000
    )
      throw new TypeError("invalid MCP configuration");
    this.#timeout = timeoutMs;
    for (const input of targets) {
      const target = /** @type {Target} */ (
        /** @type {unknown} */ (snapshot(input, 16384))
      );
      if (
        ![
          target.id,
          target.revision,
          target.clientId,
          target.clientSecret,
          target.scope,
        ].every(
          (v) =>
            typeof v === "string" &&
            v.length > 0 &&
            v.length <= 4096 &&
            !/[\u0000-\u001f\u007f]/.test(v),
        ) ||
        !target.recipient?.startsWith("urn:xeip:entity:") ||
        !Array.isArray(target.tools) ||
        !target.tools.length ||
        target.tools.length > 256 ||
        !target.tools.every(
          (v) => typeof v === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(v),
        ) ||
        new Set(target.tools).size !== target.tools.length ||
        this.#targets.has(target.id) ||
        (target.allowInsecureLoopback !== undefined &&
          typeof target.allowInsecureLoopback !== "boolean")
      )
        throw new TypeError("invalid MCP target");
      decodeKeyId(target.recipient.slice("urn:xeip:entity:".length));
      const resource = endpoint(
          target.endpoint,
          target.allowInsecureLoopback === true,
        ),
        metadata = endpoint(
          target.resourceMetadataUrl,
          target.allowInsecureLoopback === true,
        );
      // Issuer identifiers conventionally omit their origin's trailing slash.
      const issuer = endpoint(
          new URL(target.issuer).href,
          target.allowInsecureLoopback === true,
        ),
        token = endpoint(
          target.tokenEndpoint,
          target.allowInsecureLoopback === true,
        );
      if (
        target.issuer !== issuer.href.replace(/\/$/, "") ||
        resource.origin !== metadata.origin ||
        issuer.origin !== token.origin
      )
        throw new TypeError("invalid MCP trust boundary");
      this.#targets.set(target.id, target);
    }
  }
  /** @param {Action} input @param {{signal?:AbortSignal,beforeSend:()=>Promise<boolean>,dispatch?:import('./contracts.js').ToolDispatch}} options */
  async call(input, { signal, beforeSend, dispatch }) {
    let sent = false;
    const abort = new AbortController(),
      timer = setTimeout(() => abort.abort(), this.#timeout);
    const combined = signal
      ? AbortSignal.any([signal, abort.signal])
      : abort.signal;
    /** @type {Client | undefined} */ let client;
    try {
      const action = /** @type {Action} */ (
          /** @type {unknown} */ (snapshot(input, 69632))
        ),
        target = this.#targets.get(action.target.id);
      if (
        !target ||
        target.revision !== action.target.revision ||
        target.recipient !== action.target.recipient ||
        !target.tools.includes(action.tool) ||
        typeof beforeSend !== "function" ||
        (dispatch !== undefined && typeof dispatch !== "function")
      )
        throw new Error();
      combined.throwIfAborted();
      const discovery = new Set(
        buildDiscoveryUrls(target.issuer).map((entry) => entry.url.href),
      );
      let requests = 0,
        resourceVerified = false,
        issuerVerified = false;
      /** @type {import('@modelcontextprotocol/client').FetchLike} */
      const boundedFetch = async (input, init) => {
        const req = new Request(input, init),
          url = req.url;
        combined.throwIfAborted();
        if (++requests > 12) throw new Error("request limit");
        const resource =
            url === target.resourceMetadataUrl && req.method === "GET",
          issuer = discovery.has(url) && req.method === "GET";
        const grant = url === target.tokenEndpoint && req.method === "POST",
          mcp = url === target.endpoint && req.method === "POST";
        if (!resource && !issuer && !grant && !mcp)
          throw new Error("endpoint denied");
        if (grant && (!resourceVerified || !issuerVerified))
          throw new Error("undiscovered grant");
        let effect = false;
        if (mcp) {
          const message = await req.clone().json();
          if (message.method === "tools/call") {
            if (
              sent ||
              message.params?.name !== action.tool ||
              JSON.stringify(message.params?.arguments) !==
                JSON.stringify(action.arguments) ||
              !(await beforeSend())
            )
              throw new Error("effect denied");
            combined.throwIfAborted();
            effect = true;
          } else if (message.method !== "server/discover")
            throw new Error("unsupported MCP operation");
        }
        // workerd supports manual redirects; never forward credentials or effects.
        const send = () => {
          combined.throwIfAborted();
          req.signal.throwIfAborted();
          if (effect) {
            if (sent) throw new Error("effect already sent");
            sent = true;
          }
          return fetch(req, {
            redirect: "manual",
            signal: AbortSignal.any([combined, req.signal]),
          });
        };
        const received = await (effect && dispatch ? dispatch(send) : send());
        if (received.status >= 300 && received.status < 400) {
          void received.body?.cancel().catch(() => {});
          throw new Error("redirect denied");
        }
        const response = await boundedResponse(received, mcp ? 196608 : 65536);
        if (response.ok && (resource || issuer)) {
          const data = await response.clone().json();
          if (resource) {
            if (
              data.resource !== target.endpoint ||
              !Array.isArray(data.authorization_servers) ||
              data.authorization_servers.length !== 1 ||
              data.authorization_servers[0] !== target.issuer
            )
              throw new Error("resource mismatch");
            resourceVerified = true;
          } else {
            if (
              data.issuer !== target.issuer ||
              data.token_endpoint !== target.tokenEndpoint
            )
              throw new Error("issuer mismatch");
            issuerVerified = true;
          }
        }
        return response;
      };
      // Discover explicitly and require both metadata documents; no insecure fallback.
      const resourceMetadata = await discoverOAuthProtectedResourceMetadata(
        target.endpoint,
        { resourceMetadataUrl: target.resourceMetadataUrl },
        boundedFetch,
      );
      const metadata = await discoverAuthorizationServerMetadata(
        target.issuer,
        { fetchFn: boundedFetch },
      );
      if (!metadata || !resourceVerified || !issuerVerified) throw new Error();
      const provider = new ClientCredentialsProvider({
        clientId: target.clientId,
        clientSecret: target.clientSecret,
        expectedIssuer: target.issuer,
        scope: target.scope,
      });
      const cached = Object.assign(provider, {
        discoveryState: () => ({
          authorizationServerUrl: target.issuer,
          resourceMetadata,
          authorizationServerMetadata: metadata,
          resourceMetadataUrl: target.resourceMetadataUrl,
        }),
      });
      if (
        (await auth(cached, {
          serverUrl: target.endpoint,
          resourceMetadataUrl: new URL(target.resourceMetadataUrl),
          scope: target.scope,
          fetchFn: boundedFetch,
        })) !== "AUTHORIZED"
      )
        throw new Error();
      const tokens = provider.tokens();
      if (
        !tokens ||
        typeof tokens.access_token !== "string" ||
        tokens.access_token.length > 16384 ||
        tokens.token_type.toLowerCase() !== "bearer"
      )
        throw new Error();
      client = new Client(
        { name: "xeip-organization", version: "0.1.0" },
        {
          capabilities: {},
          versionNegotiation: {
            mode: { pin: "2026-07-28" },
            probe: { maxRetries: 0, timeoutMs: this.#timeout },
          },
        },
      );
      const transport = new StreamableHTTPClientTransport(
        new URL(target.endpoint),
        {
          // A token-only provider cannot refresh and resend an effect on 401/403.
          authProvider: { token: async () => tokens.access_token },
          fetch: boundedFetch,
          requestInit: { redirect: "manual" },
          onInsufficientScope: "throw",
          maxStepUpRetries: 0,
          reconnectionOptions: {
            maxRetries: 0,
            maxReconnectionDelay: 1,
            initialReconnectionDelay: 1,
            reconnectionDelayGrowFactor: 1,
          },
        },
      );
      await client.connect(transport, {
        signal: combined,
        timeout: this.#timeout,
      });
      const result = await client.callTool(
        { name: action.tool, arguments: action.arguments },
        { signal: combined, timeout: this.#timeout },
      );
      return snapshot(result, 131072);
    } catch {
      throw new ConnectorFailure(sent);
    } finally {
      clearTimeout(timer);
      abort.abort();
      await client?.close().catch(() => {});
    }
  }
}
