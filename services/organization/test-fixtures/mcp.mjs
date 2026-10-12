import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import {
  McpServer,
  createMcpHandler,
  fromJsonSchema,
} from "@modelcontextprotocol/server";

// An independent official-SDK server plus a small OAuth resource/issuer fixture.
export async function mcpFixture(t) {
  const secret = randomBytes(24).toString("hex"),
    token = randomBytes(24).toString("hex");
  const state = {
    calls: [],
    requests: [],
    grants: [],
    mode: "ok",
    metadata: {},
    issuerMetadata: {},
    beforeTool: null,
    beforeGrant: null,
    redirects: {},
  };
  let origin;
  const handler = createMcpHandler(
    () => {
      const server = new McpServer({
        name: "independent-fixture",
        version: "1.0.0",
      });
      server.registerTool(
        "lookup",
        {
          inputSchema: fromJsonSchema({
            type: "object",
            properties: { query: { type: "string" } },
            required: ["query"],
            additionalProperties: false,
          }),
        },
        async (args) => {
          state.calls.push(structuredClone(args));
          if (state.beforeTool) await state.beforeTool();
          if (state.mode === "continuation")
            return {
              resultType: "input_required",
              requestState: "fixture-opaque-state",
            };
          return {
            content: [
              {
                type: "text",
                text:
                  state.mode === "oversize"
                    ? "x".repeat(300000)
                    : "fixture result",
              },
            ],
            isError: state.mode === "tool-error",
          };
        },
      );
      return server;
    },
    { legacy: "reject" },
  );
  const server = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString("utf8");
      state.requests.push({
        path: req.url,
        method: req.method,
        authorization: req.headers.authorization,
        body: body && req.url === "/mcp" ? JSON.parse(body) : undefined,
      });
      const json = (status, value, headers = {}) => {
        res.writeHead(status, {
          "Content-Type": "application/json",
          ...headers,
        });
        res.end(JSON.stringify(value));
      };
      if (state.redirects[req.url])
        return json(307, {}, { Location: state.redirects[req.url] });
      if (req.url === "/resource")
        return json(200, {
          resource: origin + "/mcp",
          authorization_servers: [origin],
          scopes_supported: ["tools:lookup"],
          ...state.metadata,
        });
      if (req.url === "/.well-known/oauth-authorization-server")
        return json(200, {
          issuer: origin,
          token_endpoint: origin + "/token",
          authorization_endpoint: origin + "/authorize",
          response_types_supported: ["code"],
          grant_types_supported: ["client_credentials"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
          ...state.issuerMetadata,
        });
      if (req.url === "/token") {
        if (state.beforeGrant) await state.beforeGrant();
        const grant = new URLSearchParams(body);
        state.grants.push(Object.fromEntries(grant));
        if (
          req.headers.authorization !==
            "Basic " +
              Buffer.from("xeip-connector:" + secret).toString("base64") ||
          grant.get("resource") !== origin + "/mcp" ||
          grant.get("grant_type") !== "client_credentials" ||
          grant.get("scope") !== "tools:lookup"
        )
          return json(401, { error: "invalid_client" });
        return json(200, {
          access_token: token,
          token_type: "Bearer",
          expires_in: 60,
          scope: "tools:lookup",
        });
      }
      if (req.url !== "/mcp") return json(404, {});
      if (req.headers.authorization !== "Bearer " + token)
        return json(
          401,
          {},
          {
            "WWW-Authenticate":
              'Bearer resource_metadata="' + origin + '/resource"',
          },
        );
      const message = JSON.parse(body);
      if (message.method === "tools/call") {
        if (state.mode === "unauthorized") return json(401, {});
        if (state.mode === "redirect")
          return json(307, {}, { Location: origin + "/stolen" });
        if (state.mode === "disconnect") {
          state.calls.push(message.params.arguments);
          req.socket.destroy();
          return;
        }
        if (state.mode === "malformed")
          return json(200, {
            jsonrpc: "2.0",
            id: message.id,
            result: { invalid: true },
          });
        if (state.mode === "invalid-utf8") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            Buffer.concat([
              Buffer.from(
                '{"jsonrpc":"2.0","id":' +
                  JSON.stringify(message.id) +
                  ',"result":{"resultType":"complete","content":[{"type":"text","text":"',
              ),
              Buffer.from([0xc3, 0x28]),
              Buffer.from('"}]}}'),
            ]),
          );
          return;
        }
      }
      const response = await handler.fetch(
        new Request(origin + req.url, {
          method: req.method,
          headers: req.headers,
          body: body || undefined,
        }),
      );
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!res.destroyed) {
        res.writeHead(500);
        res.end();
      }
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = "http://127.0.0.1:" + server.address().port;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return {
    state,
    origin,
    token,
    config: {
      id: "internal",
      revision: "deployment-1",
      recipient:
        "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
      tools: ["lookup"],
      endpoint: origin + "/mcp",
      resourceMetadataUrl: origin + "/resource",
      issuer: origin,
      tokenEndpoint: origin + "/token",
      clientId: "xeip-connector",
      clientSecret: secret,
      scope: "tools:lookup",
      allowInsecureLoopback: true,
    },
  };
}
