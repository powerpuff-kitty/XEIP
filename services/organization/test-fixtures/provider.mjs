import { createServer } from "node:http";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
const key = await generateKeyPair("RS256");
const jwk = {
  ...(await exportJWK(key.publicKey)),
  kid: "realm-key",
  alg: "RS256",
  use: "sig",
};
export const entity =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
export const kid = "z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
export async function fixture(t) {
  const state = {
    active: true,
    jwks: { keys: [jwk] },
    jwksStatus: 200,
    introspectionStatus: 200,
    introspection: undefined,
    delay: 0,
    introspectionCalls: 0,
    beforeIntrospection: null,
    discovery: undefined,
  };
  const tokens = new Map();
  const server = createServer(async (req, res) => {
    if (state.delay)
      await new Promise((resolve) => setTimeout(resolve, state.delay));
    res.setHeader("Content-Type", "application/json");
    if (req.url.endsWith("/.well-known/openid-configuration")) {
      res.end(
        JSON.stringify(
          state.discovery ?? {
            issuer,
            jwks_uri: issuer + "/protocol/openid-connect/certs",
            introspection_endpoint:
              issuer + "/protocol/openid-connect/token/introspect",
          },
        ),
      );
      return;
    }
    if (req.url.endsWith("/certs")) {
      res.statusCode = state.jwksStatus;
      res.setHeader("Location", "/redirected");
      res.end(JSON.stringify(state.jwks));
      return;
    }
    if (req.url.endsWith("/token/introspect")) {
      state.introspectionCalls++;
      if (state.beforeIntrospection)
        await state.beforeIntrospection(state.introspectionCalls);
      let body = "";
      for await (const part of req) body += part;
      const form = new URLSearchParams(body);
      if (
        form.get("client_id") !== "xeip-introspection" ||
        form.get("client_secret") !== "fixture-only-secret"
      ) {
        res.writeHead(401);
        res.end("{}");
        return;
      }
      const claims = tokens.get(form.get("token"));
      res.statusCode = state.introspectionStatus;
      res.end(
        JSON.stringify(
          state.introspection ?? {
            active: state.active && !!claims,
            sub: claims?.sub,
            client_id: claims?.azp,
            exp: claims?.exp,
          },
        ),
      );
      return;
    }
    res.writeHead(404);
    res.end("{}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  const issuer = "http://127.0.0.1:" + server.address().port + "/realms/xeip";
  const config = {
    issuer,
    audience: "xeip-api",
    clientIds: ["xeip-console", "xeip-agent"],
    bindings: [{ subject: "user-1", entity, kid }],
    introspectionClientId: "xeip-introspection",
    introspectionClientSecret: "fixture-only-secret",
    allowInsecureLoopback: true,
    timeoutMs: 3000,
  };
  async function token(patch = {}, signingKey = key.privateKey, header = {}) {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: issuer,
      aud: ["xeip-api", "xeip-introspection"],
      azp: "xeip-console",
      sub: "user-1",
      typ: "Bearer",
      jti: "token-1",
      iat: now,
      exp: now + 120,
      resource_access: {
        "xeip-api": { roles: ["approver"] },
        other: { roles: ["admin"] },
      },
      ...patch,
    };
    const jwt = await new SignJWT(claims)
      .setProtectedHeader({
        alg: "RS256",
        kid: "realm-key",
        typ: "JWT",
        ...header,
      })
      .sign(signingKey);
    tokens.set(jwt, claims);
    return jwt;
  }
  return { config, state, token };
}
