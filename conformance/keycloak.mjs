import { registerFixtureCleanup } from "./fixture-cleanup.mjs";
// Isolated provider conformance fixture. Development-mode Keycloak is NOT a deployment.
import assert from "node:assert/strict";
import { pathToFileURL, fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { KeycloakAuthenticator } from "../services/organization/auth.mjs";
import {
  decodeJwt,
  decodeProtectedHeader,
  createRemoteJWKSet,
  jwtVerify,
} from "jose";
const image =
  "quay.io/keycloak/keycloak:26.8.0@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741";
export async function withKeycloak(
  verify,
  { population = false, browserOrigin } = {},
) {
  if (
    browserOrigin !== undefined &&
    (!/^https:\/\/127\.0\.0\.1:[0-9]+$/.test(browserOrigin) || population)
  )
    throw new TypeError(
      "browser fixture requires a loopback HTTPS origin without population mode",
    );
  const name =
    "xeip-keycloak-fixture-" +
    process.pid +
    "-" +
    randomBytes(4).toString("hex");
  const directory = mkdtempSync(join(tmpdir(), "xeip-keycloak-"));
  const agentSecret = randomBytes(32).toString("base64url");
  const introspectionSecret = randomBytes(32).toString("base64url");
  const subject = randomUUID();
  const humanSubject = randomUUID(),
    humanSecret = randomBytes(32).toString("base64url");
  const entity =
    "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
  const kid = "z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
  const client = (clientId, secret) => ({
    clientId,
    enabled: true,
    protocol: "openid-connect",
    publicClient: false,
    secret,
    serviceAccountsEnabled: true,
    standardFlowEnabled: false,
    directAccessGrantsEnabled: false,
    defaultClientScopes: ["roles"],
  });
  const realm = {
    realm: "xeip-fixture",
    enabled: true,
    sslRequired: "none",
    accessTokenLifespan: 120,
    roles: { client: { "xeip-api": [{ name: "agent" }] } },
    clients: [
      {
        clientId: "xeip-api",
        enabled: true,
        bearerOnly: true,
        protocol: "openid-connect",
      },
      {
        ...client("xeip-agent", agentSecret),
        protocolMappers: [
          {
            name: "xeip-introspection-audience",
            protocol: "openid-connect",
            protocolMapper: "oidc-audience-mapper",
            config: {
              "included.client.audience": "xeip-introspection",
              "id.token.claim": "false",
              "access.token.claim": "true",
            },
          },
          {
            name: "xeip-audience",
            protocol: "openid-connect",
            protocolMapper: "oidc-audience-mapper",
            config: {
              "included.client.audience": "xeip-api",
              "id.token.claim": "false",
              "access.token.claim": "true",
            },
          },
        ],
      },
      client("xeip-introspection", introspectionSecret),
    ],
    users: [
      {
        id: subject,
        username: "service-account-xeip-agent",
        enabled: true,
        serviceAccountClientId: "xeip-agent",
        clientRoles: { "xeip-api": ["agent"] },
      },
    ],
  };
  realm.roles.client["xeip-api"].push({ name: "approver" });
  realm.clients.push({
    ...client("xeip-console", humanSecret),
    protocolMappers: structuredClone(realm.clients[1].protocolMappers),
  });
  realm.users.push({
    id: humanSubject,
    username: "service-account-xeip-console",
    enabled: true,
    serviceAccountClientId: "xeip-console",
    clientRoles: { "xeip-api": ["approver"] },
  });
  const identities = {
    agent: [{ subject, clientId: "xeip-agent", secret: agentSecret }],
    human: [
      { subject: humanSubject, clientId: "xeip-console", secret: humanSecret },
    ],
  };
  const browser = browserOrigin
    ? {
        subject: randomUUID(),
        username: "fixture-approver",
        password: randomBytes(32).toString("base64url"),
        clientId: "approval-console",
      }
    : undefined;
  if (browser) {
    realm.clients.push({
      clientId: browser.clientId,
      enabled: true,
      protocol: "openid-connect",
      publicClient: true,
      standardFlowEnabled: true,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false,
      redirectUris: [browserOrigin + "/console/"],
      webOrigins: [browserOrigin],
      attributes: {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": browserOrigin + "/console/",
      },
      defaultClientScopes: ["basic", "roles"],
      protocolMappers: structuredClone(realm.clients[1].protocolMappers),
    });
    realm.users.push({
      id: browser.subject,
      username: browser.username,
      enabled: true,
      email: "fixture-approver@example.invalid",
      emailVerified: true,
      firstName: "Fixture",
      lastName: "Approver",
      requiredActions: [],
      credentials: [
        { type: "password", value: browser.password, temporary: false },
      ],
      clientRoles: { "xeip-api": ["approver"] },
    });
  }
  const pendingIdentities = [];
  const adminSecret = randomBytes(32).toString("base64url"),
    adminId = randomUUID();
  if (population) {
    realm.clients.push({
      id: adminId,
      ...client("xeip-fixture-admin", adminSecret),
    });
    realm.users.push({
      id: randomUUID(),
      username: "service-account-xeip-fixture-admin",
      enabled: true,
      serviceAccountClientId: "xeip-fixture-admin",
      clientRoles: { "realm-management": ["realm-admin"] },
    });
  }
  if (population)
    for (const [role, count] of [
      ["agent", 200],
      ["human", 500],
    ])
      for (let i = 1; i < count; i++) {
        const item = {
          subject: randomUUID(),
          clientId: "xeip-load-" + role + "-" + i,
          secret: randomBytes(32).toString("base64url"),
        };
        identities[role].push(item);
        pendingIdentities.push({ item, role });
      }
  const realmFile = join(directory, "xeip-fixture-realm.json");
  // The host directory is private; read-only file mount lets the container's non-root user import it.
  writeFileSync(realmFile, JSON.stringify(realm), { mode: 0o444 });
  const docker = (args) =>
    execFileSync("docker", args, {
      encoding: "utf8",
      timeout: 30000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  let created = false;
  const cleanup = () => {
    if (created) {
      try {
        docker(["rm", "-f", name]);
      } catch {
        throw new Error(
          "Keycloak fixture cleanup failed; remove owned container " + name,
        );
      }
      created = false;
    }
    rmSync(directory, { recursive: true, force: true });
  };
  const unregisterCleanup = registerFixtureCleanup(cleanup);
  async function form(url, values) {
    return await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(values),
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
  }
  try {
    docker(["image", "inspect", image]);
    docker([
      "create",
      "--name",
      name,
      "--memory",
      "1g",
      "--cpus",
      "2",
      "-p",
      browser ? "127.0.0.1::8443" : "127.0.0.1::8080",
      "--mount",
      "type=bind,src=" +
        realmFile +
        ",dst=/opt/keycloak/data/import/xeip-fixture-realm.json,readonly",
      ...(browser
        ? [
            "--mount",
            "type=bind,src=" +
              fileURLToPath(
                new URL(
                  "../services/organization/test-fixtures/tls/cert.pem",
                  import.meta.url,
                ),
              ) +
              ",dst=/tmp/fixture-cert.pem,readonly",
            "--mount",
            "type=bind,src=" +
              fileURLToPath(
                new URL(
                  "../services/organization/test-fixtures/tls/key.pem",
                  import.meta.url,
                ),
              ) +
              ",dst=/tmp/fixture-key.pem,readonly",
          ]
        : []),
      image,
      "start-dev",
      "--import-realm",
      ...(browser
        ? [
            "--http-enabled=false",
            "--https-certificate-file=/tmp/fixture-cert.pem",
            "--https-certificate-key-file=/tmp/fixture-key.pem",
          ]
        : []),
    ]);
    created = true;
    docker(["start", name]);
    const port = JSON.parse(
      docker(["inspect", "--format", "{{json .NetworkSettings.Ports}}", name]),
    )[browser ? "8443/tcp" : "8080/tcp"][0].HostPort;
    const issuer =
      (browser ? "https" : "http") +
      "://127.0.0.1:" +
      port +
      "/realms/xeip-fixture";
    console.log("Waiting for isolated Keycloak fixture (loopback only)...");
    let ready = false;
    // Cold augmentation/schema creation can be slow on a loaded Docker Desktop host.
    // This is a fixture startup deadline, not the API's authentication timeout.
    // Population accounts are provisioned afterward in bounded Admin API transactions.
    const started = Date.now();
    const deadline = started + 900000;
    let nextProgress = started + 60000;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(
          issuer + "/.well-known/openid-configuration",
          { signal: AbortSignal.timeout(3000) },
        );
        await response.arrayBuffer();
        if (response.status === 200) {
          ready = true;
          break;
        }
      } catch {
        /* bounded startup retry */
      }
      if (Date.now() >= nextProgress) {
        console.log(
          "Keycloak fixture setup: " +
            Math.floor((Date.now() - started) / 60000) +
            " minutes elapsed; operation measurement has not started",
        );
        nextProgress = Date.now() + 60000;
      }
      await delay(500);
    }
    if (!ready) {
      const state = JSON.parse(
        docker(["inspect", "--format", "{{json .State}}", name]),
      );
      console.error(
        "Keycloak startup state: " +
          JSON.stringify({
            status: state.Status,
            exitCode: state.ExitCode,
            oomKilled: state.OOMKilled,
          }),
      );
    }
    assert.ok(ready, "Keycloak fixture did not become ready");
    if (population) {
      console.log(
        "Provisioning 698 additional fixture accounts through isolated Admin API transactions...",
      );
      const adminBase = new URL("/admin/realms/xeip-fixture", issuer).href;
      const token = async () => {
        const response = await form(issuer + "/protocol/openid-connect/token", {
          grant_type: "client_credentials",
          client_id: "xeip-fixture-admin",
          client_secret: adminSecret,
        });
        assert.equal(response.status, 200, "fixture administration token");
        return (await response.json()).access_token;
      };
      const api = async (
        bearer,
        path,
        method = "GET",
        body = undefined,
        expected = 200,
      ) => {
        const response = await fetch(adminBase + path, {
          method,
          headers: {
            Authorization: "Bearer " + bearer,
            "Content-Type": "application/json",
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          redirect: "error",
          signal: AbortSignal.timeout(10000),
        });
        assert.equal(
          response.status,
          expected,
          "fixture administration " + method + " response",
        );
        if (expected === 200) return response.json();
        await response.arrayBuffer();
      };
      let bearer = await token();
      const apiClients = await api(bearer, "/clients?clientId=xeip-api");
      assert.equal(apiClients.length, 1);
      const apiId = apiClients[0].id;
      const roles = {
        agent: await api(bearer, "/clients/" + apiId + "/roles/agent"),
        human: await api(bearer, "/clients/" + apiId + "/roles/approver"),
      };
      const provisioningDeadline = Date.now() + 1200000;
      for (let offset = 0; offset < pendingIdentities.length; offset += 6) {
        assert.ok(
          Date.now() < provisioningDeadline,
          "fixture population provisioning deadline",
        );
        bearer = await token();
        const batch = await Promise.allSettled(
          pendingIdentities
            .slice(offset, offset + 6)
            .map(async ({ item, role }) => {
              const id = randomUUID();
              await api(
                bearer,
                "/clients",
                "POST",
                {
                  id,
                  ...client(item.clientId, item.secret),
                  protocolMappers: structuredClone(
                    realm.clients[1].protocolMappers,
                  ),
                },
                201,
              );
              const account = await api(
                bearer,
                "/clients/" + id + "/service-account-user",
              );
              assert.equal(typeof account.id, "string");
              item.subject = account.id;
              await api(
                bearer,
                "/users/" + account.id + "/role-mappings/clients/" + apiId,
                "POST",
                [roles[role]],
                204,
              );
            }),
        );
        for (const result of batch)
          if (result.status === "rejected") throw result.reason;
        if (offset % 120 === 0)
          console.log(
            "Fixture accounts provisioned: " +
              Math.min(offset + 6, pendingIdentities.length) +
              "/698",
          );
      }
      await api(await token(), "/clients/" + adminId, "DELETE", undefined, 204);
      console.log(
        "PASS fixture population: 200 agents and 500 simulated approvers; bootstrap administration client removed",
      );
    }
    const response = await form(issuer + "/protocol/openid-connect/token", {
      grant_type: "client_credentials",
      client_id: "xeip-agent",
      client_secret: agentSecret,
    });
    assert.equal(response.status, 200, "fixture token issuance");
    const tokenResponse = await response.json();
    assert.ok(
      typeof tokenResponse.access_token === "string",
      "access token missing",
    );
    const auth = new KeycloakAuthenticator({
      issuer,
      audience: "xeip-api",
      clientIds: ["xeip-agent"],
      bindings: [{ subject, entity, kid }],
      introspectionClientId: "xeip-introspection",
      introspectionClientSecret: introspectionSecret,
      allowInsecureLoopback: !browser,
    });
    assert.equal(await auth.ready(), true, "real Keycloak startup readiness");
    const principal = await auth.authenticate(
      "Bearer " + tokenResponse.access_token,
    );
    if (!principal) {
      // Synthetic fixture diagnostics only: never print the bearer or client secrets.
      const claims = decodeJwt(tokenResponse.access_token);
      const header = decodeProtectedHeader(tokenResponse.access_token);
      console.error(
        "Fixture claim checks: " +
          JSON.stringify({
            algorithm: header.alg,
            headerType: header.typ,
            tokenType: claims.typ,
            audience: claims.aud,
            client: claims.azp,
            subjectMatches: claims.sub === subject,
            issuerMatches: claims.iss === issuer,
            issuedAt: claims.iat,
            expiresAt: claims.exp,
            now: Math.floor(Date.now() / 1000),
            hasTokenId: typeof claims.jti === "string",
          }),
      );
      try {
        await jwtVerify(
          tokenResponse.access_token,
          createRemoteJWKSet(
            new URL(issuer + "/protocol/openid-connect/certs"),
          ),
          {
            issuer,
            audience: "xeip-api",
            algorithms: ["RS256"],
            typ: "JWT",
            requiredClaims: ["iss", "aud", "sub", "azp", "iat", "exp", "jti"],
          },
        );
        console.error("Fixture independent JWT verification: passed");
      } catch (error) {
        console.error(
          "Fixture independent JWT verification code: " + error.code,
        );
      }
      const diagnostic = await form(
        issuer + "/protocol/openid-connect/token/introspect",
        {
          token: tokenResponse.access_token,
          token_type_hint: "access_token",
          client_id: "xeip-introspection",
          client_secret: introspectionSecret,
        },
      );
      const introspection = await diagnostic.json();
      console.error(
        "Fixture introspection checks: " +
          JSON.stringify({
            status: diagnostic.status,
            active: introspection.active,
            subjectMatches: introspection.sub === subject,
            clientMatches: introspection.client_id === "xeip-agent",
            expiryMatches: introspection.exp === claims.exp,
          }),
      );
    }
    assert.ok(principal, "real Keycloak access token rejected");
    assert.equal(principal.subject, subject);
    assert.equal(principal.entity, entity);
    assert.equal(principal.kid, kid);
    assert.ok(principal.roles.includes("agent"), "API client role missing");
    assert.equal(await auth.revalidate(principal), true);
    const revoked = await form(issuer + "/protocol/openid-connect/revoke", {
      token: tokenResponse.access_token,
      token_type_hint: "access_token",
      client_id: "xeip-agent",
      client_secret: agentSecret,
    });
    assert.equal(revoked.status, 200, "provider revocation");
    await revoked.arrayBuffer();
    assert.equal(
      await auth.revalidate(principal),
      false,
      "revoked access token must not remain active",
    );
    console.log(
      "PASS real Keycloak: JWT/JWKS, explicit identity mapping, client roles, confidential introspection and live revocation",
    );
    console.log(
      "Image digest: " +
        docker([
          "image",
          "inspect",
          "--format",
          "{{index .RepoDigests 0}}",
          image,
        ]),
    );
    if (verify)
      await verify({
        browser,
        config: {
          issuer,
          audience: "xeip-api",
          clientIds: [
            ...identities.agent,
            ...identities.human,
            ...(browser ? [browser] : []),
          ].map((item) => item.clientId),
          introspectionClientId: "xeip-introspection",
          introspectionClientSecret: introspectionSecret,
          allowInsecureLoopback: !browser,
        },
        subjects: {
          agent: subject,
          human: humanSubject,
          agents: identities.agent.map((item) => item.subject),
          humans: identities.human.map((item) => item.subject),
        },
        token: async (role, index = 0) => {
          const item = identities[role][index];
          const response = await form(
            issuer + "/protocol/openid-connect/token",
            {
              grant_type: "client_credentials",
              client_id: item.clientId,
              client_secret: item.secret,
            },
          );
          assert.equal(response.status, 200);
          return (await response.json()).access_token;
        },
        revoke: async (token) => {
          const response = await form(
            issuer + "/protocol/openid-connect/revoke",
            {
              token,
              token_type_hint: "access_token",
              client_id: "xeip-agent",
              client_secret: agentSecret,
            },
          );
          assert.equal(response.status, 200);
          await response.arrayBuffer();
        },
      });
  } finally {
    try {
      cleanup();
    } finally {
      unregisterCleanup();
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await withKeycloak();
