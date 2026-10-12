import { registerFixtureCleanup } from "./fixture-cleanup.mjs";
// Real browser + Keycloak + PostgreSQL + official MCP. All identities are synthetic.
// Run in a child with the fixture CA, never with global TLS verification disabled.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createServer as createNetServer } from "node:net";
import { randomBytes, randomUUID, createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { chromium, expect } from "@playwright/test";
import { withKeycloak } from "./keycloak.mjs";
import { withPostgres } from "./postgres.mjs";
import { mcpFixture } from "../services/organization/test-fixtures/mcp.mjs";
import { encodeKeyId } from "../tools/derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed } from "../tools/signed-envelope.mjs";
import { signKeyDocument } from "../tools/key-document.mjs";
import { signStatusDocument } from "../tools/identity-status.mjs";
import { signEntityEnvelope } from "../packages/identity/entity-envelope.mjs";
import { EntityTrustPolicy } from "../services/relay/entity-trust.mjs";
import { KeycloakAuthenticator } from "../services/organization/auth.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import { ActionStore } from "../services/organization/store.mjs";
import { OrganizationController } from "../services/organization/controller.mjs";
import { createOrganizationServer } from "../services/organization/http.mjs";
import {
  createConsole,
  loadConsoleAssets,
} from "../services/organization/console-server.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { McpConnector } from "../services/organization/mcp.mjs";

const ca = fileURLToPath(
  new URL(
    "../services/organization/test-fixtures/tls/cert.pem",
    import.meta.url,
  ),
);
if (process.argv[2] !== "--fixture-ca") {
  const child = spawn(
    process.execPath,
    [fileURLToPath(import.meta.url), "--fixture-ca"],
    {
      stdio: "inherit",
      env: { ...process.env, NODE_EXTRA_CA_CERTS: ca, DEBUG: "", PWDEBUG: "0" },
    },
  );
  const interrupt = () => child.kill("SIGINT");
  const terminate = () => child.kill("SIGTERM");
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", terminate);
  try {
    const status = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code) => resolve(code));
    });
    process.exitCode = status ?? 1;
  } finally {
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", terminate);
  }
  process.exit();
}
assert.equal(
  process.env.NODE_EXTRA_CA_CERTS,
  ca,
  "fixture CA must be explicitly trusted",
);
assert.notEqual(
  process.env.NODE_TLS_REJECT_UNAUTHORIZED,
  "0",
  "TLS verification must remain enabled",
);
assert.ok(
  !process.env.DEBUG && (!process.env.PWDEBUG || process.env.PWDEBUG === "0"),
  "fixture browser debug logging must be disabled",
);
const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
function identity(subject, deviceKid, seed = randomBytes(32)) {
  const root = encodeKeyId(
    createPublicKey(ed25519PrivateKeyFromSeed(seed))
      .export({ format: "der", type: "spki" })
      .subarray(-32),
  );
  const entity = "urn:xeip:entity:" + root;
  const issuedAt = utc(Math.floor(Date.now() / 1000));
  return {
    subject,
    seed,
    entity,
    kid: deviceKid ?? root,
    keyDocument: {
      document: signKeyDocument(
        {
          xeip: "xeip.keydoc/0.1",
          entity,
          genesis: root,
          generation: 1,
          issuedAt,
          roots: [root],
          devices: deviceKid ? [deviceKid] : [],
          signatures: [],
        },
        { privateKey: seed, kid: root },
      ),
      anchor: { genesisKid: root },
    },
    status: {
      document: signStatusDocument(
        {
          xeip: "xeip.status/0.1",
          entity,
          serial: 1,
          issuedAt,
          revoked: [],
          signatures: [],
        },
        { privateKey: seed, kid: root },
      ),
    },
  };
}
const cleanup = [];
let cleaning;
function clean() {
  return (cleaning ??= (async () => {
    const failures = [];
    for (const close of [...cleanup].reverse())
      try {
        await close();
      } catch (error) {
        failures.push(error);
      }
    if (failures.length)
      throw new Error("owned browser fixture cleanup failed");
  })());
}
const unregisterCleanup = registerFixtureCleanup(clean);
try {
  // Reserve an ephemeral port, then bind the real server before starting dependencies.
  // A collision fails setup; it never redirects a test to another listener.
  const reservation = createNetServer();
  await new Promise((resolve) => reservation.listen(0, "127.0.0.1", resolve));
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const origin = "https://127.0.0.1:" + port;
  let controller, consoleService;
  const server = createOrganizationServer({
    origin,
    tls: {
      cert: readFileSync(ca),
      key: readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/key.pem",
          import.meta.url,
        ),
      ),
    },
    controller: { handle: (...args) => controller.handle(...args) },
    console: {
      asset: (path) => consoleService?.asset(path),
      profile: (...args) => consoleService.profile(...args),
    },
    ready: async () => Boolean(controller),
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  cleanup.push(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  await withKeycloak(
    async (provider) => {
      await withPostgres(async ({ pool }) => {
        const upstream = await mcpFixture({ after: (fn) => cleanup.push(fn) });
        const browserStarting = chromium.launch({
          executablePath: process.env.XEIP_CHROME_PATH || undefined,
        });
        cleanup.push(async () => (await browserStarting).close());
        const browser = await browserStarting;
        // The exception is confined to this disposable browser context and fixture certificate.
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await context.newPage();
        const loginDiagnostics = [];
        let expectedNonce;
        page.on("console", (entry) => {
          if (entry.type() !== "error") return;
          const message = entry.text();
          loginDiagnostics.push({
            browserError: message.includes("CORS")
              ? "cors"
              : message.includes("Content Security Policy")
                ? "csp"
                : "other",
          });
        });
        page.on("request", (request) => {
          const url = new URL(request.url());
          if (
            url.origin + url.pathname ===
            provider.config.issuer + "/protocol/openid-connect/auth"
          )
            expectedNonce = url.searchParams.get("nonce");
        });
        page.on("requestfailed", (request) => {
          const url = new URL(request.url());
          if (
            url.origin === origin ||
            url.origin === new URL(provider.config.issuer).origin
          )
            loginDiagnostics.push({ failedPath: url.pathname });
        });
        page.on("response", async (response) => {
          if (
            response.url() !==
            provider.config.issuer + "/protocol/openid-connect/token"
          )
            return;
          const diagnostic = { tokenStatus: response.status() };
          loginDiagnostics.push(diagnostic);
          try {
            const body = await response.json();
            if (response.status() !== 200) {
              diagnostic.rejected = true;
              return;
            }
            const decode = (token) =>
              JSON.parse(
                Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
              );
            const claims = decode(body.access_token),
              idClaims = decode(body.id_token);
            Object.assign(diagnostic, {
              issuerMatches: claims.iss === provider.config.issuer,
              clientMatches: claims.azp === provider.browser.clientId,
              audienceMatches: [claims.aud]
                .flat()
                .includes(provider.config.audience),
              subjectMatches: claims.sub === provider.browser.subject,
              unexpired: claims.exp > Math.floor(Date.now() / 1000),
              nonceMatches: idClaims.nonce === expectedNonce,
            });
          } catch {
            diagnostic.unreadable = true;
          }
        });
        page.setDefaultTimeout(15000);
        page.setDefaultNavigationTimeout(60000);
        const agent = identity(provider.subjects.agent);
        let human = identity(provider.browser.subject);
        const session = "urn:test:browser:" + randomUUID();
        const directory = mkdtempSync(join(tmpdir(), "xeip-browser-trust-"));
        cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
        let trust;
        cleanup.push(() => trust?.close());
        function configure(enrolled) {
          if (enrolled) {
            trust.update({
              keyDocuments: [agent, human].map((a) => a.keyDocument),
              statusDocuments: [agent, human].map((a) => a.status),
            });
          } else {
            // Human root exists offline but is not published until operator enrollment.
            trust = new EntityTrustPolicy(
              { trustDir: join(directory, "trust"), maxAgeSeconds: 300 },
              [agent.keyDocument],
              [agent.status],
            );
          }
          const authentication = new KeycloakAuthenticator({
            ...provider.config,
            bindings: [agent, human].map(({ subject, entity, kid }) => ({
              subject,
              entity,
              kid,
            })),
          });
          const policy = new ActionPolicy({
            targets: [
              {
                id: upstream.config.id,
                revision: upstream.config.revision,
                recipient: upstream.config.recipient,
                tools: upstream.config.tools,
              },
            ],
            sessions: [
              {
                id: session,
                agents: [agent.subject],
                approvers: [human.subject],
                targets: ["internal"],
              },
            ],
          });
          controller = new OrganizationController({
            authentication,
            trust,
            gateway: upstream.config.recipient,
            createStore: (authorize) =>
              new ActionStore(pool, policy, authorize),
            execute: createActionExecutor(
              policy,
              new McpConnector([upstream.config]),
            ),
          });
          consoleService = createConsole({
            authentication,
            assets: loadConsoleAssets(),
            configuration: {
              issuer: provider.config.issuer,
              clientId: provider.browser.clientId,
              audience: provider.config.audience,
              gateway: upstream.config.recipient,
            },
          });
        }
        configure(false);
        let lastBearer;
        // Observe only in memory for a post-logout denial; never log tokens or record traces.
        page.on("request", (request) => {
          if (request.url() === origin + "/v1/console/profile")
            lastBearer = request.headers().authorization;
        });
        await page.goto(origin + "/console/");
        await page.locator("#sign-in").click({ timeout: 60000 });
        await expect(page).toHaveURL(
          new RegExp("/protocol/openid-connect/auth"),
        );
        const authUrl = new URL(page.url());
        expectedNonce = authUrl.searchParams.get("nonce");
        assert.equal(authUrl.origin, new URL(provider.config.issuer).origin);
        assert.equal(
          authUrl.pathname,
          new URL(provider.config.issuer).pathname +
            "/protocol/openid-connect/auth",
        );
        assert.equal(
          authUrl.searchParams.get("client_id"),
          provider.browser.clientId,
        );
        assert.equal(authUrl.searchParams.get("response_type"), "code");
        assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
        assert.ok(authUrl.searchParams.get("code_challenge"));
        assert.equal(
          authUrl.searchParams.get("redirect_uri"),
          origin + "/console/",
        );
        await page.locator("#username").fill(provider.browser.username);
        try {
          await page.locator("#password").fill(provider.browser.password);
        } catch {
          // Playwright includes fill values in error call logs; do not retain a cause.
          throw new Error("fixture password entry failed");
        }
        await page.locator("#kc-login").click({ timeout: 60000 });
        try {
          await expect(page.locator("#create-device")).toBeVisible();
        } catch (error) {
          console.error(
            "Redacted login diagnostics:",
            JSON.stringify(loginDiagnostics),
          );
          throw error;
        }
        await expect(page.locator("#session-id")).toBeDisabled();
        await expect(
          page.locator('#inspect-form button[type="submit"]'),
        ).toBeDisabled();
        await page.locator("#create-device").click();
        await expect(page.locator("#device-status")).toContainText(
          "not enrolled",
        );
        await expect(page.locator("#session-id")).toBeDisabled();
        await expect(
          page.locator('#inspect-form button[type="submit"]'),
        ).toBeDisabled();
        const enrollment = JSON.parse(
          await page.locator("#enrollment").inputValue(),
        );
        assert.deepEqual(Object.keys(enrollment).sort(), [
          "issuer",
          "kid",
          "subject",
        ]);
        assert.equal(enrollment.issuer, provider.config.issuer);
        assert.equal(enrollment.subject, provider.browser.subject);
        // Test operator endorses the browser's public key. No root key enters the browser.
        human = identity(provider.browser.subject, enrollment.kid, human.seed);
        configure(true);
        await page.locator("#check-enrollment").click();
        await expect(page.locator("#notice")).toContainText("Ready.");
        await page.reload();
        await page.locator("#sign-in").click({ timeout: 60000 }); // Existing real Keycloak SSO session; no password replay.
        await expect(page.locator("#notice")).toContainText("Ready.");
        assert.equal(
          JSON.parse(await page.locator("#enrollment").inputValue()).kid,
          enrollment.kid,
          "device persists across reload",
        );
        async function send(operation, id, digest) {
          const now = Math.floor(Date.now() / 1000);
          const data =
            operation === "propose"
              ? {
                  operation,
                  request: {
                    id,
                    session,
                    target: "internal",
                    tool: "lookup",
                    arguments: { query: "human reviewed fixture" },
                    expiresAt: now + 240,
                  },
                }
              : { operation, session, id, digest };
          const envelope = signEntityEnvelope(
            {
              xeip: "0.1",
              id: operation === "propose" ? id : "urn:test:op:" + randomUUID(),
              kind: "command",
              sender: agent.entity,
              recipient: upstream.config.recipient,
              session,
              timestamp: utc(now),
              expiresAt: utc(now + 60),
              body: {
                contentType: "application/vnd.xeip.organization-action+json",
                data,
              },
            },
            { privateKey: agent.seed, kid: agent.kid },
          );
          const response = await fetch(origin + "/v1/actions", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + (await provider.token("agent")),
            },
            body: JSON.stringify(envelope),
            signal: AbortSignal.timeout(30000),
            redirect: "error",
          });
          return { status: response.status, ...(await response.json()) };
        }
        const id = "urn:test:human-approved:" + randomUUID();
        const proposed = await send("propose", id);
        assert.equal(proposed.status, 200);
        assert.equal(proposed.state, "pending");
        await page.locator("#session-id").fill(session);
        await page.locator("#action-id").fill(id);
        await page.locator('#inspect-form button[type="submit"]').click();
        await expect(page.locator("#action-state")).toHaveText("pending");
        const action = proposed.proposal.action;
        await expect(page.locator("#action-heading")).toHaveText(action.tool);
        const readDetails = (selector) =>
          page
            .locator(selector)
            .evaluate((list) =>
              Object.fromEntries(
                [...list.querySelectorAll("dt")].map((term) => [
                  term.textContent,
                  term.nextElementSibling.textContent,
                ]),
              ),
            );
        assert.deepEqual(await readDetails("#action-details"), {
          Action: action.id,
          Session: action.session,
          Requester: action.actor.subject,
          Entity: action.actor.entity,
          "Device key": action.actor.kid,
          Target: action.target.id,
          Revision: action.target.revision,
          Recipient: action.target.recipient,
          Expires: new Date(action.expiresAt * 1000).toISOString(),
        });
        assert.deepEqual(await readDetails("#proof-details"), {
          Policy: action.policy,
          Digest: proposed.proposal.digest,
        });
        assert.deepEqual(
          JSON.parse(await page.locator("#arguments").textContent()),
          action.arguments,
        );
        assert.equal(upstream.state.calls.length, 0);
        await page.locator("#approve").click();
        await expect(page.locator("#action-state")).toHaveText("approved");
        assert.equal(
          upstream.state.calls.length,
          0,
          "human approval must not execute the tool",
        );
        const executed = await send("execute", id, proposed.proposal.digest);
        assert.equal(executed.status, 200);
        assert.equal(executed.state, "succeeded");
        assert.deepEqual(upstream.state.calls, [action.arguments]);
        assert.equal(
          (await send("execute", id, proposed.proposal.digest)).status,
          409,
        );
        assert.equal(
          upstream.state.calls.length,
          1,
          "replay must not repeat the effect",
        );
        assert.ok(lastBearer, "observed authenticated profile request");
        const tokenExpiry = JSON.parse(
          Buffer.from(lastBearer.slice(7).split(".")[1], "base64url").toString(
            "utf8",
          ),
        ).exp;
        assert.ok(
          tokenExpiry > Math.floor(Date.now() / 1000) + 30,
          "logout check requires an unexpired token with time remaining",
        );
        const beforeLogout = await fetch(origin + "/v1/console/profile", {
          headers: { Authorization: lastBearer },
          signal: AbortSignal.timeout(10000),
        });
        assert.equal(
          beforeLogout.status,
          200,
          "former token must be active immediately before logout",
        );
        await beforeLogout.arrayBuffer();
        await page.locator("#sign-out").click({ timeout: 60000 });
        await expect(page.locator("#sign-in")).toBeVisible();
        const loggedOut = await fetch(origin + "/v1/console/profile", {
          headers: { Authorization: lastBearer },
          signal: AbortSignal.timeout(10000),
        });
        assert.equal(
          loggedOut.status,
          401,
          "real provider logout revokes the former browser access token",
        );
        await loggedOut.arrayBuffer();
        assert.ok(
          tokenExpiry > Math.floor(Date.now() / 1000),
          "logout denial must precede token expiry",
        );
        lastBearer = undefined;
        console.log(
          "PASS real Keycloak browser: HTTPS PKCE login, explicit device enrollment, persistent key, exact review/approval, one MCP effect, replay refusal and live logout denial",
        );
      });
    },
    { browserOrigin: origin },
  );
} finally {
  try {
    await clean();
  } finally {
    unregisterCleanup();
  }
}
