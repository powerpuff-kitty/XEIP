/** Controlled OIDC/transport fixture, not real Keycloak or organization authorization. */
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { ActionPolicy } from "../actions.mjs";
import { entityEnvelopeSigningInput } from "../../../sdks/typescript/dist/entity-envelope.js";
import { decodeKeyId } from "../../../sdks/typescript/dist/identity.js";
import { createConsole } from "../console-server.mjs";
const origin = "https://xeip.example",
  issuer = "https://identity.example/realms/org";
const human =
  "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const agent =
  "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG";
const jwt = (value) =>
  Buffer.from('{"alg":"none"}').toString("base64url") +
  "." +
  Buffer.from(JSON.stringify(value)).toString("base64url") +
  ".fixture";
async function fixture(page) {
  const state = {
    kid: null,
    nonce: null,
    challenge: null,
    calls: [],
    decision: "pending",
    lose: false,
    account: "human",
    tokenLifetime: 600,
    tokenRequests: 0,
    corrupt: false,
    refreshFail: false,
    tokenGate: null,
  };
  const securityHeaders = createConsole({
    configuration: {
      issuer,
      clientId: "console",
      gateway: human,
      audience: "xeip-api",
    },
    authentication: {},
    assets: new Map(),
  }).asset("/console/config").headers;
  const now = Math.floor(Date.now() / 1000);
  const proposal = new ActionPolicy({
    targets: [
      {
        id: "internal",
        revision: "deployment-1",
        recipient: agent,
        tools: ["lookup"],
      },
    ],
    sessions: [
      {
        id: "urn:xeip:session:operations",
        agents: ["agent"],
        approvers: ["human"],
        targets: ["internal"],
      },
    ],
  }).propose(
    {
      subject: "agent",
      entity: agent,
      kid: agent.slice(16),
      clientId: "agent",
      roles: ["agent"],
      expiresAt: now + 600,
    },
    {
      id: "request-1",
      session: "urn:xeip:session:operations",
      target: "internal",
      tool: "lookup",
      arguments: {
        query: '<img src=x onerror="window.injected=true">',
        limit: 1,
      },
      expiresAt: now + 300,
    },
  );
  await page.route(issuer + "/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/auth")) {
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("redirect_uri")).toBe(origin + "/console/");
      state.nonce = url.searchParams.get("nonce");
      state.challenge = url.searchParams.get("code_challenge");
      await route.fulfill({
        status: 302,
        headers: {
          location:
            origin +
            "/console/#" +
            new URLSearchParams({
              code: "controlled-code",
              state: url.searchParams.get("state"),
              iss: issuer,
            }),
        },
      });
      return;
    }
    if (url.pathname.endsWith("/token")) {
      state.tokenRequests++;
      if (state.tokenGate) await state.tokenGate;
      const body = new URLSearchParams(route.request().postData());
      if (state.refreshFail && body.get("grant_type") === "refresh_token") {
        await route.fulfill({
          status: 401,
          json: { error: "invalid_grant" },
          headers: {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
          },
        });
        return;
      }
      if (body.get("grant_type") === "authorization_code")
        expect(
          createHash("sha256")
            .update(body.get("code_verifier"))
            .digest("base64url"),
        ).toBe(state.challenge);
      const now = Math.floor(Date.now() / 1000),
        claims = {
          sub: state.account,
          iss: issuer,
          azp: "console",
          aud: "xeip-api",
          iat: now,
          exp: now + state.tokenLifetime,
        };
      await route.fulfill({
        json: {
          access_token: jwt(claims),
          refresh_token: jwt({ ...claims, exp: now + 3600 }),
          id_token: jwt({ ...claims, nonce: state.nonce }),
          expires_in: state.tokenLifetime,
          token_type: "Bearer",
        },
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
        },
      });
      return;
    }
    if (url.pathname.endsWith("/logout")) {
      await route.fulfill({
        status: 302,
        headers: { location: origin + "/console/" },
      });
      return;
    }
    await route.abort();
  });
  await page.route(origin + "/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const files = {
      "/console/": ["index.html", "text/html"],
      "/console/app.js": ["app.js", "text/javascript"],
      "/console/app.css": ["app.css", "text/css"],
    };
    if (files[path]) {
      await route.fulfill({
        body: await readFile(
          new URL("../../../dist/console/" + files[path][0], import.meta.url),
        ),
        contentType: files[path][1],
        headers: securityHeaders,
      });
      return;
    }
    if (path === "/console/config") {
      await route.fulfill({
        json: {
          issuer,
          clientId: "console",
          gateway: human,
          audience: "xeip-api",
        },
      });
      return;
    }
    if (path === "/v1/console/profile") {
      await route.fulfill(
        state.kid
          ? {
              json: {
                subject: "human",
                entity: human,
                kid: state.kid,
                expiresAt: Math.floor(Date.now() / 1000) + 600,
              },
            }
          : { status: 403, json: { error: "forbidden" } },
      );
      return;
    }
    if (path === "/v1/actions") {
      const envelope = route.request().postDataJSON(),
        command = envelope.body.data;
      const key = await crypto.subtle.importKey(
        "raw",
        decodeKeyId(state.kid),
        "Ed25519",
        false,
        ["verify"],
      );
      expect(
        await crypto.subtle.verify(
          "Ed25519",
          key,
          Buffer.from(envelope.extensions["xeip.sig"].sig, "base64url"),
          new TextEncoder().encode(entityEnvelopeSigningInput(envelope)),
        ),
      ).toBe(true);
      expect(envelope.sender).toBe(human);
      expect(envelope.extensions["xeip.sig"].kid).toBe(state.kid);
      state.calls.push(command);
      if (command.operation !== "inspect") {
        expect(command.digest).toBe(proposal.digest);
        state.decision = {
          approve: "approved",
          reject: "rejected",
          revoke: "revoked",
        }[command.operation];
      }
      if (state.lose && command.operation !== "inspect") {
        state.lose = false;
        await route.abort("failed");
        return;
      }
      await route.fulfill({
        json: {
          state: state.decision,
          proposal: state.corrupt
            ? { ...proposal, digest: "0".repeat(64) }
            : proposal,
          result: null,
        },
      });
      return;
    }
    await route.fulfill({ status: 404, body: "" });
  });
  return state;
}
async function enrolled(page, state) {
  await page.goto(origin + "/console/");
  await page.getByRole("button", { name: "Sign in with Keycloak" }).click();
  await page.getByRole("button", { name: "Create device key" }).click();
  const enrollment = page.getByLabel("Public enrollment request");
  await expect(enrollment).toBeVisible();
  state.kid = JSON.parse(await enrollment.inputValue()).kid;
  await page.getByRole("button", { name: "Check enrollment" }).click();
  await expect(page.getByLabel("Session ID")).toBeEnabled();
}
async function inspect(page) {
  await page.getByLabel("Session ID").fill("urn:xeip:session:operations");
  await page.getByLabel("Action ID", { exact: true }).fill("request-1");
  await page
    .getByRole("button", { name: "Inspect action", exact: true })
    .click();
  await expect(page.locator("#review")).toBeVisible();
}
test("code/PKCE login, enrollment, exact review and explicit approval/revoke work in a browser", async ({
  page,
}) => {
  const state = await fixture(page);
  await enrolled(page, state);
  expect(state.tokenRequests).toBe(1);
  await inspect(page);
  await expect(page.locator("#arguments")).toContainText("<img src=x");
  expect(await page.evaluate(() => window.injected)).toBeUndefined();
  await expect(
    page.getByRole("button", { name: "Approve this action" }),
  ).toBeEnabled();
  await page.screenshot({
    path: "/tmp/xeip-console-desktop.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Approve this action" }).click();
  await expect(page.locator("#action-state")).toHaveText("approved");
  await expect(
    page.getByRole("button", { name: "Approve this action" }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Revoke consent" }).click();
  await expect(page.locator("#action-state")).toHaveText("revoked");
  expect(state.calls.map((x) => x.operation)).toEqual([
    "inspect",
    "approve",
    "revoke",
  ]);
  const storage = await page.evaluate(() =>
    JSON.stringify({
      local: { ...localStorage },
      session: { ...sessionStorage },
    }),
  );
  expect(storage).not.toContain("access_token");
  expect(storage).not.toContain("refresh_token");
});
test("lost decision response requires inspection and does not retry", async ({
  page,
}) => {
  const state = await fixture(page);
  await enrolled(page, state);
  await inspect(page);
  state.lose = true;
  await page.getByRole("button", { name: "Approve this action" }).click();
  await expect(page.locator("#review")).toBeHidden();
  await expect(page.locator("#notice")).toContainText("could not be confirmed");
  expect(state.calls.filter((x) => x.operation === "approve")).toHaveLength(1);
  await inspect(page);
  await expect(page.locator("#action-state")).toHaveText("approved");
});
test("digest mismatch cannot enable a decision", async ({ page }) => {
  const state = await fixture(page);
  await enrolled(page, state);
  state.corrupt = true;
  await page.getByLabel("Session ID").fill("urn:xeip:session:operations");
  await page.getByLabel("Action ID", { exact: true }).fill("request-1");
  await page
    .getByRole("button", { name: "Inspect action", exact: true })
    .click();
  await expect(page.locator("#notice")).toContainText("could not be verified");
  await expect(page.locator("#review")).toBeHidden();
  expect(state.calls).toHaveLength(1);
});
test("rejection is explicit and mobile review remains within the viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const state = await fixture(page);
  await enrolled(page, state);
  await inspect(page);
  await page
    .getByRole("button", { name: "Reject action", exact: true })
    .click();
  await expect(page.locator("#action-state")).toHaveText("rejected");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "/tmp/xeip-console-mobile.png",
    fullPage: true,
  });
});
test("unmapped or changed device cannot inspect", async ({ page }) => {
  const state = await fixture(page);
  await enrolled(page, state);
  state.kid = agent.slice(16);
  await page.getByRole("button", { name: "Check enrollment" }).click();
  await expect(page.getByLabel("Session ID")).toBeDisabled();
  await expect(page.locator("#notice")).toContainText("does not match");
  expect(state.calls).toHaveLength(0);
});
test("refresh changing the account clears the review before any decision is sent", async ({
  page,
}) => {
  const state = await fixture(page);
  state.tokenLifetime = 20;
  await enrolled(page, state);
  await inspect(page);
  state.account = "other";
  await page.getByRole("button", { name: "Approve this action" }).click();
  await expect(page.locator("#notice")).toContainText("session ended");
  await expect(page.locator("#review")).toBeHidden();
  expect(state.calls.map((x) => x.operation)).toEqual(["inspect"]);
});
test("refresh failure clears approval authority", async ({ page }) => {
  const state = await fixture(page);
  state.tokenLifetime = 20;
  await enrolled(page, state);
  await inspect(page);
  state.refreshFail = true;
  await page.getByRole("button", { name: "Approve this action" }).click();
  await expect(page.locator("#review")).toBeHidden();
  await expect(page.locator("#notice")).toContainText("session ended");
  expect(state.calls).toHaveLength(1);
});
test("duplicate clicks record only one decision", async ({ page }) => {
  const state = await fixture(page);
  await enrolled(page, state);
  await inspect(page);
  await page.locator("#approve").evaluate((button) => {
    button.click();
    button.click();
  });
  await expect(page.locator("#action-state")).toHaveText("approved");
  expect(state.calls.filter((x) => x.operation === "approve")).toHaveLength(1);
});
test("expiry disables decision controls while preserving inspectable history", async ({
  page,
}) => {
  await page.clock.install();
  const state = await fixture(page);
  await enrolled(page, state);
  await inspect(page);
  await page.clock.fastForward(301000);
  await expect(
    page.getByRole("button", { name: "Approve this action" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Reject action", exact: true }),
  ).toBeDisabled();
  await expect(page.locator("#review")).toBeVisible();
  expect(state.calls).toHaveLength(1);
});
test("signing out clears the view and does not revoke previously granted consent", async ({
  page,
}) => {
  const state = await fixture(page);
  await enrolled(page, state);
  await inspect(page);
  await page.getByRole("button", { name: "Approve this action" }).click();
  await expect(page.locator("#action-state")).toHaveText("approved");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Sign in with Keycloak" }),
  ).toBeVisible();
  await expect(page.locator("#review")).toBeHidden();
  expect(state.decision).toBe("approved");
  expect(state.calls.filter((x) => x.operation === "revoke")).toHaveLength(0);
});
test("a stalled code exchange expires the local session and a late token cannot reactivate it", async ({
  page,
}) => {
  await page.clock.install();
  const state = await fixture(page);
  let release;
  state.tokenGate = new Promise((resolve) => {
    release = resolve;
  });
  await page.goto(origin + "/console/");
  await page.getByRole("button", { name: "Sign in with Keycloak" }).click();
  await expect.poll(() => state.tokenRequests).toBe(1);
  await page.clock.fastForward(26000);
  await expect(page.locator("#notice")).toContainText("session ended");
  release();
  await expect(
    page.getByRole("button", { name: "Create device key" }),
  ).toBeHidden();
  await expect(page.getByLabel("Session ID")).toBeDisabled();
  expect(state.calls).toHaveLength(0);
});
