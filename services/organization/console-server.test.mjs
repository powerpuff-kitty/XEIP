import test from "node:test";
import assert from "node:assert/strict";
import { createConsole } from "./console-server.mjs";
const configuration = {
  issuer: "https://identity.example/realms/org",
  clientId: "human-console",
  gateway: "gateway",
  audience: "xeip-api",
};
const principal = {
  subject: "human",
  entity: "entity",
  kid: "key",
  clientId: "human-console",
  roles: ["approver"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};
function fixture(value = principal) {
  let releases = 0;
  const authentication = {
    authenticate: async () => value,
    revalidate: async () => true,
    release: (p) => {
      assert.equal(p, value);
      releases++;
    },
  };
  const console = createConsole({
    configuration,
    authentication,
    assets: new Map([
      [
        "/console/",
        { type: "text/html; charset=utf-8", body: Buffer.from("fixture") },
      ],
    ]),
  });
  return { console, authentication, releases: () => releases };
}
test("profile requires the configured client and approver role and releases every mapped principal", async () => {
  for (const value of [
    null,
    { ...principal, clientId: "agent" },
    { ...principal, roles: ["agent"] },
    { ...principal, expiresAt: 0 },
  ]) {
    const f = fixture(value);
    await assert.rejects(
      f.console.profile("Bearer token", {
        signal: new AbortController().signal,
      }),
      (e) => [401, 403].includes(e.status),
    );
    assert.equal(f.releases(), value ? 1 : 0);
  }
});
test("profile returns only enrollment mapping; bearer and role internals stay private", async () => {
  const f = fixture();
  assert.deepEqual(
    await f.console.profile("Bearer token", {
      signal: new AbortController().signal,
    }),
    {
      subject: "human",
      entity: "entity",
      kid: "key",
      expiresAt: principal.expiresAt,
    },
  );
  assert.equal(f.releases(), 1);
});
test("aborted profile releases a principal returned after the client leaves", async () => {
  const f = fixture(),
    abort = new AbortController();
  f.authentication.authenticate = async () => {
    abort.abort();
    return principal;
  };
  await assert.rejects(
    f.console.profile("Bearer token", { signal: abort.signal }),
    (e) => e.status === 503,
  );
  assert.equal(f.releases(), 1);
});
test("fixed assets and bootstrap expose no arbitrary path or authentication secrets", () => {
  const f = fixture();
  assert.equal(f.console.asset("/console/../main.mjs"), undefined);
  assert.equal(f.console.asset("/console/?token=secret"), undefined);
  const response = f.console.asset("/console/config");
  assert.deepEqual(JSON.parse(response.body.toString()), configuration);
  assert.match(
    response.headers["Content-Security-Policy"],
    /connect-src 'self' https:\/\/identity.example/,
  );
  assert.equal(response.headers["Referrer-Policy"], "no-referrer");
});
