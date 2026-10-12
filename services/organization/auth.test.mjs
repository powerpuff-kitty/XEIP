import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK } from "jose";
import { KeycloakAuthenticator, IdentityProviderUnavailable } from "./auth.mjs";
import { fixture, entity, kid } from "./test-fixtures/provider.mjs";
test("readiness checks pinned discovery, fresh JWKS and configured introspection credentials", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config);
  assert.equal(await auth.ready(), true);
  f.state.discovery = { issuer: "https://wrong.invalid" };
  assert.equal(await auth.ready(), false);
  f.state.discovery = undefined;
  f.state.jwksStatus = 302;
  assert.equal(await auth.ready(), false);
  f.state.jwksStatus = 200;
  assert.equal(
    await new KeycloakAuthenticator({
      ...f.config,
      introspectionClientSecret: "wrong",
    }).ready(),
    false,
  );
  f.state.introspection = { active: true };
  assert.equal(await auth.ready(), false);
  f.state.introspection = undefined;
  f.state.jwks = { keys: [] };
  assert.equal(await auth.ready(), false);
});
test("readiness fails closed on a bounded provider timeout", async (t) => {
  const f = await fixture(t);
  f.state.delay = 200;
  assert.equal(
    await new KeycloakAuthenticator({ ...f.config, timeoutMs: 100 }).ready(),
    false,
  );
});
test("Keycloak access tokens map to immutable explicit principals and revalidate live status", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config),
    token = await f.token();
  const principal = await auth.authenticate("Bearer " + token);
  assert.equal(principal.subject, "user-1");
  assert.equal(principal.entity, entity);
  assert.equal(principal.kid, kid);
  assert.deepEqual(principal.roles, ["approver"]);
  assert.equal(Object.isFrozen(principal), true);
  assert.equal(Object.isFrozen(principal.roles), true);
  assert.equal(JSON.stringify(principal).includes(token), false);
  assert.equal(
    JSON.stringify(principal).includes("fixture-only-secret"),
    false,
  );
  assert.equal(await auth.revalidate(principal), true);
  assert.equal(await auth.revalidate({ ...principal }), false);
  f.state.active = false;
  assert.equal(await auth.revalidate(principal), false);
  assert.equal(await auth.authenticate("Bearer " + token), null);
});
for (const [name, patch] of [
  ["wrong issuer", { iss: "https://other.invalid/realm" }],
  ["wrong audience", { aud: "other" }],
  ["wrong authorized client", { azp: "other" }],
  ["ID token", { typ: "ID" }],
  ["missing subject", { sub: undefined }],
  ["unknown subject", { sub: "unknown" }],
  ["missing token ID", { jti: undefined }],
  ["missing expiration", { exp: undefined }],
  ["noninteger expiration", { exp: 100.5 }],
  ["expired", { exp: 1 }],
  ["future issuance", { iat: 4102444800, exp: 4102444920 }],
  ["overlong lifetime", { iat: 1, exp: 4102444800 }],
  ["missing issuance", { iat: undefined }],
])
  test("rejects " + name, async (t) => {
    const f = await fixture(t),
      auth = new KeycloakAuthenticator(f.config);
    assert.equal(
      await auth.authenticate("Bearer " + (await f.token(patch))),
      null,
    );
  });
test("forged signatures and unsupported algorithms are unauthenticated", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config);
  const other = await generateKeyPair("RS256");
  assert.equal(
    await auth.authenticate("Bearer " + (await f.token({}, other.privateKey))),
    null,
  );
  const hmac = new Uint8Array(32).fill(7);
  assert.equal(
    await auth.authenticate(
      "Bearer " + (await f.token({}, hmac, { alg: "HS256" })),
    ),
    null,
  );
  assert.equal(await auth.authenticate("Bearer " + "a".repeat(17000)), null);
  assert.equal(await auth.authenticate("Basic abc"), null);
});
test("configuration pins issuer and explicit unique subject mappings", async (t) => {
  const f = await fixture(t);
  for (const patch of [
    { allowInsecureLoopback: false },
    { issuer: "http://example.com/realms/a" },
    { issuer: f.config.issuer + "?x=1" },
    { issuer: "https://user:pass@example.com/realm" },
    { audience: "" },
    { clientIds: [] },
    { bindings: [f.config.bindings[0], f.config.bindings[0]] },
    { bindings: [{ subject: "a", entity, kid: "bad" }] },
    { introspectionClientSecret: "" },
    { maxTokenLifetimeSeconds: 99999 },
    { timeoutMs: 0 },
  ])
    assert.throws(() => new KeycloakAuthenticator({ ...f.config, ...patch }));
  const auth = new KeycloakAuthenticator(f.config);
  f.config.bindings[0].entity = "urn:untrusted";
  assert.equal(
    (await auth.authenticate("Bearer " + (await f.token()))).entity,
    entity,
  );
});
for (const [name, mutate] of [
  [
    "JWKS server failure",
    (f) => {
      f.state.jwksStatus = 503;
    },
  ],
  [
    "JWKS redirect",
    (f) => {
      f.state.jwksStatus = 302;
    },
  ],
  [
    "oversized JWKS",
    (f) => {
      f.state.jwks = { padding: "x".repeat(70000) };
    },
  ],
  [
    "introspection server failure",
    (f) => {
      f.state.introspectionStatus = 503;
    },
  ],
  [
    "malformed active response",
    (f) => {
      f.state.introspection = { active: "true" };
    },
  ],
  [
    "mismatched active subject",
    (f) => {
      f.state.introspection = {
        active: true,
        sub: "other",
        client_id: "xeip-console",
        exp: 1,
      };
    },
  ],
  [
    "provider timeout",
    (f) => {
      f.state.delay = 400;
    },
  ],
])
  test(name + " fails unavailable without leaking credentials", async (t) => {
    const f = await fixture(t);
    if (name === "provider timeout") f.config.timeoutMs = 100;
    const auth = new KeycloakAuthenticator(f.config),
      token = await f.token();
    mutate(f);
    await assert.rejects(auth.authenticate("Bearer " + token), (error) => {
      assert.ok(error instanceof IdentityProviderUnavailable);
      assert.equal(String(error).includes(token), false);
      assert.equal(String(error).includes("fixture-only-secret"), false);
      return true;
    });
  });

test("unknown signing keys are denied and a rotated realm key is fetched after cooldown", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config);
  assert.ok(await auth.authenticate("Bearer " + (await f.token())));
  const rotated = await generateKeyPair("RS256");
  const token = await f.token({}, rotated.privateKey, { kid: "rotated-key" });
  assert.equal(await auth.authenticate("Bearer " + token), null);
  f.state.jwks = {
    keys: [
      {
        ...(await exportJWK(rotated.publicKey)),
        kid: "rotated-key",
        alg: "RS256",
        use: "sig",
      },
    ],
  };
  const realNow = Date.now();
  t.mock.method(Date, "now", () => realNow + 31000);
  assert.ok(await auth.authenticate("Bearer " + token));
});

test("released and expired principals cannot be reused even while callers retain them", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config),
    token = await f.token();
  const principal = await auth.authenticate("Bearer " + token);
  auth.release(principal);
  assert.equal(await auth.revalidate(principal), false);
  const expiring = await auth.authenticate("Bearer " + token);
  const now = Date.now();
  const mocked = t.mock.method(Date, "now", () => now + 121000);
  assert.equal(await auth.revalidate(expiring), false);
  mocked.mock.restore();
  assert.equal(await auth.revalidate(expiring), false);
});
for (const [name, nbf] of [
  ["negative", -1],
  ["fractional", 0.5],
  ["nonnumeric", "yesterday"],
  ["future", 4102444800],
]) {
  test("rejects " + name + " not-before claim", async (t) => {
    const f = await fixture(t),
      auth = new KeycloakAuthenticator(f.config);
    assert.equal(
      await auth.authenticate("Bearer " + (await f.token({ nbf }))),
      null,
    );
  });
}

test("releasing a principal during asynchronous revalidation cannot reactivate it", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config);
  const principal = await auth.authenticate("Bearer " + (await f.token()));
  const pending = auth.revalidate(principal);
  auth.release(principal);
  assert.equal(await pending, false);
});

test("rejects a token that does not authorize the confidential introspection audience", async (t) => {
  const f = await fixture(t),
    auth = new KeycloakAuthenticator(f.config);
  assert.equal(
    await auth.authenticate("Bearer " + (await f.token({ aud: "xeip-api" }))),
    null,
  );
});
