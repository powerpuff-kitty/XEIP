import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// Exercise the exact session logic with only the imported provider adapter
// replaced. Browser conformance separately runs the real pinned adapter.
async function fixture(t, phase) {
  let complete;
  const pending = new Promise((resolve) => {
    complete = resolve;
  });
  const adapter = {
    authenticated: true,
    token: undefined,
    refreshToken: undefined,
    install() {
      this.token = "synthetic-access";
      this.refreshToken = "synthetic-refresh";
      this.tokenParsed = {
        sub: "human",
        iss: "https://id.example/realms/org",
        azp: "console",
        aud: "api",
        exp: Math.floor(Date.now() / 1000) + 300,
      };
    },
    async init() {
      if (phase === "init") await pending;
      this.install();
      return true;
    },
    async updateToken() {
      await pending;
      this.install();
      return true;
    },
    clearToken() {
      const had = !!this.token;
      this.token = undefined;
      this.refreshToken = undefined;
      this.authenticated = false;
      if (had) this.onAuthLogout?.();
    },
  };
  const key = "xeip-session-test-" + crypto.randomUUID();
  globalThis[key] = adapter;
  const before = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", {
    value: { origin: "https://xeip.example" },
    configurable: true,
  });
  t.after(() => {
    delete globalThis[key];
    if (before) Object.defineProperty(globalThis, "location", before);
    else delete globalThis.location;
  });
  const source = await readFile(
    new URL("./session.mjs", import.meta.url),
    "utf8",
  );
  const original = 'import Keycloak from "keycloak-js";';
  assert.ok(source.includes(original));
  const isolated = source.replace(
    original,
    `const Keycloak=class {constructor(){return globalThis[${JSON.stringify(key)}];}};`,
  );
  const { browserSession } = await import(
    "data:text/javascript;base64," + Buffer.from(isolated).toString("base64")
  );
  let invalidations = 0;
  const session = browserSession(
    {
      issuer: "https://id.example/realms/org",
      clientId: "console",
      gateway: "unused",
      audience: "api",
    },
    () => {
      invalidations++;
    },
  );
  return { adapter, session, complete, invalidations: () => invalidations };
}
for (const phase of ["init", "refresh"])
  test(`late ${phase} clears newly installed tokens after local closure`, async (t) => {
    const f = await fixture(t, phase);
    if (phase === "refresh") await f.session.init();
    const pending = phase === "init" ? f.session.init() : f.session.token();
    f.session.close();
    f.complete();
    await assert.rejects(pending);
    assert.equal(f.adapter.token, undefined);
    assert.equal(f.adapter.refreshToken, undefined);
    assert.equal(f.invalidations(), 1);
    await assert.rejects(f.session.token());
  });
