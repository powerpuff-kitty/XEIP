import test from "node:test";
import assert from "node:assert/strict";
import { liveActionAuthorizer } from "./authorization.mjs";

test("requires provider revalidation and current trust for requester and approving key", async () => {
  const principal = Object.freeze({ entity: "agent", kid: "key-1" });
  const approver = Object.freeze({ entity: "human", kid: "key-2" });
  const allowed = new Set([principal.kid, approver.kid]);
  let active = true,
    calls = 0;
  const authorize = liveActionAuthorizer(
    {
      revalidate: async (p) => {
        calls++;
        return p === principal && active;
      },
    },
    { allows: (p) => allowed.has(p.kid) },
  );
  assert.equal(await authorize(principal, { phase: "claim", approver }), true);
  allowed.delete(approver.kid);
  assert.equal(await authorize(principal, { phase: "claim", approver }), false);
  allowed.add(approver.kid);
  allowed.delete(principal.kid);
  assert.equal(await authorize(principal, { phase: "propose" }), false);
  allowed.add(principal.kid);
  active = false;
  assert.equal(await authorize(principal, { phase: "propose" }), false);
  active = true;
  assert.equal(await authorize({ ...principal }, { phase: "propose" }), false);
  assert.equal(calls, 5);
});

test("trust revocation during provider await takes effect; provider failure propagates", async () => {
  let resolve,
    allowed = true;
  const principal = Object.freeze({ entity: "agent", kid: "key" });
  const authorize = liveActionAuthorizer(
    {
      revalidate: () =>
        new Promise((r) => {
          resolve = r;
        }),
    },
    { allows: () => allowed },
  );
  const result = authorize(principal, { phase: "propose" });
  allowed = false;
  resolve(true);
  assert.equal(await result, false);
  const failure = new Error("provider unavailable");
  const unavailable = liveActionAuthorizer(
    {
      revalidate: async () => {
        throw failure;
      },
    },
    { allows: () => true },
  );
  await assert.rejects(
    unavailable(principal, { phase: "propose" }),
    (error) => error === failure,
  );
});
