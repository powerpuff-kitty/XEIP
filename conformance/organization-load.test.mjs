import test from "node:test";
import assert from "node:assert/strict";
import { measureOrganizationLoad } from "./organization-load.mjs";

test("capacity reports requested, dispatched and failed actions independently", async () => {
  let now = 0;
  const report = await measureOrganizationLoad({
    agents: Array.from({ length: 200 }, (_, i) => ({ subject: "agent-" + i })),
    humans: Array.from({ length: 500 }, (_, i) => ({ subject: "human-" + i })),
    clock: {
      now: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    },
    send: async () => ({ status: 503, latencyMs: 10 }),
  });
  assert.equal(report.requestedActions, 600);
  assert.equal(report.dispatchedActions, 600);
  assert.equal(report.completed, 0);
  assert.equal(report.failedActions, 600);
  assert.equal(report.failures.length, 600);
  assert.equal(report.passed, false);
});
