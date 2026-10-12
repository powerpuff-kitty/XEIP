import test from "node:test";
import assert from "node:assert/strict";
import { createActionExecutor } from "./execution.mjs";
import { ConnectorFailure } from "./mcp.mjs";
import { StoreUnavailable } from "./store.mjs";
function fixture(captureControl) {
  const events = [],
    agent = Object.freeze({ subject: "agent" }),
    approver = Object.freeze({ subject: "human" }),
    proposal = {
      action: { tool: "lookup", arguments: { query: "approved" } },
      digest: "a".repeat(64),
    };
  const state = {
    eligible: true,
    finishFailure: false,
    claimFailure: false,
    outcome: { content: [{ type: "text", text: "ok" }] },
    gate: true,
  };
  const store = {
    claim: async () => {
      events.push("claim");
      if (state.claimFailure) throw new StoreUnavailable();
      return { state: "executing", claimId: "claim", proposal, approver };
    },
    finish: async (...args) => {
      events.push(["finish", ...args]);
      if (state.finishFailure) throw new StoreUnavailable();
      return { state: args[3], proposal, result: args[4] };
    },
  };
  const policy = {
    canExecute: () => state.eligible,
    canApprove: () => state.eligible,
  };
  const connector = {
    call: async (action, { beforeSend, dispatch }) => {
      events.push("connect");
      assert.equal(action, proposal.action);
      if (!(await beforeSend())) throw new ConnectorFailure(false);
      const send = () => {
        events.push("send");
        if (state.outcome instanceof Error) throw state.outcome;
        return state.outcome;
      };
      return dispatch ? dispatch(send) : send();
    },
  };
  const authorize = async (principal, context) => {
    events.push("authorize");
    assert.equal(principal, agent);
    assert.equal(context.approver, approver);
    return state.gate;
  };
  return {
    events,
    state,
    execute: createActionExecutor(policy, connector, captureControl),
    run: () => {},
    agent,
    context: { store, authorize },
    command: { session: "session", id: "request", digest: proposal.digest },
  };
}
test("persists a unique claim before sending and persists the result before returning success", async () => {
  const f = fixture(),
    result = await f.execute(f.agent, f.command, f.context);
  assert.equal(result.state, "succeeded");
  assert.deepEqual(result.result, f.state.outcome);
  assert.deepEqual(f.events.slice(0, 4), [
    "claim",
    "connect",
    "authorize",
    "send",
  ]);
  assert.equal(f.events[4][0], "finish");
});
test("ambiguous claim commit never starts a connector", async () => {
  const f = fixture();
  f.state.claimFailure = true;
  await assert.rejects(
    f.execute(f.agent, f.command, f.context),
    StoreUnavailable,
  );
  assert.deepEqual(f.events, ["claim"]);
});
test("ambiguous completion never returns success or retries the upstream call", async () => {
  const f = fixture();
  f.state.finishFailure = true;
  await assert.rejects(
    f.execute(f.agent, f.command, f.context),
    StoreUnavailable,
  );
  assert.equal(f.events.filter((e) => e === "send").length, 1);
});
for (const sent of [false, true])
  test(
    "records " +
      (sent ? "indeterminate" : "failed") +
      " on " +
      (sent ? "post-send" : "pre-send") +
      " connector failure",
    async () => {
      const f = fixture();
      f.state.outcome = new ConnectorFailure(sent);
      const result = await f.execute(f.agent, f.command, f.context);
      assert.equal(result.state, sent ? "indeterminate" : "failed");
      assert.equal(result.result, null);
    },
  );
test("explicit tool errors record failed with their bounded result", async () => {
  const f = fixture();
  f.state.outcome = { content: [], isError: true };
  assert.equal(
    (await f.execute(f.agent, f.command, f.context)).state,
    "failed",
  );
});
test("revocation and policy denial after the claim prevent the effect", async () => {
  for (const mode of ["gate", "eligible"]) {
    const f = fixture();
    f.state[mode] = false;
    assert.equal(
      (await f.execute(f.agent, f.command, f.context)).state,
      "failed",
    );
    assert.equal(f.events.includes("send"), false);
  }
});
test("request cancellation after the durable claim prevents the effect", async () => {
  const f = fixture(),
    abort = new AbortController();
  abort.abort();
  assert.equal(
    (
      await f.execute(f.agent, f.command, {
        ...f.context,
        signal: abort.signal,
      })
    ).state,
    "failed",
  );
  assert.equal(f.events.includes("send"), false);
});

for (const mode of ["revision", "request"]) {
  test(`final ${mode} change after asynchronous validation consumes claim without sending`, async () => {
    let current = true,
      validated = 0;
    const f = fixture(() => ({
      validate: async () => {
        validated++;
        current = false;
      },
      dispatch: (send) => {
        if (mode === "revision" && !current) throw new ConnectorFailure(false);
        return send();
      },
    }));
    const result = await f.execute(f.agent, f.command, {
      ...f.context,
      current: () => mode !== "request" || current,
    });
    assert.equal(validated, 1);
    assert.equal(result.state, "failed");
    assert.equal(f.events.includes("claim"), true);
    assert.equal(f.events.includes("send"), false);
    assert.equal(f.events.at(-1)[0], "finish");
  });
}

test("provider revocation during the durable head wait is rechecked before dispatch", async () => {
  const f = fixture(() => ({
    validate: async () => {
      f.state.gate = false;
    },
    dispatch: (send) => send(),
  }));
  const result = await f.execute(f.agent, f.command, f.context);
  assert.equal(result.state, "failed");
  assert.equal(f.events.includes("send"), false);
});
