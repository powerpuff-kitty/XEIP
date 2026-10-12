import test from "node:test";
import assert from "node:assert/strict";
import { Telemetry } from "./telemetry.mjs";
test("request metrics have bounded labels and logs omit arbitrary secrets, paths and payloads", () => {
  const logs = [];
  const telemetry = new Telemetry((line) => logs.push(line));
  telemetry.request({
    id: "ignored secret id",
    route: "actions",
    operation: "execute",
    status: 200,
    state: "succeeded",
    elapsedMs: 1200,
    password: "do-not-log",
  });
  telemetry.request({
    id: "other secret",
    route: "/secret/path",
    operation: "secret-tool",
    status: 999,
    state: "secret-result",
    elapsedMs: NaN,
  });
  const output = telemetry.metrics();
  assert.match(
    output,
    /xeip_requests_total\{route="actions",operation="execute",status="200"\} 1/,
  );
  assert.match(
    output,
    /xeip_request_duration_seconds_bucket\{route="actions",le="2"\} 1/,
  );
  assert.match(output, /xeip_action_outcomes_total\{state="succeeded"\} 1/);
  assert.equal(logs.length, 2);
  for (const secret of ["do-not-log", "secret", "password", "NaN"])
    assert.equal((output + logs.join("")).includes(secret), false);
  assert.equal(JSON.parse(logs[0]).operation, "execute");
  assert.match(JSON.parse(logs[0]).requestId, /^[0-9a-f-]{36}$/);
});
test("health and lifecycle events use fixed codes and failing logging does not break operation recording", () => {
  const telemetry = new Telemetry(() => {
    throw new Error("secret sink");
  });
  telemetry.event("started");
  telemetry.event("secret code");
  telemetry.health(true, 3);
  telemetry.request({
    route: "actions",
    operation: "approve",
    status: 403,
    state: "unknown",
    elapsedMs: 20,
  });
  const metrics = telemetry.metrics();
  assert.match(metrics, /xeip_ready 1/);
  assert.match(metrics, /xeip_active_operations 3/);
  assert.match(metrics, /xeip_log_failures_total 2/);
  assert.equal(metrics.includes("secret"), false);
});
