// Open-loop machine workload. Approval actors are simulated; no human timing claim.
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
export async function measureOrganizationLoad({
  agents,
  humans,
  send,
  actions = 600,
  rate = 120,
  clock = { now: () => performance.now(), sleep: delay },
}) {
  if (
    agents.length !== 200 ||
    humans.length !== 500 ||
    actions < 500 ||
    rate !== 120
  )
    throw new Error("selected organization workload required");
  const pending = new Set(),
    failures = [],
    samples = { propose: [], approve: [], execute: [], inspect: [] },
    agentsUsed = new Set(),
    humansUsed = new Set();
  let completed = 0,
    dispatched = 0,
    failedActions = 0,
    maxPending = 0;
  const start = clock.now();
  async function operation(actor, op, id, digest, state) {
    const response = await send(actor, op, id, digest);
    if (response.status !== 200 || response.state !== state)
      throw new Error(op + ":" + response.status + ":" + response.state);
    samples[op].push(response.latencyMs);
    return response;
  }
  async function action(index) {
    const agent = agents[index % agents.length],
      human = humans[index % humans.length],
      id = "urn:test:load:" + randomUUID();
    agentsUsed.add(agent.subject);
    humansUsed.add(human.subject);
    const proposed = await operation(
        agent,
        "propose",
        id,
        undefined,
        "pending",
      ),
      digest = proposed.proposal.digest;
    await operation(human, "approve", id, digest, "approved");
    await operation(agent, "execute", id, digest, "succeeded");
    await operation(human, "inspect", id, undefined, "succeeded");
    completed++;
  }
  for (let i = 0; i < actions; i++) {
    await clock.sleep(Math.max(0, start + (i * 60000) / rate - clock.now()));
    if (pending.size >= 64) {
      failures.push("load concurrency limit");
      break;
    }
    const task = action(i)
      .catch((error) => {
        failedActions++;
        failures.push(error.message);
      })
      .finally(() => pending.delete(task));
    pending.add(task);
    dispatched++;
    maxPending = Math.max(maxPending, pending.size);
    if (i % 120 === 0)
      console.log(
        "Load progress: " +
          i +
          "/" +
          actions +
          " scheduled; " +
          completed +
          " completed",
      );
  }
  await Promise.all(pending);
  const elapsedMs = clock.now() - start;
  const percentiles = Object.fromEntries(
    Object.entries(samples).map(([operation, values]) => {
      const sorted = values.toSorted((a, b) => a - b),
        at = (p) =>
          sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)] ?? null;
      return [
        operation,
        {
          count: sorted.length,
          p50Ms: at(0.5),
          p95Ms: at(0.95),
          p99Ms: at(0.99),
          maxMs: at(1),
        },
      ];
    }),
  );
  const report = {
    date: new Date().toISOString(),
    runtime: process.version,
    population: {
      users: humans.length,
      agents: agents.length,
      usersUsed: humansUsed.size,
      agentsUsed: agentsUsed.size,
    },
    requestedActions: actions,
    dispatchedActions: dispatched,
    scheduledActions: dispatched,
    completed,
    failedActions,
    failures,
    elapsedMs,
    completedActionsPerMinute: (completed * 60000) / elapsedMs,
    maxPending,
    percentiles,
    humanApproval: "simulated, excluded from machine latency",
    provider: "real Keycloak 26.8.0",
    database: "real PostgreSQL 18.6",
    mcp: "independent official SDK 2.3.1 fixture",
    latencyScope:
      "signed HTTPS operation including live introspection, durable transactions and MCP execution; excludes token issuance, human review and client signing",
  };
  report.passed =
    failures.length === 0 &&
    completed === actions &&
    humansUsed.size === 500 &&
    agentsUsed.size === 200 &&
    report.completedActionsPerMinute >= rate * 0.95 &&
    Object.values(percentiles).every(
      (p) => p.p95Ms !== null && p.p95Ms <= 2000,
    );
  return report;
}
