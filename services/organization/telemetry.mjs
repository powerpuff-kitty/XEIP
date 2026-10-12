/** Bounded aggregate metrics and redacted events. The PostgreSQL audit remains authoritative. */
import { randomUUID } from "node:crypto";
const routes = ["actions", "live", "ready", "other"];
const operations = [
  "propose",
  "approve",
  "reject",
  "revoke",
  "execute",
  "inspect",
  "unknown",
];
const states = [
  "pending",
  "approved",
  "rejected",
  "revoked",
  "executing",
  "succeeded",
  "failed",
  "indeterminate",
  "unknown",
];
const statuses = [
  200, 400, 401, 403, 404, 405, 408, 409, 413, 415, 429, 499, 500, 503, 504,
];
const buckets = [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, Infinity];
const events = [
  "started",
  "draining",
  "shutdown_complete",
  "shutdown_forced",
  "startup_failed",
  "listener_failed",
  "control_lease_lost",
  "configuration_valid",
  "database_unavailable",
  "trust_reloaded",
  "trust_reload_rejected",
];
/** @typedef {{id?:unknown,route?:unknown,operation?:unknown,status?:unknown,state?:unknown,elapsedMs?:unknown}} Observation */
export class Telemetry {
  #write;
  /** @type {Map<string,number>} */ #requests = new Map();
  /** @type {Map<string,number>} */ #outcomes = new Map();
  #histograms = new Map(
    routes.map((route) => [
      route,
      { count: 0, sum: 0, buckets: buckets.map(() => 0) },
    ]),
  );
  #ready = 0;
  #active = 0;
  #logFailures = 0;
  /** @param {(line:string)=>unknown} write */
  constructor(write) {
    this.#write = write;
  }
  /** @param {object} event */
  #log(event) {
    try {
      this.#write(
        JSON.stringify({ ...event, time: new Date().toISOString() }) + "\n",
      );
    } catch {
      this.#logFailures++;
    }
  }
  /** @param {string} event */
  event(event) {
    if (events.includes(event)) this.#log({ event });
  }
  /** @param {boolean} ready @param {number} active */
  health(ready, active) {
    this.#ready = ready === true ? 1 : 0;
    this.#active =
      Number.isInteger(active) && active >= 0 && active <= 256 ? active : 0;
  }
  /** @param {Observation} input */
  request(input) {
    const route =
      typeof input.route === "string" && routes.includes(input.route)
        ? input.route
        : "other";
    const operation =
      typeof input.operation === "string" &&
      operations.includes(input.operation)
        ? input.operation
        : "unknown";
    const status =
      typeof input.status === "number" && statuses.includes(input.status)
        ? input.status
        : 503;
    const state =
      typeof input.state === "string" && states.includes(input.state)
        ? input.state
        : "unknown";
    const elapsedMs =
      typeof input.elapsedMs === "number" &&
      Number.isFinite(input.elapsedMs) &&
      input.elapsedMs >= 0
        ? Math.min(input.elapsedMs, 1e12)
        : 0;
    const requestId =
      typeof input.id === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        input.id,
      )
        ? input.id
        : randomUUID();
    const label = `route="${route}",operation="${operation}",status="${status}"`;
    this.#requests.set(label, (this.#requests.get(label) ?? 0) + 1);
    if (
      operation === "execute" &&
      ["succeeded", "failed", "indeterminate"].includes(state)
    )
      this.#outcomes.set(state, (this.#outcomes.get(state) ?? 0) + 1);
    const histogram =
      /** @type {{count:number,sum:number,buckets:number[]}} */ (
        this.#histograms.get(route)
      );
    histogram.count++;
    histogram.sum += elapsedMs / 1000;
    buckets.forEach((bound, i) => {
      if (elapsedMs / 1000 <= bound) histogram.buckets[i]++;
    });
    this.#log({
      event: "request_finished",
      requestId,
      route,
      operation,
      status,
      state,
      elapsedMs: Math.round(elapsedMs),
    });
  }
  metrics() {
    const lines = ["# TYPE xeip_requests_total counter"];
    for (const [labels, count] of this.#requests)
      lines.push(`xeip_requests_total{${labels}} ${count}`);
    lines.push("# TYPE xeip_request_duration_seconds histogram");
    for (const [route, histogram] of this.#histograms) {
      buckets.forEach((bound, i) =>
        lines.push(
          `xeip_request_duration_seconds_bucket{route="${route}",le="${bound === Infinity ? "+Inf" : bound}"} ${histogram.buckets[i]}`,
        ),
      );
      lines.push(
        `xeip_request_duration_seconds_sum{route="${route}"} ${histogram.sum}`,
        `xeip_request_duration_seconds_count{route="${route}"} ${histogram.count}`,
      );
    }
    lines.push("# TYPE xeip_action_outcomes_total counter");
    for (const [state, count] of this.#outcomes)
      lines.push(`xeip_action_outcomes_total{state="${state}"} ${count}`);
    lines.push(
      "# TYPE xeip_ready gauge",
      `xeip_ready ${this.#ready}`,
      "# TYPE xeip_active_operations gauge",
      `xeip_active_operations ${this.#active}`,
      "# TYPE xeip_log_failures_total counter",
      `xeip_log_failures_total ${this.#logFailures}`,
    );
    return lines.join("\n") + "\n";
  }
}
