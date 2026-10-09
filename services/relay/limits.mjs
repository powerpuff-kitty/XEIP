import { performance } from "node:perf_hooks";

export const LOCAL_LIMITS_PROFILE = "xeip.local-limits/0.1";
// Bound on distinct rate-limit keys retained at once. This is a safety valve
// against unbounded key growth, not a guarantee about the number of peers or
// principals a deployment will see.
export const MAX_TRACKED_KEYS = 4096;
const FIELDS = ["requestsPerSecond", "burst", "maxConnections", "maxSubscriptions", "keyBy"];
const MAX_VALUE = 100000;

// Advisory, in-memory local rate/connection limits. This is a token bucket on a
// process-monotonic clock plus bounded global connection/subscription counters.
// It is not fair scheduling, not a production rate limiter and not durable.
export class LimitPolicy {
  #requestsPerSecond;
  #burst;
  #maxConnections;
  #maxSubscriptions;
  #keyBy;
  #buckets = new Map(); // key -> { tokens, at }, insertion order is least-recently-used first
  #connections = 0;
  #subscriptions = 0;
  #elapsed = 0;

  constructor(configuration = {}) {
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
        Object.keys(configuration).some(key => !FIELDS.includes(key))) {
      throw new TypeError("invalid limits configuration");
    }
    const requestsPerSecond = Object.hasOwn(configuration, "requestsPerSecond") ? configuration.requestsPerSecond : 50;
    const burst = Object.hasOwn(configuration, "burst") ? configuration.burst : 100;
    const maxConnections = Object.hasOwn(configuration, "maxConnections") ? configuration.maxConnections : 256;
    const maxSubscriptions = Object.hasOwn(configuration, "maxSubscriptions") ? configuration.maxSubscriptions : 256;
    const keyBy = Object.hasOwn(configuration, "keyBy") ? configuration.keyBy : "principal";
    if (!Number.isInteger(requestsPerSecond) || requestsPerSecond < 1 || requestsPerSecond > MAX_VALUE ||
        !Number.isInteger(burst) || burst < 1 || burst > MAX_VALUE ||
        !Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > MAX_VALUE ||
        !Number.isInteger(maxSubscriptions) || maxSubscriptions < 1 || maxSubscriptions > MAX_VALUE) {
      throw new RangeError("invalid limits configuration");
    }
    if (keyBy !== "principal" && keyBy !== "peer") throw new TypeError("limits keyBy must be principal or peer");
    this.#requestsPerSecond = requestsPerSecond;
    this.#burst = burst;
    this.#maxConnections = maxConnections;
    this.#maxSubscriptions = maxSubscriptions;
    this.#keyBy = keyBy;
  }

  get profile() { return LOCAL_LIMITS_PROFILE; }
  get activeConnections() { return this.#connections; }
  get activeSubscriptions() { return this.#subscriptions; }

  // Returns a fresh copy so callers cannot mutate retained policy state.
  get limits() {
    return {
      requestsPerSecond: this.#requestsPerSecond,
      burst: this.#burst,
      maxConnections: this.#maxConnections,
      maxSubscriptions: this.#maxSubscriptions,
      keyBy: this.#keyBy
    };
  }

  /**
   * Derives the bucket key from the authenticated principal and the socket peer.
   * `peer` keys shared-token/native mode; `principal` requires an authenticated
   * entity and otherwise falls back to the peer so a token-less request still
   * gets a usable bucket instead of sharing a null key.
   */
  keyFor(principal, peer) {
    const entity = principal && typeof principal === "object" ? principal.entity : undefined;
    if (this.#keyBy === "principal" && typeof entity === "string" && entity.length > 0) {
      return "principal\u0000" + entity;
    }
    return "peer\u0000" + (typeof peer === "string" && peer.length > 0 ? peer : "unknown");
  }

  /**
   * Consumes one token for `key` and reports whether the request is allowed. The
   * caller supplies a string key (see `keyFor`) and may inject a monotonic
   * elapsed time for tests. When denied, `retryAfter` is the whole number of
   * seconds to wait for the next token (at least 1).
   */
  take(key, elapsedMs = performance.now()) {
    if (typeof key !== "string" || key.length === 0) throw new TypeError("limit key must be a non-empty string");
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || elapsedMs > Number.MAX_SAFE_INTEGER) {
      throw new RangeError("invalid limits elapsed time");
    }
    const now = Math.max(this.#elapsed, elapsedMs);
    this.#elapsed = now;
    let bucket = this.#buckets.get(key);
    if (bucket) {
      const refill = ((now - bucket.at) / 1000) * this.#requestsPerSecond;
      bucket.tokens = Math.min(this.#burst, bucket.tokens + refill);
      bucket.at = now;
      // A denied take is still an access and refreshes the key's recency.
      this.#buckets.delete(key);
      this.#buckets.set(key, bucket);
    } else {
      bucket = { tokens: this.#burst, at: now };
      this.#buckets.set(key, bucket);
      while (this.#buckets.size > MAX_TRACKED_KEYS) this.#buckets.delete(this.#buckets.keys().next().value);
    }
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, retryAfter: 0 };
    }
    const seconds = (1 - bucket.tokens) / this.#requestsPerSecond;
    return { allowed: false, retryAfter: Math.max(1, Math.ceil(seconds)) };
  }

  acquireConnection() {
    if (this.#connections >= this.#maxConnections) return false;
    this.#connections += 1;
    return true;
  }

  releaseConnection() {
    if (this.#connections > 0) this.#connections -= 1;
  }

  acquireSubscription() {
    if (this.#subscriptions >= this.#maxSubscriptions) return false;
    this.#subscriptions += 1;
    return true;
  }

  releaseSubscription() {
    if (this.#subscriptions > 0) this.#subscriptions -= 1;
  }
}
