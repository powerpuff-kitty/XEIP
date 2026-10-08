import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

export const LOCAL_REPLAY_PROFILE = "xeip.local-replay/0.1";
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");

// Internal equality of validated parsed JSON, not a signing serialization standard.
function orderedJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(orderedJson).join(",") + "]";
  return "{" + Object.keys(value).sort().map(key => JSON.stringify(key) + ":" + orderedJson(value[key])).join(",") + "}";
}

export class ReplayWindow {
  #windowMs;
  #maxEntries;
  #entries = new Map();
  #elapsed = 0;

  constructor(configuration = {}) {
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
        Object.keys(configuration).some(key => !["windowMs", "maxEntries"].includes(key))) {
      throw new TypeError("invalid replay configuration");
    }
    const windowMs = Object.hasOwn(configuration, "windowMs") ? configuration.windowMs : 300000;
    const maxEntries = Object.hasOwn(configuration, "maxEntries") ? configuration.maxEntries : 4096;
    if (!Number.isInteger(windowMs) || windowMs < 1 || windowMs > 3600000 ||
        !Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 4096) throw new RangeError("invalid replay limits");
    this.#windowMs = windowMs;
    this.#maxEntries = maxEntries;
  }

  get limits() { return { windowMs: this.#windowMs, maxEntries: this.#maxEntries }; }

  /** Caller supplies a validated, transport-bounded parsed JSON envelope after admission checks. */
  accept(message, elapsedMs = performance.now()) {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || elapsedMs > Number.MAX_SAFE_INTEGER - this.#windowMs) {
      throw new RangeError("invalid replay elapsed time");
    }
    const now = Math.max(this.#elapsed, elapsedMs);
    const key = digest(JSON.stringify([message.session, message.sender, message.id]));
    const content = digest(orderedJson(message));
    this.#elapsed = now;
    // Fixed windows plus monotonic insertion keep expiry order stable. Hits never move records.
    for (const [scope, record] of this.#entries) {
      if (record.expiresAt > now) break;
      this.#entries.delete(scope);
    }
    const previous = this.#entries.get(key);
    if (previous) return { status: previous.content === content ? "duplicate" : "conflict" };
    if (this.#entries.size >= this.#maxEntries) {
      const earliest = this.#entries.values().next().value.expiresAt;
      return { status: "full", retryAfter: Math.max(1, Math.ceil((earliest - now) / 1000)) };
    }
    this.#entries.set(key, { content, expiresAt: now + this.#windowMs });
    return { status: "new" };
  }
}
