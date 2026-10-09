import { performance } from "node:perf_hooks";
import { advanceElapsed, boundedOption, digestHex, requireOptions } from "./primitives.mjs";

export const LOCAL_REPLAY_PROFILE = "xeip.local-replay/0.1";
const FIELDS = ["windowMs", "maxEntries"];

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
    requireOptions(configuration, FIELDS, "invalid replay configuration");
    this.#windowMs = boundedOption(configuration, "windowMs", { default: 300000, min: 1, max: 3600000, message: "invalid replay limits" });
    this.#maxEntries = boundedOption(configuration, "maxEntries", { default: 4096, min: 1, max: 4096, message: "invalid replay limits" });
  }

  get limits() { return { windowMs: this.#windowMs, maxEntries: this.#maxEntries }; }

  /** Caller supplies a validated, transport-bounded parsed JSON envelope after admission checks. */
  accept(message, elapsedMs = performance.now()) {
    const now = advanceElapsed(this.#elapsed, elapsedMs, { windowMs: this.#windowMs, label: "replay" });
    const key = digestHex(JSON.stringify([message.session, message.sender, message.id]));
    const content = digestHex(orderedJson(message));
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
