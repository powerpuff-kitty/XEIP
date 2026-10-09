import { createHash } from "node:crypto";

// SHA-256 of a UTF-8 string, hex encoded. This is the digest used by the local
// replay, delivery and receipts profiles for opaque scope/content/identity keys.
export function digestHex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

// Byte variant kept for admission-format digests (hash.compare / map keys).
export function digestBytes(value) {
  return createHash("sha256").update(value, "utf8").digest();
}

// Advances a monotonic elapsed clock, never moving it backwards. The upper
// bound mirrors the per-module guards: a caller with a fixed window rejects any
// elapsed time that could make `elapsed + windowMs` leave the safe-integer
// range, a caller with no window uses the default `max`, and `max: Infinity`
// reproduces the unbounded guard used by the delivery resume path.
export function advanceElapsed(previous, elapsedMs, { windowMs = 0, max = Number.MAX_SAFE_INTEGER, label = "monotonic" } = {}) {
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || elapsedMs > max - windowMs) {
    throw new RangeError(`invalid ${label} elapsed time`);
  }
  return Math.max(previous, elapsedMs);
}

// Validates the plain-object shape of a configuration: not null, not an array,
// and no fields beyond `allowedFields`. Throws the caller's TypeError message.
export function requireOptions(configuration, allowedFields, message = "invalid configuration") {
  if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
      Object.keys(configuration).some(key => !allowedFields.includes(key))) {
    throw new TypeError(message);
  }
}

// True when `value` is an integer inside the inclusive [min, max] range.
export function boundedInteger(value, min, max) {
  return Number.isInteger(value) && value >= min && value <= max;
}

// Reads an optional integer field from a validated configuration, applying the
// documented default, and throws the caller's RangeError message when the value
// (or default) is out of range.
export function boundedOption(configuration, field, { default: fallback, min, max, message = "invalid configuration" }) {
  const value = Object.hasOwn(configuration, field) ? configuration[field] : fallback;
  if (!boundedInteger(value, min, max)) throw new RangeError(message);
  return value;
}

// Insertion-ordered map with a hard size bound. Setting an existing key or
// calling `touch` moves it to the most-recent position; overflow evicts the
// least-recently-used key and, when supplied, reports it through `onEvict`.
// `max: Infinity` disables eviction for indexes bounded elsewhere.
export class BoundedMap {
  #map = new Map();
  #max;
  #onEvict;

  constructor(max, { onEvict } = {}) {
    if (max !== Infinity && (!Number.isInteger(max) || max < 0)) throw new RangeError("invalid bounded map size");
    this.#max = max;
    this.#onEvict = typeof onEvict === "function" ? onEvict : undefined;
  }

  get size() { return this.#map.size; }
  has(key) { return this.#map.has(key); }
  get(key) { return this.#map.get(key); }

  set(key, value) {
    if (this.#map.has(key)) this.#map.delete(key);
    this.#map.set(key, value);
    while (this.#map.size > this.#max) {
      const oldest = this.#map.keys().next().value;
      const evicted = this.#map.get(oldest);
      this.#map.delete(oldest);
      this.#onEvict?.(oldest, evicted);
    }
    return this;
  }

  touch(key) {
    if (!this.#map.has(key)) return false;
    const value = this.#map.get(key);
    this.#map.delete(key);
    this.#map.set(key, value);
    return true;
  }

  delete(key) { return this.#map.delete(key); }
  clear() { this.#map.clear(); }
  keys() { return this.#map.keys(); }
  values() { return this.#map.values(); }
  entries() { return this.#map.entries(); }
  [Symbol.iterator]() { return this.#map[Symbol.iterator](); }
}
