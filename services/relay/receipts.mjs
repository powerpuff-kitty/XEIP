import { performance } from "node:perf_hooks";
import { advanceElapsed, boundedOption, BoundedMap, digestHex, requireOptions } from "./primitives.mjs";

export const LOCAL_RECEIPTS_PROFILE = "xeip.local-receipts/0.1";
const FIELDS = ["windowMs", "maxPerSession", "maxPerPrincipal"];

// Bounded, per-principal, in-memory ledger of recipient acknowledgments. It
// stores only digests, the correlated delivery sequence and a monotonic expiry;
// the delivery log already retains the envelope. It is NOT durable: records
// expire by a fixed window, are evicted under bounds and are lost on restart.
// Unlike admission it exposes no change listener: receipts are advisory and
// never broadcast, so nothing outside this process observes ledger updates.
export class ReceiptLedger {
  #windowMs;
  #maxPerSession;
  #maxPerPrincipal;
  #entries = new BoundedMap(Infinity); // full key -> record, insertion order is expiry order
  #pairs = new Map(); // (principal, session) key -> BoundedMap(record key -> record)
  #principals = new Map(); // principal digest -> BoundedMap(record key -> record)
  #elapsed = 0;

  constructor(configuration = {}) {
    requireOptions(configuration, FIELDS, "invalid receipts configuration");
    this.#windowMs = boundedOption(configuration, "windowMs", { default: 300000, min: 1, max: 3600000, message: "invalid receipts limits" });
    this.#maxPerSession = boundedOption(configuration, "maxPerSession", { default: 512, min: 1, max: 4096, message: "invalid receipts limits" });
    this.#maxPerPrincipal = boundedOption(configuration, "maxPerPrincipal", { default: 4096, min: 1, max: 8192, message: "invalid receipts limits" });
  }

  get limits() { return { windowMs: this.#windowMs, maxPerSession: this.#maxPerSession, maxPerPrincipal: this.#maxPerPrincipal }; }

  /**
   * Records or refreshes one receipt keyed by (principal, session, seq) and
   * returns { duplicate: true } when the key was already remembered. Repeated
   * acknowledgment is idempotent: no second record is added, only the expiry is
   * refreshed. A full bound never fails the request; the oldest receipt within
   * the exceeded bound is evicted instead, because a receipt is advisory.
   */
  record(principal, session, seq, id, elapsedMs = performance.now()) {
    if (!principal || typeof principal !== "object" || typeof principal.entity !== "string") {
      throw new TypeError("receipt principal must be an authenticated entity");
    }
    if (typeof session !== "string" || typeof id !== "string" || !Number.isSafeInteger(seq) || seq < 0) {
      throw new TypeError("invalid receipt record");
    }
    const now = advanceElapsed(this.#elapsed, elapsedMs, { windowMs: this.#windowMs, label: "receipt" });
    this.#elapsed = now;
    this.#expire(now);
    const principalKey = digestHex(principal.entity);
    const pairKey = principalKey + "\u0000" + digestHex(session);
    const key = pairKey + "\u0000" + seq;
    const existing = this.#entries.get(key);
    if (existing) {
      existing.expiresAt = now + this.#windowMs;
      this.#touch(existing);
      return { duplicate: true };
    }
    const record = { key, principalKey, pairKey, id: digestHex(id), seq, expiresAt: now + this.#windowMs };
    this.#entries.set(key, record);
    this.#bucket(this.#pairs, pairKey, this.#maxPerSession).set(key, record);
    this.#bucket(this.#principals, principalKey, this.#maxPerPrincipal).set(key, record);
    return { duplicate: false };
  }

  #bucket(map, key, max) {
    let bucket = map.get(key);
    if (!bucket) {
      bucket = new BoundedMap(max, { onEvict: evictedKey => this.#delete(evictedKey) });
      map.set(key, bucket);
    }
    return bucket;
  }

  // Refreshing a record moves it to the end of every ordered index so the
  // global insertion order keeps matching non-decreasing expiry order.
  #touch(record) {
    this.#pairs.get(record.pairKey)?.touch(record.key);
    this.#principals.get(record.principalKey)?.touch(record.key);
    this.#entries.touch(record.key);
  }

  #delete(key) {
    const record = this.#entries.get(key);
    if (!record) return;
    this.#entries.delete(key);
    const pairs = this.#pairs.get(record.pairKey);
    if (pairs) { pairs.delete(key); if (pairs.size === 0) this.#pairs.delete(record.pairKey); }
    const principals = this.#principals.get(record.principalKey);
    if (principals) { principals.delete(key); if (principals.size === 0) this.#principals.delete(record.principalKey); }
  }

  #expire(now) {
    for (const [key, record] of this.#entries) {
      if (record.expiresAt > now) break;
      this.#delete(key);
    }
  }
}
