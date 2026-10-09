import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

export const LOCAL_RECEIPTS_PROFILE = "xeip.local-receipts/0.1";
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
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
  #entries = new Map(); // full key -> record, insertion order is expiry order
  #pairs = new Map(); // (principal, session) key -> Map(record key -> record)
  #principals = new Map(); // principal digest -> Map(record key -> record)
  #elapsed = 0;

  constructor(configuration = {}) {
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
        Object.keys(configuration).some(key => !FIELDS.includes(key))) {
      throw new TypeError("invalid receipts configuration");
    }
    const windowMs = Object.hasOwn(configuration, "windowMs") ? configuration.windowMs : 300000;
    const maxPerSession = Object.hasOwn(configuration, "maxPerSession") ? configuration.maxPerSession : 512;
    const maxPerPrincipal = Object.hasOwn(configuration, "maxPerPrincipal") ? configuration.maxPerPrincipal : 4096;
    if (!Number.isInteger(windowMs) || windowMs < 1 || windowMs > 3600000 ||
        !Number.isInteger(maxPerSession) || maxPerSession < 1 || maxPerSession > 4096 ||
        !Number.isInteger(maxPerPrincipal) || maxPerPrincipal < 1 || maxPerPrincipal > 8192) {
      throw new RangeError("invalid receipts limits");
    }
    this.#windowMs = windowMs;
    this.#maxPerSession = maxPerSession;
    this.#maxPerPrincipal = maxPerPrincipal;
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
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || elapsedMs > Number.MAX_SAFE_INTEGER - this.#windowMs) {
      throw new RangeError("invalid receipt elapsed time");
    }
    const now = Math.max(this.#elapsed, elapsedMs);
    this.#elapsed = now;
    this.#expire(now);
    const principalKey = digest(principal.entity);
    const pairKey = principalKey + "\u0000" + digest(session);
    const key = pairKey + "\u0000" + seq;
    const existing = this.#entries.get(key);
    if (existing) {
      existing.expiresAt = now + this.#windowMs;
      this.#touch(existing);
      return { duplicate: true };
    }
    const record = { key, principalKey, pairKey, id: digest(id), seq, expiresAt: now + this.#windowMs };
    this.#entries.set(key, record);
    this.#bucket(this.#pairs, pairKey).set(key, record);
    this.#bucket(this.#principals, principalKey).set(key, record);
    const pairs = this.#bucket(this.#pairs, pairKey);
    while (pairs.size > this.#maxPerSession) this.#delete(pairs.keys().next().value);
    const principals = this.#bucket(this.#principals, principalKey);
    while (principals.size > this.#maxPerPrincipal) this.#delete(principals.keys().next().value);
    return { duplicate: false };
  }

  #bucket(map, key) {
    let bucket = map.get(key);
    if (!bucket) { bucket = new Map(); map.set(key, bucket); }
    return bucket;
  }

  // Refreshing a record moves it to the end of every ordered index so the
  // global insertion order keeps matching non-decreasing expiry order.
  #touch(record) {
    const pairs = this.#pairs.get(record.pairKey);
    if (pairs) { pairs.delete(record.key); pairs.set(record.key, record); }
    const principals = this.#principals.get(record.principalKey);
    if (principals) { principals.delete(record.key); principals.set(record.key, record); }
    this.#entries.delete(record.key);
    this.#entries.set(record.key, record);
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
