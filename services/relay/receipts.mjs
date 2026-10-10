import { performance } from "node:perf_hooks";
import { advanceElapsed, boundedOption, BoundedMap, digestHex, requireOptions } from "./primitives.mjs";

export const LOCAL_RECEIPTS_PROFILE = "xeip.local-receipts/0.1";
const FIELDS = ["windowMs", "maxPerSession", "maxPerPrincipal"];

// Bounded, per-principal ledger of recipient acknowledgments. It stores only
// digests, the correlated delivery sequence and an expiry; the delivery log
// already retains the envelope. In its default, backend-free form it is
// in-memory and NOT durable: records expire by a fixed window, are evicted
// under bounds and are lost on restart. When constructed with a persistence
// `backend` (see `ReceiptLog` in durable.mjs) each new or refreshed record is
// written as a digest-only opaque line and reloaded on construction, so the
// ledger survives a restart when the durable profile is enabled. The backend log
// is compacted online on a bounded trigger (appended lines or byte budget) so
// duplicate refreshes cannot grow it without bound. It exposes no
// change listener: receipts are advisory and never broadcast, so nothing
// outside this process observes ledger updates.
export class ReceiptLedger {
  #windowMs;
  #maxPerSession;
  #maxPerPrincipal;
  #entries = new BoundedMap(Infinity); // full key -> record, insertion order is expiry order
  #pairs = new Map(); // (principal, session) key -> BoundedMap(record key -> record)
  #principals = new Map(); // principal digest -> BoundedMap(record key -> record)
  #elapsed = 0;
  #backend;

  constructor(configuration = {}, backend = null) {
    requireOptions(configuration, FIELDS, "invalid receipts configuration");
    this.#windowMs = boundedOption(configuration, "windowMs", { default: 300000, min: 1, max: 3600000, message: "invalid receipts limits" });
    this.#maxPerSession = boundedOption(configuration, "maxPerSession", { default: 512, min: 1, max: 4096, message: "invalid receipts limits" });
    this.#maxPerPrincipal = boundedOption(configuration, "maxPerPrincipal", { default: 4096, min: 1, max: 8192, message: "invalid receipts limits" });
    if (backend !== null && backend !== undefined) {
      if (typeof backend.load !== "function" || typeof backend.append !== "function") {
        throw new TypeError("invalid receipts persistence backend");
      }
      this.#backend = backend;
      this.#reload();
    }
  }

  get limits() { return { windowMs: this.#windowMs, maxPerSession: this.#maxPerSession, maxPerPrincipal: this.#maxPerPrincipal }; }

  /**
   * Records or refreshes one receipt keyed by (principal, session, seq) and
   * returns { duplicate: true } when the key was already remembered. Repeated
   * acknowledgment is idempotent: no second record is added, only the expiry is
   * refreshed. A full bound never fails the request; the oldest receipt within
   * the exceeded bound is evicted instead, because a receipt is advisory. With a
   * persistence backend every new or refreshed record is written so the
   * idempotency and expiry survive a restart.
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
    const sessionKey = digestHex(session);
    const pairKey = principalKey + "\u0000" + sessionKey;
    const key = pairKey + "\u0000" + seq;
    const existing = this.#entries.get(key);
    if (existing) {
      existing.expiresAt = now + this.#windowMs;
      this.#touch(existing);
      this.#persist(existing);
      return { duplicate: true };
    }
    const record = { key, principalKey, sessionKey, pairKey, id: digestHex(id), seq, expiresAt: now + this.#windowMs };
    this.#entries.set(key, record);
    this.#bucket(this.#pairs, pairKey, this.#maxPerSession).set(key, record);
    this.#bucket(this.#principals, principalKey, this.#maxPerPrincipal).set(key, record);
    this.#persist(record);
    return { duplicate: false };
  }

  // Reloads the unexpired, bounded set from the backend at construction. The
  // persisted expiry is wall-clock (it must survive a process restart), so it is
  // re-anchored onto this process's monotonic clock: a record past its wall
  // expiry is dropped, and a live one keeps its remaining lifetime. Duplicate
  // keys collapse to the last persisted line (a refresh), and records are
  // adopted oldest-expiry-first so the existing per-(session, principal) and
  // per-principal bounds evict the oldest on overflow exactly as at runtime.
  #reload() {
    const wallNow = Date.now();
    const elapsedNow = performance.now();
    this.#elapsed = Math.max(this.#elapsed, elapsedNow);
    let persisted;
    try { persisted = this.#backend.load(); }
    catch { return; }
    const latest = new Map();
    for (const record of Array.isArray(persisted) ? persisted : []) {
      if (!record || typeof record !== "object" ||
          typeof record.principal !== "string" || typeof record.session !== "string" ||
          typeof record.id !== "string" || !Number.isSafeInteger(record.seq) || record.seq < 0 ||
          !Number.isFinite(record.expiresAt)) continue;
      latest.set(record.principal + "\u0000" + record.session + "\u0000" + record.seq, record);
    }
    const live = [...latest.values()].filter(record => record.expiresAt > wallNow)
      .sort((left, right) => left.expiresAt - right.expiresAt);
    for (const record of live) {
      this.#adopt(record.principal, record.session, record.id, record.seq, this.#elapsed + (record.expiresAt - wallNow));
    }
    // Rebase the append-only log to the bounded live set so duplicate refreshes
    // and expired records do not accumulate on disk across restarts. While the
    // process runs, `#persist` compacts online on the same bounded trigger.
    if (Array.isArray(persisted) && persisted.length > 0) this.#compactBackend();
  }

  // Rewrites the backend to exactly the current bounded live set. Wall expiries
  // are reconstructed from the monotonic remaining lifetime. Best-effort: a
  // failed compaction leaves the prior log intact and the ledger still holds the
  // records in memory.
  #compactBackend() {
    if (!this.#backend || typeof this.#backend.compact !== "function") return;
    const wallNow = Date.now();
    const records = [];
    for (const record of this.#entries.values()) {
      records.push({ principal: record.principalKey, session: record.sessionKey, id: record.id, seq: record.seq,
        expiresAt: wallNow + (record.expiresAt - this.#elapsed) });
    }
    try { this.#backend.compact(records); } catch { /* persistence is best-effort on reload */ }
  }

  // Inserts a reloaded record with an already-computed monotonic expiry. It
  // mirrors the two indexing writes in `record` but never persists (the record
  // came from disk) and never expires (records were pre-filtered).
  #adopt(principalKey, sessionKey, idDigest, seq, expiresAt) {
    const pairKey = principalKey + "\u0000" + sessionKey;
    const key = pairKey + "\u0000" + seq;
    const record = { key, principalKey, sessionKey, pairKey, id: idDigest, seq, expiresAt };
    this.#entries.set(key, record);
    this.#bucket(this.#pairs, pairKey, this.#maxPerSession).set(key, record);
    this.#bucket(this.#principals, principalKey, this.#maxPerPrincipal).set(key, record);
  }

  // Writes the digest-only opaque record. The wall expiry is recomputed from
  // `Date.now()` rather than the monotonic `expiresAt`, because only wall time
  // is meaningful across a restart. When the backend reports its append-line or
  // byte budget is reached the live set is rewritten online so duplicate
  // refreshes cannot grow the log without bound between restarts.
  #persist(record) {
    if (!this.#backend) return;
    const backend = this.#backend;
    const outcome = backend.append({
      principal: record.principalKey,
      session: record.sessionKey,
      id: record.id,
      seq: record.seq,
      expiresAt: Date.now() + this.#windowMs
    });
    const full = outcome === "full";
    const saturated = typeof backend.saturated === "function" && backend.saturated();
    const due = typeof backend.shouldCompact === "function" && backend.shouldCompact();
    // Rewrite the live set when the line budget is reached, or once when an
    // append overflows the byte budget. If even the live set is over budget the
    // write is simply dropped (the log is bounded by the bounded live set).
    if ((full && !saturated) || due) this.#compactBackend();
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
