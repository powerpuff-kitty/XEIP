import { performance } from "node:perf_hooks";

export const LOCAL_DELIVERY_PROFILE = "xeip.local-delivery/0.1";

// Bounded, in-order per-session retention for reconnect resume. It is NOT a
// durable queue: entries are in memory, expire by a fixed window and are
// dropped on restart or when per-session or session-count bounds are exceeded.
export class DeliveryLog {
  #windowMs;
  #maxPerSession;
  #maxSessions;
  #sessions = new Map(); // session ID -> { entries: [{seq, at, message}], nextSeq }
  #known = new Map(); // evicted session ID -> last assigned seq, for honest gap reporting
  #elapsed = 0;

  constructor(configuration = {}) {
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
        Object.keys(configuration).some(key => !["windowMs", "maxPerSession", "maxSessions"].includes(key))) {
      throw new TypeError("invalid delivery configuration");
    }
    const windowMs = Object.hasOwn(configuration, "windowMs") ? configuration.windowMs : 300000;
    const maxPerSession = Object.hasOwn(configuration, "maxPerSession") ? configuration.maxPerSession : 512;
    const maxSessions = Object.hasOwn(configuration, "maxSessions") ? configuration.maxSessions : 256;
    if (!Number.isInteger(windowMs) || windowMs < 1 || windowMs > 3600000 ||
        !Number.isInteger(maxPerSession) || maxPerSession < 1 || maxPerSession > 4096 ||
        !Number.isInteger(maxSessions) || maxSessions < 1 || maxSessions > 1024) {
      throw new RangeError("invalid delivery limits");
    }
    this.#windowMs = windowMs;
    this.#maxPerSession = maxPerSession;
    this.#maxSessions = maxSessions;
  }

  get limits() { return { windowMs: this.#windowMs, maxPerSession: this.#maxPerSession, maxSessions: this.#maxSessions }; }

  /** Appends a validated, admitted envelope and returns its per-session sequence. */
  append(session, message, elapsedMs = performance.now()) {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || elapsedMs > Number.MAX_SAFE_INTEGER - this.#windowMs) {
      throw new RangeError("invalid delivery elapsed time");
    }
    const now = Math.max(this.#elapsed, elapsedMs);
    this.#elapsed = now;
    let log = this.#sessions.get(session);
    if (log) {
      // Move to the most-recently-used position for bounded session eviction.
      this.#sessions.delete(session);
    } else {
      // Restore monotonicity if this session was previously evicted.
      const last = this.#known.get(session);
      log = { entries: [], nextSeq: last === undefined ? 1 : last + 1 };
      this.#known.delete(session);
    }
    this.#sessions.set(session, log);
    this.#expire(log, now);
    const seq = log.nextSeq++;
    log.entries.push({ seq, at: now, message });
    while (log.entries.length > this.#maxPerSession) log.entries.shift();
    while (this.#sessions.size > this.#maxSessions) {
      const oldestSession = this.#sessions.keys().next().value;
      if (oldestSession === session) break;
      this.#remember(oldestSession, this.#sessions.get(oldestSession).nextSeq - 1);
      this.#sessions.delete(oldestSession);
    }
    return seq;
  }

  /**
   * Returns retained entries with sequence strictly greater than `after`.
   * Entries past the fixed monotonic window are reclaimed first, even when no
   * new message has been appended. `gap` is true when one or more sequences
   * between `after` and the oldest retained entry were already dropped (or the
   * whole session was evicted), so a client must not assume continuity.
   */
  since(session, after, elapsedMs = performance.now()) {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0) throw new RangeError("invalid delivery elapsed time");
    const now = Math.max(this.#elapsed, elapsedMs);
    this.#elapsed = now;
    const log = this.#sessions.get(session);
    if (!log) {
      const last = this.#known.get(session);
      if (last !== undefined && after < last) return { entries: [], gap: true, from: last + 1 };
      return { entries: [], gap: false, from: after + 1 };
    }
    this.#expire(log, now);
    // Reading is activity: keep an actively resumed session from being evicted.
    this.#sessions.delete(session);
    this.#sessions.set(session, log);
    const oldest = log.entries.length > 0 ? log.entries[0].seq : log.nextSeq;
    return {
      entries: log.entries.filter(entry => entry.seq > after),
      gap: after < oldest - 1,
      from: oldest
    };
  }

  /**
   * Read-only correlation lookup: the retained entry with this exact sequence,
   * or null when it is unknown or no longer retained. Unlike `since` it does not
   * count as activity, so a receipt can never change retention or eviction order.
   */
  lookup(session, seq, elapsedMs = performance.now()) {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0) throw new RangeError("invalid delivery elapsed time");
    const log = this.#sessions.get(session);
    if (!log) return null;
    const now = Math.max(this.#elapsed, elapsedMs);
    this.#elapsed = now;
    this.#expire(log, now);
    return log.entries.find(entry => entry.seq === seq) ?? null;
  }

  /** The first retained entry whose message id equals `id`, or null when none. */
  lookupById(session, id, elapsedMs = performance.now()) {
    return this.lookupAllById(session, id, elapsedMs)[0] ?? null;
  }

  /**
   * Every retained entry whose message id equals `id`, oldest first. An id-only
   * receipt needs this to reject more than one match as ambiguous.
   */
  lookupAllById(session, id, elapsedMs = performance.now()) {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0) throw new RangeError("invalid delivery elapsed time");
    const log = this.#sessions.get(session);
    if (!log) return [];
    const now = Math.max(this.#elapsed, elapsedMs);
    this.#elapsed = now;
    this.#expire(log, now);
    return log.entries.filter(entry => entry.message.id === id);
  }

  #remember(session, lastSeq) {
    this.#known.delete(session);
    this.#known.set(session, lastSeq);
    while (this.#known.size > this.#maxSessions * 4) this.#known.delete(this.#known.keys().next().value);
  }

  #expire(log, now) {
    const cutoff = now - this.#windowMs;
    while (log.entries.length > 0 && log.entries[0].at <= cutoff) log.entries.shift();
  }
}
