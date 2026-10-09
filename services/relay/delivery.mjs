import { performance } from "node:perf_hooks";
import { advanceElapsed, boundedOption, BoundedMap, requireOptions } from "./primitives.mjs";

export const LOCAL_DELIVERY_PROFILE = "xeip.local-delivery/0.1";
const FIELDS = ["windowMs", "maxPerSession", "maxSessions"];

// Bounded, in-order per-session retention for reconnect resume. It is NOT a
// durable queue: entries are in memory, expire by a fixed window and are
// dropped on restart or when per-session or session-count bounds are exceeded.
export class DeliveryLog {
  #windowMs;
  #maxPerSession;
  #maxSessions;
  #sessions; // session ID -> { entries: [{seq, at, message}], nextSeq }, least-recently-used first
  #known; // evicted session ID -> last assigned seq, for honest gap reporting
  #elapsed = 0;

  constructor(configuration = {}) {
    requireOptions(configuration, FIELDS, "invalid delivery configuration");
    this.#windowMs = boundedOption(configuration, "windowMs", { default: 300000, min: 1, max: 3600000, message: "invalid delivery limits" });
    this.#maxPerSession = boundedOption(configuration, "maxPerSession", { default: 512, min: 1, max: 4096, message: "invalid delivery limits" });
    this.#maxSessions = boundedOption(configuration, "maxSessions", { default: 256, min: 1, max: 1024, message: "invalid delivery limits" });
    this.#sessions = new BoundedMap(this.#maxSessions, {
      onEvict: (sessionId, log) => this.#remember(sessionId, log.nextSeq - 1)
    });
    this.#known = new BoundedMap(this.#maxSessions * 4);
  }

  get limits() { return { windowMs: this.#windowMs, maxPerSession: this.#maxPerSession, maxSessions: this.#maxSessions }; }

  /** Appends a validated, admitted envelope and returns its per-session sequence. */
  append(session, message, elapsedMs = performance.now()) {
    const now = advanceElapsed(this.#elapsed, elapsedMs, { windowMs: this.#windowMs, label: "delivery" });
    this.#elapsed = now;
    let log = this.#sessions.get(session);
    if (log) {
      // Move to the most-recently-used position for bounded session eviction.
      this.#sessions.touch(session);
    } else {
      // Restore monotonicity if this session was previously evicted.
      const last = this.#known.get(session);
      log = { entries: [], nextSeq: last === undefined ? 1 : last + 1 };
      this.#known.delete(session);
      this.#sessions.set(session, log);
    }
    this.#expire(log, now);
    const seq = log.nextSeq++;
    log.entries.push({ seq, at: now, message });
    while (log.entries.length > this.#maxPerSession) log.entries.shift();
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
    const now = advanceElapsed(this.#elapsed, elapsedMs, { max: Infinity, label: "delivery" });
    this.#elapsed = now;
    const log = this.#sessions.get(session);
    if (!log) {
      const last = this.#known.get(session);
      if (last !== undefined && after < last) return { entries: [], gap: true, from: last + 1 };
      return { entries: [], gap: false, from: after + 1 };
    }
    this.#expire(log, now);
    // Reading is activity: keep an actively resumed session from being evicted.
    this.#sessions.touch(session);
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
    const now = advanceElapsed(this.#elapsed, elapsedMs, { windowMs: this.#windowMs, label: "delivery" });
    const log = this.#sessions.get(session);
    if (!log) return null;
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
    const now = advanceElapsed(this.#elapsed, elapsedMs, { windowMs: this.#windowMs, label: "delivery" });
    const log = this.#sessions.get(session);
    if (!log) return [];
    this.#elapsed = now;
    this.#expire(log, now);
    return log.entries.filter(entry => entry.message.id === id);
  }

  #remember(session, lastSeq) {
    this.#known.set(session, lastSeq);
  }

  #expire(log, now) {
    const cutoff = now - this.#windowMs;
    while (log.entries.length > 0 && log.entries[0].at <= cutoff) log.entries.shift();
  }
}
