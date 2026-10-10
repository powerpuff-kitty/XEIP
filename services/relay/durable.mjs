/**
 * Bounded, restart-surviving delivery store for the xeip.local-durable/0.1
 * profile. It is a dependency-free segmented append-only log plus an atomically
 * swapped manifest, using only node:fs / node:path / node:crypto.
 *
 * It mirrors the in-memory DeliveryLog method shapes (append, since, lookup,
 * lookupAllById, limits) so the relay can use either store. It is NOT a queue
 * with exactly-once semantics: a reserved-but-unappended sequence is a
 * permanent hole, interior corruption fails closed, and only a torn tail is
 * recovered. Bounded compaction reclaims evicted bytes crash-safely. An
 * exclusive `<dir>/LOCK` file serialises writers: a stale lock left by a
 * crashed process must be removed by the operator (it is never stolen). At-rest
 * encryption is deferred.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export const LOCAL_DURABLE_PROFILE = "xeip.local-durable/0.1";
export const STORE_VERSION = 1;
const FIELDS = ["backend", "dir", "retentionMs", "maxEntriesPerSession", "maxSessions", "maxBytes", "fsync", "lock"];
const FSYNC_MODES = ["always", "batch", "never"];
// Roll the append-only log before a single segment grows past this size.
const SEGMENT_BYTES = 1024 * 1024;
// With fsync:"batch" the active segment (and the receipt log) is flushed every N
// appends and on close/compact.
export const BATCH_FSYNC = 64;
// The receipt log is compacted online after this many appended lines, so
// duplicate refreshes never accumulate without bound between restarts.
export const RECEIPT_COMPACT_LINES = 1024;
// The receipt log's hard byte budget is derived from the durable `maxBytes` as a
// fraction, clamped so a tiny store still gets a usable floor and a large store
// cannot devote its whole budget to advisory receipts.
const RECEIPT_BUDGET_FRACTION = 16;
const RECEIPT_BUDGET_MIN = 64 * 1024;
const RECEIPT_BUDGET_MAX = 8 * 1024 * 1024;
const RECORD_HEADER = 4 + 32; // uint32 payload length + SHA-256(payload)
const MANIFEST = "manifest.json";
const RECEIPT_LOG = "receipts.log";
const LOCK = "LOCK";
const SEGMENT_PATTERN = /^segment-([0-9]+)\.log$/;
const COMPACT_FAULTS = ["after-write", "after-manifest", "torn"];

const sha256 = value => createHash("sha256").update(value).digest();
const encodeRecord = raw => {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(raw.length, 0);
  return Buffer.concat([header, sha256(raw), raw]);
};

// Reads length-prefixed, checksummed records from one segment. A truncated or
// checksum-failing final record is a torn tail and is dropped (torn === true).
// A checksum failure with further bytes behind it is interior corruption and
// fails closed. Nothing is ever repaired or fabricated.
function readRecords(buffer) {
  const records = [];
  let offset = 0;
  const torn = () => ({ records, torn: true, validBytes: offset });
  while (offset < buffer.length) {
    if (offset + RECORD_HEADER > buffer.length) return torn();
    const length = buffer.readUInt32BE(offset);
    const recordEnd = offset + RECORD_HEADER + length;
    if (recordEnd > buffer.length) return torn();
    const expected = buffer.subarray(offset + 4, offset + 4 + 32);
    const payload = buffer.subarray(offset + RECORD_HEADER, recordEnd);
    if (!sha256(payload).equals(expected)) {
      if (recordEnd === buffer.length) return torn();
      throw new Error("durable store: interior corruption detected");
    }
    let record;
    try { record = JSON.parse(payload.toString("utf8")); }
    catch { throw new Error("durable store: invalid record payload"); }
    records.push({ record, raw: payload, bytes: recordEnd - offset });
    offset = recordEnd;
  }
  return { records, torn: false, validBytes: offset };
}

// One persisted receipt line: digest-only, never a copy of the envelope. The
// fields are the authenticated principal digest, the session digest, the ID
// digest, the correlated `seq` and a wall-clock expiry (the monotonic clock does
// not survive restart).
const validReceiptRecord = record =>
  record !== null && typeof record === "object" && !Array.isArray(record) &&
  typeof record.principal === "string" && record.principal.length > 0 &&
  typeof record.session === "string" && record.session.length > 0 &&
  typeof record.id === "string" &&
  Number.isSafeInteger(record.seq) && record.seq >= 0 &&
  Number.isFinite(record.expiresAt);

/**
 * Digest-only, append-only persistence for the local receipts ledger. It lives
 * in the durable store directory as `receipts.log` and reuses the same
 * length-prefixed, SHA-256-checksummed record framing as the delivery segments.
 * A truncated final record is a torn tail that is dropped and reported
 * "recovered"; interior corruption *and* a structurally invalid record fail
 * closed to "degraded", move the unreadable file aside (`receipts.log.corrupt`)
 * and start a fresh log so appends never sit behind bad bytes. It stores no
 * envelope copy.
 *
 * Growth is bounded online. Appends are tracked; once `compactAfter` lines have
 * been appended (or a write would pass the hard `maxBytes` budget) the ledger
 * rewrites only its live set via `compact` (temp + fsync + rename). A write that
 * would still exceed the hard budget after compaction is dropped, so the file
 * cannot grow without bound. `fsync` mirrors the delivery policy: "always"
 * fsyncs each line, "batch" every `BATCH_FSYNC` appends and on close/compact,
 * "never" never does.
 */
export class ReceiptLog {
  #dir;
  #file;
  #fd;
  #fsync;
  #maxBytes;
  #compactAfter;
  #status = "ok";
  #records = [];
  #bytes = 0;
  #appended = 0;
  #pending = 0;
  #fsyncs = 0;
  #saturated = false;
  #closed = false;

  constructor(configuration = {}) {
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
        Object.keys(configuration).some(key => !["dir", "fsync", "maxBytes", "compactAfter"].includes(key))) {
      throw new TypeError("invalid receipt log configuration");
    }
    if (typeof configuration.dir !== "string" || configuration.dir.length === 0) {
      throw new TypeError("receipt log directory is required");
    }
    const fsync = configuration.fsync ?? "always";
    if (!FSYNC_MODES.includes(fsync)) throw new RangeError("invalid receipt log fsync");
    const maxBytes = configuration.maxBytes ?? RECEIPT_BUDGET_MAX;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 17179869184) {
      throw new RangeError("invalid receipt log maxBytes");
    }
    const compactAfter = configuration.compactAfter ?? RECEIPT_COMPACT_LINES;
    if (!Number.isSafeInteger(compactAfter) || compactAfter < 1 || compactAfter > 1048576) {
      throw new RangeError("invalid receipt log compactAfter");
    }
    this.#dir = path.resolve(configuration.dir);
    this.#fsync = fsync;
    this.#maxBytes = maxBytes;
    this.#compactAfter = compactAfter;
    this.#file = path.join(this.#dir, RECEIPT_LOG);
    fs.mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    this.#records = this.#load();
    this.#fd = fs.openSync(this.#file, "a", 0o600);
    this.#bytes = fs.fstatSync(this.#fd).size;
  }

  /** "ok", "recovered" (torn tail dropped) or "degraded" (corrupt, failed closed). */
  get status() { return this.#status; }
  get path() { return this.#file; }
  /** Current on-disk log size in bytes. */
  get bytes() { return this.#bytes; }
  /** Number of fsync calls issued (test/diagnostic signal for the fsync policy). */
  get fsyncs() { return this.#fsyncs; }

  /** Every valid persisted record; expiry filtering and bounds are the ledger's. */
  load() { return this.#records; }

  /**
   * Appends one checksummed line. Returns "ok" when written, "full" when the hard
   * byte budget would be exceeded (nothing is written; the ledger compacts and
   * re-persists its live set) or "closed".
   */
  append(record) {
    if (this.#closed) return "closed";
    const encoded = encodeRecord(Buffer.from(JSON.stringify(record), "utf8"));
    if (this.#bytes + encoded.length > this.#maxBytes) return "full";
    fs.writeSync(this.#fd, encoded);
    this.#bytes += encoded.length;
    this.#appended += 1;
    if (this.#fsync === "always") this.#sync();
    else if (this.#fsync === "batch" && ++this.#pending >= BATCH_FSYNC) this.#sync();
    return "ok";
  }

  /** True once the appended-line trigger has been reached. */
  shouldCompact() { return !this.#saturated && this.#appended >= this.#compactAfter; }

  /** True when the compacted live set alone exceeds the hard byte budget. */
  saturated() { return this.#saturated; }

  /** Atomically replaces the log with exactly `records` (temp + fsync + rename). */
  compact(records) {
    if (this.#closed) return;
    const data = Buffer.concat(records.map(record => encodeRecord(Buffer.from(JSON.stringify(record), "utf8"))));
    const tmp = this.#file + ".tmp";
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, data);
      if (this.#fsync !== "never") { fs.fsyncSync(fd); this.#fsyncs += 1; }
    } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, this.#file);
    if (this.#fsync !== "never") this.#fsyncDir();
    if (this.#fd !== undefined) { try { fs.closeSync(this.#fd); } catch { /* best-effort */ } }
    this.#fd = fs.openSync(this.#file, "a", 0o600);
    this.#bytes = data.length;
    this.#appended = 0;
    this.#pending = 0;
    // Once even the live set cannot fit, stop re-compacting on every dropped
    // append; the file is already bounded by the (bounded) live set.
    this.#saturated = this.#bytes > this.#maxBytes;
  }

  close() {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#fd !== undefined) {
      if (this.#fsync !== "never") { try { this.#sync(); } catch { /* best-effort */ } }
      try { fs.closeSync(this.#fd); } catch { /* best-effort */ }
      this.#fd = undefined;
    }
  }

  #sync() {
    fs.fsyncSync(this.#fd);
    this.#pending = 0;
    this.#fsyncs += 1;
  }

  #load() {
    if (!fs.existsSync(this.#file)) return [];
    let buffer;
    try { buffer = fs.readFileSync(this.#file); }
    catch { this.#status = "degraded"; return []; }
    let result;
    try { result = readRecords(buffer); }
    catch {
      // Interior corruption: fail closed to no receipts and preserve the file
      // for inspection so new appends never sit behind unreadable bytes.
      this.#status = "degraded";
      this.#quarantine();
      return [];
    }
    if (result.torn) {
      this.#status = "recovered";
      try { fs.truncateSync(this.#file, result.validBytes); } catch { /* reported as recovered regardless */ }
    }
    const records = [];
    for (const { record } of result.records) {
      if (!validReceiptRecord(record)) {
        // A checksum-valid but structurally invalid record is corruption too: it
        // would otherwise poison every future load, so quarantine the whole file
        // (as for interior corruption) and start a fresh, bounded log.
        this.#status = "degraded";
        this.#quarantine();
        return [];
      }
      records.push(record);
    }
    return records;
  }

  // Moves the unreadable or poisoned log aside so the next append starts a clean
  // file. Best-effort: a failed rename still reports "degraded".
  #quarantine() {
    try { fs.renameSync(this.#file, this.#file + ".corrupt"); } catch { /* best-effort */ }
  }

  #fsyncDir() {
    let fd;
    try {
      fd = fs.openSync(this.#dir, "r");
      fs.fsyncSync(fd);
    } catch {
      // A directory fsync is not supported on every platform; the rename is
      // still atomic and the file itself was fsynced above.
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }
}

export class DurableStore {
  #dir;
  #manifestPath;
  #segments = [];
  #activeFile;
  #activeFd;
  #activeBytes = 0;
  #sessions = new Map(); // session -> { entries: [{seq, at, message, raw, bytes}], nextSeq, oldestSeq, lastAccess }
  #known = new Map(); // session -> last assigned seq, retained after an empty session is reaped
  #totalBytes = 0;
  #diskBytes = 0;
  #nextSegmentIndex = 0;
  #retentionMs;
  #maxEntriesPerSession;
  #maxSessions;
  #maxBytes;
  #fsync;
  #status = "ok";
  #clock = 0;
  #pending = 0;
  #closed = false;
  #lockPath;
  #lockHeld = false;
  #manifestPending = 0;
  #faulted = false;
  #receiptLog = null;

  constructor(configuration = {}) {
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration) ||
        Object.keys(configuration).some(key => !FIELDS.includes(key))) {
      throw new TypeError("invalid durable configuration");
    }
    const backend = configuration.backend ?? "segments";
    if (backend !== "segments") throw new RangeError("unsupported durable backend");
    if (typeof configuration.dir !== "string" || configuration.dir.length === 0) {
      throw new TypeError("durable store directory is required");
    }
    const retentionMs = configuration.retentionMs ?? 3600000;
    const maxEntriesPerSession = configuration.maxEntriesPerSession ?? 4096;
    const maxSessions = configuration.maxSessions ?? 1024;
    const maxBytes = configuration.maxBytes ?? 268435456;
    const fsync = configuration.fsync ?? "batch";
    const lock = configuration.lock ?? "exclusive";
    if (!Number.isInteger(retentionMs) || retentionMs < 1 || retentionMs > 2592000000) {
      throw new RangeError("invalid durable retentionMs");
    }
    if (!Number.isInteger(maxEntriesPerSession) || maxEntriesPerSession < 1 || maxEntriesPerSession > 1000000) {
      throw new RangeError("invalid durable maxEntriesPerSession");
    }
    if (!Number.isInteger(maxSessions) || maxSessions < 1 || maxSessions > 100000) {
      throw new RangeError("invalid durable maxSessions");
    }
    // The 0.1 file format does not enforce a 1 MiB floor so failure-injection
    // tests can pressure the byte budget with small envelopes.
    if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 17179869184) {
      throw new RangeError("invalid durable maxBytes");
    }
    if (!FSYNC_MODES.includes(fsync)) throw new RangeError("invalid durable fsync");
    if (lock !== "exclusive") throw new RangeError("unsupported durable lock mode");
    this.#retentionMs = retentionMs;
    this.#maxEntriesPerSession = maxEntriesPerSession;
    this.#maxSessions = maxSessions;
    this.#maxBytes = maxBytes;
    this.#fsync = fsync;
    this.#dir = path.resolve(configuration.dir);
    fs.mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    this.#manifestPath = path.join(this.#dir, MANIFEST);
    this.#lockPath = path.join(this.#dir, LOCK);
    // The lock is the correctness boundary for a single writer: hold it before
    // touching any state, and release it if opening fails partway through.
    this.#acquireLock();
    try {
      this.#load();
    } catch (error) {
      if (this.#activeFd !== undefined) {
        try { fs.closeSync(this.#activeFd); } catch { /* best-effort */ }
        this.#activeFd = undefined;
      }
      this.#releaseLock();
      throw error;
    }
  }

  // Numeric durable limits. `resumeLimits` mirrors the in-memory DeliveryLog
  // shape the relay advertises as `resume` so either store reports the same key.
  get limits() {
    return { retentionMs: this.#retentionMs, maxEntriesPerSession: this.#maxEntriesPerSession,
      maxSessions: this.#maxSessions, maxBytes: this.#maxBytes };
  }
  get resumeLimits() {
    return { windowMs: this.#retentionMs, maxPerSession: this.#maxEntriesPerSession, maxSessions: this.#maxSessions };
  }
  get backend() { return "segments"; }
  get fsync() { return this.#fsync; }

  /** "ok", or "recovered" after a torn tail was dropped or a counter reconstructed. */
  status() { return this.#status; }

  /**
   * Creates (once) and returns the digest-only receipt log that shares this
   * store's directory, exclusive lock and fsync policy. Its recovery state is
   * folded into this store's `status()` so health reports it under the existing
   * `durable.state` field without exposing any per-principal receipt state.
   */
  openReceiptLog() {
    if (this.#receiptLog) return this.#receiptLog;
    // The receipt log's hard byte budget is derived from (and smaller than) the
    // delivery budget, so advisory receipts cannot consume the whole store.
    const maxBytes = Math.min(RECEIPT_BUDGET_MAX,
      Math.max(RECEIPT_BUDGET_MIN, Math.floor(this.#maxBytes / RECEIPT_BUDGET_FRACTION)));
    const log = new ReceiptLog({ dir: this.#dir, fsync: this.#fsync, maxBytes, compactAfter: RECEIPT_COMPACT_LINES });
    if (log.status === "degraded") this.#status = "degraded";
    else if (log.status === "recovered" && this.#status === "ok") this.#status = "recovered";
    this.#receiptLog = log;
    return log;
  }

  /**
   * Reserves and persists a strictly increasing per-session sequence BEFORE the
   * record is written, then appends the verbatim envelope and returns the seq.
   * A crash between the two leaves a hole: the sequence is never reused. A
   * reserved seq whose record is evicted immediately is likewise never reused.
   */
  append(session, message, receivedAt = Date.now()) {
    if (this.#closed) throw new Error("durable store is closed");
    if (typeof session !== "string" || session.length === 0) throw new TypeError("invalid durable session");
    if (message === undefined || message === null) throw new TypeError("invalid durable message");
    const at = this.#tick(receivedAt);
    let state = this.#sessions.get(session);
    if (!state) {
      // Restore the monotonic sequence if this session was reaped when empty.
      const last = this.#known.get(session);
      const nextSeq = last === undefined ? 1 : last + 1;
      state = { entries: [], nextSeq, oldestSeq: nextSeq, lastAccess: at };
      this.#sessions.set(session, state);
      this.#known.delete(session);
    }
    const seq = state.nextSeq++;
    const raw = Buffer.from(JSON.stringify({ session, seq, at, message }), "utf8");
    const entry = { seq, at, message, raw, bytes: RECORD_HEADER + raw.length };
    state.entries.push(entry);
    state.lastAccess = at;
    this.#totalBytes += entry.bytes;
    this.#enforce(state, entry, at);
    // Persist the manifest state before the record so an interrupted append
    // cannot reuse the seq. "batch"/"never" throttle this rewrite (see
    // #maybeWriteManifest); recovery reconstructs nextSeq from the records.
    const segmentsBefore = this.#segments.length;
    this.#rollIfNeeded(entry.bytes);
    this.#maybeWriteManifest(this.#segments.length !== segmentsBefore);
    this.#appendRecord(entry);
    this.#syncSegment(false);
    // Reclaim bytes evicted by capacity/retention once they dominate the budget.
    if (this.#deadBytes() > this.#maxBytes / 2) this.#compactBestEffort();
    return seq;
  }

  /**
   * Retained entries with seq strictly greater than `after`, oldest first.
   * `gap` is true when sequences between the cursor and the oldest retained
   * entry were dropped (eviction, retention or a reserved hole); `from` is the
   * oldest retained seq (or the next seq when nothing is retained).
   */
  since(session, after, now = Date.now()) {
    const time = this.#tick(now);
    const state = this.#sessions.get(session);
    if (state) this.#retire(state, time);
    if (!state) {
      const last = this.#known.get(session);
      if (last !== undefined && after < last) return { entries: [], gap: true, from: last + 1 };
      return { entries: [], gap: false, from: after + 1 };
    }
    if (state.entries.length === 0) {
      const last = state.nextSeq - 1;
      if (after < last) return { entries: [], gap: true, from: last + 1 };
      return { entries: [], gap: false, from: after + 1 };
    }
    state.lastAccess = time;
    const oldest = state.entries[0].seq;
    return {
      entries: state.entries.filter(entry => entry.seq > after).map(toEntry),
      gap: after < oldest - 1,
      from: oldest
    };
  }

  /** The retained entry with this exact sequence, or null. Read-only (no reorder). */
  lookup(session, seq, now = Date.now()) {
    const time = this.#tick(now);
    const state = this.#sessions.get(session);
    if (!state) return null;
    this.#retire(state, time);
    const entry = state.entries.find(candidate => candidate.seq === seq);
    return entry === undefined ? null : toEntry(entry);
  }

  lookupById(session, id, now = Date.now()) {
    return this.lookupAllById(session, id, now)[0] ?? null;
  }

  /** Every retained entry whose message id equals `id`, oldest first. */
  lookupAllById(session, id, now = Date.now()) {
    const time = this.#tick(now);
    const state = this.#sessions.get(session);
    if (!state) return [];
    this.#retire(state, time);
    return state.entries.filter(entry => entry.message.id === id).map(toEntry);
  }

  /** Flushes, reclaims dead segments and releases the active segment. Idempotent. */
  close() {
    if (this.#closed) return;
    // After an injected compaction crash the process is considered dead: it must
    // not rewrite the manifest or compact, or the crash state under test would be
    // erased. The lock is still released so a recovery store can open.
    if (!this.#faulted) {
      if (this.#deadBytes() > 0) this.#compactBestEffort();
      // Persist the latest reservations on close even in "batch" mode.
      try { this.#writeManifest(true); } catch { /* best-effort flush on close */ }
    }
    this.#closed = true;
    if (this.#activeFd !== undefined) {
      try { this.#syncSegment(true); } catch { /* best-effort flush on close */ }
      fs.closeSync(this.#activeFd);
      this.#activeFd = undefined;
    }
    this.#receiptLog?.close();
    this.#releaseLock();
  }

  /**
   * Rewrites only the live records into fresh segment(s), atomically swaps the
   * manifest (temp + fsync + rename) and then unlinks the superseded segments.
   * The previous generation stays valid and referenced until the new manifest
   * is durably in place, so an interruption cannot lose live records or reuse a
   * `seq`. `options.fault` is a test-only crash injection: "after-write" (new
   * segments written, manifest not swapped), "after-manifest" (swapped, old
   * segments not yet unlinked) or "torn" (a truncated new segment).
   */
  compact(options) {
    if (this.#closed) throw new Error("durable store is closed");
    let fault;
    if (options !== undefined) {
      if (!options || typeof options !== "object" || Array.isArray(options)) {
        throw new TypeError("invalid durable compact options");
      }
      fault = options.fault;
      if (fault !== undefined && !COMPACT_FAULTS.includes(fault)) {
        throw new RangeError("invalid durable compact fault");
      }
    }
    this.#compact(fault);
  }

  #compactBestEffort() {
    try { this.#compact(); }
    catch { /* a failed compaction leaves the previous generation intact */ }
  }

  #deadBytes() { return this.#diskBytes - this.#totalBytes; }

  #allocateSegmentName() {
    const name = "segment-" + String(this.#nextSegmentIndex).padStart(6, "0") + ".log";
    this.#nextSegmentIndex += 1;
    return name;
  }

  #refreshOldest() {
    for (const state of this.#sessions.values()) {
      state.oldestSeq = state.entries.length > 0 ? state.entries[0].seq : state.nextSeq;
    }
  }

  #compact(fault) {
    // Freeze the current generation: sync and close the active fd so every
    // appended byte is durable before the live set is rewritten.
    if (this.#activeFd !== undefined) {
      this.#syncSegment(true);
      fs.closeSync(this.#activeFd);
      this.#activeFd = undefined;
    }
    const oldSegments = this.#segments.slice();

    // Pack live records into fresh segments, preserving verbatim payload bytes.
    const outputs = [];
    let chunks = [];
    let chunkBytes = 0;
    const flushChunk = () => { outputs.push(Buffer.concat(chunks)); chunks = []; chunkBytes = 0; };
    for (const state of this.#sessions.values()) {
      for (const entry of state.entries) {
        const record = encodeRecord(entry.raw);
        if (chunkBytes > 0 && chunkBytes + record.length > SEGMENT_BYTES) flushChunk();
        chunks.push(record);
        chunkBytes += record.length;
      }
    }
    if (chunks.length > 0) flushChunk();

    const names = [];
    const count = Math.max(outputs.length, 1);
    for (let index = 0; index < count; index++) names.push(this.#allocateSegmentName());
    for (let index = 0; index < outputs.length; index++) {
      const file = path.join(this.#dir, names[index]);
      const fd = fs.openSync(file, "w", 0o600);
      try {
        fs.writeSync(fd, outputs[index]);
        if (this.#fsync !== "never") fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    }
    if (outputs.length === 0) fs.writeFileSync(path.join(this.#dir, names[0]), Buffer.alloc(0), { mode: 0o600 });
    this.#syncDir();

    if (fault === "after-write" || fault === "torn") {
      if (fault === "torn") fs.appendFileSync(path.join(this.#dir, names[names.length - 1]), Buffer.from([0, 0, 0]));
      this.#faulted = true;
      throw new Error("durable store: compaction interrupted");
    }

    // Commit: reference the fresh generation before deleting the old one.
    this.#segments = names;
    this.#activeFile = names[names.length - 1];
    this.#activeFd = fs.openSync(path.join(this.#dir, this.#activeFile), "a");
    this.#activeBytes = outputs.length > 0 ? outputs[outputs.length - 1].length : 0;
    this.#diskBytes = this.#totalBytes;
    this.#refreshOldest();
    this.#writeManifest(true);

    if (fault === "after-manifest") { this.#faulted = true; throw new Error("durable store: compaction interrupted"); }

    for (const name of oldSegments) {
      if (names.includes(name)) continue;
      try { fs.unlinkSync(path.join(this.#dir, name)); } catch { /* already gone */ }
    }
    this.#syncDir();
  }

  // A crashed compaction can leave unreferenced segment files behind. After a
  // successful load the manifest is authoritative, so they are safe to remove.
  #cleanupOrphans() {
    const referenced = new Set(this.#segments);
    let names;
    try { names = fs.readdirSync(this.#dir); } catch { return; }
    for (const name of names) {
      if (!SEGMENT_PATTERN.test(name) || referenced.has(name)) continue;
      try { fs.unlinkSync(path.join(this.#dir, name)); } catch { /* best-effort */ }
    }
  }

  #tick(now) {
    if (!Number.isFinite(now) || now < 0 || now > Number.MAX_SAFE_INTEGER) {
      throw new RangeError("invalid durable time");
    }
    this.#clock = Math.max(this.#clock, now);
    return this.#clock;
  }

  #load() {
    let manifest = null;
    if (fs.existsSync(this.#manifestPath)) {
      let text;
      try { text = fs.readFileSync(this.#manifestPath, "utf8"); }
      catch { throw new Error("durable store: unreadable manifest"); }
      try { manifest = JSON.parse(text); }
      catch { throw new Error("durable store: unreadable manifest"); }
      if (!manifest || typeof manifest !== "object" || manifest.version !== STORE_VERSION ||
          !Array.isArray(manifest.segments) || manifest.sessions === null || typeof manifest.sessions !== "object") {
        throw new Error("durable store: incompatible manifest");
      }
    } else if (fs.readdirSync(this.#dir).some(name => SEGMENT_PATTERN.test(name))) {
      // Segments without a manifest cannot be interpreted; fail closed.
      throw new Error("durable store: missing manifest");
    }
    const sessions = manifest?.sessions ?? {};
    for (const [session, meta] of Object.entries(sessions)) {
      if (!meta || !Number.isSafeInteger(meta.nextSeq) || meta.nextSeq < 1) {
        throw new Error("durable store: invalid manifest session");
      }
      this.#sessions.set(session, {
        entries: [],
        nextSeq: meta.nextSeq,
        oldestSeq: Number.isSafeInteger(meta.oldestSeq) ? meta.oldestSeq : 1,
        lastAccess: Number.isFinite(meta.lastAccess) ? meta.lastAccess : 0
      });
    }
    this.#segments = (manifest?.segments ?? []).filter(name => typeof name === "string" && SEGMENT_PATTERN.test(name));
    this.#diskBytes = 0;
    for (const name of fs.readdirSync(this.#dir)) {
      const match = SEGMENT_PATTERN.exec(name);
      if (match) this.#nextSegmentIndex = Math.max(this.#nextSegmentIndex, Number(match[1]) + 1);
    }
    for (let index = 0; index < this.#segments.length; index++) {
      const file = path.join(this.#dir, this.#segments[index]);
      let buffer;
      try { buffer = fs.readFileSync(file); }
      catch { throw new Error("durable store: missing segment " + this.#segments[index]); }
      const { records, torn, validBytes } = readRecords(buffer);
      this.#diskBytes += torn ? validBytes : buffer.length;
      for (const { record, raw, bytes } of records) {
        if (!record || typeof record.session !== "string" || !Number.isSafeInteger(record.seq) || record.seq < 1 ||
            record.message === undefined || record.message === null) {
          throw new Error("durable store: invalid record");
        }
        let state = this.#sessions.get(record.session);
        if (!state) {
          state = { entries: [], nextSeq: 1, oldestSeq: 1, lastAccess: 0 };
          this.#sessions.set(record.session, state);
        }
        state.entries.push({ seq: record.seq, at: Number.isFinite(record.at) ? record.at : 0,
          message: record.message, raw, bytes });
        if (record.seq + 1 > state.nextSeq) { state.nextSeq = record.seq + 1; this.#status = "recovered"; }
      }
      if (torn) {
        // Discard this segment's torn tail. Appends only ever extend the last
        // segment, so nothing valid can follow a torn tail. Truncating the tail
        // keeps later appends from writing behind the bad bytes.
        this.#status = "recovered";
        try { fs.truncateSync(file, validBytes); } catch { /* reported as recovered regardless */ }
        this.#segments = this.#segments.slice(0, index + 1);
        break;
      }
    }
    // Retention on open is a wall-clock policy; it must not advance the
    // monotonic clock used for later appends, or synthetic/past timestamps lose
    // their relative ordering.
    const now = Date.now();
    this.#totalBytes = 0;
    for (const state of this.#sessions.values()) {
      state.entries.sort((left, right) => left.seq - right.seq);
      const maxSeq = state.entries.length > 0 ? state.entries[state.entries.length - 1].seq : 0;
      if (maxSeq + 1 > state.nextSeq) { state.nextSeq = maxSeq + 1; this.#status = "recovered"; }
      state.entries = state.entries.filter(entry => entry.seq >= state.oldestSeq);
      this.#retire(state, now);
      state.oldestSeq = state.entries.length > 0 ? state.entries[0].seq : state.nextSeq;
      for (const entry of state.entries) this.#totalBytes += entry.bytes;
    }
    this.#enforceAll();
    this.#cleanupOrphans();
    if (this.#segments.length > 0) {
      this.#activeFile = this.#segments[this.#segments.length - 1];
      const file = path.join(this.#dir, this.#activeFile);
      if (!fs.existsSync(file)) fs.writeFileSync(file, Buffer.alloc(0), { mode: 0o600 });
      this.#activeFd = fs.openSync(file, "a");
      this.#activeBytes = fs.fstatSync(this.#activeFd).size;
    } else {
      this.#rollSegment();
    }
    // Write the manifest only after the active segment is known, so it always
    // references every segment that holds records. This is what lets "batch"/
    // "never" skip later manifest rewrites until a roll or the batch interval.
    this.#writeManifest(true);
  }

  #rollIfNeeded(bytes) {
    if (this.#activeFd === undefined) { this.#rollSegment(); return; }
    if (this.#activeBytes > 0 && this.#activeBytes + bytes > SEGMENT_BYTES) this.#rollSegment();
  }

  #rollSegment() {
    if (this.#activeFd !== undefined) {
      this.#syncSegment(true);
      fs.closeSync(this.#activeFd);
      this.#activeFd = undefined;
    }
    const name = this.#allocateSegmentName();
    const file = path.join(this.#dir, name);
    fs.writeFileSync(file, Buffer.alloc(0), { mode: 0o600 });
    this.#activeFd = fs.openSync(file, "a");
    this.#activeBytes = 0;
    this.#activeFile = name;
    this.#segments.push(name);
  }

  #appendRecord(entry) {
    const record = encodeRecord(entry.raw);
    fs.writeSync(this.#activeFd, record);
    this.#activeBytes += record.length;
    this.#diskBytes += record.length;
    this.#pending += 1;
  }

  // Manifest write policy. "always" rewrites on every append. "batch"/"never"
  // rewrite only when a segment rolls (the manifest records #segments, so a new
  // segment MUST be referenced before it can be authoritative) or every
  // BATCH_FSYNC appends; close/compact/load force it. Recovery reconstructs
  // nextSeq from records, so a skipped write never reuses a sequence.
  #maybeWriteManifest(rolled) {
    if (this.#fsync === "always" || rolled || this.#manifestPending + 1 >= BATCH_FSYNC) {
      this.#writeManifest();
    } else {
      this.#manifestPending += 1;
    }
  }

  #writeManifest(forceFsync = false) {
    this.#manifestPending = 0;
    const sessions = {};
    for (const [session, state] of this.#sessions) {
      sessions[session] = { nextSeq: state.nextSeq, oldestSeq: state.oldestSeq, lastAccess: state.lastAccess };
    }
    const data = Buffer.from(JSON.stringify({ version: STORE_VERSION, segments: this.#segments, sessions }), "utf8");
    const tmp = this.#manifestPath + ".tmp";
    // fsync:"always" fsyncs every manifest; "batch" only on compact/close
    // (recovery reconstructs nextSeq from records); "never" never fsyncs.
    const sync = this.#fsync === "always" || (forceFsync && this.#fsync !== "never");
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, data);
      if (sync) fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.#manifestPath);
    // Only sync the directory when the rename is meant to be durable.
    if (sync) this.#syncDir();
  }

  // An exclusive writer lock is the existence of <dir>/LOCK, created atomically
  // with "wx". We deliberately do not steal or time out an existing lock: a
  // stale lock from a crashed process is an operator-visible condition ("remove
  // <dir>/LOCK") rather than a silent corruption risk.
  #acquireLock() {
    try {
      const fd = fs.openSync(this.#lockPath, "wx", 0o600);
      try { fs.writeSync(fd, String(process.pid) + "\n"); }
      finally { fs.closeSync(fd); }
      this.#lockHeld = true;
    } catch (error) {
      if (error && error.code === "EEXIST") {
        throw new Error("durable store is locked (another process holds " + this.#dir + ")");
      }
      throw error;
    }
  }

  #releaseLock() {
    if (!this.#lockHeld) return;
    this.#lockHeld = false;
    try { fs.unlinkSync(this.#lockPath); } catch { /* already gone */ }
  }

  #syncSegment(force) {
    if (this.#activeFd === undefined || this.#fsync === "never") return;
    if (this.#fsync === "always" || force || this.#pending >= BATCH_FSYNC) {
      fs.fsyncSync(this.#activeFd);
      this.#pending = 0;
    }
  }

  #syncDir() {
    if (this.#fsync === "never") return;
    let fd;
    try {
      fd = fs.openSync(this.#dir, "r");
      fs.fsyncSync(fd);
    } catch {
      // A directory fsync is not supported on every platform; the rename is
      // still atomic and the manifest itself was fsynced above.
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }

  #retire(state, now) {
    const cutoff = now - this.#retentionMs;
    while (state.entries.length > 0 && state.entries[0].at <= cutoff) {
      const dropped = state.entries.shift();
      this.#totalBytes -= dropped.bytes;
    }
    state.oldestSeq = state.entries.length > 0 ? state.entries[0].seq : state.nextSeq;
  }

  #enforce(state, protectedEntry, now) {
    this.#retire(state, now);
    while (state.entries.length > this.#maxEntriesPerSession) {
      const dropped = state.entries.shift();
      this.#totalBytes -= dropped.bytes;
    }
    state.oldestSeq = state.entries.length > 0 ? state.entries[0].seq : state.nextSeq;
    this.#evictToBytes(protectedEntry);
    this.#evictSessions(state);
    // Deleting emptied sessions keeps the session map and the per-append
    // manifest bounded; the monotonic sequence is retained in #known.
    this.#reapEmpty(state);
  }

  // Post-load capacity enforcement: no entry is protected, retention is applied
  // by the caller, and the logical result is persisted by the caller's manifest.
  #enforceAll() {
    for (const state of this.#sessions.values()) {
      while (state.entries.length > this.#maxEntriesPerSession) {
        const dropped = state.entries.shift();
        this.#totalBytes -= dropped.bytes;
      }
    }
    this.#evictToBytes(undefined);
    this.#evictSessions(undefined);
    for (const state of this.#sessions.values()) {
      state.oldestSeq = state.entries.length > 0 ? state.entries[0].seq : state.nextSeq;
    }
    this.#reapEmpty(undefined);
  }

  #evictToBytes(protectedEntry) {
    while (this.#totalBytes > this.#maxBytes) {
      let victim;
      for (const state of this.#sessions.values()) {
        const oldest = state.entries[0];
        if (oldest === undefined || oldest === protectedEntry) continue;
        if (victim === undefined || oldest.at < victim.entry.at ||
            (oldest.at === victim.entry.at && oldest.seq < victim.entry.seq)) {
          victim = { state, entry: oldest };
        }
      }
      if (victim === undefined) break;
      victim.state.entries.shift();
      this.#totalBytes -= victim.entry.bytes;
      victim.state.oldestSeq = victim.state.entries.length > 0 ? victim.state.entries[0].seq : victim.state.nextSeq;
    }
  }

  #evictSessions(protectedState) {
    // Empty sessions are reaped, so this is O(1) while under the session cap.
    if (this.#sessions.size <= this.#maxSessions) return;
    const retained = [...this.#sessions.values()].filter(state => state.entries.length > 0);
    if (retained.length <= this.#maxSessions) return;
    retained.sort((left, right) => left.lastAccess - right.lastAccess);
    let count = retained.length;
    for (const state of retained) {
      if (count <= this.#maxSessions) break;
      if (state === protectedState) continue;
      for (const entry of state.entries) this.#totalBytes -= entry.bytes;
      state.entries = [];
      state.oldestSeq = state.nextSeq;
      count -= 1;
    }
  }

  #reapEmpty(protectedState) {
    for (const [session, state] of this.#sessions) {
      if (state === protectedState || state.entries.length > 0) continue;
      this.#remember(session, state.nextSeq - 1);
      this.#sessions.delete(session);
    }
  }

  #remember(session, lastSeq) {
    this.#known.delete(session);
    this.#known.set(session, lastSeq);
    while (this.#known.size > this.#maxSessions * 4) this.#known.delete(this.#known.keys().next().value);
  }
}

const toEntry = entry => ({ seq: entry.seq, at: entry.at, message: entry.message });
