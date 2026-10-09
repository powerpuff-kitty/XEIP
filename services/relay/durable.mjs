/**
 * Bounded, restart-surviving delivery store for the xeip.local-durable/0.1
 * profile. It is a dependency-free segmented append-only log plus an atomically
 * swapped manifest, using only node:fs / node:path / node:crypto.
 *
 * It mirrors the in-memory DeliveryLog method shapes (append, since, lookup,
 * lookupAllById, limits) so the relay can use either store. It is NOT a queue
 * with exactly-once semantics: a reserved-but-unappended sequence is a
 * permanent hole, interior corruption fails closed, and only a torn tail is
 * recovered. Bounded compaction reclaims evicted bytes crash-safely;
 * multi-process locking and encryption are deferred.
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
// With fsync:"batch" the active segment is flushed every N appends (and on close).
const BATCH_FSYNC = 64;
const RECORD_HEADER = 4 + 32; // uint32 payload length + SHA-256(payload)
const MANIFEST = "manifest.json";
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

export class DurableStore {
  #dir;
  #manifestPath;
  #segments = [];
  #activeFile;
  #activeFd;
  #activeBytes = 0;
  #sessions = new Map(); // session -> { entries: [{seq, at, message, raw, bytes}], nextSeq, oldestSeq, lastAccess }
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
    this.#load();
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
      state = { entries: [], nextSeq: 1, oldestSeq: 1, lastAccess: at };
      this.#sessions.set(session, state);
    }
    const seq = state.nextSeq++;
    const raw = Buffer.from(JSON.stringify({ session, seq, at, message }), "utf8");
    const entry = { seq, at, message, raw, bytes: RECORD_HEADER + raw.length };
    state.entries.push(entry);
    state.lastAccess = at;
    this.#totalBytes += entry.bytes;
    this.#enforce(state, entry, at);
    // Persist the manifest (counter reservation and current capacity state)
    // before the record, so an interrupted append cannot reuse the seq.
    this.#rollIfNeeded(entry.bytes);
    this.#writeManifest();
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
    if (!state || state.entries.length === 0) {
      const last = state === undefined ? undefined : state.nextSeq - 1;
      if (last !== undefined && after < last) return { entries: [], gap: true, from: last + 1 };
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
    if (this.#deadBytes() > 0) this.#compactBestEffort();
    this.#closed = true;
    if (this.#activeFd !== undefined) {
      try { this.#syncSegment(true); } catch { /* best-effort flush on close */ }
      fs.closeSync(this.#activeFd);
      this.#activeFd = undefined;
    }
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
      throw new Error("durable store: compaction interrupted");
    }

    // Commit: reference the fresh generation before deleting the old one.
    this.#segments = names;
    this.#activeFile = names[names.length - 1];
    this.#activeFd = fs.openSync(path.join(this.#dir, this.#activeFile), "a");
    this.#activeBytes = outputs.length > 0 ? outputs[outputs.length - 1].length : 0;
    this.#diskBytes = this.#totalBytes;
    this.#refreshOldest();
    this.#writeManifest();

    if (fault === "after-manifest") throw new Error("durable store: compaction interrupted");

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
    this.#writeManifest();
    if (this.#segments.length > 0) {
      this.#activeFile = this.#segments[this.#segments.length - 1];
      const file = path.join(this.#dir, this.#activeFile);
      if (!fs.existsSync(file)) fs.writeFileSync(file, Buffer.alloc(0), { mode: 0o600 });
      this.#activeFd = fs.openSync(file, "a");
      this.#activeBytes = fs.fstatSync(this.#activeFd).size;
    } else {
      this.#rollSegment();
    }
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

  #writeManifest() {
    const sessions = {};
    for (const [session, state] of this.#sessions) {
      sessions[session] = { nextSeq: state.nextSeq, oldestSeq: state.oldestSeq, lastAccess: state.lastAccess };
    }
    const data = Buffer.from(JSON.stringify({ version: STORE_VERSION, segments: this.#segments, sessions }), "utf8");
    const tmp = this.#manifestPath + ".tmp";
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, data);
      if (this.#fsync !== "never") fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.#manifestPath);
    this.#syncDir();
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
    this.#evictToBytes(protectedEntry);
    this.#evictSessions(state);
    for (const candidate of this.#sessions.values()) {
      candidate.oldestSeq = candidate.entries.length > 0 ? candidate.entries[0].seq : candidate.nextSeq;
    }
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
    }
  }

  #evictSessions(protectedState) {
    const retained = [...this.#sessions.values()].filter(state => state.entries.length > 0);
    if (retained.length <= this.#maxSessions) return;
    retained.sort((left, right) => left.lastAccess - right.lastAccess);
    let count = retained.length;
    for (const state of retained) {
      if (count <= this.#maxSessions) break;
      if (state === protectedState) continue;
      for (const entry of state.entries) this.#totalBytes -= entry.bytes;
      state.entries = [];
      count -= 1;
    }
  }
}

const toEntry = entry => ({ seq: entry.seq, at: entry.at, message: entry.message });
