/** Experimental independent byte journal. Not exported by the production Worker. */
import { createHash } from "node:crypto";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import {
  canonicalize,
  recoveryOptions,
  genesis,
  validateAppend,
  validateEntry,
  sealEntry,
  decodePart,
  integer,
  PART_BYTES,
} from "./recovery-record.mjs";
import {
  initializeRecoverySchema,
  verifyRecoverySchema,
} from "./recovery-schema.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {import('./recovery-record.mjs').Entry} Entry */
export class RecoveryJournal {
  #storage;
  #options;
  #state = "opening";
  /** @type {Entry|null} */ #tail = null;
  /** @param {Storage} storage @param {unknown} options */
  constructor(storage, options) {
    this.#storage = storage;
    this.#options = recoveryOptions(options);
  }
  /** @param {Storage} storage @param {unknown} options */
  static async initialize(storage, options) {
    const journal = new RecoveryJournal(storage, options);
    try {
      initializeRecoverySchema(storage, journal.#options);
      await journal.#activate();
      return journal;
    } catch (error) {
      journal.close();
      if (error instanceof StoreConflict) throw error;
      throw new StoreUnavailable();
    }
  }
  /** @param {Storage} storage @param {unknown} options */
  static async open(storage, options) {
    const journal = new RecoveryJournal(storage, options);
    try {
      await journal.#activate();
      return journal;
    } catch {
      journal.close();
      throw new StoreUnavailable();
    }
  }
  async #activate() {
    this.#tail = this.#reconcile();
    const before = canonicalize(this.#tail);
    await this.#sync();
    this.#tail = this.#reconcile();
    if (canonicalize(this.#tail) !== before) throw new StoreUnavailable();
    this.#state = "ready";
  }
  async #sync() {
    /** @type {ReturnType<typeof setTimeout>|undefined} */ let timer;
    try {
      await Promise.race([
        this.#storage.sync(),
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new StoreUnavailable()),
            this.#options.timeoutMs,
          );
        }),
      ]);
      if (this.#state === "closed" || this.#state === "failed")
        throw new StoreUnavailable();
    } finally {
      clearTimeout(timer);
    }
  }
  close() {
    this.#state = "closed";
  }
  healthy() {
    if (this.#state !== "ready") return false;
    try {
      this.#current();
      return true;
    } catch {
      return false;
    }
  }
  #ready() {
    if (this.#state !== "ready") throw new StoreUnavailable();
  }
  /** @template T @param {()=>T} callback @returns {T} */
  #checked(callback) {
    try {
      return callback();
    } catch {
      if (this.#state !== "closed") this.#state = "failed";
      throw new StoreUnavailable();
    }
  }
  #head() {
    return {
      organization: this.#options.organization,
      stream: this.#options.stream,
      sequence: this.#tail?.sequence ?? 0,
      checksum: this.#tail?.checksum ?? genesis(this.#options),
    };
  }
  #current() {
    this.#ready();
    return this.#checked(() => {
      verifyRecoverySchema(this.#storage, this.#options);
      const rows = this.#storage.sql
        .exec(
          "SELECT sequence FROM xeip_recovery_entries ORDER BY sequence DESC LIMIT 1",
        )
        .toArray();
      const tail = rows.length ? this.#record(Number(rows[0].sequence)) : null;
      if (canonicalize(tail) !== canonicalize(this.#tail))
        throw new StoreUnavailable();
      return this.#head();
    });
  }
  head() {
    return this.#current();
  }
  /** @param {number} sequence @returns {Entry} */
  #record(sequence) {
    const rows = this.#storage.sql
      .exec("SELECT * FROM xeip_recovery_entries WHERE sequence=?", sequence)
      .toArray();
    if (rows.length !== 1 || typeof rows[0].canonical !== "string")
      throw new StoreUnavailable();
    const row = rows[0],
      entry = validateEntry(JSON.parse(String(row.canonical)), this.#options);
    if (
      canonicalize(entry) !== row.canonical ||
      entry.sequence !== sequence ||
      entry.id !== row.id ||
      entry.previous !== row.previous ||
      entry.bytes !== row.bytes ||
      entry.parts !== row.parts ||
      entry.totalBytes !== row.total_bytes ||
      entry.checksum !== row.checksum
    )
      throw new StoreUnavailable();
    return entry;
  }
  /** @param {Entry} entry */
  #payload(entry) {
    const count = this.#storage.sql
      .exec(
        "SELECT COUNT(*) AS n FROM xeip_recovery_chunks WHERE sequence=?",
        entry.sequence,
      )
      .toArray()[0].n;
    if (count !== entry.parts) throw new StoreUnavailable();
    const h = createHash("sha256");
    for (let i = 0; i < entry.parts; i++)
      h.update(
        decodePart(
          this.#data(entry.sequence, i),
          Math.min(PART_BYTES, entry.bytes - i * PART_BYTES),
        ),
      );
    if (h.digest("hex") !== entry.payloadDigest) throw new StoreUnavailable();
  }
  /** @param {number} sequence @param {number} part @returns {string} */
  #data(sequence, part) {
    const rows = this.#storage.sql
      .exec(
        "SELECT data FROM xeip_recovery_chunks WHERE sequence=? AND part=?",
        sequence,
        part,
      )
      .toArray();
    if (rows.length !== 1 || typeof rows[0].data !== "string")
      throw new StoreUnavailable();
    return rows[0].data;
  }
  /** @param {Entry|null} previous @param {Entry} entry */
  #link(previous, entry) {
    if (
      entry.sequence !== (previous?.sequence ?? 0) + 1 ||
      entry.previous !== (previous?.checksum ?? genesis(this.#options)) ||
      entry.totalBytes !== (previous?.totalBytes ?? 0) + entry.bytes
    )
      throw new StoreUnavailable();
  }
  #reconcile() {
    verifyRecoverySchema(this.#storage, this.#options);
    /** @type {Entry|null} */ let previous = null;
    while (true) {
      const rows = this.#storage.sql
        .exec(
          "SELECT sequence FROM xeip_recovery_entries WHERE sequence>? ORDER BY sequence LIMIT 128",
          previous?.sequence ?? 0,
        )
        .toArray();
      if (!rows.length) break;
      for (const row of rows) {
        const entry = this.#record(Number(row.sequence));
        this.#link(previous, entry);
        this.#payload(entry);
        previous = entry;
      }
    }
    if (
      this.#storage.sql
        .exec(
          "SELECT 1 FROM xeip_recovery_chunks c LEFT JOIN xeip_recovery_entries e ON c.sequence=e.sequence WHERE e.sequence IS NULL LIMIT 1",
        )
        .toArray().length
    )
      throw new StoreUnavailable();
    return previous;
  }
  /** @param {number} sequence */
  #selected(sequence) {
    const entry = this.#record(sequence),
      previous = sequence > 1 ? this.#record(sequence - 1) : null;
    this.#link(previous, entry);
    this.#payload(entry);
    if (sequence < (this.#tail?.sequence ?? 0))
      this.#link(entry, this.#record(sequence + 1));
    return entry;
  }
  /** @param {number} sequence */
  entry(sequence) {
    this.#current();
    integer(sequence, 1, this.#tail?.sequence ?? 0);
    return this.#checked(() => this.#selected(sequence));
  }
  /** @param {number} sequence @param {number} index */
  part(sequence, index) {
    const entry = this.entry(sequence);
    integer(index, 0, entry.parts - 1);
    return this.#checked(() => ({
      entry,
      part: index,
      data: this.#data(sequence, index),
    }));
  }
  /** @param {unknown} input */
  async append(input) {
    if (this.#state === "writing") throw new StoreConflict();
    this.#ready();
    const value = validateAppend(input, this.#options),
      head = this.#current();
    const duplicate = this.#checked(() =>
      this.#storage.sql
        .exec("SELECT sequence FROM xeip_recovery_entries WHERE id=?", value.id)
        .toArray(),
    );
    /** @type {Entry} */ let entry;
    let retry = false;
    if (duplicate.length) {
      if (!this.#tail || duplicate[0].sequence !== this.#tail.sequence)
        throw new StoreConflict();
      entry = this.#checked(() => this.#selected(this.#tail?.sequence ?? 0));
      if (
        value.expected.sequence !== entry.sequence - 1 ||
        value.expected.checksum !== entry.previous ||
        value.bytes !== entry.bytes ||
        value.payloadDigest !== entry.payloadDigest ||
        value.chunks.length !== entry.parts
      )
        throw new StoreConflict();
      // Compare actual canonical parts as well as the payload digest.
      for (let i = 0; i < entry.parts; i++)
        if (
          this.#checked(() => this.#data(entry.sequence, i)) !== value.chunks[i]
        )
          throw new StoreConflict();
      retry = true;
    } else {
      if (
        canonicalize(value.expected) !== canonicalize(head) ||
        head.sequence >= this.#options.maxEntries ||
        (this.#tail?.totalBytes ?? 0) + value.bytes > this.#options.maxBytes
      )
        throw new StoreConflict();
      entry = sealEntry({
        schema: "xeip.recovery-entry/1",
        organization: head.organization,
        stream: head.stream,
        sequence: head.sequence + 1,
        id: value.id,
        previous: head.checksum,
        payloadDigest: value.payloadDigest,
        bytes: value.bytes,
        parts: value.chunks.length,
        totalBytes: (this.#tail?.totalBytes ?? 0) + value.bytes,
      });
    }
    this.#state = "writing";
    try {
      if (!retry)
        this.#storage.transactionSync(() => {
          this.#storage.sql.exec(
            "INSERT INTO xeip_recovery_entries(sequence,id,previous,bytes,parts,total_bytes,checksum,canonical) VALUES(?,?,?,?,?,?,?,?)",
            entry.sequence,
            entry.id,
            entry.previous,
            entry.bytes,
            entry.parts,
            entry.totalBytes,
            entry.checksum,
            canonicalize(entry),
          );
          for (let i = 0; i < value.chunks.length; i++)
            this.#storage.sql.exec(
              "INSERT INTO xeip_recovery_chunks(sequence,part,data) VALUES(?,?,?)",
              entry.sequence,
              i,
              value.chunks[i],
            );
          this.#payload(this.#record(entry.sequence));
        });
      await this.#sync();
      verifyRecoverySchema(this.#storage, this.#options);
      const last = this.#storage.sql
        .exec("SELECT MAX(sequence) AS n FROM xeip_recovery_entries")
        .toArray()[0].n;
      const persisted = this.#record(entry.sequence);
      this.#payload(persisted);
      this.#link(
        entry.sequence > 1 ? this.#record(entry.sequence - 1) : null,
        persisted,
      );
      if (
        last !== entry.sequence ||
        canonicalize(persisted) !== canonicalize(entry)
      )
        throw new StoreUnavailable();
      this.#tail = entry;
      this.#state = "ready";
      return { ...entry };
    } catch {
      if (this.#state !== "closed") this.#state = "failed";
      throw new StoreUnavailable();
    }
  }
}
