/** Object-local append-only owner journal. The service owns durability ordering. */
import { randomUUID } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { snapshot } from "../actions.mjs";
import { verifyLedgerSchema } from "./schema.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
import {
  auditSummary,
  metadata,
  auditEvent,
  encodeAuditEvent,
  auditChecksum,
  auditPageOptions,
} from "./admin-record.mjs";
export {
  auditSummary,
  auditEvent,
  auditChecksum,
  auditPageOptions,
  validateAuditPage,
} from "./admin-record.mjs";
import {
  adminCheckpointDigest,
  validateAdminCheckpoint,
  adminHistoryCursor,
  validateAdminHistoryPage,
} from "./admin-checkpoint.mjs";
/** @typedef {import("./admin-record.mjs").Event} Event */
/** @typedef {import("./admin-record.mjs").Summary} Summary */
/** @typedef {import("./admin-record.mjs").Metadata} Metadata */
/** @typedef {import("./admin-record.mjs").RecordEntry} RecordEntry */
/** @typedef {{sequence:number,attempt_id:string,outcome:string,canonical:string,previous:string,checksum:string,start_sequence:number|null,start_canonical:string|null}} Row */
const zero = "0".repeat(64);
/** @param {unknown} value */
const integer = (value) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
export class OwnerJournal {
  #organization = "";
  #storage;
  #clock;
  #max;
  #failed = false;
  #head = 0;
  #checksum = zero;
  #time = 0;
  /** @type {{ticket:object,event:Event,phase:'staged'|'durable'|'finishing'}|undefined} */ #active;
  #syncing = false;
  /** @param {Storage} storage @param {{maxRecords?:number,clock?:()=>number}} [options] */
  constructor(storage, { maxRecords = 100000, clock = Date.now } = {}) {
    if (!Number.isInteger(maxRecords) || maxRecords < 2 || maxRecords > 100000)
      throw new TypeError("invalid journal capacity");
    this.#storage = storage;
    this.#max = maxRecords;
    this.#clock = clock;
    this.#verify();
  }
  #usable() {
    if (this.#failed) throw new StoreUnavailable();
  }
  #fail() {
    this.#failed = true;
    this.#active = undefined;
    return new StoreUnavailable();
  }
  /** Full validation uses bounded pages and O(1) event memory, with indexed start lookups. */
  #verify() {
    this.#usable();
    try {
      verifyLedgerSchema(this.#storage);
      const metadata = this.#storage.sql
        .exec("SELECT organization_id FROM xeip_metadata WHERE singleton=1")
        .toArray();
      const organization = metadata[0]?.organization_id;
      if (
        metadata.length !== 1 ||
        typeof organization !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization) ||
        (this.#organization && organization !== this.#organization)
      )
        throw new Error();
      let sequence = 0,
        previous = zero,
        time = 0;
      for (;;) {
        const rows = /** @type {Row[]} */ (
          /** @type {unknown} */ (
            this.#storage.sql
              .exec(
                "SELECT e.sequence,e.attempt_id,e.outcome,e.canonical,e.previous,e.checksum,s.sequence AS start_sequence,s.canonical AS start_canonical FROM xeip_owner_events e LEFT JOIN xeip_owner_events s ON s.attempt_id=e.attempt_id AND s.outcome='started' WHERE e.sequence>? ORDER BY e.sequence LIMIT 256",
                sequence,
              )
              .toArray()
          )
        );
        if (!rows.length) break;
        for (const row of rows) {
          const { event, encoded } = encodeAuditEvent(
            JSON.parse(row.canonical),
          );
          if (
            row.sequence !== sequence + 1 ||
            row.sequence > this.#max ||
            row.previous !== previous ||
            row.attempt_id !== event.attemptId ||
            row.outcome !== event.outcome ||
            encoded !== row.canonical ||
            event.occurredAt < time ||
            row.checksum !==
              auditChecksum(row.sequence, row.previous, row.canonical)
          )
            throw new Error();
          if (event.outcome !== "started") {
            if (
              row.start_sequence === null ||
              row.start_sequence >= row.sequence ||
              row.start_canonical === null
            )
              throw new Error();
            const start = auditEvent(JSON.parse(row.start_canonical));
            if (
              start.outcome !== "started" ||
              event.operator !== start.operator ||
              event.requestId !== start.requestId ||
              event.operation !== start.operation ||
              event.commandDigest !== start.commandDigest ||
              event.attemptId !== start.attemptId ||
              event.before.state !== start.before.state ||
              event.before.trustRevision !== start.before.trustRevision ||
              event.before.authorityRevision !== start.before.authorityRevision
            )
              throw new Error();
          }
          sequence = row.sequence;
          previous = row.checksum;
          time = event.occurredAt;
        }
      }
      // Never accept truncation beneath an already observed head in this instance.
      if (
        sequence < this.#head ||
        (sequence === this.#head && previous !== this.#checksum)
      )
        throw new Error();
      this.#head = sequence;
      this.#checksum = previous;
      this.#time = time;
      this.#organization = organization;
    } catch {
      throw this.#fail();
    }
  }
  /** @param {Event} event */
  #append(event) {
    const sequence = this.#head + 1,
      previous = this.#checksum,
      { encoded } = encodeAuditEvent(event);
    const checksum = auditChecksum(sequence, previous, encoded);
    this.#storage.sql.exec(
      "INSERT INTO xeip_owner_events(sequence,attempt_id,outcome,canonical,previous,checksum) VALUES (?,?,?,?,?,?)",
      sequence,
      event.attemptId,
      event.outcome,
      encoded,
      previous,
      checksum,
    );
    this.#head = sequence;
    this.#checksum = checksum;
    this.#time = event.occurredAt;
  }
  #now() {
    const now = this.#clock();
    if (!integer(now)) throw new TypeError("invalid audit clock");
    return Math.max(now, this.#time);
  }
  /** Stage inside the caller's initialization transaction when necessary; await sync before mutation.
   * @param {unknown} value @param {unknown} state */
  start(value, state) {
    this.#usable();
    if (this.#active || this.#syncing) throw new StoreConflict();
    const meta = metadata(snapshot(value, 1024)),
      before = auditSummary(snapshot(state, 256));
    this.#verify();
    if (this.#head + 2 > this.#max) throw new StoreConflict();
    const event = {
      ...meta,
      attemptId: randomUUID(),
      outcome: "started",
      occurredAt: this.#now(),
      before,
    };
    const ticket = Object.freeze({});
    try {
      this.#storage.transactionSync(() => this.#append(event));
    } catch {
      throw this.#fail();
    }
    this.#active = { ticket, event, phase: "staged" };
    return ticket;
  }
  /** @param {unknown} ticket @param {unknown} outcome @param {unknown} state */
  finish(ticket, outcome, state) {
    this.#usable();
    if (
      !this.#active ||
      ticket !== this.#active.ticket ||
      this.#active.phase !== "durable" ||
      this.#syncing
    )
      throw new StoreConflict();
    if (
      typeof outcome !== "string" ||
      !["completed", "conflict", "invalid_request", "unavailable"].includes(
        outcome,
      )
    )
      throw new TypeError("invalid audit outcome");
    const after = auditSummary(snapshot(state, 256));
    this.#verify();
    const event = {
      ...this.#active.event,
      outcome,
      occurredAt: this.#now(),
      after,
    };
    try {
      this.#storage.transactionSync(() => this.#append(event));
    } catch {
      throw this.#fail();
    }
    this.#active.phase = "finishing";
  }
  async sync() {
    this.#usable();
    if (this.#syncing || !this.#active || this.#active.phase === "durable")
      throw new StoreConflict();
    this.#syncing = true;
    try {
      await this.#storage.sync();
      this.#usable();
      if (this.#active.phase === "staged") this.#active.phase = "durable";
      else this.#active = undefined;
    } catch {
      throw this.#fail();
    } finally {
      this.#syncing = false;
    }
  }
  /** @param {unknown} [options] */
  export(options) {
    this.#usable();
    if (this.#syncing || (this.#active && this.#active.phase !== "durable"))
      throw new StoreConflict();
    const cursor = auditPageOptions(options);
    this.#verify();
    auditPageOptions(options, this.#head);
    try {
      const rows = this.#storage.sql
        .exec(
          "SELECT sequence,canonical,previous,checksum FROM xeip_owner_events WHERE sequence>? ORDER BY sequence LIMIT ?",
          cursor.after,
          cursor.limit,
        )
        .toArray();
      const records = rows.map((row) => ({
        sequence: Number(row.sequence),
        event: auditEvent(JSON.parse(/** @type {string} */ (row.canonical))),
        previous: String(row.previous),
        checksum: String(row.checksum),
      }));
      return {
        records,
        next: records.at(-1)?.sequence ?? cursor.after,
        headSequence: this.#head,
        headChecksum: this.#checksum,
      };
    } catch {
      throw this.#fail();
    }
  }
  /** Fixed locally settled history; no independent durability or restoration permission. */
  checkpoint() {
    this.#usable();
    if (this.#active || this.#syncing) throw new StoreConflict();
    this.#verify();
    const body = {
      schema: /** @type {const} */ ("xeip.admin-checkpoint/1"),
      organization: this.#organization,
      headSequence: this.#head,
      headChecksum: this.#checksum,
    };
    try {
      return validateAdminCheckpoint(
        { ...body, digest: adminCheckpointDigest(body) },
        this.#organization,
      );
    } catch {
      throw this.#fail();
    }
  }
  /** @param {unknown} value @param {unknown} [options] */
  historyPage(value, options = {}) {
    return this.#historyPage(value, options, false);
  }
  /** Retained historical head, anchored to verified source history; never completes an attempt.
   * @param {unknown} value @param {unknown} [options] */
  historyPageAt(value, options = {}) {
    return this.#historyPage(value, options, true);
  }
  /** Capture the fully verified current head and its scoped reader in one synchronous pass. */
  captureHistoryReader() {
    const checkpoint = this.checkpoint();
    return Object.freeze({
      checkpoint,
      reader: this.#historyReader(checkpoint),
    });
  }
  /** Fully verify once, then expose bounded selected-history reads. Not continuous whole-source attestation.
   * @param {unknown} value */
  historyReaderAt(value) {
    const checkpoint = validateAdminCheckpoint(value, this.#organization);
    this.#historyPage(checkpoint, {}, true);
    return this.#historyReader(checkpoint);
  }
  /** Only accepts an internally validated checkpoint.
   * @param {import('./admin-checkpoint.mjs').Checkpoint} checkpoint */
  #historyReader(checkpoint) {
    let closed = false;
    return Object.freeze({
      page: (/** @type {unknown} */ options = {}) => {
        if (closed) throw new StoreUnavailable();
        return this.#historyPage(checkpoint, options, true, true);
      },
      close: () => {
        closed = true;
      },
    });
  }
  /** Only for a reader that already verified complete history. */
  #readerHead() {
    this.#usable();
    if (this.#active || this.#syncing) throw new StoreConflict();
    try {
      verifyLedgerSchema(this.#storage);
      const scope = this.#storage.sql
        .exec("SELECT organization_id FROM xeip_metadata")
        .toArray();
      const tail = this.#storage.sql
        .exec(
          "SELECT sequence,checksum FROM xeip_owner_events ORDER BY sequence DESC LIMIT 1",
        )
        .toArray();
      if (
        scope.length !== 1 ||
        scope[0].organization_id !== this.#organization ||
        (this.#head === 0
          ? tail.length !== 0
          : tail.length !== 1 ||
            tail[0].sequence !== this.#head ||
            tail[0].checksum !== this.#checksum)
      )
        throw Error();
    } catch {
      throw this.#fail();
    }
  }
  /** @param {unknown} value @param {unknown} options @param {boolean} historical @param {boolean} verified */
  #historyPage(value, options, historical, verified = false) {
    this.#usable();
    const expected = validateAdminCheckpoint(value, this.#organization),
      cursor = adminHistoryCursor(options, expected.headSequence);
    if (verified) this.#readerHead();
    else {
      const current = this.checkpoint();
      if (!historical && current.digest !== expected.digest)
        throw new StoreConflict();
    }
    if (historical) {
      if (expected.headSequence > this.#head) throw new StoreConflict();
      let anchor = zero;
      try {
        if (expected.headSequence > 0) {
          const rows = this.#storage.sql
            .exec(
              "SELECT checksum FROM xeip_owner_events WHERE sequence=?",
              expected.headSequence,
            )
            .toArray();
          if (rows.length !== 1 || typeof rows[0].checksum !== "string")
            throw Error();
          anchor = rows[0].checksum;
        }
      } catch {
        throw this.#fail();
      }
      if (anchor !== expected.headChecksum) {
        if (verified) throw this.#fail();
        throw new StoreConflict();
      }
    }
    let previous = zero;
    try {
      if (cursor.after > 0) {
        const rows = this.#storage.sql
          .exec(
            "SELECT checksum FROM xeip_owner_events WHERE sequence=?",
            cursor.after,
          )
          .toArray();
        if (rows.length !== 1 || typeof rows[0].checksum !== "string")
          throw Error();
        previous = rows[0].checksum;
      }
    } catch {
      throw this.#fail();
    }
    if (previous !== cursor.previousChecksum)
      throw new TypeError("invalid administrative history predecessor");
    try {
      const rows = this.#storage.sql
        .exec(
          "SELECT sequence,canonical,previous,checksum FROM xeip_owner_events WHERE sequence>? AND sequence<=? ORDER BY sequence LIMIT ?",
          cursor.after,
          expected.headSequence,
          cursor.limit,
        )
        .toArray();
      const records = rows.map((row) => ({
        sequence: Number(row.sequence),
        event: auditEvent(JSON.parse(/** @type {string} */ (row.canonical))),
        previous: String(row.previous),
        checksum: String(row.checksum),
      }));
      const next = cursor.after + records.length;
      return validateAdminHistoryPage(
        {
          schema: "xeip.admin-history-page/1",
          checkpointDigest: expected.digest,
          after: cursor.after,
          records,
          next,
          complete: next === expected.headSequence,
        },
        expected,
        cursor,
      );
    } catch {
      throw this.#fail();
    }
  }
}
