/** Rebuild historical action data in an isolated, permanently fenced candidate. Never executes tools. */
import { createHash } from "node:crypto";
import {
  initializeLedger,
  verifyRecoverySchema,
  upgradeActionRestoreSchema,
} from "./schema.mjs";
import {
  canonicalize,
  genesis,
  integer,
  recoveryOptions,
} from "./recovery-record.mjs";
import {
  manifestValue,
  filesHasher,
  recoveryFilename,
  hash,
} from "./recovery-archive-record.mjs";
import {
  decodeActionRecovery,
  actionRecoveryPayload,
  prepareActionRecovery,
} from "./action-recovery-record.mjs";
import { recoveryDescriptor } from "./action-recovery.mjs";
import { validateActionEvidence, projectAction } from "./action-export.mjs";
import { WireDeadline } from "./recovery-wire.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {import('./contracts.js').SqlValue} SqlValue */
/** @typedef {import('./store.mjs').Row} ActionRow */
/** @typedef {{intent:string,sequence:number,head_checksum:string,total_bytes:number,phase:'restoring'|'verified',checksum:string}} Progress */
/** @param {Omit<Progress,'checksum'>} row */
const progressChecksum = (row) =>
  createHash("sha256")
    .update("XEIP staged action restore v1\n" + canonicalize(row))
    .digest("hex");
const actionColumns = [
  "session_id",
  "request_id",
  "digest",
  "canonical",
  "expires_at",
  "state",
  "version",
  "approver",
  "approval_expires_at",
  "claim_id",
  "result_canonical",
];
export class StagedActionRestore {
  #storage;
  #manifest;
  #intent;
  #options;
  #timeout;
  #ready = false;
  #failed = false;
  #closed = false;
  #busy = false;
  /** @param {Storage} storage @param {unknown} manifest @param {{timeoutMs?:number}} [settings] */
  constructor(storage, manifest, { timeoutMs = 10000 } = {}) {
    this.#storage = storage;
    this.#timeout = integer(timeoutMs, 100, 10000);
    this.#intent = canonicalize(manifestValue(manifest));
    if (Buffer.byteLength(this.#intent) > 16384)
      throw new TypeError("invalid restore intent");
    this.#manifest = manifestValue(JSON.parse(this.#intent));
    this.#options = recoveryOptions(this.#manifest.source.options);
    if (
      this.#manifest.head.sequence > 40000 ||
      (this.#manifest.head.sequence === 0 &&
        this.#manifest.filesChecksum !== filesHasher().digest("hex"))
    )
      throw new TypeError("invalid action restore manifest");
  }
  /** @param {Storage} storage @param {unknown} manifest @param {{timeoutMs?:number}} [settings] */
  static async initialize(storage, manifest, settings) {
    const restore = new StagedActionRestore(storage, manifest, settings);
    await restore.#run(async () => {
      storage.transactionSync(() => {
        if (
          restore.#sql(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'",
          ).length
        )
          throw new StoreConflict();
        initializeLedger(storage, restore.#options.organization);
        restore.#sql(
          "INSERT INTO xeip_action_recovery(singleton,canonical) VALUES(1,?)",
          canonicalize(recoveryDescriptor(restore.#options)),
        );
        const row = {
          intent: restore.#intent,
          sequence: 0,
          head_checksum: genesis(restore.#options),
          total_bytes: 0,
          phase: /** @type {const} */ ("restoring"),
        };
        restore.#sql(
          "INSERT INTO xeip_action_restore(singleton,intent,sequence,head_checksum,total_bytes,phase,checksum) VALUES(1,?,?,?,?,?,?)",
          row.intent,
          row.sequence,
          row.head_checksum,
          row.total_bytes,
          row.phase,
          progressChecksum(row),
        );
      });
      await restore.#sync();
      restore.#reconcile();
    }, true);
    restore.#ready = true;
    return restore;
  }
  /** @param {Storage} storage @param {unknown} manifest @param {{timeoutMs?:number}} [settings] */
  static async open(storage, manifest, settings) {
    const restore = new StagedActionRestore(storage, manifest, settings);
    await restore.#run(async () => {
      storage.transactionSync(() => {
        upgradeActionRestoreSchema(storage);
        restore.#reconcile();
      });
      await restore.#sync();
      restore.#reconcile();
    }, true);
    restore.#ready = true;
    return restore;
  }
  close() {
    this.#closed = true;
    this.#ready = false;
  }
  /** @param {string} query @param {...SqlValue} values */
  #sql(query, ...values) {
    return this.#storage.sql.exec(query, ...values).toArray();
  }
  #alive() {
    if (this.#failed || this.#closed) throw new StoreUnavailable();
  }
  /** @template T @param {()=>Promise<T>} work @param {boolean} [opening] */
  async #run(work, opening = false) {
    this.#alive();
    if (!this.#ready && !opening) throw new StoreUnavailable();
    if (this.#busy) throw new StoreConflict();
    this.#busy = true;
    try {
      const value = await work();
      this.#alive();
      return value;
    } catch (error) {
      if (error instanceof StoreConflict) throw error;
      this.#failed = true;
      throw new StoreUnavailable();
    } finally {
      this.#busy = false;
    }
  }
  async #sync() {
    const deadline = new WireDeadline();
    await deadline.wait(
      Promise.resolve().then(() => this.#storage.sync()),
      this.#timeout,
    );
    this.#alive();
  }
  /** @returns {Progress} */
  #read() {
    verifyRecoverySchema(this.#storage);
    const rows = this.#sql(
      "SELECT intent,sequence,head_checksum,total_bytes,phase,checksum FROM xeip_action_restore",
    );
    if (rows.length !== 1) throw Error();
    const row = /** @type {Progress} */ (/** @type {unknown} */ (rows[0]));
    const { checksum, ...data } = row;
    if (
      row.intent !== this.#intent ||
      !["restoring", "verified"].includes(row.phase) ||
      checksum !== progressChecksum(data)
    )
      throw Error();
    integer(row.sequence, 0, this.#manifest.head.sequence);
    integer(row.total_bytes, 0, this.#manifest.totalBytes);
    const metadata = this.#sql(
      "SELECT organization_id,action_count FROM xeip_metadata WHERE singleton=1",
    );
    if (
      metadata.length !== 1 ||
      metadata[0].organization_id !== this.#options.organization
    )
      throw Error();
    const binding = this.#sql("SELECT canonical FROM xeip_action_recovery");
    if (
      binding.length !== 1 ||
      binding[0].canonical !== canonicalize(recoveryDescriptor(this.#options))
    )
      throw Error();
    for (const table of [
      "xeip_organization_restore",
      "xeip_service_state",
      "xeip_trust_state",
      "xeip_trust_checkpoints",
      "xeip_trust_chunks",
      "xeip_authority_state",
      "xeip_authority_events",
      "xeip_owner_events",
    ])
      if (this.#sql("SELECT 1 FROM " + table + " LIMIT 1").length)
        throw Error();
    return row;
  }
  /** @param {string} session @param {string} request @param {number} cut */
  #evidence(session, request, cut) {
    const rows = this.#sql(
      "SELECT * FROM xeip_actions WHERE session_id=? AND request_id=?",
      session,
      request,
    );
    if (rows.length !== 1) throw Error();
    const row = /** @type {ActionRow} */ (/** @type {unknown} */ (rows[0]));
    const history = this.#sql(
      "SELECT * FROM xeip_audit WHERE session_id=? AND request_id=? ORDER BY sequence LIMIT 5",
      session,
      request,
    );
    validateActionEvidence({ row, history }, this.#manifest.head.sequence);
    return projectAction(row, history, cut);
  }
  /** @param {Progress} row @param {number} actions */
  #receipt(row, actions) {
    return {
      schema: "xeip.action-restore-receipt/1",
      manifestChecksum: this.#manifest.manifestChecksum,
      phase: row.phase,
      head: {
        organization: this.#options.organization,
        stream: this.#options.stream,
        sequence: row.sequence,
        checksum: row.head_checksum,
      },
      totalBytes: row.total_bytes,
      actions,
      blocked: true,
    };
  }
  #counts() {
    const actions = Number(
        this.#sql("SELECT COUNT(*) AS n FROM xeip_actions")[0].n,
      ),
      audit = this.#sql(
        "SELECT COUNT(*) AS n,COALESCE(MAX(sequence),0) AS cut FROM xeip_audit",
      )[0];
    if (
      actions > 10000 ||
      this.#sql("SELECT action_count FROM xeip_metadata")[0].action_count !==
        actions ||
      audit.n !== audit.cut ||
      this.#sql(
        "SELECT 1 FROM xeip_actions a WHERE NOT EXISTS(SELECT 1 FROM xeip_audit e WHERE e.session_id=a.session_id AND e.request_id=a.request_id) LIMIT 1",
      ).length ||
      this.#sql(
        "SELECT 1 FROM xeip_audit e LEFT JOIN xeip_actions a ON a.session_id=e.session_id AND a.request_id=e.request_id WHERE a.request_id IS NULL LIMIT 1",
      ).length
    )
      throw Error();
    return { actions, sequence: Number(audit.cut) };
  }
  #reconcile() {
    const row = this.#read(),
      counts = this.#counts();
    if (counts.sequence !== row.sequence) throw Error();
    let head = {
        organization: this.#options.organization,
        stream: this.#options.stream,
        sequence: 0,
        checksum: genesis(this.#options),
      },
      total = 0;
    const files = filesHasher();
    for (let sequence = 1; sequence <= row.sequence; sequence++) {
      const events = this.#sql(
        "SELECT session_id,request_id FROM xeip_audit WHERE sequence=?",
        sequence,
      );
      if (events.length !== 1) throw Error();
      const record = this.#evidence(
        String(events[0].session_id),
        String(events[0].request_id),
        sequence,
      );
      const prepared = prepareActionRecovery(
        actionRecoveryPayload(this.#options.organization, sequence, record),
        head,
        total,
      );
      const raw =
        canonicalize({
          entry: prepared.entry,
          chunks: prepared.request.chunks,
        }) + "\n";
      files.update(canonicalize([recoveryFilename(sequence), hash(raw)]));
      head = { ...head, sequence, checksum: prepared.entry.checksum };
      total = prepared.entry.totalBytes;
      if (
        this.#manifest.previous?.head.sequence === sequence &&
        canonicalize(this.#manifest.previous.head) !== canonicalize(head)
      )
        throw Error();
    }
    if (head.checksum !== row.head_checksum || total !== row.total_bytes)
      throw Error();
    const complete = row.sequence === this.#manifest.head.sequence;
    if (
      (row.phase === "verified" && !complete) ||
      (complete &&
        (canonicalize(head) !== canonicalize(this.#manifest.head) ||
          total !== this.#manifest.totalBytes ||
          files.digest("hex") !== this.#manifest.filesChecksum))
    )
      throw Error();
    return this.#receipt(row, counts.actions);
  }
  /** Read-only status verifies the full reconstructed prefix; not an activation receipt. */
  status() {
    return this.#run(async () => this.#reconcile());
  }
  /** @param {unknown} value */
  apply(value) {
    return this.#run(async () => {
      const input = decodeActionRecovery(value, this.#options),
        { entry, record } = input,
        row = this.#read();
      if (
        entry.sequence === row.sequence &&
        entry.checksum === row.head_checksum
      ) {
        if (
          canonicalize(
            this.#evidence(
              record.row.session_id,
              record.row.request_id,
              row.sequence,
            ),
          ) !== canonicalize(record)
        )
          throw Error();
        await this.#sync();
        const current = this.#read();
        if (canonicalize(current) !== canonicalize(row)) throw Error();
        return this.#receipt(current, this.#counts().actions);
      }
      if (row.phase !== "restoring" || entry.sequence !== row.sequence + 1)
        throw new StoreConflict();
      if (
        entry.sequence > this.#manifest.head.sequence ||
        entry.previous !== row.head_checksum ||
        entry.totalBytes !== row.total_bytes + entry.bytes
      )
        throw Error();
      this.#storage.transactionSync(() => {
        const current = this.#read();
        if (canonicalize(current) !== canonicalize(row)) throw Error();
        const prior = this.#sql(
          "SELECT 1 FROM xeip_actions WHERE session_id=? AND request_id=?",
          record.row.session_id,
          record.row.request_id,
        );
        const values = actionColumns.map(
          (k) => record.row[/** @type {keyof ActionRow} */ (k)],
        );
        if (!prior.length) {
          if (record.history.length !== 1) throw Error();
          this.#sql(
            "INSERT INTO xeip_actions(" +
              actionColumns.join(",") +
              ") VALUES(" +
              values.map(() => "?").join(",") +
              ")",
            ...values,
          );
        } else {
          const previous = this.#evidence(
              record.row.session_id,
              record.row.request_id,
              row.sequence,
            ),
            last = Number(previous.history.at(-1)?.sequence);
          if (
            record.history.length !== previous.history.length + 1 ||
            Number(record.history.at(-2)?.sequence) !== last ||
            canonicalize(projectAction(record.row, record.history, last)) !==
              canonicalize(previous)
          )
            throw Error();
          this.#sql(
            "UPDATE xeip_actions SET " +
              actionColumns.map((k) => k + "=?").join(",") +
              " WHERE session_id=? AND request_id=?",
            ...values,
            record.row.session_id,
            record.row.request_id,
          );
        }
        const event = record.history.at(-1);
        if (!event) throw Error();
        this.#sql(
          "INSERT INTO xeip_audit(sequence,session_id,request_id,digest,event,actor,occurred_at) VALUES(?,?,?,?,?,?,?)",
          entry.sequence,
          record.row.session_id,
          record.row.request_id,
          record.row.digest,
          String(event.event),
          String(event.actor),
          Number(event.occurred_at),
        );
        const progress = {
          intent: this.#intent,
          sequence: entry.sequence,
          head_checksum: entry.checksum,
          total_bytes: entry.totalBytes,
          phase: /** @type {const} */ ("restoring"),
        };
        this.#sql(
          "UPDATE xeip_action_restore SET sequence=?,head_checksum=?,total_bytes=?,checksum=? WHERE singleton=1",
          progress.sequence,
          progress.head_checksum,
          progress.total_bytes,
          progressChecksum(progress),
        );
      });
      await this.#sync();
      const current = this.#read(),
        counts = this.#counts();
      if (
        current.sequence !== entry.sequence ||
        current.head_checksum !== entry.checksum ||
        counts.sequence !== entry.sequence ||
        canonicalize(
          this.#evidence(
            record.row.session_id,
            record.row.request_id,
            entry.sequence,
          ),
        ) !== canonicalize(record)
      )
        throw Error();
      return this.#receipt(current, counts.actions);
    });
  }
  verify() {
    return this.#run(async () => {
      const receipt = this.#reconcile();
      if (receipt.head.sequence !== this.#manifest.head.sequence)
        throw new StoreConflict();
      const row = this.#read();
      if (row.phase !== "verified") {
        const { checksum, ...prior } = row,
          progress = { ...prior, phase: /** @type {const} */ ("verified") };
        this.#storage.transactionSync(() => {
          if (canonicalize(this.#read()) !== canonicalize(row)) throw Error();
          this.#sql(
            "UPDATE xeip_action_restore SET phase='verified',checksum=? WHERE singleton=1",
            progressChecksum(progress),
          );
        });
      }
      await this.#sync();
      return this.#reconcile();
    });
  }
}
