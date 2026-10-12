/** Complete historical reconstruction. A verified candidate still cannot execute or become live. */
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { initializeLedger, verifyRecoverySchema } from "./schema.mjs";
import { validateOrganizationCheckpoint } from "./organization-checkpoint.mjs";
import {
  bundleValue,
  checks,
  finish,
  counts,
  components,
  filesHasher,
  filename,
  hash,
} from "./organization-bundle-record.mjs";
import {
  controlRows,
  installControls,
  verifyControls,
  historicalInsert,
  insertRow,
} from "./organization-restore-state.mjs";
import {
  ACTION_PAGE_BYTES,
  validateActionEvidence,
  projectAction,
} from "./action-export.mjs";
import { WireDeadline } from "./recovery-wire.mjs";
import { integer } from "./recovery-record.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {import('./contracts.js').SqlValue} SqlValue */
/** @typedef {{intent:string,sequence:number,files_checksum:string,phase:'restoring'|'verified',checksum:string}} Progress */
/** @typedef {import('./organization-bundle-record.mjs').Section} Section */
/** @typedef {{organization:string,timeoutMs?:number}} Settings */
/** @param {Omit<Progress,'checksum'>} row */
const checksum = (row) =>
  hash("XEIP organization restore progress v1\n" + canonicalize(row));
/** @param {ReturnType<typeof filesHasher>} files @param {string} name @param {unknown} value */
const addFile = (files, name, value) =>
  files.update(canonicalize([name, hash(canonicalize(value) + "\n")]));
export class StagedOrganizationRestore {
  #storage;
  #checkpoint;
  #manifest;
  #intent;
  #controls;
  #counts;
  #total;
  #timeout;
  #closed = false;
  #failed = false;
  #ready = false;
  #busy = false;
  /** @type {ReturnType<typeof checks>|undefined} */ #checks;
  /** @type {ReturnType<typeof filesHasher>|undefined} */ #files;
  /** @type {Progress|undefined} */ #progress;
  /** @param {Storage} storage @param {unknown} checkpoint @param {unknown} manifest @param {Settings} settings */
  constructor(
    storage,
    checkpoint,
    manifest,
    { organization, timeoutMs = 10000 },
  ) {
    this.#storage = storage;
    this.#timeout = integer(timeoutMs, 100, 10000);
    this.#checkpoint = validateOrganizationCheckpoint(checkpoint, organization);
    this.#manifest = bundleValue(manifest, {
      organization,
      expectedDigest: this.#checkpoint.manifest.digest,
    });
    this.#intent = canonicalize(this.#manifest);
    this.#controls = controlRows(this.#checkpoint);
    this.#counts = counts(this.#checkpoint);
    this.#total = Object.values(this.#counts).reduce((a, b) => a + b, 0);
    integer(this.#total, 1, Number.MAX_SAFE_INTEGER);
  }
  /** @param {Storage} storage @param {unknown} checkpoint @param {unknown} manifest @param {Settings} settings */
  static async initialize(storage, checkpoint, manifest, settings) {
    const restore = new StagedOrganizationRestore(
      storage,
      checkpoint,
      manifest,
      settings,
    );
    await restore.#run(async () => {
      storage.transactionSync(() => {
        if (
          restore.#sql(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'",
          ).length
        )
          throw new StoreConflict();
        initializeLedger(storage, restore.#checkpoint.manifest.organization);
        const row = {
          intent: restore.#intent,
          sequence: 0,
          files_checksum: restore.#initialFiles().digest("hex"),
          phase: /** @type {const} */ ("restoring"),
        };
        insertRow(storage, "xeip_organization_restore", {
          singleton: 1,
          ...row,
          checksum: checksum(row),
        });
        installControls(storage, restore.#controls);
      });
      await restore.#sync();
      restore.#reconcile();
    }, true);
    restore.#ready = true;
    return restore;
  }
  /** @param {Storage} storage @param {unknown} checkpoint @param {unknown} manifest @param {Settings} settings */
  static async open(storage, checkpoint, manifest, settings) {
    const restore = new StagedOrganizationRestore(
      storage,
      checkpoint,
      manifest,
      settings,
    );
    await restore.#run(async () => {
      restore.#reconcile();
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
    if (this.#closed || this.#failed) throw new StoreUnavailable();
  }
  /** @template T @param {()=>Promise<T>} work @param {boolean} [opening] */
  async #run(work, opening = false) {
    this.#alive();
    if (!opening && !this.#ready) throw new StoreUnavailable();
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
  #initialFiles() {
    const files = filesHasher();
    for (const key of components)
      addFile(files, key + ".json", this.#checkpoint[key]);
    return files;
  }
  /** @returns {Progress} */
  #read() {
    verifyRecoverySchema(this.#storage);
    const rows = this.#sql(
      "SELECT intent,sequence,files_checksum,phase,checksum FROM xeip_organization_restore",
    );
    if (
      rows.length !== 1 ||
      this.#sql("SELECT 1 FROM xeip_action_restore LIMIT 1").length
    )
      throw Error();
    const row = /** @type {Progress} */ (/** @type {unknown} */ (rows[0]));
    const { checksum: encoded, ...body } = row;
    if (
      row.intent !== this.#intent ||
      !["restoring", "verified"].includes(row.phase) ||
      encoded !== checksum(body)
    )
      throw Error();
    integer(row.sequence, 0, this.#total);
    if (row.phase === "verified" && row.sequence !== this.#total) throw Error();
    const metadata = this.#sql(
      "SELECT organization_id,action_count FROM xeip_metadata",
    );
    const actionCount = Math.min(row.sequence, this.#counts.actions);
    const authorityPages = Math.min(
      Math.max(0, row.sequence - this.#counts.actions),
      this.#counts.authority,
    );
    const adminPages = Math.max(
      0,
      row.sequence - this.#counts.actions - this.#counts.authority,
    );
    if (
      metadata.length !== 1 ||
      metadata[0].organization_id !== this.#checkpoint.manifest.organization ||
      metadata[0].action_count !== actionCount
    )
      throw Error();
    for (const [table, expected] of [
      ["xeip_actions", actionCount],
      [
        "xeip_authority_events",
        Math.min(authorityPages * 128, this.#checkpoint.authority.revision + 1),
      ],
      [
        "xeip_owner_events",
        Math.min(adminPages * 16, this.#checkpoint.administration.headSequence),
      ],
    ])
      if (this.#sql("SELECT COUNT(*) AS n FROM " + table)[0].n !== expected)
        throw Error();
    return row;
  }
  /** @param {number} sequence @returns {{section:Section,index:number,name:string}} */
  #position(sequence) {
    integer(sequence, 1, this.#total);
    let index = sequence;
    for (const section of /** @type {const} */ ([
      "actions",
      "authority",
      "administration",
    ])) {
      if (index <= this.#counts[section])
        return { section, index, name: filename(section, index) };
      index -= this.#counts[section];
    }
    throw Error();
  }
  /** Reconstruct a bundle page from rows, never from a saved copy of the imported page.
   * @param {number} sequence @param {Record<string,SqlValue>} [actionKey] @returns {unknown} */
  #page(sequence, actionKey) {
    const { section, index } = this.#position(sequence);
    if (section === "actions") {
      const key =
        actionKey ??
        this.#sql(
          "SELECT session_id,request_id FROM xeip_audit WHERE event='proposed' ORDER BY sequence LIMIT 1 OFFSET ?",
          index - 1,
        )[0];
      if (!key) throw Error();
      const rows = this.#sql(
        "SELECT * FROM xeip_actions WHERE session_id=? AND request_id=?",
        key.session_id,
        key.request_id,
      );
      const history = this.#sql(
        "SELECT * FROM xeip_audit WHERE session_id=? AND request_id=? ORDER BY sequence LIMIT 5",
        key.session_id,
        key.request_id,
      );
      if (rows.length !== 1) throw Error();
      return validateActionEvidence(
        { row: rows[0], history },
        this.#checkpoint.manifest.actions.cut,
      );
    }
    const isAuthority = section === "authority",
      after = (index - 1) * (isAuthority ? 128 : 16) - (isAuthority ? 1 : 0);
    const records = isAuthority
      ? this.#sql(
          "SELECT revision,configuration_digest,previous_checksum,checksum FROM xeip_authority_events WHERE revision>? ORDER BY revision LIMIT 128",
          after,
        ).map((r) => ({
          revision: r.revision,
          configurationDigest: r.configuration_digest,
          previousChecksum: r.previous_checksum,
          checksum: r.checksum,
        }))
      : this.#sql(
          "SELECT sequence,canonical,previous,checksum FROM xeip_owner_events WHERE sequence>? ORDER BY sequence LIMIT 16",
          after,
        ).map((r) => ({
          sequence: r.sequence,
          event: JSON.parse(String(r.canonical)),
          previous: r.previous,
          checksum: r.checksum,
        }));
    const next = after + records.length;
    return {
      schema: isAuthority
        ? "xeip.authority-history-page/1"
        : "xeip.admin-history-page/1",
      checkpointDigest: this.#checkpoint[section].digest,
      after,
      records,
      next,
      complete:
        next ===
        (isAuthority
          ? this.#checkpoint.authority.revision
          : this.#checkpoint.administration.headSequence),
    };
  }
  /** @param {Progress} row */
  #receipt(row) {
    return {
      schema: "xeip.organization-restore-receipt/1",
      bundleChecksum: this.#manifest.checksum,
      checkpointDigest: this.#checkpoint.manifest.digest,
      sequence: row.sequence,
      pages: this.#total,
      phase: row.phase,
      blocked: true,
    };
  }
  #reconcile() {
    const row = this.#read(),
      check = checks(this.#checkpoint),
      files = this.#initialFiles();
    verifyControls(this.#storage, this.#controls);
    const keys = this.#sql(
      "SELECT session_id,request_id FROM xeip_audit WHERE event='proposed' ORDER BY sequence LIMIT 10001",
    );
    if (keys.length !== Math.min(row.sequence, this.#counts.actions))
      throw Error();
    for (let seq = 1; seq <= row.sequence; seq++) {
      const { section, name } = this.#position(seq),
        value = this.#page(
          seq,
          section === "actions" ? keys[seq - 1] : undefined,
        );
      check[section].accept(value);
      addFile(files, name, value);
    }
    if (
      this.#sql("SELECT COUNT(*) AS n FROM xeip_audit")[0].n !==
        check.actions.sequences.size ||
      files.copy().digest("hex") !== row.files_checksum
    )
      throw Error();
    if (row.sequence === this.#total) {
      finish(check, this.#checkpoint);
      if (row.files_checksum !== this.#manifest.filesChecksum) throw Error();
    }
    this.#progress = row;
    this.#checks = check;
    this.#files = files;
    return this.#receipt(row);
  }
  status() {
    return this.#run(async () => this.#reconcile());
  }
  /** @param {number} sequence @param {unknown} input */
  apply(sequence, input) {
    return this.#run(async () => {
      const row = this.#read();
      if (
        !this.#progress ||
        canonicalize(row) !== canonicalize(this.#progress) ||
        !this.#checks ||
        !this.#files
      )
        throw Error();
      if (
        !Number.isSafeInteger(sequence) ||
        sequence < 1 ||
        sequence > this.#total
      )
        throw new StoreConflict();
      const { section, name } = this.#position(sequence);
      const value = snapshot(
        input,
        section === "actions"
          ? ACTION_PAGE_BYTES
          : section === "authority"
            ? 131072
            : 65536,
      );
      if (sequence === row.sequence) {
        if (canonicalize(value) !== canonicalize(this.#page(sequence)))
          throw Error();
        await this.#sync();
        if (
          canonicalize(this.#read()) !== canonicalize(row) ||
          canonicalize(value) !== canonicalize(this.#page(sequence))
        )
          throw Error();
        return this.#receipt(row);
      }
      if (row.phase !== "restoring" || sequence !== row.sequence + 1)
        throw new StoreConflict();
      this.#checks[section].accept(value);
      const files = this.#files.copy();
      addFile(files, name, value);
      const progress = {
        intent: this.#intent,
        sequence,
        files_checksum: files.copy().digest("hex"),
        phase: /** @type {const} */ ("restoring"),
      };
      this.#storage.transactionSync(() => {
        if (canonicalize(this.#read()) !== canonicalize(row)) throw Error();
        this.#writePage(section, value);
        this.#sql(
          "UPDATE xeip_organization_restore SET sequence=?,files_checksum=?,checksum=? WHERE singleton=1",
          sequence,
          progress.files_checksum,
          checksum(progress),
        );
      });
      await this.#sync();
      const current = this.#read();
      if (
        canonicalize(current) !==
          canonicalize({ ...progress, checksum: checksum(progress) }) ||
        canonicalize(this.#page(sequence)) !== canonicalize(value)
      )
        throw Error();
      this.#progress = current;
      this.#files = files;
      return this.#receipt(current);
    });
  }
  /** @param {Section} section @param {unknown} value */
  #writePage(section, value) {
    if (section === "actions") {
      const record = validateActionEvidence(
        value,
        this.#checkpoint.manifest.actions.cut,
      );
      for (const [i, event] of record.history.entries()) {
        const projection = projectAction(
          record.row,
          record.history,
          Number(event.sequence),
        );
        if (i === 0) insertRow(this.#storage, "xeip_actions", projection.row);
        else {
          const keys = Object.keys(projection.row);
          this.#sql(
            "UPDATE xeip_actions SET " +
              keys.map((k) => k + "=?").join(",") +
              " WHERE session_id=? AND request_id=?",
            ...Object.values(projection.row),
            record.row.session_id,
            record.row.request_id,
          );
        }
        insertRow(
          this.#storage,
          "xeip_audit",
          /** @type {Record<string,SqlValue>} */ (event),
        );
      }
    } else if (section === "authority") {
      const page = /** @type {import('./authority-checkpoint.mjs').Page} */ (
        value
      );
      historicalInsert(this.#storage, ["xeip_authority_event_new"], () => {
        for (const r of page.records)
          insertRow(this.#storage, "xeip_authority_events", {
            revision: r.revision,
            configuration_digest: r.configurationDigest,
            previous_checksum: r.previousChecksum,
            checksum: r.checksum,
          });
      });
    } else {
      const page = /** @type {import('./admin-checkpoint.mjs').Page} */ (value);
      for (const r of page.records)
        insertRow(this.#storage, "xeip_owner_events", {
          sequence: r.sequence,
          attempt_id: r.event.attemptId,
          outcome: r.event.outcome,
          canonical: canonicalize(r.event),
          previous: r.previous,
          checksum: r.checksum,
        });
    }
  }
  verify() {
    return this.#run(async () => {
      this.#reconcile();
      const row = this.#read();
      if (row.sequence !== this.#total) throw new StoreConflict();
      if (row.phase !== "verified") {
        const { checksum: old, ...body } = row,
          progress = { ...body, phase: /** @type {const} */ ("verified") };
        this.#storage.transactionSync(() => {
          if (canonicalize(this.#read()) !== canonicalize(row)) throw Error();
          this.#sql(
            "UPDATE xeip_organization_restore SET phase='verified',checksum=? WHERE singleton=1",
            checksum(progress),
          );
        });
      }
      await this.#sync();
      return this.#reconcile();
    });
  }
}
