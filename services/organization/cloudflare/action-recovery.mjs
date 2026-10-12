/** Source acknowledgement gate. Transport and independent hosting are injected. */
import {
  canonicalize,
  genesis,
  recoveryOptions,
  validateEntry,
  validateHead,
} from "./recovery-record.mjs";
import {
  actionRecoveryPayload,
  prepareActionRecovery as prepare,
} from "./action-recovery-record.mjs";
export {
  actionRecoveryPayload,
  actionRecoveryId,
} from "./action-recovery-record.mjs";
import { verifyLedgerSchema } from "./schema.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { PolicyDenied } from "../actions.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {import('./recovery-record.mjs').Entry} Entry */
/** @typedef {import('./recovery-record.mjs').Head} Head */
/** @typedef {{head:()=>Promise<unknown>,entry:(sequence:number)=>Promise<unknown>,append:(value:unknown)=>Promise<unknown>}} Client */
/** @typedef {{options:unknown,client:Client,initialize?:boolean}} Settings */
/** @param {unknown} options */
export function recoveryDescriptor(options) {
  const { timeoutMs, ...o } = recoveryOptions(options);
  return { ...o, genesis: genesis({ ...o, timeoutMs }) };
}
export class ActionRecovery {
  #storage;
  #options;
  #client;
  #source;
  #binding;
  #state = "opening";
  /** @type {Head} */ #head;
  #total = 0;
  /** @type {{resolve:()=>void,reject:(error:Error)=>void,timer:ReturnType<typeof setTimeout>}[]} */ #waiting =
    [];
  /** @param {Storage} storage @param {string} organization @param {Settings} settings @param {{cut:()=>number,record:(sequence:number)=>unknown}} source */
  constructor(storage, organization, settings, source) {
    this.#options = recoveryOptions(settings.options);
    this.#client = settings.client;
    this.#source = source;
    this.#storage = storage;
    if (
      this.#options.organization !== organization ||
      !this.#client ||
      ["head", "entry", "append"].some(
        (k) =>
          typeof this.#client[/** @type {keyof Client} */ (k)] !== "function",
      ) ||
      (settings.initialize !== undefined &&
        typeof settings.initialize !== "boolean")
    )
      throw new TypeError("invalid recovery adapter");
    this.#head = {
      organization,
      stream: this.#options.stream,
      sequence: 0,
      checksum: genesis(this.#options),
    };
    this.#binding = canonicalize(recoveryDescriptor(settings.options));
    verifyLedgerSchema(storage);
    const rows = storage.sql
      .exec("SELECT canonical FROM xeip_action_recovery")
      .toArray();
    if (!rows.length) {
      if (settings.initialize !== true || source.cut() !== 0)
        throw new StoreUnavailable();
      storage.transactionSync(() =>
        storage.sql.exec(
          "INSERT INTO xeip_action_recovery(singleton,canonical) VALUES(1,?)",
          this.#binding,
        ),
      );
    }
    this.#verifyBinding();
  }
  #verifyBinding() {
    verifyLedgerSchema(this.#storage);
    const rows = this.#storage.sql
      .exec("SELECT singleton,canonical FROM xeip_action_recovery")
      .toArray();
    if (
      rows.length !== 1 ||
      rows[0].singleton !== 1 ||
      rows[0].canonical !== this.#binding
    )
      throw new StoreUnavailable();
  }
  #alive() {
    if (this.#state === "closed" || this.#state === "failed")
      throw new StoreUnavailable();
  }
  /** @template T @param {Promise<T>} work @returns {Promise<T>} */
  async #await(work) {
    /** @type {ReturnType<typeof setTimeout>|undefined} */ let timer;
    try {
      const result = await Promise.race([
        work,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new StoreUnavailable()),
            this.#options.timeoutMs,
          );
        }),
      ]);
      this.#alive();
      return /** @type {T} */ (result);
    } finally {
      clearTimeout(timer);
    }
  }
  /** @param {Head} head @param {Entry} entry */
  #next(head, entry) {
    return { ...head, sequence: entry.sequence, checksum: entry.checksum };
  }
  async #remote() {
    return validateHead(await this.#await(this.#client.head()), this.#options);
  }
  /** @param {Head} a @param {Head} b */
  #equal(a, b) {
    if (canonicalize(a) !== canonicalize(b)) throw new StoreUnavailable();
  }
  /** @param {number} sequence @param {Head} previous @param {number} total */
  #prepared(sequence, previous, total) {
    const value = prepare(
      actionRecoveryPayload(
        this.#options.organization,
        sequence,
        this.#source.record(sequence),
      ),
      previous,
      total,
    );
    validateEntry(value.entry, this.#options);
    return value;
  }
  /** @param {ReturnType<typeof prepare>} value */
  async #publish(value) {
    const entry = validateEntry(
      await this.#await(this.#client.append(value.request)),
      this.#options,
    );
    if (canonicalize(entry) !== canonicalize(value.entry))
      throw new StoreUnavailable();
    return entry;
  }
  async open() {
    if (this.#state !== "opening") throw new StoreUnavailable();
    try {
      await this.#await(this.#storage.sync());
      this.#verifyBinding();
      const cut = this.#source.cut(),
        remote = await this.#remote();
      if (remote.sequence > cut || cut - remote.sequence > 1)
        throw new StoreUnavailable();
      let expected = this.#head,
        total = 0;
      for (let sequence = 1; sequence <= cut; sequence++) {
        const value = this.#prepared(sequence, expected, total);
        if (sequence <= remote.sequence) {
          const entry = validateEntry(
            await this.#await(this.#client.entry(sequence)),
            this.#options,
          );
          if (canonicalize(entry) !== canonicalize(value.entry))
            throw new StoreUnavailable();
        } else {
          this.#equal(remote, expected);
          await this.#publish(value);
        }
        expected = this.#next(expected, value.entry);
        total = value.entry.totalBytes;
      }
      this.#equal(await this.#remote(), expected);
      this.#verifyBinding();
      // Recompute synchronously after remote awaits to reject source changes during open.
      let fresh = this.#head,
        bytes = 0;
      if (this.#source.cut() !== cut) throw new StoreUnavailable();
      for (let sequence = 1; sequence <= cut; sequence++) {
        const value = this.#prepared(sequence, fresh, bytes);
        fresh = this.#next(fresh, value.entry);
        bytes = value.entry.totalBytes;
      }
      this.#equal(fresh, expected);
      this.#alive();
      this.#head = expected;
      this.#total = total;
      this.#state = "ready";
    } catch {
      this.close();
      throw new StoreUnavailable();
    }
  }
  close() {
    this.#state = "closed";
    for (const waiter of this.#waiting.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(new StoreUnavailable());
    }
  }
  /** Reserve one admission slot; only already-issued execution work may wait.
   * @param {boolean} wait */
  async #enter(wait) {
    if (this.#state !== "busy" || !wait) {
      this.assertReady();
      this.#state = "busy";
      return;
    }
    if (this.#waiting.length >= 32) throw new StoreUnavailable();
    await new Promise((resolve, reject) => {
      const waiter = {
        resolve: () => resolve(undefined),
        reject,
        timer: setTimeout(() => {
          const index = this.#waiting.indexOf(waiter);
          if (index >= 0) {
            this.#waiting.splice(index, 1);
            reject(new StoreUnavailable());
          }
        }, this.#options.timeoutMs),
      };
      this.#waiting.push(waiter);
    });
    this.#alive();
  }
  #release() {
    this.#alive();
    const next = this.#waiting.shift();
    // Transfer ownership before waking the next waiter; public work cannot overtake it.
    if (next) {
      clearTimeout(next.timer);
      this.#state = "busy";
      next.resolve();
    } else this.#state = "ready";
  }
  healthy() {
    return this.#state === "ready";
  }
  assertReady() {
    if (this.#state === "busy") throw new StoreConflict();
    if (!this.healthy()) throw new StoreUnavailable();
  }
  /** @template T @param {()=>Promise<T>} callback @param {boolean} [wait] @returns {Promise<T>} */
  async run(callback, wait = false) {
    await this.#enter(wait);
    try {
      this.#verifyBinding();
      this.#equal(await this.#remote(), this.#head);
      const result = await callback();
      this.#alive();
      this.#release();
      return result;
    } catch (error) {
      let benign = false;
      if (
        this.#state === "busy" &&
        (error instanceof StoreConflict || error instanceof PolicyDenied)
      ) {
        try {
          benign = this.#source.cut() === this.#head.sequence;
        } catch {
          /* corrupt storage must quarantine, not strand admission */
        }
      }
      if (benign) {
        this.#release();
        throw error;
      }
      this.close();
      throw new StoreUnavailable();
    }
  }
  /** Called only after the existing source storage synchronization, before late authorization. */
  async confirm() {
    if (this.#state !== "busy") throw new StoreUnavailable();
    this.#verifyBinding();
    const cut = this.#source.cut();
    this.#equal(await this.#remote(), this.#head);
    if (cut !== this.#head.sequence) {
      if (cut !== this.#head.sequence + 1) throw new StoreUnavailable();
      const value = this.#prepared(cut, this.#head, this.#total);
      await this.#publish(value);
      this.#equal(await this.#remote(), this.#next(this.#head, value.entry));
      this.#head = this.#next(this.#head, value.entry);
      this.#total = value.entry.totalBytes;
    }
    this.#alive();
    if (this.#source.cut() !== cut) throw new StoreUnavailable();
  }
}
