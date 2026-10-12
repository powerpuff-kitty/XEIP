/** Tracks actual controller completion, including work outliving its HTTP response. */
import { OperationError } from "./controller.mjs";
/** @typedef {{handle:(authorization:unknown,body:unknown,options:{signal:AbortSignal})=>Promise<unknown>}} Controller */
/** @typedef {{controller:Controller,trust:{status:()=>{state:string},updateAsync:(value:unknown,options:{signal:AbortSignal})=>Promise<void>,close:()=>void},authentication:{ready:()=>Promise<boolean>},checkDatabase:()=>Promise<void>,closeDatabase:()=>Promise<void>,closeListeners:()=>Promise<void>,forceCloseListeners:()=>void,provisioning:()=>unknown,shutdownMs:number}} Dependencies */
/** @param {Promise<unknown>} task @param {number} milliseconds */
async function settledWithin(task, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      task.then(
        () => true,
        () => false,
      ),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), Math.max(0, milliseconds));
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
export class RuntimeLifecycle {
  #dependencies;
  #state = "starting";
  #abort = new AbortController();
  /** @type {Set<Promise<unknown>>} */ #workers = new Set();
  /** @type {Promise<boolean>|undefined} */ #checking;
  #checkedAt = 0;
  #healthy = false;
  /** @type {Promise<{forced:boolean}>|undefined} */ #stopping;
  /** @param {Dependencies} dependencies */
  constructor(dependencies) {
    this.#dependencies = dependencies;
  }
  async #probe() {
    if (this.#dependencies.trust.status().state !== "ready") return false;
    if (Date.now() - this.#checkedAt < 5000) return this.#healthy;
    if (!this.#checking) {
      const work = Promise.all([
        Promise.resolve().then(() => this.#dependencies.checkDatabase()),
        Promise.resolve().then(() => this.#dependencies.authentication.ready()),
      ]).then(
        ([, provider]) => provider === true,
        () => false,
      );
      this.#checking = work;
      void work.then((healthy) => {
        this.#healthy = healthy;
        this.#checkedAt = Date.now();
        this.#checking = undefined;
      });
    }
    const work = this.#checking;
    if (!(await settledWithin(work, 10000))) return false;
    return (await work) && this.#dependencies.trust.status().state === "ready";
  }
  async start() {
    if (this.#state !== "starting" || !(await this.#probe()))
      throw new Error("organization startup unavailable");
    this.#state = "running";
  }
  async ready() {
    return (
      this.#state === "running" &&
      (await this.#probe()) &&
      this.#state === "running"
    );
  }
  /** Fail readiness immediately on an idle pool error; the next probe may establish recovery. */
  invalidateHealth() {
    this.#checkedAt = 0;
    this.#healthy = false;
  }
  status() {
    return {
      ready:
        this.#state === "running" &&
        this.#healthy &&
        this.#dependencies.trust.status().state === "ready" &&
        Date.now() - this.#checkedAt < 15000,
      active: this.#workers.size,
    };
  }
  /** @param {unknown} authorization @param {unknown} body @param {{signal:AbortSignal}} options */
  async handle(authorization, body, { signal }) {
    return this.run(
      (combined) =>
        this.#dependencies.controller.handle(authorization, body, {
          signal: combined,
        }),
      { signal },
    );
  }
  /** Track auxiliary authenticated work under the same drain/abort boundary.
   * @template T @param {(signal:AbortSignal)=>Promise<T>} operation @param {{signal:AbortSignal}} options
   */
  async run(operation, { signal }) {
    if (this.#state !== "running") throw new OperationError(503, "unavailable");
    const combined = AbortSignal.any([signal, this.#abort.signal]);
    const work = Promise.resolve().then(() => {
      if (combined.aborted) throw new OperationError(503, "unavailable");
      return operation(combined);
    });
    this.#workers.add(work);
    try {
      return await work;
    } finally {
      this.#workers.delete(work);
    }
  }
  async reloadTrust() {
    if (this.#state !== "running") return false;
    try {
      await this.run(
        async (signal) =>
          this.#dependencies.trust.updateAsync(
            this.#dependencies.provisioning(),
            { signal },
          ),
        { signal: this.#abort.signal },
      );
      return true;
    } catch {
      return false;
    }
  }
  stop() {
    this.#stopping ??= this.#stop();
    return this.#stopping;
  }
  async #stop() {
    this.#state = "draining";
    const deadline = Date.now() + this.#dependencies.shutdownMs;
    const completionWindow = Math.min(10000, this.#dependencies.shutdownMs / 3);
    const listeners = Promise.resolve().then(() =>
      this.#dependencies.closeListeners(),
    );
    const work = Promise.all(
      [...this.#workers].map((worker) => worker.catch(() => {})),
    );
    const dependencies = Promise.all([
      listeners,
      work,
      ...(this.#checking ? [this.#checking] : []),
    ]);
    let drained = await settledWithin(
      dependencies,
      this.#dependencies.shutdownMs - completionWindow,
    );
    if (!drained) {
      this.#abort.abort();
      this.#dependencies.forceCloseListeners();
      drained = await settledWithin(dependencies, deadline - Date.now());
    }
    // Never close the ledger under unfinished effects. The launcher must exit on forced=true.
    const closed =
      drained &&
      (await settledWithin(
        Promise.resolve().then(() => this.#dependencies.closeDatabase()),
        deadline - Date.now(),
      ));
    this.#dependencies.trust.close();
    this.#state = "stopped";
    return { forced: !closed };
  }
}
