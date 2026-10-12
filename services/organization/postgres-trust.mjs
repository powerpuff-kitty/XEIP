/** Live trust activates only after the enrolled PostgreSQL head is durably known. */
import { prepareEntityTrustInWorker } from "../../packages/identity/trust-preparation.mjs";
import { verifyEntityEnvelope } from "../../packages/identity/trust-state.mjs";
import { canonicalize } from "../../packages/identity/signed-envelope.mjs";
import { snapshot } from "./actions.mjs";
/** @typedef {import('./control-store.mjs').Current} Current */
/** @typedef {Pick<import('./control-store.mjs').ControlStore,'open'|'publishTrust'|'assertCurrent'|'checkCurrent'>} Store */
/** @typedef {import('./control-state.mjs').PublicAuthority} Authority */
/** @typedef {import('./control-state.mjs').Provisioning} Provisioning */
/** @typedef {Awaited<ReturnType<typeof prepareEntityTrustInWorker>>} Prepared */
/** @typedef {{store:Store,authority:Authority,provisioning:unknown,signal?:AbortSignal,nowSeconds?:()=>number}} Options */
const denied = Object.freeze({ valid: false, reason: "untrusted identity" });
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
class TrustUnavailable extends Error {
  constructor() {
    super("organization trust unavailable");
    this.name = "TrustUnavailable";
  }
}
/** @param {()=>number} clock */
function time(clock) {
  const now = clock();
  if (!Number.isSafeInteger(now) || now < 0) throw new TrustUnavailable();
  return now;
}
/** @param {unknown} value @returns {Provisioning} */
function provisioning(value) {
  const copy = snapshot(value, 8 * 1024 * 1024, 262144);
  if (
    !object(copy) ||
    Object.keys(copy).sort().join(",") !== "keyDocuments,statusDocuments" ||
    !Array.isArray(copy.keyDocuments) ||
    !Array.isArray(copy.statusDocuments) ||
    copy.keyDocuments.length > 4096 ||
    copy.statusDocuments.length > 4096
  )
    throw new TrustUnavailable();
  return /** @type {Provisioning} */ (copy);
}
/** @param {Current} current @returns {Authority} */
function authorityOf(current) {
  const state = current.snapshot.state;
  return Object.freeze({
    value: state.authority,
    canonical: canonicalize(state.authority),
    digest: state.authorityDigest,
  });
}
/** @param {Prepared} prepared */
function expiry(prepared) {
  let result = Infinity;
  for (const bundle of prepared.bundles.values())
    result = Math.min(result, bundle.issuedSeconds + bundle.maxAgeSeconds);
  return result;
}
/** This class cannot be constructed without the factory's verified durable open. */
class PostgresTrust {
  #store;
  #authority;
  #clock;
  #now;
  /** @type {Current|null} */ #current;
  #bundles;
  #expiry;
  /** @type {'ready'|'publishing'|'failed'|'closed'} */ #phase = "ready";
  /** @type {AbortController|undefined} */ #preparing;
  /** @param {Store} store @param {Current} current @param {Prepared} prepared @param {()=>number} clock @param {number} now */
  constructor(store, current, prepared, clock, now) {
    this.#store = store;
    this.#current = current;
    this.#authority = authorityOf(current);
    this.#bundles = prepared.bundles;
    this.#expiry = expiry(prepared);
    this.#clock = clock;
    this.#now = now;
  }
  #observeTime() {
    this.#now = Math.max(this.#now, time(this.#clock));
    return this.#now;
  }
  #failPublication() {
    if (this.#phase !== "closed") this.#phase = "failed";
  }
  status() {
    /** @type {string} */ let state = this.#phase;
    if (state === "ready") {
      try {
        if (this.#observeTime() > this.#expiry) state = "stale";
        else if (this.#bundles.size === 0) state = "empty";
      } catch {
        this.#phase = "failed";
        state = "failed";
      }
    }
    return { state, entities: this.#bundles.size };
  }
  get entityCount() {
    return this.#bundles.size;
  }
  get token() {
    if (this.status().state !== "ready" || !this.#current) return null;
    return Object.freeze({
      revision: this.#current.revision,
      digest: this.#current.digest,
    });
  }
  /** Capture before any request pool/SQL wait. Never follows a newer snapshot.
   * @returns {import('./contracts.js').ControlDispatchFence} */
  controlFence() {
    const expected = this.token;
    const current = () => {
      const actual = this.token;
      return (
        !!expected &&
        !!actual &&
        expected.revision === actual.revision &&
        expected.digest === actual.digest
      );
    };
    return Object.freeze({
      current,
      validate: async () => {
        if (!expected || !current()) throw new TrustUnavailable();
        await this.#store.checkCurrent(expected);
        if (!current()) throw new TrustUnavailable();
      },
      dispatch: (send) => {
        // No await between this check and fetch invocation. JS run-to-completion
        // is the local permit; publication holds the conflicting phase through
        // commit and activation. The response may outlive this permit.
        if (!current()) throw new TrustUnavailable();
        return send();
      },
      lock: async (client) => {
        if (!expected || !current()) throw new TrustUnavailable();
        await this.#store.assertCurrent(client, expected);
        if (!current()) throw new TrustUnavailable();
      },
    });
  }
  /** @param {{entity:string,kid:string}} principal */
  allows(principal) {
    if (this.status().state !== "ready" || !principal) return false;
    const bundle = this.#bundles.get(principal.entity);
    return (
      !!bundle &&
      bundle.keys.has(principal.kid) &&
      !bundle.revoked.has(principal.kid)
    );
  }
  /** @param {unknown} message */
  verify(message) {
    if (this.status().state !== "ready") return denied;
    try {
      const value = snapshot(message, 98304);
      if (!object(value) || typeof value.sender !== "string") return denied;
      const bundle = this.#bundles.get(value.sender);
      if (!bundle) return denied;
      return verifyEntityEnvelope(value, { ...bundle, nowSeconds: this.#now });
    } catch {
      return denied;
    }
  }
  /** @param {unknown} input @param {{signal?:AbortSignal}} [options] */
  async updateAsync(input, { signal } = {}) {
    if (this.#preparing || this.#phase !== "ready" || !this.#current)
      throw new TrustUnavailable();
    const cancellation = new AbortController();
    const combined = signal
      ? AbortSignal.any([signal, cancellation.signal])
      : cancellation.signal;
    this.#preparing = cancellation;
    let publishing = false;
    try {
      if (combined.aborted) throw new TrustUnavailable();
      const copy = provisioning(input);
      const prepared = await prepareEntityTrustInWorker(
        this.#authority.value.trust,
        copy,
        this.#observeTime(),
        combined,
      );
      if (
        combined.aborted ||
        this.#phase !== "ready" ||
        this.#observeTime() > expiry(prepared)
      )
        throw new TrustUnavailable();
      const current = this.#current;
      this.#phase = "publishing";
      publishing = true;
      const published = await this.#store.publishTrust(
        current,
        {
          authority: this.#authority,
          provisioning: copy,
          acceptedAt: this.#observeTime(),
        },
        { signal: combined },
      );
      if (
        combined.aborted ||
        this.#phase !== "publishing" ||
        this.#observeTime() > expiry(prepared)
      )
        throw new TrustUnavailable();
      this.#current = published;
      this.#bundles = prepared.bundles;
      this.#expiry = expiry(prepared);
      this.#phase = "ready";
    } catch {
      if (publishing) this.#failPublication();
      throw new TrustUnavailable();
    } finally {
      this.#preparing = undefined;
    }
  }
  close() {
    this.#phase = "closed";
    this.#preparing?.abort();
    this.#current = null;
    this.#bundles.clear();
  }
}
/** Opens existing enrollment only. No file checkpoint, migration or enrollment.
 * @param {Options} options */
export async function openPostgresTrust({
  store,
  authority,
  provisioning: input,
  signal,
  nowSeconds = () => Math.floor(Date.now() / 1000),
}) {
  const cancellation = signal ?? new AbortController().signal;
  try {
    if (cancellation.aborted) throw new TrustUnavailable();
    const copy = provisioning(input);
    let now = time(nowSeconds);
    const current = await store.open(
      {
        authority,
        provisioning: copy,
        acceptedAt: now,
      },
      { signal: cancellation },
    );
    if (cancellation.aborted) throw new TrustUnavailable();
    now = Math.max(now, time(nowSeconds), current.snapshot.state.acceptedAt);
    const prepared = await prepareEntityTrustInWorker(
      current.snapshot.state.authority.trust,
      current.snapshot.state.provisioning,
      now,
      cancellation,
    );
    if (cancellation.aborted) throw new TrustUnavailable();
    const reopened = await store.open(
      {
        authority: authorityOf(current),
        provisioning: copy,
        acceptedAt: now,
      },
      { signal: cancellation },
    );
    now = Math.max(now, time(nowSeconds));
    if (
      cancellation.aborted ||
      reopened.revision !== current.revision ||
      reopened.digest !== current.digest ||
      now > expiry(prepared)
    )
      throw new TrustUnavailable();
    return new PostgresTrust(store, current, prepared, nowSeconds, now);
  } catch {
    throw new TrustUnavailable();
  }
}
