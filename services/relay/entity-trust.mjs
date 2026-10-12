/** Pinned provisioning plus persistent rollback protection for the 0.2 relay. */
import { verifyEntityEnvelope } from "../../packages/identity/entity-envelope.mjs";
import { prepareEntityTrust } from "../../packages/identity/trust-state.mjs";
import { prepareEntityTrustInWorker } from "../../packages/identity/trust-preparation.mjs";
import { TrustCheckpoint } from "./trust-checkpoint.mjs";
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
export class EntityTrustPolicy {
  #bundles = new Map();
  #checkpoint;
  #now;
  #configuration;
  #closed = false;
  #preparing;
  constructor(configuration, keyDocuments, statusDocuments) {
    if (
      !object(configuration) ||
      Object.keys(configuration).some(
        (key) =>
          !["trustDir", "maxAgeSeconds", "knownExtensions"].includes(key),
      )
    )
      throw new TypeError("invalid entitySignatures configuration");
    const { trustDir, maxAgeSeconds, knownExtensions = [] } = configuration;
    if (typeof trustDir !== "string" || !trustDir)
      throw new TypeError("trustDir is required");
    if (
      !Number.isSafeInteger(maxAgeSeconds) ||
      maxAgeSeconds < 1 ||
      maxAgeSeconds > 86400
    )
      throw new TypeError("maxAgeSeconds must be 1–86400");
    if (
      !Array.isArray(knownExtensions) ||
      knownExtensions.some(
        (name) => typeof name !== "string" || !name || name === "xeip.sig",
      ) ||
      new Set(knownExtensions).size !== knownExtensions.length
    )
      throw new TypeError("invalid knownExtensions");
    this.#configuration = {
      maxAgeSeconds,
      knownExtensions: [...knownExtensions],
    };
    this.#now = Math.floor(Date.now() / 1000);
    const prepared = this.#prepare(keyDocuments, statusDocuments);
    this.#checkpoint = new TrustCheckpoint(
      trustDir,
      prepared.checkpoints,
      prepared.chainDigests,
    );
    this.#bundles = prepared.bundles;
  }
  #prepare(keyDocuments, statusDocuments) {
    return prepareEntityTrust(
      this.#configuration,
      keyDocuments,
      statusDocuments,
      this.#now,
    );
  }
  #observeTime() {
    this.#now = Math.max(this.#now, Math.floor(Date.now() / 1000));
    return this.#now;
  }
  #assertUpdate(provisioning) {
    if (this.#preparing) throw new Error("entity trust update in progress");
    if (this.#closed) throw new Error("entity trust is closed");
    if (!this.#checkpoint.healthy)
      throw new Error("entity trust failed; reopen required");
    if (
      !object(provisioning) ||
      Object.keys(provisioning).sort().join(",") !==
        "keyDocuments,statusDocuments"
    )
      throw new TypeError("complete entity provisioning required");
  }
  update(provisioning) {
    this.#assertUpdate(provisioning);
    this.#observeTime();
    const prepared = this.#prepare(
      provisioning.keyDocuments,
      provisioning.statusDocuments,
    );
    this.#checkpoint.update(prepared.checkpoints, prepared.chainDigests);
    this.#bundles = prepared.bundles;
  }
  async updateAsync(provisioning, { signal } = {}) {
    this.#assertUpdate(provisioning);
    const cancellation = new AbortController();
    const combined = signal
      ? AbortSignal.any([signal, cancellation.signal])
      : cancellation.signal;
    this.#preparing = cancellation;
    try {
      const prepared = await prepareEntityTrustInWorker(
        this.#configuration,
        provisioning,
        this.#observeTime(),
        combined,
      );
      if (this.#closed || combined.aborted)
        throw new Error("entity trust preparation cancelled");
      if (!this.#checkpoint.healthy)
        throw new Error("entity trust failed; reopen required");
      const now = this.#observeTime();
      if (
        [...prepared.bundles.values()].some(
          (bundle) => now - bundle.issuedSeconds > bundle.maxAgeSeconds,
        )
      )
        throw new Error("stale entity trust preparation");
      this.#checkpoint.update(prepared.checkpoints, prepared.chainDigests);
      this.#bundles = prepared.bundles;
    } finally {
      this.#preparing = undefined;
    }
  }
  allows(principal) {
    if (
      !this.#checkpoint.healthy ||
      !principal ||
      typeof principal.kid !== "string"
    )
      return false;
    const bundle = this.#bundles.get(principal.entity);
    return (
      !!bundle &&
      this.#observeTime() - bundle.issuedSeconds <= bundle.maxAgeSeconds &&
      bundle.keys.has(principal.kid) &&
      !bundle.revoked.has(principal.kid)
    );
  }
  status() {
    let state = this.#closed
      ? "closed"
      : !this.#checkpoint.healthy
        ? "failed"
        : "ready";
    if (state === "ready") {
      const now = this.#observeTime();
      if (
        [...this.#bundles.values()].some(
          (bundle) => now - bundle.issuedSeconds > bundle.maxAgeSeconds,
        )
      )
        state = "stale";
      else if (this.#bundles.size === 0) state = "empty";
    }
    return { state, entities: this.#bundles.size };
  }
  get entityCount() {
    return this.#bundles.size;
  }
  verify(message) {
    if (!this.#checkpoint.healthy)
      return { valid: false, reason: "untrusted identity" };
    this.#observeTime();
    const bundle = this.#bundles.get(message.sender);
    if (!bundle) return { valid: false, reason: "untrusted identity" };
    return verifyEntityEnvelope(message, { ...bundle, nowSeconds: this.#now });
  }
  close() {
    this.#closed = true;
    this.#preparing?.abort();
    this.#checkpoint?.close();
  }
}
