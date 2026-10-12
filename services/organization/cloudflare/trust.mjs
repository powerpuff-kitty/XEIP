/** Durable signed trust. Owner-only provisioning; no public administration API. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import {
  prepareEntityTrust,
  mergeTrustRecords,
  validateTrustRecords,
  verifyEntityEnvelope,
} from "../../../packages/identity/trust-state.mjs";
import { PolicyDenied, snapshot } from "../actions.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { initializeLedger, verifyLedgerSchema } from "./schema.mjs";
import {
  trustStateChecksum as checksum,
  validateTrustCheckpoint,
} from "./trust-checkpoint.mjs";
import { encodeProvisioning, resolveProvisioning } from "./trust-chunks.mjs";
/** @typedef {import('../../../packages/identity/trust-state.mjs').TrustConfiguration} Configuration */
/** @typedef {import('../../../packages/identity/trust-state.mjs').TrustRecords} Records */
/** @typedef {import('../../../packages/identity/trust-state.mjs').TrustBundle} Bundle */
/** @typedef {{configuration:string,provisioning:string,revision:number,accepted_at:number,checkpoints_digest:string,checksum:string}} State */
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {unknown} value @param {Configuration} configuration @param {number} nowSeconds */
function prepare(value, configuration, nowSeconds) {
  const copy = snapshot(value, 8388608, 262144);
  if (
    !object(copy) ||
    Object.keys(copy).sort().join(",") !== "keyDocuments,statusDocuments"
  )
    throw new PolicyDenied();
  const prepared = prepareEntityTrust(
    configuration,
    copy.keyDocuments,
    copy.statusDocuments,
    nowSeconds,
  );
  return { canonical: canonicalize(copy), ...prepared };
}
export class DurableEntityTrust {
  #storage;
  #configuration;
  #encodedConfiguration;
  #organization;
  #timeout;
  #state = "opening";
  #now = 0;
  /** @type {State|undefined} */ #row;
  /** @type {Map<string,Bundle>} */ #bundles = new Map();
  /** @type {Records} */ #records = Object.create(null);
  /** @param {import('./contracts.js').LedgerStorage} storage
   * @param {{organization:string,configuration:Configuration,initialize?:boolean,timeoutMs?:number}} options
   */
  static async open(storage, options) {
    const trust = new DurableEntityTrust(storage, options);
    await trust.#open(options.initialize ?? false);
    return trust;
  }
  /** Construct through open; an unopened instance cannot authorize.
   * @param {import('./contracts.js').LedgerStorage} storage
   * @param {{organization:string,configuration:Configuration,timeoutMs?:number}} options
   */
  constructor(storage, { organization, configuration, timeoutMs = 10000 }) {
    const copy = /** @type {Configuration} */ (
      /** @type {unknown} */ (snapshot(configuration, 65536))
    );
    prepareEntityTrust(copy, [], [], 0);
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000)
      throw new TypeError("invalid trust timeout");
    this.#configuration = {
      maxAgeSeconds: copy.maxAgeSeconds,
      knownExtensions: [...(copy.knownExtensions ?? [])],
    };
    this.#encodedConfiguration = canonicalize(this.#configuration);
    this.#storage = storage;
    this.#organization = organization;
    this.#timeout = timeoutMs;
  }
  #quarantine() {
    if (this.#state !== "closed") this.#state = "failed";
  }
  #observeTime() {
    const time = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(time) || time < 0) {
      this.#quarantine();
      throw new StoreUnavailable();
    }
    this.#now = Math.max(this.#now, time);
    return this.#now;
  }
  /** @param {string} query @param {...import('./contracts.js').SqlValue} bindings */
  #sql(query, ...bindings) {
    if (["failed", "closed"].includes(this.#state))
      throw new StoreUnavailable();
    try {
      return this.#storage.sql.exec(query, ...bindings).toArray();
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  async #sync() {
    let timer;
    try {
      await Promise.race([
        this.#storage.sync(),
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new StoreUnavailable()),
            this.#timeout,
          );
        }),
      ]);
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    } finally {
      clearTimeout(timer);
    }
    if (["failed", "closed"].includes(this.#state))
      throw new StoreUnavailable();
  }
  /** Read and verify persisted representation and integrity. Callers must still
   * validate signed content through live preparation or the historical codec. */
  #readState() {
    const rows = this.#sql(
      "SELECT configuration,provisioning,revision,accepted_at,checkpoints_digest,checksum FROM xeip_trust_state WHERE singleton=1",
    );
    if (rows.length !== 1) throw new StoreUnavailable();
    const row = /** @type {State} */ (/** @type {unknown} */ (rows[0]));
    row.provisioning = resolveProvisioning(
      row.provisioning,
      row.revision,
      this.#sql(
        "SELECT revision,part,data FROM xeip_trust_chunks ORDER BY revision,part LIMIT 33",
      ),
    );
    /** @type {Records} */ const records = Object.create(null);
    for (const entry of this.#sql(
      "SELECT * FROM xeip_trust_checkpoints ORDER BY entity",
    )) {
      if (
        typeof entry.entity !== "string" ||
        Object.hasOwn(records, entry.entity)
      )
        throw new StoreUnavailable();
      records[entry.entity] =
        /** @type {import('../../../packages/identity/trust-state.mjs').TrustCheckpointRecord} */ (
          /** @type {unknown} */ ({
            anchor: entry.anchor,
            generation: entry.generation,
            keyDigest: entry.key_digest,
            serial: entry.serial,
            statusDigest: entry.status_digest,
          })
        );
    }
    validateTrustRecords(records);
    if (
      row.configuration !== this.#encodedConfiguration ||
      !Number.isSafeInteger(row.revision) ||
      row.revision < 0 ||
      !Number.isSafeInteger(row.accepted_at) ||
      row.accepted_at < 0 ||
      row.checkpoints_digest !== hash(canonicalize(records)) ||
      row.checksum !== checksum(row)
    )
      throw new StoreUnavailable();
    return { row, records };
  }
  #read() {
    const { row, records } = this.#readState();
    const prepared = prepare(
      JSON.parse(row.provisioning),
      this.#configuration,
      row.accepted_at,
    );
    if (prepared.canonical !== row.provisioning) throw new StoreUnavailable();
    for (const [entity, candidate] of Object.entries(prepared.checkpoints))
      if (canonicalize(candidate) !== canonicalize(records[entity]))
        throw new StoreUnavailable();
    return { row, records, prepared };
  }
  /** @param {boolean} initialize */
  async #open(initialize) {
    try {
      initializeLedger(this.#storage, this.#organization);
      if (typeof initialize !== "boolean") throw new StoreUnavailable();
      if (initialize)
        this.#storage.transactionSync(() => {
          if (this.#sql("SELECT singleton FROM xeip_trust_state").length)
            throw new StoreConflict();
          if (
            this.#sql("SELECT entity FROM xeip_trust_checkpoints").length ||
            this.#sql("SELECT 1 FROM xeip_trust_chunks LIMIT 1").length
          )
            throw new StoreUnavailable();
          const row = {
            configuration: this.#encodedConfiguration,
            provisioning: canonicalize({
              keyDocuments: [],
              statusDocuments: [],
            }),
            revision: 0,
            accepted_at: this.#observeTime(),
            checkpoints_digest: hash(canonicalize({})),
          };
          this.#sql(
            "INSERT INTO xeip_trust_state(singleton,configuration,provisioning,revision,accepted_at,checkpoints_digest,checksum) VALUES (1,?,?,?,?,?,?)",
            row.configuration,
            row.provisioning,
            row.revision,
            row.accepted_at,
            row.checkpoints_digest,
            checksum(row),
          );
        });
      const loaded = this.#read();
      this.#now = Math.max(this.#now, loaded.row.accepted_at);
      await this.#sync();
      const confirmed = this.#read();
      if (confirmed.row.checksum !== loaded.row.checksum)
        throw new StoreUnavailable();
      this.#row = loaded.row;
      this.#records = loaded.records;
      this.#bundles = loaded.prepared.bundles;
      this.#state = "ready";
    } catch (error) {
      this.#quarantine();
      if (error instanceof StoreConflict) throw error;
      throw new StoreUnavailable();
    }
  }
  /** Validate a feed against the owner's active roster; no mutation or freshness extension.
   * @param {unknown} provisioning @returns {boolean} whether the canonical data changed */
  validateRefresh(provisioning) {
    if (this.#state !== "ready" || !this.#row || this.#bundles.size === 0)
      throw new StoreUnavailable();
    try {
      if (this.#read().row.checksum !== this.#row.checksum)
        throw new StoreUnavailable();
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
    try {
      const candidate = prepare(
        provisioning,
        this.#configuration,
        this.#observeTime(),
      );
      if (
        candidate.bundles.size !== this.#bundles.size ||
        [...candidate.bundles.keys()].some(
          (entity) => !this.#bundles.has(entity),
        )
      )
        throw new PolicyDenied();
      mergeTrustRecords(
        this.#records,
        candidate.checkpoints,
        candidate.chainDigests,
      );
      return candidate.canonical !== this.#row.provisioning;
    } catch (error) {
      if (error instanceof StoreUnavailable) throw error;
      throw new PolicyDenied();
    }
  }
  /** Trusted owner call; the candidate is a complete replacement, not a patch. @param {unknown} provisioning */
  async update(provisioning) {
    if (this.#state === "updating") throw new StoreConflict();
    if (this.#state !== "ready" || !this.#row) throw new StoreUnavailable();
    let prepared, merged;
    try {
      prepared = prepare(
        provisioning,
        this.#configuration,
        this.#observeTime(),
      );
      merged = mergeTrustRecords(
        this.#records,
        prepared.checkpoints,
        prepared.chainDigests,
      );
    } catch (error) {
      if (error instanceof StoreUnavailable) throw error;
      throw new PolicyDenied();
    }
    const acceptedAt = this.#observeTime();
    if (
      [...prepared.bundles.values()].some(
        (bundle) => acceptedAt - bundle.issuedSeconds > bundle.maxAgeSeconds,
      )
    )
      throw new PolicyDenied();
    const old = this.#row;
    if (old.revision >= Number.MAX_SAFE_INTEGER) throw new StoreUnavailable();
    const next = {
      configuration: this.#encodedConfiguration,
      provisioning: prepared.canonical,
      revision: old.revision + 1,
      accepted_at: acceptedAt,
      checkpoints_digest: hash(canonicalize(merged)),
    };
    const nextChecksum = checksum(next);
    const encoded = encodeProvisioning(next.provisioning, next.revision);
    this.#state = "updating";
    try {
      this.#storage.transactionSync(() => {
        const persisted = this.#read();
        if (persisted.row.checksum !== old.checksum)
          throw new StoreUnavailable();
        for (const [entity, record] of Object.entries(prepared.checkpoints)) {
          const values = [
            record.anchor,
            record.generation,
            record.keyDigest,
            record.serial,
            record.statusDigest,
            entity,
          ];
          if (Object.hasOwn(this.#records, entity))
            this.#sql(
              "UPDATE xeip_trust_checkpoints SET anchor=?,generation=?,key_digest=?,serial=?,status_digest=? WHERE entity=?",
              ...values,
            );
          else
            this.#sql(
              "INSERT INTO xeip_trust_checkpoints(anchor,generation,key_digest,serial,status_digest,entity) VALUES (?,?,?,?,?,?)",
              ...values,
            );
        }
        this.#sql(
          "UPDATE xeip_trust_state SET provisioning=?,revision=?,accepted_at=?,checkpoints_digest=?,checksum=? WHERE singleton=1",
          encoded.stored,
          next.revision,
          next.accepted_at,
          next.checkpoints_digest,
          nextChecksum,
        );
        this.#sql(
          "DELETE FROM xeip_trust_chunks WHERE revision<?",
          next.revision,
        );
        for (const chunk of encoded.chunks)
          this.#sql(
            "INSERT INTO xeip_trust_chunks(revision,part,data) VALUES (?,?,?)",
            chunk.revision,
            chunk.part,
            chunk.data,
          );
      });
      await this.#sync();
      if (this.#state !== "updating") throw new StoreUnavailable();
      const confirmed = this.#read();
      if (confirmed.row.checksum !== nextChecksum) throw new StoreUnavailable();
      this.#row = confirmed.row;
      this.#records = merged;
      this.#bundles = prepared.bundles;
      this.#state = "ready";
      return this.status();
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  /** Capture historical trust only; a caller still needs a coordinated durable recovery cut. */
  checkpoint() {
    if (this.#state !== "ready" || !this.#row) throw new StoreUnavailable();
    try {
      verifyLedgerSchema(this.#storage);
      const { row, records } = this.#readState();
      if (row.checksum !== this.#row.checksum) throw new StoreUnavailable();
      const checkpoint = validateTrustCheckpoint(
        {
          schema: "xeip.trust-checkpoint/1",
          organization: this.#organization,
          configuration: JSON.parse(row.configuration),
          provisioning: JSON.parse(row.provisioning),
          revision: row.revision,
          acceptedAt: row.accepted_at,
          records,
          checksum: row.checksum,
        },
        this.#organization,
      );
      // Preserve literal persisted-byte equality as well as both checksum checks.
      // The codec already prepared signed content at its original accepted time.
      if (canonicalize(checkpoint.provisioning) !== row.provisioning)
        throw new StoreUnavailable();
      return checkpoint;
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  revision() {
    return `${this.#row?.revision ?? "uninitialized"}:${this.#state}`;
  }
  /** @param {{entity:string,kid:string}} principal */
  allows(principal) {
    if (this.#state !== "ready" || !principal) return false;
    try {
      const bundle = this.#bundles.get(principal.entity);
      return (
        !!bundle &&
        this.#observeTime() - bundle.issuedSeconds <= bundle.maxAgeSeconds &&
        bundle.keys.has(principal.kid) &&
        !bundle.revoked.has(principal.kid)
      );
    } catch {
      this.#quarantine();
      return false;
    }
  }
  /** @param {unknown} envelope */
  verify(envelope) {
    const denied = { valid: false, reason: "untrusted identity" };
    if (
      this.#state !== "ready" ||
      !object(envelope) ||
      typeof envelope.sender !== "string"
    )
      return denied;
    try {
      const bundle = this.#bundles.get(envelope.sender);
      return bundle
        ? verifyEntityEnvelope(envelope, {
            ...bundle,
            nowSeconds: this.#observeTime(),
          })
        : denied;
    } catch {
      return denied;
    }
  }
  status() {
    let state = this.#state;
    if (state === "ready") {
      try {
        const now = this.#observeTime();
        state =
          this.#bundles.size === 0
            ? "empty"
            : [...this.#bundles.values()].some(
                  (bundle) => now - bundle.issuedSeconds > bundle.maxAgeSeconds,
                )
              ? "stale"
              : "ready";
      } catch {
        state = "failed";
      }
    }
    return {
      state,
      entities: this.#bundles.size,
      revision: this.#row?.revision ?? null,
    };
  }
  close() {
    this.#state = "closed";
    this.#bundles.clear();
  }
}
