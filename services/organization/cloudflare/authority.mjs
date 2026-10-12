/** Object-local provider, policy and signed-trust authority. Owner-only configuration. */
import { createHash, randomUUID } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { KeycloakAuthenticator } from "../auth.mjs";
import { ActionPolicy, PolicyDenied, snapshot } from "../actions.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { initializeLedger, verifyLedgerSchema } from "./schema.mjs";
import {
  authorityEventChecksum as eventChecksum,
  authorityCheckpointDigest,
  validateAuthorityCheckpoint,
  authorityHistoryCursor,
  validateAuthorityHistoryPage,
} from "./authority-checkpoint.mjs";
/** @typedef {import('../contracts.js').OrganizationPrincipal} Principal */
/** @typedef {import('../contracts.js').AuthorizationContext} Context */
/** @typedef {Omit<import('../auth.mjs').AuthConfiguration,'introspectionClientSecret'>} PublicAuthentication */
/** @typedef {{authentication:PublicAuthentication,policy:import('../actions.mjs').PolicyConfiguration}} Configuration */
/** @typedef {{revision:number,configuration:string,checksum:string}} Row */
/** @typedef {{row:Row,provider:KeycloakAuthenticator,policy:ActionPolicy,configuration:Configuration,bindings:Map<string,{entity:string,kid:string}>}} Prepared */
/** @typedef {{organization:string,trust:import('./trust.mjs').DurableEntityTrust,introspectionClientSecret:string,initialize?:Configuration,timeoutMs?:number}} Options */
/** @typedef {{checkpoint:import('./authority-checkpoint.mjs').Checkpoint,configurationDigest:string}} HistoryProof */
const initialChecksum = "0".repeat(64);
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {number} revision @param {string} configuration @param {string} previousChecksum */
const checksum = (revision, configuration, previousChecksum) =>
  eventChecksum(revision, hash(configuration), previousChecksum);
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
export class DurableOrganizationAuthority {
  #storage;
  #trust;
  #secret;
  #organization;
  #timeout;
  #state = "opening";
  #instance = randomUUID();
  /** @type {Prepared|undefined} */ #active;
  /** @type {WeakMap<Principal,{provider:KeycloakAuthenticator,revision:string}>} */ #issued =
    new WeakMap();
  /** @param {import('./contracts.js').LedgerStorage} storage @param {Options} options */
  static async open(storage, options) {
    const authority = new DurableOrganizationAuthority(storage, options);
    await authority.#open(options.initialize);
    return authority;
  }
  /** Construct through open; unopened authority never authenticates. @param {import('./contracts.js').LedgerStorage} storage @param {Options} options */
  constructor(
    storage,
    { organization, trust, introspectionClientSecret, timeoutMs = 10000 },
  ) {
    if (
      typeof introspectionClientSecret !== "string" ||
      !introspectionClientSecret ||
      introspectionClientSecret.length > 4096 ||
      /[\u0000-\u001f\u007f]/.test(introspectionClientSecret) ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 10000
    )
      throw new TypeError("invalid authority configuration");
    this.#storage = storage;
    this.#organization = organization;
    this.#trust = trust;
    this.#secret = introspectionClientSecret;
    this.#timeout = timeoutMs;
  }
  #quarantine() {
    if (this.#state !== "closed") this.#state = "failed";
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
  /** @param {unknown} value @param {number} revision @param {string} [previousChecksum] @returns {Prepared} */
  #prepare(value, revision, previousChecksum = initialChecksum) {
    const copy = snapshot(value, 1048576);
    if (
      !object(copy) ||
      Object.keys(copy).sort().join(",") !== "authentication,policy" ||
      !object(copy.authentication) ||
      Object.hasOwn(copy.authentication, "introspectionClientSecret")
    )
      throw new TypeError("invalid public authority configuration");
    const configuration = /** @type {Configuration} */ (
      /** @type {unknown} */ (copy)
    );
    const provider = new KeycloakAuthenticator({
        ...configuration.authentication,
        introspectionClientSecret: this.#secret,
      }),
      policy = new ActionPolicy(configuration.policy),
      encoded = canonicalize(copy);
    return {
      configuration,
      provider,
      policy,
      row: {
        revision,
        configuration: encoded,
        checksum: checksum(revision, encoded, previousChecksum),
      },
      bindings: new Map(
        configuration.authentication.bindings.map((b) => [
          b.subject,
          { entity: b.entity, kid: b.kid },
        ]),
      ),
    };
  }
  #read() {
    const rows = this.#sql(
      "SELECT revision,configuration,checksum FROM xeip_authority_state WHERE singleton=1",
    );
    if (rows.length !== 1) throw new StoreUnavailable();
    const row = /** @type {Row} */ (/** @type {unknown} */ (rows[0]));
    if (
      !Number.isSafeInteger(row.revision) ||
      row.revision < 0 ||
      typeof row.configuration !== "string" ||
      typeof row.checksum !== "string"
    )
      throw new StoreUnavailable();
    let expectedRevision = 0,
      previousChecksum = initialChecksum;
    /** @type {{revision:number,configuration_digest:string,previous_checksum:string,checksum:string}|undefined} */
    let last;
    for (;;) {
      const events = this.#sql(
        "SELECT revision,configuration_digest,previous_checksum,checksum FROM xeip_authority_events WHERE revision>=? ORDER BY revision LIMIT 256",
        expectedRevision,
      );
      if (!events.length) break;
      for (const raw of events) {
        const event = /** @type {NonNullable<typeof last>} */ (
          /** @type {unknown} */ (raw)
        );
        if (
          event.revision !== expectedRevision ||
          event.previous_checksum !== previousChecksum ||
          typeof event.configuration_digest !== "string" ||
          !/^[a-f0-9]{64}$/.test(event.configuration_digest) ||
          event.checksum !==
            eventChecksum(
              event.revision,
              event.configuration_digest,
              event.previous_checksum,
            )
        )
          throw new StoreUnavailable();
        last = event;
        previousChecksum = event.checksum;
        expectedRevision++;
      }
    }
    if (
      !last ||
      expectedRevision !== row.revision + 1 ||
      last.checksum !== row.checksum ||
      last.configuration_digest !== hash(row.configuration)
    )
      throw new StoreUnavailable();
    const prepared = this.#prepare(
      JSON.parse(row.configuration),
      row.revision,
      last.previous_checksum,
    );
    if (prepared.row.configuration !== row.configuration)
      throw new StoreUnavailable();
    return prepared;
  }
  /** @param {Configuration|undefined} initial */
  async #open(initial) {
    try {
      initializeLedger(this.#storage, this.#organization);
      if (initial !== undefined) {
        const candidate = this.#prepare(initial, 0);
        this.#storage.transactionSync(() => {
          if (
            this.#sql("SELECT singleton FROM xeip_authority_state").length ||
            this.#sql("SELECT revision FROM xeip_authority_events LIMIT 1")
              .length
          )
            throw new StoreConflict();
          this.#sql(
            "INSERT INTO xeip_authority_state(singleton,revision,configuration,checksum) VALUES (1,0,?,?)",
            candidate.row.configuration,
            candidate.row.checksum,
          );
          this.#sql(
            "INSERT INTO xeip_authority_events(revision,configuration_digest,previous_checksum,checksum) VALUES (0,?,?,?)",
            hash(candidate.row.configuration),
            initialChecksum,
            candidate.row.checksum,
          );
        });
      }
      const prepared = this.#read();
      await this.#sync();
      if (this.#read().row.checksum !== prepared.row.checksum)
        throw new StoreUnavailable();
      this.#active = prepared;
      this.#state = "ready";
    } catch (error) {
      this.#quarantine();
      if (error instanceof StoreConflict) throw error;
      throw new StoreUnavailable();
    }
  }
  /** Owner-only complete replacement. @param {unknown} configuration @param {{expectedRevision:number}} options */
  async update(configuration, { expectedRevision }) {
    if (this.#state === "updating") throw new StoreConflict();
    if (this.#state !== "ready" || !this.#active) throw new StoreUnavailable();
    const old = this.#active;
    if (
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision !== old.row.revision
    )
      throw new StoreConflict();
    if (expectedRevision >= Number.MAX_SAFE_INTEGER)
      throw new StoreUnavailable();
    let candidate;
    try {
      candidate = this.#prepare(
        configuration,
        expectedRevision + 1,
        old.row.checksum,
      );
      for (const key of /** @type {const} */ ([
        "issuer",
        "audience",
        "introspectionClientId",
      ]))
        if (
          candidate.configuration.authentication[key] !==
          old.configuration.authentication[key]
        )
          throw new Error("identity domain is immutable");
    } catch {
      throw new PolicyDenied();
    }
    this.#state = "updating";
    try {
      this.#storage.transactionSync(() => {
        if (this.#read().row.checksum !== old.row.checksum)
          throw new StoreUnavailable();
        this.#sql(
          "UPDATE xeip_authority_state SET revision=?,configuration=?,checksum=? WHERE singleton=1",
          candidate.row.revision,
          candidate.row.configuration,
          candidate.row.checksum,
        );
        this.#sql(
          "INSERT INTO xeip_authority_events(revision,configuration_digest,previous_checksum,checksum) VALUES (?,?,?,?)",
          candidate.row.revision,
          hash(candidate.row.configuration),
          old.row.checksum,
          candidate.row.checksum,
        );
      });
      await this.#sync();
      if (
        this.#state !== "updating" ||
        this.#read().row.checksum !== candidate.row.checksum
      )
        throw new StoreUnavailable();
      this.#active = candidate;
      this.#state = "ready";
      return this.status();
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  /** Historical capture only. This does not activate authority or prove independent durability. */
  checkpoint() {
    if (this.#state !== "ready" || !this.#active) throw new StoreUnavailable();
    try {
      verifyLedgerSchema(this.#storage);
      const current = this.#read();
      if (current.row.checksum !== this.#active.row.checksum)
        throw new StoreUnavailable();
      const rows = this.#sql(
        "SELECT previous_checksum FROM xeip_authority_events WHERE revision=?",
        current.row.revision,
      );
      if (rows.length !== 1 || typeof rows[0].previous_checksum !== "string")
        throw new StoreUnavailable();
      const body = {
        schema: /** @type {const} */ ("xeip.authority-checkpoint/1"),
        organization: this.#organization,
        configuration: current.configuration,
        revision: current.row.revision,
        previousChecksum: rows[0].previous_checksum,
        checksum: current.row.checksum,
      };
      return validateAuthorityCheckpoint(
        { ...body, digest: authorityCheckpointDigest(body) },
        this.#organization,
      );
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  /** Bounded history pinned to one captured head; no mixed-revision snapshots.
   * @param {unknown} value @param {unknown} [options] */
  historyPage(value, options = {}) {
    return this.#historyPage(value, options, false);
  }
  /** Retained historical head, anchored to the verified source chain; no authority activation.
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
  /** Fully verify once, then read selected retained history without activating old policy.
   * @param {unknown} value */
  historyReaderAt(value) {
    const checkpoint = validateAuthorityCheckpoint(value, this.#organization);
    this.#historyPage(checkpoint, {}, true);
    return this.#historyReader(checkpoint);
  }
  /** Only accepts an internally validated checkpoint.
   * @param {import('./authority-checkpoint.mjs').Checkpoint} checkpoint */
  #historyReader(checkpoint) {
    const proof = Object.freeze({
      checkpoint,
      configurationDigest: hash(canonicalize(checkpoint.configuration)),
    });
    let closed = false;
    return Object.freeze({
      page: (/** @type {unknown} */ options = {}) => {
        if (closed) throw new StoreUnavailable();
        return this.#historyPage(null, options, true, proof);
      },
      close: () => {
        closed = true;
      },
    });
  }
  /** Only for a reader whose source history was already verified. */
  #readerHead() {
    if (this.#state !== "ready" || !this.#active) throw new StoreUnavailable();
    try {
      verifyLedgerSchema(this.#storage);
      const scope = this.#sql("SELECT organization_id FROM xeip_metadata"),
        state = this.#sql("SELECT revision,checksum FROM xeip_authority_state"),
        tail = this.#sql(
          "SELECT revision,checksum FROM xeip_authority_events ORDER BY revision DESC LIMIT 1",
        ),
        accepted = this.#active.row;
      if (
        scope.length !== 1 ||
        scope[0].organization_id !== this.#organization ||
        state.length !== 1 ||
        tail.length !== 1 ||
        state[0].revision !== accepted.revision ||
        state[0].checksum !== accepted.checksum ||
        tail[0].revision !== accepted.revision ||
        tail[0].checksum !== accepted.checksum
      )
        throw Error();
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  /** @param {unknown} value @param {unknown} options @param {boolean} historical @param {HistoryProof} [verified] */
  #historyPage(value, options, historical, verified) {
    if (this.#state !== "ready" || !this.#active) throw new StoreUnavailable();
    const expected =
        verified?.checkpoint ??
        validateAuthorityCheckpoint(value, this.#organization),
      cursor = authorityHistoryCursor(options, expected.revision);
    if (verified) this.#readerHead();
    else {
      const current = this.checkpoint();
      if (!historical && expected.digest !== current.digest)
        throw new StoreConflict();
    }
    if (historical) {
      if (expected.revision > this.#active.row.revision)
        throw new StoreConflict();
      let anchor;
      try {
        const rows = this.#sql(
          "SELECT configuration_digest,previous_checksum,checksum FROM xeip_authority_events WHERE revision=?",
          expected.revision,
        );
        if (rows.length !== 1) throw Error();
        anchor = rows[0];
      } catch {
        this.#quarantine();
        throw new StoreUnavailable();
      }
      if (
        anchor.configuration_digest !==
          (verified?.configurationDigest ??
            hash(canonicalize(expected.configuration))) ||
        anchor.previous_checksum !== expected.previousChecksum ||
        anchor.checksum !== expected.checksum
      ) {
        if (verified) {
          this.#quarantine();
          throw new StoreUnavailable();
        }
        throw new StoreConflict();
      }
    }
    if (cursor.after >= 0) {
      const previous = this.#sql(
        "SELECT checksum FROM xeip_authority_events WHERE revision=?",
        cursor.after,
      );
      if (previous.length !== 1) {
        this.#quarantine();
        throw new StoreUnavailable();
      }
      if (previous[0].checksum !== cursor.previousChecksum)
        throw new TypeError("invalid authority history cursor");
    }
    try {
      const records = this.#sql(
        "SELECT revision,configuration_digest,previous_checksum,checksum FROM xeip_authority_events WHERE revision>? AND revision<=? ORDER BY revision LIMIT ?",
        cursor.after,
        expected.revision,
        cursor.limit,
      ).map((row) => ({
        revision: row.revision,
        configurationDigest: row.configuration_digest,
        previousChecksum: row.previous_checksum,
        checksum: row.checksum,
      }));
      const next = cursor.after + records.length;
      return validateAuthorityHistoryPage(
        {
          schema: "xeip.authority-history-page/1",
          checkpointDigest: expected.digest,
          after: cursor.after,
          records,
          next,
          complete: next === expected.revision,
        },
        expected,
        cursor,
      );
    } catch {
      this.#quarantine();
      throw new StoreUnavailable();
    }
  }
  revision() {
    return `${this.#instance}:${this.#active?.row.revision ?? "uninitialized"}:${this.#state}:${this.#trust.revision()}`;
  }
  policy() {
    if (this.#state !== "ready" || !this.#active) throw new StoreUnavailable();
    return this.#active.policy;
  }
  /** Local eligibility also applies to persisted approvers; it is not authentication. @param {Principal} principal */
  allows(principal) {
    if (this.#state !== "ready" || !this.#active || !principal) return false;
    const binding = this.#active.bindings.get(principal.subject);
    return (
      !!binding &&
      binding.entity === principal.entity &&
      binding.kid === principal.kid &&
      this.#active.configuration.authentication.clientIds.includes(
        principal.clientId,
      ) &&
      this.#trust.allows(principal)
    );
  }
  /** @param {unknown} header */
  async authenticate(header) {
    if (this.#state !== "ready" || !this.#active) throw new StoreUnavailable();
    const revision = this.revision(),
      provider = this.#active.provider,
      principal = await provider.authenticate(header);
    if (!principal) return null;
    if (revision !== this.revision() || !this.allows(principal)) {
      provider.release(principal);
      return null;
    }
    this.#issued.set(principal, { provider, revision });
    return principal;
  }
  /** @param {Principal} principal */
  async revalidate(principal) {
    const issued = this.#issued.get(principal);
    if (
      !issued ||
      issued.revision !== this.revision() ||
      !this.allows(principal)
    ) {
      this.release(principal);
      return false;
    }
    try {
      const valid = await issued.provider.revalidate(principal);
      if (
        !valid ||
        this.#issued.get(principal) !== issued ||
        issued.revision !== this.revision() ||
        !this.allows(principal)
      ) {
        this.release(principal);
        return false;
      }
      return true;
    } catch (error) {
      this.release(principal);
      throw error;
    }
  }
  /** @param {Principal} principal */
  release(principal) {
    this.#issued.get(principal)?.provider.release(principal);
    this.#issued.delete(principal);
  }
  /** @param {Principal} principal @param {Context} context */
  #eligible(principal, context) {
    if (
      !this.allows(principal) ||
      (context.approver && !this.allows(context.approver))
    )
      return false;
    const policy = this.policy();
    if (context.phase === "inspect")
      return policy.canInspect(principal, context.proposal);
    if (context.phase === "decide")
      return policy.canApprove(principal, context.proposal);
    if (context.phase === "revoke")
      return (
        policy.canExecute(principal, context.proposal) ||
        policy.canApprove(principal, context.proposal)
      );
    if (context.phase === "propose")
      return policy.canExecute(principal, context.proposal);
    return (
      ["claim", "effect"].includes(context.phase) &&
      policy.canExecute(principal, context.proposal) &&
      !!context.approver &&
      policy.canApprove(context.approver, context.proposal)
    );
  }
  /** @param {Principal} principal @param {Context} context */
  async authorize(principal, context) {
    const revision = this.revision();
    let copy;
    try {
      copy = /** @type {Context} */ (
        /** @type {unknown} */ (snapshot(context, 80000))
      );
      if (!this.#eligible(principal, copy)) return false;
    } catch {
      return false;
    }
    return (
      (await this.revalidate(principal)) &&
      revision === this.revision() &&
      this.#eligible(principal, copy)
    );
  }
  /** Probe the pinned provider and reject a late success after any authority change. */
  async ready() {
    if (
      this.#state !== "ready" ||
      !this.#active ||
      this.#trust.status().state !== "ready"
    )
      return false;
    const revision = this.revision(),
      provider = this.#active.provider;
    return (
      (await provider.ready()) &&
      this.#state === "ready" &&
      revision === this.revision() &&
      this.#trust.status().state === "ready"
    );
  }
  status() {
    return {
      state: this.#state,
      revision: this.#active?.row.revision ?? null,
      trust: this.#trust.status().state,
    };
  }
  close() {
    this.#state = "closed";
    this.#secret = "";
    this.#active = undefined;
  }
}
