/** Explicit object-owned service lifecycle. Owner methods must never be public HTTP routes. */
import { createHash, randomUUID } from "node:crypto";
import {
  canonicalize,
  decodeKeyId,
} from "../../../sdks/typescript/dist/identity.js";
import {
  fetchTrustFeed,
  validateTrustFeed,
  validateFeedToken,
} from "./refresh.mjs";
import { prepareEntityTrust } from "../../../packages/identity/trust-state.mjs";
import { snapshot } from "../actions.mjs";
import { validatePublicAuthority } from "./authority-checkpoint.mjs";
import {
  lifecycleChecksum as checksum,
  lifecycleCheckpointDigest,
  validatePublicRuntime,
  validateLifecycleCheckpoint,
} from "./lifecycle-checkpoint.mjs";
import { McpConnector } from "../mcp.mjs";
import { OrganizationController, OperationError } from "../controller.mjs";
import { createActionExecutor } from "../execution.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { initializeLedger, verifyLedgerSchema } from "./schema.mjs";
import { DurableEntityTrust } from "./trust.mjs";
import { DurableOrganizationAuthority } from "./authority.mjs";
import { recoveryDescriptor } from "./action-recovery.mjs";
import { recoveryOptions } from "./recovery-record.mjs";
import { recoveryConfiguration } from "./recovery-configuration.mjs";
import { createRecoveryClient } from "./recovery-client.mjs";
import { DurableActionStore } from "./store.mjs";
import { createWorkerHttp } from "./http.mjs";
import { OwnerJournal, auditPageOptions } from "./admin-audit.mjs";
import { parseOwnerCommand, operatorIdentity } from "./profile.mjs";
import { OrganizationExports } from "./organization-export.mjs";
import {
  organizationManifest,
  validateOrganizationManifest,
  organizationPageOptions,
} from "./organization-checkpoint.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {import('./authority.mjs').Configuration} AuthorityConfiguration */
/** @typedef {{organization:string,origin:string,gateway:string,trust:import('../../../packages/identity/trust-state.mjs').TrustConfiguration,targets:import('../mcp.mjs').Target[],introspectionClientSecret:string,timeoutMs?:number,trustFeed?:import('./refresh.mjs').TrustFeed,trustFeedToken?:string,recovery?:import('./recovery-configuration.mjs').RecoveryProfile,recoveryToken?:string}} Configuration */
/** @typedef {{runtime_configuration:string,initial_authority:string,checksum:string,phase:'initializing'|'initialized'}} Row */
/** @typedef {{authority?:ReturnType<DurableOrganizationAuthority["historyReaderAt"]>,administration?:ReturnType<OwnerJournal["historyReaderAt"]>}} CapturedReaders */
/** @param {unknown} value @returns {value is Record<string,unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
export class OrganizationService {
  /** @type {Storage} */ #storage;
  #configuration;
  /** @type {import("./action-recovery.mjs").Settings|undefined} */ #recovery;
  #runtime;
  #connector;
  #http;
  #timeout;
  #state = "opening";
  #busy = false;
  #ownerBusy = false;
  #refreshBusy = false;
  /** @type {OwnerJournal|undefined} */ #journal;
  /** @type {OrganizationExports|undefined} */ #exports;
  /** @type {DurableEntityTrust|undefined} */ #trust;
  /** @type {DurableOrganizationAuthority|undefined} */ #authority;
  /** @type {DurableActionStore|undefined} */ #ledger;
  /** @type {OrganizationController|undefined} */ #controller;
  /** @param {Storage} storage @param {Configuration} configuration @param {import("./action-recovery.mjs").Settings} [recovery] */
  static async open(storage, configuration, recovery) {
    const service = new OrganizationService(storage, configuration, recovery);
    await service.#open();
    return service;
  }
  /** @param {Storage} storage @param {Configuration} configuration @param {import("./action-recovery.mjs").Settings} [recovery] */
  constructor(storage, configuration, recovery) {
    this.#recovery = recovery
      ? { options: recoveryOptions(recovery.options), client: recovery.client }
      : undefined;
    const copy = /** @type {Configuration} */ (
      /** @type {unknown} */ (snapshot(configuration, 2097152))
    );
    if (
      !object(copy) ||
      Object.keys(copy).some(
        (k) =>
          ![
            "organization",
            "origin",
            "gateway",
            "trust",
            "targets",
            "introspectionClientSecret",
            "timeoutMs",
            "trustFeed",
            "trustFeedToken",
            "recovery",
            "recoveryToken",
          ].includes(k),
      ) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(copy.organization) ||
      typeof copy.gateway !== "string" ||
      !copy.gateway.startsWith("urn:xeip:entity:") ||
      typeof copy.introspectionClientSecret !== "string" ||
      !copy.introspectionClientSecret ||
      copy.introspectionClientSecret.length > 4096 ||
      /[\u0000-\u001f\u007f]/.test(copy.introspectionClientSecret)
    )
      throw new TypeError("invalid service configuration");
    decodeKeyId(copy.gateway.slice("urn:xeip:entity:".length));
    prepareEntityTrust(copy.trust, [], [], 0);
    this.#timeout = copy.timeoutMs ?? 10000;
    if (
      !Number.isInteger(this.#timeout) ||
      this.#timeout < 100 ||
      this.#timeout > 10000
    )
      throw new TypeError("invalid service timeout");
    if (
      !Array.isArray(copy.targets) ||
      copy.targets.some(
        (target) =>
          !object(target) ||
          Object.keys(target).some(
            (key) =>
              ![
                "id",
                "revision",
                "recipient",
                "tools",
                "endpoint",
                "resourceMetadataUrl",
                "issuer",
                "tokenEndpoint",
                "clientId",
                "clientSecret",
                "scope",
                "allowInsecureLoopback",
              ].includes(key),
          ),
      )
    )
      throw new TypeError("invalid service target configuration");
    if (Object.hasOwn(copy, "trustFeed")) {
      validateTrustFeed(copy.trustFeed);
      validateFeedToken(copy.trustFeedToken);
      if (copy.trust.maxAgeSeconds < 180)
        throw new TypeError("trust age too short for feed");
    } else if (Object.hasOwn(copy, "trustFeedToken"))
      throw new TypeError("unexpected feed credential");
    let recoveryUrl;
    if (Object.hasOwn(copy, "recovery")) {
      if (recovery) throw new TypeError("conflicting recovery configuration");
      const configured = recoveryConfiguration(
        copy.recovery,
        copy.organization,
      );
      recoveryUrl = configured.url;
      this.#recovery = {
        options: configured.options,
        client: createRecoveryClient({
          ...configured,
          token: copy.recoveryToken,
        }),
      };
    } else if (Object.hasOwn(copy, "recoveryToken"))
      throw new TypeError("unexpected recovery credential");
    this.#connector = new McpConnector(copy.targets);
    this.#configuration = copy;
    this.#runtime = canonicalize({
      organization: copy.organization,
      origin: copy.origin,
      gateway: copy.gateway,
      trust: copy.trust,
      targets: copy.targets.map(({ clientSecret, ...target }) => target),
      ...(copy.trustFeed ? { trustFeed: copy.trustFeed } : {}),
      ...(this.#recovery
        ? {
            recovery: {
              ...recoveryDescriptor(this.#recovery.options),
              ...(recoveryUrl ? { url: recoveryUrl } : {}),
            },
          }
        : {}),
    });
    validatePublicRuntime(JSON.parse(this.#runtime), copy.organization);
    this.#storage = {
      sql: {
        exec: (query, ...bindings) => {
          this.#usable();
          try {
            return storage.sql.exec(query, ...bindings);
          } catch {
            this.#fail();
            throw new StoreUnavailable();
          }
        },
      },
      transactionSync: (fn) => {
        this.#usable();
        return storage.transactionSync(fn);
      },
      sync: async () => {
        this.#usable();
        let timer;
        try {
          await Promise.race([
            storage.sync(),
            new Promise((_, reject) => {
              timer = setTimeout(
                () => reject(new StoreUnavailable()),
                this.#timeout,
              );
            }),
          ]);
          this.#usable();
        } catch {
          this.#fail();
          throw new StoreUnavailable();
        } finally {
          clearTimeout(timer);
        }
      },
    };
    this.#http = createWorkerHttp({
      origin: copy.origin,
      controller: {
        handle: (header, body, options) => {
          if (this.#state !== "initialized" || !this.#controller)
            throw new OperationError(503, "unavailable");
          return this.#controller.handle(header, body, options);
        },
      },
      ready: () => this.ready(),
    });
  }
  #usable() {
    if (["failed", "closed"].includes(this.#state))
      throw new StoreUnavailable();
  }
  #fail() {
    if (this.#state !== "closed") this.#state = "failed";
    this.#exports?.close();
    this.#trust?.close();
    this.#authority?.close();
    this.#ledger?.close();
  }
  /** @param {string} query @param {...import('./contracts.js').SqlValue} bindings */
  #sql(query, ...bindings) {
    return this.#storage.sql.exec(query, ...bindings).toArray();
  }
  /** @param {unknown} value @returns {AuthorityConfiguration} */
  #prepare(value) {
    const configuration = validatePublicAuthority(value);
    for (const policy of configuration.policy.targets) {
      const target = this.#configuration.targets.find(
        (t) => t.id === policy.id,
      );
      if (
        !target ||
        target.revision !== policy.revision ||
        target.recipient !== policy.recipient ||
        policy.tools.some((tool) => !target.tools.includes(tool))
      )
        throw new TypeError("unconfigured policy target");
    }
    return configuration;
  }
  /** @returns {Row} */
  #read() {
    const rows = this.#sql(
      "SELECT runtime_configuration,initial_authority,checksum,phase FROM xeip_service_state WHERE singleton=1",
    );
    if (rows.length !== 1) throw new StoreUnavailable();
    const row = /** @type {Row} */ (/** @type {unknown} */ (rows[0]));
    if (
      row.runtime_configuration !== this.#runtime ||
      !["initializing", "initialized"].includes(row.phase) ||
      row.checksum !==
        checksum(row.runtime_configuration, row.initial_authority) ||
      canonicalize(this.#prepare(JSON.parse(row.initial_authority))) !==
        row.initial_authority
    )
      throw new StoreUnavailable();
    return row;
  }
  async #open() {
    try {
      const tables = this.#sql(
        "SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'",
      );
      if (tables.length === 0) {
        this.#state = "uninitialized";
        return;
      }
      if (!tables.some((t) => t.name === "xeip_service_state"))
        throw new StoreUnavailable();
      const row = this.#read();
      initializeLedger(this.#storage, this.#configuration.organization);
      this.#journal = new OwnerJournal(this.#storage);
      this.#state = row.phase;
      if (row.phase === "initialized") {
        await this.#load(false, row);
        await this.#activate();
      }
    } catch {
      this.#fail();
    }
  }
  /** @param {boolean} resume @param {Row} row */
  async #load(resume, row) {
    const trustExists = this.#sql(
      "SELECT revision FROM xeip_trust_state WHERE singleton=1",
    );
    if (!resume && !trustExists.length) throw new StoreUnavailable();
    const trust = await DurableEntityTrust.open(this.#storage, {
      organization: this.#configuration.organization,
      configuration: this.#configuration.trust,
      initialize: resume && trustExists.length === 0,
      timeoutMs: this.#timeout,
    });
    if (this.#state === "closed" || this.#state === "failed") {
      trust.close();
      throw new StoreUnavailable();
    }
    this.#trust = trust;
    if (
      resume &&
      (trust.status().revision !== 0 || trust.status().entities !== 0)
    )
      throw new StoreUnavailable();
    const authorityExists = this.#sql(
      "SELECT revision,configuration FROM xeip_authority_state WHERE singleton=1",
    );
    if (!resume && !authorityExists.length) throw new StoreUnavailable();
    if (
      resume &&
      authorityExists.length &&
      (authorityExists[0].revision !== 0 ||
        authorityExists[0].configuration !== row.initial_authority)
    )
      throw new StoreUnavailable();
    const authority = await DurableOrganizationAuthority.open(this.#storage, {
      organization: this.#configuration.organization,
      trust,
      introspectionClientSecret: this.#configuration.introspectionClientSecret,
      ...(resume && !authorityExists.length
        ? { initialize: JSON.parse(row.initial_authority) }
        : {}),
      timeoutMs: this.#timeout,
    });
    if (this.#state === "closed" || this.#state === "failed") {
      authority.close();
      throw new StoreUnavailable();
    }
    this.#authority = authority;
    const current = this.#sql(
      "SELECT configuration FROM xeip_authority_state WHERE singleton=1",
    )[0];
    this.#prepare(JSON.parse(/** @type {string} */ (current.configuration)));
  }
  /** @param {boolean} [initialize] */
  async #activate(initialize = false) {
    if (!this.#authority || !this.#trust) throw new StoreUnavailable();
    const authority = this.#authority,
      trust = this.#trust;
    const candidate = await DurableActionStore.open(this.#storage, authority, {
      organization: this.#configuration.organization,
      timeoutMs: this.#timeout,
      ...(this.#recovery
        ? { recovery: { ...this.#recovery, initialize } }
        : {}),
    });
    if (this.#state === "closed" || this.#state === "failed") {
      candidate.close();
      throw new StoreUnavailable();
    }
    this.#ledger = candidate;
    const ledger = this.#ledger;
    this.#controller = new OrganizationController({
      authentication: authority,
      trust,
      gateway: this.#configuration.gateway,
      createStore: (guard) => ledger.withAuthorization(guard),
      execute: (p, c, context) =>
        createActionExecutor(authority.policy(), this.#connector)(p, c, {
          ...context,
          authorize: (p, c) =>
            ledger.authorizeEffect(
              async () =>
                this.#state === "initialized" &&
                (await authority.authorize(p, c)) &&
                (await context.authorize(p, c)) &&
                this.#state === "initialized",
            ),
        }),
    });
  }
  /** Capture locally synchronized historical intent; no independent recovery receipt or activation.
   * @returns {Promise<import('./lifecycle-checkpoint.mjs').Checkpoint>} */
  async lifecycleCheckpoint() {
    this.#usable();
    if (this.#busy || this.#ownerBusy || this.#refreshBusy)
      throw new StoreConflict();
    if (!["initializing", "initialized"].includes(this.#state))
      throw new StoreUnavailable();
    this.#busy = true;
    try {
      verifyLedgerSchema(this.#storage);
      const before = this.#read();
      if (before.phase !== this.#state) throw new StoreUnavailable();
      await this.#storage.sync();
      verifyLedgerSchema(this.#storage);
      const confirmed = this.#read();
      if (
        confirmed.phase !== this.#state ||
        canonicalize(confirmed) !== canonicalize(before)
      )
        throw new StoreUnavailable();
      return this.#lifecycleRecord(confirmed);
    } catch {
      this.#fail();
      throw new StoreUnavailable();
    } finally {
      this.#busy = false;
    }
  }
  /** @param {Row} row */
  #lifecycleRecord(row) {
    const body = {
      schema: /** @type {const} */ ("xeip.lifecycle-checkpoint/1"),
      organization: this.#configuration.organization,
      runtime: JSON.parse(row.runtime_configuration),
      initialAuthority: JSON.parse(row.initial_authority),
      phase: row.phase,
      checksum: row.checksum,
    };
    return validateLifecycleCheckpoint(
      { ...body, digest: lifecycleCheckpointDigest(body) },
      this.#configuration.organization,
    );
  }
  /** No awaits: all components and the action cut observe one object-local view.
   * @param {number} [cut] @param {CapturedReaders} [readers] @returns {import('./organization-checkpoint.mjs').Checkpoint} */
  #recoveryCheckpoint(cut, readers) {
    this.#usable();
    verifyLedgerSchema(this.#storage);
    const row = this.#read();
    if (
      this.#state !== "initialized" ||
      row.phase !== "initialized" ||
      !this.#trust ||
      !this.#authority ||
      !this.#ledger
    )
      throw new StoreUnavailable();
    this.#journal ??= new OwnerJournal(this.#storage);
    const lifecycle = this.#lifecycleRecord(row),
      trust = this.#trust.checkpoint();
    let authority, administration;
    if (readers) {
      const capturedAuthority = this.#authority.captureHistoryReader();
      readers.authority = capturedAuthority.reader;
      authority = capturedAuthority.checkpoint;
      const capturedAdministration = this.#journal.captureHistoryReader();
      readers.administration = capturedAdministration.reader;
      administration = capturedAdministration.checkpoint;
    } else {
      authority = this.#authority.checkpoint();
      administration = this.#journal.checkpoint();
    }
    const components = { lifecycle, trust, authority, administration };
    const manifest = organizationManifest(
      components,
      this.#ledger.actionSnapshot(cut),
    );
    return Object.freeze({ manifest, ...components });
  }
  /** Capture settled controls and a locally synchronized historical action cut; never a recovery receipt. */
  async recoveryCheckpoint() {
    return this.#synchronizedCheckpoint();
  }
  /** The caller owns any acquired readers, including when capture fails.
   * @param {CapturedReaders} [readers] */
  async #synchronizedCheckpoint(readers) {
    this.#usable();
    if (this.#busy || this.#ownerBusy || this.#refreshBusy)
      throw new StoreConflict();
    if (this.#state !== "initialized") throw new StoreUnavailable();
    this.#busy = true;
    try {
      // Only the immutable manifest is needed across sync. Release the first
      // component graph before constructing its independently validated copy.
      const before = this.#recoveryCheckpoint().manifest;
      await this.#storage.sync();
      const confirmed = this.#recoveryCheckpoint(
        before.actions.cut,
        readers,
      );
      if (confirmed.manifest.digest !== before.digest)
        throw new StoreUnavailable();
      return confirmed;
    } catch (error) {
      if (error instanceof StoreConflict) throw error;
      this.#fail();
      throw new StoreUnavailable();
    } finally {
      this.#busy = false;
    }
  }
  /** Internal export evidence only. Binding authorization belongs to the owner entrypoint. */
  #exportManager() {
    this.#usable();
    this.#exports ??= new OrganizationExports({
      organization: this.#configuration.organization,
      capture: () => this.#captureExport(),
    });
    return this.#exports;
  }
  #exportUsable() {
    this.#usable();
    if (
      this.#state !== "initialized" ||
      !this.#ledger?.healthy() ||
      !this.#authority ||
      !this.#trust ||
      ["failed", "closed"].includes(this.#authority.status().state) ||
      ["failed", "closed"].includes(this.#trust.status().state)
    )
      throw new StoreUnavailable();
  }
  /** @returns {Promise<import('./organization-export.mjs').Source>} */
  async #captureExport() {
    /** @type {CapturedReaders} */
    const readers = {};
    try {
      const checkpoint = await this.#synchronizedCheckpoint(readers);
      this.#exportUsable();
      if (this.#busy || this.#ownerBusy || this.#refreshBusy)
        throw new StoreConflict();
      const ledger = this.#ledger,
        authorityReader = readers.authority,
        administrationReader = readers.administration;
      if (!ledger || !authorityReader || !administrationReader)
        throw new StoreUnavailable();
      const manifest = checkpoint.manifest;
      return {
        checkpoint,
        assertUsable: () => this.#exportUsable(),
        close: () => {
          authorityReader.close();
          administrationReader.close();
        },
        readPage: (request) => {
          this.#exportUsable();
          if (this.#busy || this.#ownerBusy || this.#refreshBusy)
            throw new StoreConflict();
          try {
            const page =
              request.section === "actions"
                ? ledger.actionPage(manifest.actions.cut, request.cursor)
                : request.section === "authority"
                  ? authorityReader.page(request.cursor)
                  : administrationReader.page(request.cursor);
            return {
              checkpointDigest: manifest.digest,
              section: request.section,
              page,
            };
          } catch (error) {
            if (error instanceof StoreUnavailable) this.#fail();
            throw error;
          }
        },
      };
    } catch (error) {
      readers.authority?.close();
      readers.administration?.close();
      // Synchronized capture owns integrity quarantine. Ordinary preflight
      // refusal (for example, before initialization) must not poison the source.
      throw error;
    }
  }
  /** @param {unknown} operator */
  beginRecoveryExport(operator) {
    return this.#exportManager().begin(operator);
  }
  /** @param {unknown} operator @param {unknown} id @param {unknown} component @param {unknown} index */
  recoveryExportPart(operator, id, component, index) {
    return this.#exportManager().part(operator, id, component, index);
  }
  /** @param {unknown} operator @param {unknown} id @param {unknown} options */
  recoveryExportPage(operator, id, options) {
    return this.#exportManager().page(operator, id, options);
  }
  /** @param {unknown} operator @param {unknown} id */
  closeRecoveryExport(operator, id) {
    return this.#exportManager().end(operator, id);
  }
  /** Internal bounded evidence only; no owner command or public route.
   * @param {unknown} value @param {unknown} options */
  recoveryPage(value, options) {
    this.#usable();
    const manifest = validateOrganizationManifest(
        value,
        this.#configuration.organization,
      ),
      request = organizationPageOptions(options);
    if (this.#busy || this.#ownerBusy || this.#refreshBusy)
      throw new StoreConflict();
    if (this.#state !== "initialized" || !this.#ledger || !this.#authority)
      throw new StoreUnavailable();
    try {
      let page;
      if (request.section === "actions")
        page = this.#ledger.actionPage(manifest.actions.cut, request.cursor);
      else if (request.section === "authority") {
        const current = this.#authority.checkpoint();
        if (current.digest !== manifest.authorityDigest)
          throw new StoreConflict();
        page = this.#authority.historyPage(current, request.cursor);
      } else {
        this.#journal ??= new OwnerJournal(this.#storage);
        const current = this.#journal.checkpoint();
        if (current.digest !== manifest.administrationDigest)
          throw new StoreConflict();
        page = this.#journal.historyPage(current, request.cursor);
      }
      return {
        checkpointDigest: manifest.digest,
        section: request.section,
        page,
      };
    } catch (error) {
      if (error instanceof StoreUnavailable) this.#fail();
      throw error;
    }
  }
  #requireEmptyActions() {
    for (const table of ["xeip_actions", "xeip_audit"])
      if (this.#sql("SELECT 1 AS present FROM " + table + " LIMIT 1").length)
        throw new StoreUnavailable();
  }
  /** Install only the checked first intent; caller may include the audit start in an outer transaction.
   * @param {string} encoded */
  #bootstrap(encoded) {
    this.#storage.transactionSync(() => {
      initializeLedger(this.#storage, this.#configuration.organization);
      for (const table of [
        "xeip_service_state",
        "xeip_trust_state",
        "xeip_trust_checkpoints",
        "xeip_trust_chunks",
        "xeip_authority_state",
        "xeip_authority_events",
        "xeip_actions",
        "xeip_audit",
      ])
        if (this.#sql("SELECT 1 AS present FROM " + table + " LIMIT 1").length)
          throw new StoreUnavailable();
      this.#sql(
        "INSERT INTO xeip_service_state(singleton,runtime_configuration,initial_authority,checksum,phase) VALUES (1,?,?,?,'initializing')",
        this.#runtime,
        encoded,
        checksum(this.#runtime, encoded),
      );
    });
    this.#state = "initializing";
  }
  /** Explicit owner-only first setup / exact interrupted retry. @param {unknown} configuration */
  async initialize(configuration) {
    this.#usable();
    if (this.#busy) throw new StoreConflict();
    const candidate = this.#prepare(configuration),
      encoded = canonicalize(candidate);
    if (Buffer.byteLength(encoded) + Buffer.byteLength(this.#runtime) > 2097152)
      throw new TypeError("service intent too large");
    this.#busy = true;
    try {
      if (this.#state === "uninitialized") {
        this.#bootstrap(encoded);
        await this.#storage.sync();
      }
      const row = this.#read();
      if (row.initial_authority !== encoded) throw new StoreConflict();
      if (row.phase === "initialized") return this.status();
      this.#requireEmptyActions();
      await this.#load(true, row);
      this.#requireEmptyActions();
      await this.#activate(true);
      this.#sql(
        "UPDATE xeip_service_state SET phase='initialized' WHERE singleton=1 AND phase='initializing'",
      );
      await this.#storage.sync();
      if (this.#read().phase !== "initialized") throw new StoreUnavailable();
      this.#state = "initialized";
      return this.status();
    } catch (error) {
      if (!(error instanceof StoreConflict)) this.#fail();
      throw error;
    } finally {
      this.#busy = false;
    }
  }
  /** @param {unknown} provisioning @param {{expectedRevision:number}} options */
  async refreshTrust(provisioning, { expectedRevision }) {
    this.#usable();
    if (this.#busy) throw new StoreConflict();
    if (this.#state !== "initialized" || !this.#trust)
      throw new StoreUnavailable();
    if (
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision !== this.#trust.status().revision
    )
      throw new StoreConflict();
    this.#busy = true;
    try {
      await this.#trust.update(provisioning);
      this.#usable();
      return this.status();
    } finally {
      this.#busy = false;
    }
  }
  /** @param {unknown} configuration @param {{expectedRevision:number}} options */
  async updateAuthority(configuration, { expectedRevision }) {
    this.#usable();
    if (this.#busy) throw new StoreConflict();
    if (this.#state !== "initialized" || !this.#authority)
      throw new StoreUnavailable();
    const candidate = this.#prepare(configuration);
    this.#busy = true;
    try {
      await this.#authority.update(candidate, { expectedRevision });
      this.#usable();
      return this.status();
    } finally {
      this.#busy = false;
    }
  }
  /** Trusted scheduler only. Never accepts an external URL, operator, or provisioning. */
  async pollTrustFeed() {
    const feed = this.#configuration.trustFeed;
    if (!feed) return "disabled";
    this.#usable();
    if (this.#refreshBusy || this.#ownerBusy || this.#busy)
      throw new StoreConflict();
    if (
      this.#state !== "initialized" ||
      !this.#trust ||
      this.#trust.status().entities === 0
    )
      return "not_ready";
    const trust = this.#trust,
      expectedRevision = trust.status().revision;
    this.#refreshBusy = true;
    try {
      const provisioning = await fetchTrustFeed(
        feed,
        /** @type {string} */ (this.#configuration.trustFeedToken),
      );
      this.#usable();
      if (
        this.#state !== "initialized" ||
        this.#ownerBusy ||
        this.#busy ||
        trust !== this.#trust ||
        expectedRevision !== trust.status().revision
      )
        throw new StoreConflict();
      if (!trust.validateRefresh(provisioning)) return "unchanged";
      await this.manage(
        JSON.stringify({
          operation: "refreshTrust",
          requestId: randomUUID(),
          expectedRevision,
          provisioning,
        }),
        "automation:trust-feed",
      );
      return "updated";
    } catch (error) {
      if (error instanceof StoreUnavailable) this.#fail();
      throw error;
    } finally {
      this.#refreshBusy = false;
    }
  }
  #auditState() {
    return {
      state: this.#state,
      trustRevision: this.#trust?.status().revision ?? null,
      authorityRevision: this.#authority?.status().revision ?? null,
    };
  }
  /** Production private-binding administration. Lower-level methods are trusted local adapters.
   * @param {unknown} raw @param {unknown} operator */
  async manage(raw, operator) {
    const command = parseOwnerCommand(raw),
      actor = operatorIdentity({ operator });
    if (command.operation === "status") return this.status();
    this.#usable();
    if (command.operation === "organizationExportBegin")
      return this.beginRecoveryExport(actor);
    if (command.operation === "organizationExportPart")
      return this.recoveryExportPart(
        actor,
        command.exportId,
        command.component,
        command.index,
      );
    if (command.operation === "organizationExportPage")
      return this.recoveryExportPage(actor, command.exportId, {
        section: command.section,
        cursor: command.cursor,
      });
    if (command.operation === "organizationExportClose") {
      this.closeRecoveryExport(actor, command.exportId);
      return { exportId: command.exportId };
    }
    if (
      command.operation === "actionSnapshot" ||
      command.operation === "actionPage"
    ) {
      if (this.#state !== "initialized") throw new StoreUnavailable();
      try {
        if (!this.#ledger?.healthy()) throw new StoreUnavailable();
        return command.operation === "actionSnapshot"
          ? this.#ledger.actionSnapshot(command.cut)
          : this.#ledger.actionPage(command.cut, command.after);
      } catch (error) {
        if (error instanceof StoreUnavailable) this.#fail();
        throw error;
      }
    }
    if (command.operation === "auditExport") {
      const options = auditPageOptions({
        ...(command.after === undefined ? {} : { after: command.after }),
        ...(command.limit === undefined ? {} : { limit: command.limit }),
      });
      if (this.#state === "uninitialized") {
        auditPageOptions(options, 0);
        return {
          records: [],
          next: 0,
          headSequence: 0,
          headChecksum: "0".repeat(64),
        };
      }
      try {
        this.#journal ??= new OwnerJournal(this.#storage);
        return this.#journal.export(options);
      } catch (error) {
        if (error instanceof StoreUnavailable) this.#fail();
        throw error;
      }
    }
    if (this.#ownerBusy || this.#busy) throw new StoreConflict();
    this.#ownerBusy = true;
    try {
      const before = this.#auditState();
      const metadata = {
        operator: actor,
        requestId: command.requestId,
        operation: command.operation,
        commandDigest: createHash("sha256")
          .update(canonicalize(command))
          .digest("hex"),
      };
      let ticket;
      if (this.#state === "uninitialized") {
        if (command.operation !== "initialize") throw new StoreUnavailable();
        const encoded = canonicalize(this.#prepare(command.configuration));
        if (
          Buffer.byteLength(encoded) + Buffer.byteLength(this.#runtime) >
          2097152
        )
          throw new TypeError("service intent too large");
        try {
          this.#storage.transactionSync(() => {
            this.#bootstrap(encoded);
            this.#journal = new OwnerJournal(this.#storage);
            ticket = this.#journal.start(metadata, before);
          });
        } catch {
          // The outer transaction itself may fail before or after its callback.
          // Never leave an apparently resumable live instance after uncertainty.
          this.#fail();
          throw new StoreUnavailable();
        }
      } else {
        this.#journal ??= new OwnerJournal(this.#storage);
        ticket = this.#journal.start(metadata, before);
      }
      const journal = this.#journal;
      if (!journal) throw new StoreUnavailable();
      await journal.sync();
      let result, failure;
      try {
        if (command.operation === "initialize")
          result = await this.initialize(command.configuration);
        else if (command.operation === "refreshTrust")
          result = await this.refreshTrust(command.provisioning, {
            expectedRevision: /** @type {number} */ (command.expectedRevision),
          });
        else
          result = await this.updateAuthority(command.configuration, {
            expectedRevision: /** @type {number} */ (command.expectedRevision),
          });
      } catch (error) {
        failure = error;
      }
      const outcome =
        failure === undefined
          ? "completed"
          : failure instanceof StoreConflict
            ? "conflict"
            : failure instanceof TypeError
              ? "invalid_request"
              : "unavailable";
      journal.finish(ticket, outcome, this.#auditState());
      await journal.sync();
      if (failure !== undefined) throw failure;
      return result;
    } catch (error) {
      if (error instanceof StoreUnavailable) this.#fail();
      throw error;
    } finally {
      this.#ownerBusy = false;
    }
  }
  async ready() {
    if (
      this.#state !== "initialized" ||
      !this.#ledger?.healthy() ||
      this.#trust?.status().state !== "ready" ||
      !this.#authority
    )
      return false;
    const authority = this.#authority,
      revision = authority.revision();
    return (
      (await authority.ready()) &&
      this.#state === "initialized" &&
      this.#ledger.healthy() &&
      this.#trust.status().state === "ready" &&
      authority.revision() === revision
    );
  }
  /** @param {Request} request @param {import('./http.mjs').Lifetime} [lifetime] */
  fetch(request, lifetime) {
    return this.#http(request, lifetime);
  }
  status() {
    return {
      state: this.#state,
      trust: this.#trust?.status() ?? null,
      authority: this.#authority?.status() ?? null,
    };
  }
  close() {
    this.#state = "closed";
    this.#exports?.close();
    this.#trust?.close();
    this.#authority?.close();
    this.#ledger?.close();
    this.#controller = undefined;
  }
}
