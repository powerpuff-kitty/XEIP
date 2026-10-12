/** Experimental Durable Object ledger; no network ingress or provider authority. */
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { PolicyDenied, snapshot } from "../actions.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { ActionRecovery } from "./action-recovery.mjs";
import { initializeLedger } from "./schema.mjs";
import {
  validateActionHistory,
  validateActionRow,
} from "./action-integrity.mjs";
import {
  actionCursor,
  actionSnapshotHasher,
  projectAction,
  validateActionPage,
} from "./action-export.mjs";
/** @typedef {import('../contracts.js').OrganizationPrincipal} Principal */
/** @typedef {import('../contracts.js').Proposal} Proposal */
/** @typedef {import('../contracts.js').ActionLedger} ActionLedger */
/** @typedef {import('./contracts.js').SqlValue} SqlValue */
/** @typedef {{session_id:string,request_id:string,digest:string,canonical:string,expires_at:number,state:import('../contracts.js').ActionState,version:number,approver:string|null,approval_expires_at:number|null,claim_id:string|null,result_canonical:string|null}} Row */
/** @typedef {{revision:string,principal:Principal,phase:string,proposal:Proposal,approver?:Principal,guard?:import('../contracts.js').Authorizer}} Ticket */
const now = () => Math.floor(Date.now() / 1000);
/** @param {unknown} value */
const id = (value) =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
/** @param {unknown} value */
const digest = (value) =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
/** @param {Principal} principal */
const actor = (principal) => ({
  subject: principal.subject,
  entity: principal.entity,
  kid: principal.kid,
});
/** @param {Row} row @returns {Proposal} */
const proposalOf = (row) =>
  Object.freeze({
    action: /** @type {import('../contracts.js').Action} */ (
      /** @type {unknown} */ (snapshot(JSON.parse(row.canonical), 69632))
    ),
    digest: row.digest,
  });
/** @param {Row} row @returns {import('../contracts.js').ActionRecord} */
const resultOf = (row) => ({
  proposal: proposalOf(row),
  state: row.state,
  claimId: row.claim_id,
  result:
    row.result_canonical === null
      ? null
      : snapshot(JSON.parse(row.result_canonical), 131072),
});
/** @param {Row} row @returns {Principal|undefined} */
const approverOf = (row) =>
  row.approver === null
    ? undefined
    : /** @type {Principal} */ (
        /** @type {unknown} */ (snapshot(JSON.parse(row.approver), 4096))
      );

/** One shared adapter per live object. A storage fault requires a fresh runtime instance.
 * @implements {ActionLedger}
 */
export class DurableActionStore {
  #storage;
  #organization;
  #authority;
  #maximum;
  #timeout;
  #failed = false;
  /** @type {ActionRecovery|undefined} */ #recovery;
  /** @param {import('./contracts.js').LedgerStorage} storage @param {import('./contracts.js').LocalAuthority} authority
   * @param {{organization:string,maxActions?:number,timeoutMs?:number,recovery?:import("./action-recovery.mjs").Settings}} options
   */
  constructor(
    storage,
    authority,
    { organization, maxActions = 10000, timeoutMs = 10000, recovery },
  ) {
    if (
      !authority ||
      ["revision", "policy", "allows", "authorize"].some(
        (name) =>
          typeof authority[/** @type {keyof typeof authority} */ (name)] !==
          "function",
      ) ||
      !Number.isInteger(maxActions) ||
      maxActions < 1 ||
      maxActions > 10000 ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 10000
    )
      throw new TypeError("invalid durable ledger configuration");
    initializeLedger(storage, organization);
    this.#storage = storage;
    this.#organization = organization;
    this.#authority = authority;
    this.#maximum = maxActions;
    this.#timeout = timeoutMs;
    this.#reconcile();
    if (recovery)
      this.#recovery = new ActionRecovery(storage, organization, recovery, {
        cut: () => this.#recoveryCut(),
        record: (sequence) => this.#recoveryRecord(sequence),
      });
    else if (this.#sql("SELECT 1 FROM xeip_action_recovery LIMIT 1").length)
      throw new StoreUnavailable();
  }
  /** @param {import('./contracts.js').LedgerStorage} storage @param {import('./contracts.js').LocalAuthority} authority
   * @param {{organization:string,maxActions?:number,timeoutMs?:number,recovery?:import('./action-recovery.mjs').Settings}} options */
  static async open(storage, authority, options) {
    const store = new DurableActionStore(storage, authority, options);
    try {
      await store.#recovery?.open();
      return store;
    } catch {
      store.close();
      throw new StoreUnavailable();
    }
  }
  close() {
    this.#failed = true;
    this.#recovery?.close();
  }
  #recoveryCut() {
    const row = this.#sql(
      "SELECT COALESCE(MAX(sequence),0) AS cut,COUNT(*) AS n FROM xeip_audit",
    )[0];
    if (row.cut !== row.n || typeof row.cut !== "number")
      throw new StoreUnavailable();
    return row.cut;
  }
  /** @param {number} sequence */
  #recoveryRecord(sequence) {
    const key = this.#sql(
      "SELECT session_id,request_id FROM xeip_audit WHERE sequence=?",
      sequence,
    )[0];
    if (!key) throw new StoreUnavailable();
    return this.#evidence(
      String(key.session_id),
      String(key.request_id),
      sequence,
    );
  }
  /** @template T @param {()=>Promise<T>} callback @param {boolean} [wait] @returns {Promise<T>} */
  #run(callback, wait = false) {
    if (this.#failed) return Promise.reject(new StoreUnavailable());
    return this.#recovery ? this.#recovery.run(callback, wait) : callback();
  }

  /** Preserve issued claims through unrelated admission without weakening the final guard.
   * @param {()=>Promise<boolean>} authorize */
  async authorizeEffect(authorize) {
    try {
      return await this.#run(async () => {
        if (!(await authorize()) || this.#failed) return false;
        if (this.#recovery) await this.#sync();
        return !this.#failed;
      }, true);
    } catch {
      return false;
    }
  }

  /** No awaits: scan one consistent object-local view without retaining payload pages. */
  #reconcile() {
    try {
      if (
        this.#sql(
          "SELECT 1 FROM xeip_audit e LEFT JOIN xeip_actions a ON a.session_id=e.session_id AND a.request_id=e.request_id WHERE a.request_id IS NULL LIMIT 1",
        ).length
      )
        throw Error();
      let session = "",
        request = "",
        count = 0;
      for (;;) {
        const keys = this.#sql(
          "SELECT session_id,request_id FROM xeip_actions WHERE (session_id,request_id)>(?,?) ORDER BY session_id,request_id LIMIT 128",
          session,
          request,
        );
        if (!keys.length) break;
        for (const key of keys) {
          if (
            typeof key.session_id !== "string" ||
            typeof key.request_id !== "string" ||
            ++count > 10000
          )
            throw Error();
          this.#row(key.session_id, key.request_id);
          session = key.session_id;
          request = key.request_id;
        }
      }
      if (
        count !==
        this.#sql("SELECT action_count FROM xeip_metadata WHERE singleton=1")[0]
          ?.action_count
      )
        throw Error();
    } catch {
      this.#failed = true;
      throw new StoreUnavailable();
    }
  }
  /** @param {unknown} cut @returns {number} */
  #cut(cut) {
    actionCursor(cut);
    if (
      cut !== 0 &&
      !this.#sql("SELECT 1 FROM xeip_audit WHERE sequence=?", cut).length
    ) {
      // A missing caller cut is retryable only when stored history is intact.
      // In particular, a deleted tail must not bypass row/history validation.
      this.#reconcile();
      throw new StoreConflict();
    }
    return cut;
  }
  /** Private evidence capture; never returned by the per-request ActionLedger facade.
   * @param {unknown} [requestedCut] */
  actionSnapshot(requestedCut) {
    this.#recovery?.assertReady();
    if (requestedCut !== undefined) actionCursor(requestedCut);
    return this.#transaction(() => {
      this.#reconcile();
      const cut = this.#cut(
        requestedCut ??
          this.#sql(
            "SELECT COALESCE(MAX(sequence),0) AS head FROM xeip_audit",
          )[0].head,
      );
      const actions = Number(
        this.#sql(
          "SELECT COUNT(*) AS n FROM xeip_audit WHERE event='proposed' AND sequence<=?",
          cut,
        )[0].n,
      );
      const header = {
        schema: "xeip.action-snapshot/1",
        organization: this.#organization,
        cut,
        actions,
      };
      const hasher = actionSnapshotHasher(header);
      let after = 0,
        count = 0;
      for (;;) {
        const keys = this.#sql(
          "SELECT sequence,session_id,request_id FROM xeip_audit WHERE event='proposed' AND sequence>? AND sequence<=? ORDER BY sequence LIMIT 128",
          after,
          cut,
        );
        if (!keys.length) break;
        for (const key of keys) {
          const record = this.#evidence(
            String(key.session_id),
            String(key.request_id),
            cut,
          );
          hasher.update(canonicalize(record) + "\n");
          after = Number(key.sequence);
          if (++count > 10000) throw new StoreUnavailable();
        }
      }
      if (count !== actions) throw new StoreUnavailable();
      return { ...header, digest: hasher.digest("hex") };
    });
  }
  /** @param {string} session @param {string} request @param {number} cut */
  #evidence(session, request, cut) {
    const row = this.#row(session, request);
    return projectAction(
      row,
      this.#sql(
        "SELECT * FROM xeip_audit WHERE session_id=? AND request_id=? ORDER BY sequence LIMIT 5",
        session,
        request,
      ),
      cut,
    );
  }
  /** @param {unknown} requestedCut @param {unknown} [requestedAfter] */
  actionPage(requestedCut, requestedAfter = 0) {
    this.#recovery?.assertReady();
    actionCursor(requestedCut);
    actionCursor(requestedAfter);
    return this.#transaction(() => {
      const cut = this.#cut(requestedCut),
        after = requestedAfter;
      if (
        after > cut ||
        (after !== 0 &&
          !this.#sql(
            "SELECT 1 FROM xeip_audit WHERE sequence=? AND event='proposed'",
            after,
          ).length)
      )
        throw new StoreConflict();
      const key = this.#sql(
        "SELECT sequence,session_id,request_id FROM xeip_audit WHERE event='proposed' AND sequence>? AND sequence<=? ORDER BY sequence LIMIT 1",
        after,
        cut,
      )[0];
      const page = {
        cut,
        after,
        next: key ? Number(key.sequence) : after,
        record: key
          ? this.#evidence(String(key.session_id), String(key.request_id), cut)
          : null,
      };
      return validateActionPage(page, { cut, after });
    });
  }
  /** Local quarantine status for service readiness; does not authorize or mutate work. */
  healthy() {
    return !this.#failed && (!this.#recovery || this.#recovery.healthy());
  }
  /** Narrow one request without creating a new storage/fault owner.
   * @param {import('../contracts.js').Authorizer} guard @returns {ActionLedger}
   */
  withAuthorization(guard) {
    if (typeof guard !== "function")
      throw new TypeError("request guard required");
    return Object.freeze({
      inspect: (principal, session, id) =>
        this.inspect(principal, session, id, guard),
      propose: (principal, request) => this.propose(principal, request, guard),
      decide: (principal, session, id, digest, decision) =>
        this.decide(principal, session, id, digest, decision, guard),
      revoke: (principal, session, id, digest) =>
        this.revoke(principal, session, id, digest, guard),
      claim: (principal, session, id, digest) =>
        this.claim(principal, session, id, digest, guard),
      finish: (session, id, claimId, outcome, result) =>
        this.finish(session, id, claimId, outcome, result),
    });
  }
  /** @param {string} query @param {...SqlValue} values */
  #sql(query, ...values) {
    if (this.#failed) throw new StoreUnavailable();
    try {
      return this.#storage.sql.exec(query, ...values).toArray();
    } catch {
      this.#failed = true;
      throw new StoreUnavailable();
    }
  }
  /** @template T @param {()=>T} callback @returns {T} */
  #transaction(callback) {
    if (this.#failed) throw new StoreUnavailable();
    try {
      return this.#storage.transactionSync(callback);
    } catch (error) {
      if (error instanceof PolicyDenied || error instanceof StoreConflict)
        throw error;
      this.#failed = true;
      throw new StoreUnavailable();
    }
  }
  /** @template T @param {Promise<T>} work @returns {Promise<T>} */
  async #bounded(work) {
    let timer;
    try {
      return await Promise.race([
        work,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new StoreUnavailable()),
            this.#timeout,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  async #sync() {
    if (this.#failed) throw new StoreUnavailable();
    try {
      await this.#bounded(this.#storage.sync());
      await this.#recovery?.confirm();
    } catch {
      this.#failed = true;
      throw new StoreUnavailable();
    }
    if (this.#failed) throw new StoreUnavailable();
  }
  #revision() {
    if (this.#failed) throw new StoreUnavailable();
    const value = this.#authority.revision();
    if (typeof value !== "string" || value.length < 1 || value.length > 256)
      throw new StoreUnavailable();
    return value;
  }
  /** @param {Ticket} ticket */
  #check(ticket) {
    const { principal, proposal, phase, approver } = ticket;
    if (
      ticket.revision !== this.#revision() ||
      !this.#authority.allows(principal) ||
      (approver && !this.#authority.allows(approver))
    )
      throw new PolicyDenied();
    const policy = this.#authority.policy();
    const eligible =
      phase === "inspect"
        ? policy.canInspect(principal, proposal)
        : phase === "propose" || phase === "claim"
          ? policy.canExecute(principal, proposal)
          : phase === "decide"
            ? policy.canApprove(principal, proposal)
            : policy.canExecute(principal, proposal) ||
              policy.canApprove(principal, proposal);
    if (
      !eligible ||
      (phase === "claim" &&
        (!approver || !policy.canApprove(approver, proposal)))
    )
      throw new PolicyDenied();
  }
  /** @param {Principal} principal @param {Proposal} proposal @param {string} phase @param {Principal} [approver] @param {import('../contracts.js').Authorizer} [guard] @returns {Ticket} */
  #ticket(principal, proposal, phase, approver, guard) {
    if (!Object.isFrozen(principal) || !Object.isFrozen(principal?.roles))
      throw new PolicyDenied();
    const ticket = {
      revision: this.#revision(),
      principal,
      proposal,
      phase,
      ...(guard ? { guard } : {}),
      ...(approver ? { approver } : {}),
    };
    this.#check(ticket);
    return ticket;
  }
  /** @param {Ticket} ticket */
  async #authorize(ticket) {
    let allowed;
    try {
      allowed = await this.#bounded(
        Promise.resolve().then(async () => {
          const context = {
            phase: ticket.phase,
            proposal: ticket.proposal,
            ...(ticket.approver ? { approver: ticket.approver } : {}),
          };
          return (
            (await this.#authority.authorize(ticket.principal, context)) &&
            (!ticket.guard || (await ticket.guard(ticket.principal, context)))
          );
        }),
      );
    } catch (error) {
      if (error instanceof PolicyDenied) throw error;
      throw new StoreUnavailable();
    }
    if (allowed !== true) throw new PolicyDenied();
    this.#check(ticket);
  }
  /** @param {string} session @param {string} requestId @param {string} [expectedDigest] @param {boolean} [history] @returns {Row} */
  #row(session, requestId, expectedDigest, history = true) {
    if (
      !id(session) ||
      !id(requestId) ||
      (expectedDigest !== undefined && !digest(expectedDigest))
    )
      throw new StoreConflict();
    const row = /** @type {Row|undefined} */ (
      /** @type {unknown} */ (
        this.#sql(
          "SELECT * FROM xeip_actions WHERE session_id=? AND request_id=?",
          session,
          requestId,
        )[0]
      )
    );
    if (!row) throw new StoreConflict();
    // Treat persisted data as an integrity boundary, including internal finish.
    // JSON policy validation alone cannot bind its identity to the SQL row key.
    try {
      if (row.session_id !== session || row.request_id !== requestId)
        throw Error();
      validateActionRow(row);
    } catch {
      this.#failed = true;
      throw new StoreUnavailable();
    }
    if (history) this.#history(row);
    if (expectedDigest !== undefined && row.digest !== expectedDigest)
      throw new StoreConflict();
    return row;
  }
  /** @param {Row} row */
  #history(row) {
    try {
      validateActionHistory(
        row,
        this.#sql(
          "SELECT * FROM xeip_audit WHERE session_id=? AND request_id=? ORDER BY sequence LIMIT 5",
          row.session_id,
          row.request_id,
        ),
      );
    } catch {
      this.#failed = true;
      throw new StoreUnavailable();
    }
  }
  /** @param {Row} row @param {string} event @param {object} actor */
  #audit(row, event, actor) {
    this.#sql(
      "INSERT INTO xeip_audit(session_id,request_id,digest,event,actor,occurred_at) VALUES (?,?,?,?,?,?)",
      row.session_id,
      row.request_id,
      row.digest,
      event,
      canonicalize(actor),
      now(),
    );
    this.#history(row);
  }
  /** @template T @param {T} result @param {Ticket} ticket @returns {Promise<T>} */
  async #confirmed(result, ticket) {
    await this.#sync();
    this.#check(ticket);
    return result;
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {import('../contracts.js').Authorizer} [guard] */
  inspect(principal, session, requestId, guard) {
    return this.#run(() => this.#inspect(principal, session, requestId, guard));
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {import('../contracts.js').Authorizer} [guard] */
  async #inspect(principal, session, requestId, guard) {
    const row = this.#row(session, requestId),
      ticket = this.#ticket(
        principal,
        proposalOf(row),
        "inspect",
        undefined,
        guard,
      );
    await this.#authorize(ticket);
    const result = this.#transaction(() => {
      this.#check(ticket);
      const current = this.#row(session, requestId, row.digest);
      if (current.version !== row.version) throw new StoreConflict();
      const { claimId, ...publicResult } = resultOf(current);
      return publicResult;
    });
    return this.#confirmed(result, ticket);
  }
  /** @param {Principal} principal @param {import('../contracts.js').ActionRequest} request @param {import('../contracts.js').Authorizer} [guard] */
  propose(principal, request, guard) {
    return this.#run(() => this.#propose(principal, request, guard));
  }
  /** @param {Principal} principal @param {import('../contracts.js').ActionRequest} request @param {import('../contracts.js').Authorizer} [guard] */
  async #propose(principal, request, guard) {
    const proposal = this.#authority.policy().propose(principal, request),
      ticket = this.#ticket(principal, proposal, "propose", undefined, guard);
    await this.#authorize(ticket);
    const result = this.#transaction(() => {
      this.#check(ticket);
      const a = proposal.action;
      const existing = this.#sql(
        "SELECT digest FROM xeip_actions WHERE session_id=? AND request_id=?",
        a.session,
        a.id,
      )[0];
      if (existing) {
        return resultOf(this.#row(a.session, a.id, proposal.digest));
      }
      const count = this.#sql(
        "SELECT action_count FROM xeip_metadata WHERE singleton=1",
      )[0]?.action_count;
      if (typeof count !== "number") throw new StoreUnavailable();
      if (count >= this.#maximum) throw new StoreConflict();
      this.#sql(
        "INSERT INTO xeip_actions(session_id,request_id,digest,canonical,expires_at,state) VALUES (?,?,?,?,?,'pending')",
        a.session,
        a.id,
        proposal.digest,
        canonicalize(a),
        a.expiresAt,
      );
      const row = this.#row(a.session, a.id, proposal.digest, false);
      this.#audit(row, "proposed", actor(principal));
      this.#check(ticket);
      return resultOf(row);
    });
    return this.#confirmed(result, ticket);
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {'approve'|'reject'} decision @param {import('../contracts.js').Authorizer} [guard] */
  decide(principal, session, requestId, expectedDigest, decision, guard) {
    return this.#run(() =>
      this.#decide(
        principal,
        session,
        requestId,
        expectedDigest,
        decision,
        guard,
      ),
    );
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {'approve'|'reject'} decision @param {import('../contracts.js').Authorizer} [guard] */
  async #decide(
    principal,
    session,
    requestId,
    expectedDigest,
    decision,
    guard,
  ) {
    if (!["approve", "reject"].includes(decision)) throw new StoreConflict();
    return this.#change(
      principal,
      session,
      requestId,
      expectedDigest,
      "decide",
      decision,
      guard,
    );
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {import('../contracts.js').Authorizer} [guard] */
  revoke(principal, session, requestId, expectedDigest, guard) {
    return this.#run(() =>
      this.#revoke(principal, session, requestId, expectedDigest, guard),
    );
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {import('../contracts.js').Authorizer} [guard] */
  async #revoke(principal, session, requestId, expectedDigest, guard) {
    return this.#change(
      principal,
      session,
      requestId,
      expectedDigest,
      "revoke",
      undefined,
      guard,
    );
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {import('../contracts.js').Authorizer} [guard] */
  claim(principal, session, requestId, expectedDigest, guard) {
    return this.#run(() =>
      this.#claim(principal, session, requestId, expectedDigest, guard),
    );
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {import('../contracts.js').Authorizer} [guard] */
  async #claim(principal, session, requestId, expectedDigest, guard) {
    const result = await this.#change(
      principal,
      session,
      requestId,
      expectedDigest,
      "claim",
      undefined,
      guard,
    );
    return /** @type {import('../contracts.js').ExecutionClaim} */ (result);
  }
  /** @param {Principal} principal @param {string} session @param {string} requestId @param {string} expectedDigest @param {'decide'|'revoke'|'claim'} phase @param {'approve'|'reject'} [decision] @param {import('../contracts.js').Authorizer} [guard] */
  async #change(
    principal,
    session,
    requestId,
    expectedDigest,
    phase,
    decision,
    guard,
  ) {
    if (!digest(expectedDigest)) throw new StoreConflict();
    const original = this.#row(session, requestId, expectedDigest),
      approver = phase === "claim" ? approverOf(original) : undefined;
    const ticket = this.#ticket(
      principal,
      proposalOf(original),
      phase,
      approver,
      guard,
    );
    await this.#authorize(ticket);
    const result = this.#transaction(() => {
      this.#check(ticket);
      const row = this.#row(session, requestId, expectedDigest);
      if (row.version !== original.version) throw new StoreConflict();
      let event;
      if (phase === "decide") {
        if (row.state !== "pending") throw new StoreConflict();
        const grant = {
          ...actor(principal),
          clientId: principal.clientId,
          roles: ["approver"],
          expiresAt: Math.min(principal.expiresAt, row.expires_at),
        };
        event = decision === "approve" ? "approved" : "rejected";
        this.#sql(
          "UPDATE xeip_actions SET state=?,version=version+1,approver=?,approval_expires_at=? WHERE session_id=? AND request_id=?",
          event,
          canonicalize(grant),
          grant.expiresAt,
          session,
          requestId,
        );
      } else if (phase === "revoke") {
        if (!["pending", "approved"].includes(row.state))
          throw new StoreConflict();
        event = "revoked";
        this.#sql(
          "UPDATE xeip_actions SET state='revoked',version=version+1 WHERE session_id=? AND request_id=?",
          session,
          requestId,
        );
      } else {
        if (row.state !== "approved" || !approver) throw new StoreConflict();
        event = "claimed";
        this.#sql(
          "UPDATE xeip_actions SET state='executing',version=version+1,claim_id=? WHERE session_id=? AND request_id=?",
          crypto.randomUUID(),
          session,
          requestId,
        );
      }
      const updated = this.#row(session, requestId, expectedDigest, false);
      this.#audit(updated, event, actor(principal));
      this.#check(ticket);
      return {
        ...resultOf(updated),
        ...(phase === "claim" ? { approver } : {}),
      };
    });
    return this.#confirmed(result, ticket);
  }
  /** Internal completion does not require the caller's still-live credentials.
   * @param {string} session @param {string} requestId @param {string} claimId @param {import('../contracts.js').ActionOutcome} outcome @param {import('../types.js').Json} [result]
   */
  finish(session, requestId, claimId, outcome, result = null) {
    return this.#run(
      () => this.#finish(session, requestId, claimId, outcome, result),
      true,
    );
  }
  /** Internal completion does not require the caller's still-live credentials.
   * @param {string} session @param {string} requestId @param {string} claimId @param {import('../contracts.js').ActionOutcome} outcome @param {import('../types.js').Json} [result]
   */
  async #finish(session, requestId, claimId, outcome, result = null) {
    if (
      !id(session) ||
      !id(requestId) ||
      typeof claimId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
        claimId,
      ) ||
      !["succeeded", "failed", "indeterminate"].includes(outcome)
    )
      throw new StoreConflict();
    let encoded;
    try {
      encoded = result === null ? null : canonicalize(snapshot(result, 131072));
      if (outcome === "indeterminate" && encoded !== null) throw Error();
    } catch {
      throw new StoreConflict();
    }
    const recorded = this.#transaction(() => {
      const row = this.#row(session, requestId);
      if (row.claim_id !== claimId) throw new StoreConflict();
      if (row.state === outcome) {
        if (row.result_canonical !== encoded) throw new StoreConflict();
        return resultOf(row);
      }
      if (row.state !== "executing") throw new StoreConflict();
      this.#sql(
        "UPDATE xeip_actions SET state=?,version=version+1,result_canonical=? WHERE session_id=? AND request_id=?",
        outcome,
        encoded,
        session,
        requestId,
      );
      const updated = this.#row(session, requestId, undefined, false);
      this.#audit(updated, outcome, { worker: "execution", claimId });
      return resultOf(updated);
    });
    await this.#sync();
    return recorded;
  }
}
