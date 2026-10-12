/** Transactional action ledger. Production callers must supply a live authorization gate. */
import { randomUUID } from "node:crypto";
import { migrations } from "./schema.mjs";
import { boundedPool, transaction } from "./transactions.mjs";
import { canonicalize } from "../../sdks/typescript/dist/identity.js";
import { PolicyDenied, snapshot } from "./actions.mjs";
import { StoreConflict, StoreUnavailable } from "./errors.mjs";
export { StoreConflict, StoreUnavailable } from "./errors.mjs";
/** @typedef {import('pg').Pool} Pool */
/** @typedef {import('pg').PoolClient} Client */
/** @typedef {import('./contracts.js').OrganizationPrincipal} Principal */
/** @typedef {import('./actions.mjs').Proposal} Proposal */
/** @typedef {import('./contracts.js').AuthorizationContext} AuthorizationContext */
/** @typedef {import('./contracts.js').Authorizer} Authorizer */
/** @typedef {{session_id: string, request_id: string, digest: string, canonical: string, expires_at: string, state: import('./contracts.js').ActionState, approver: Principal | null, approval_expires_at: string | null, claim_id: string | null, result_canonical: string | null}} Row */

/** Owner-only migration. Runtime credentials must not have schema/DDL privileges.
 * @param {import('./transactions.mjs').TransactionPool} pool
 */
export async function migrate(pool) {
  return transaction(pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(1480935760, 1)");
    const durability = (
      await client.query(
        "SELECT current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes",
      )
    ).rows[0];
    if (durability.fsync !== "on" || durability.full_page_writes !== "on")
      throw new StoreUnavailable();
    await client.query("CREATE SCHEMA IF NOT EXISTS xeip_org");
    await client.query(
      "CREATE TABLE IF NOT EXISTS xeip_org.migrations (version integer PRIMARY KEY, checksum text NOT NULL, installed_at timestamptz NOT NULL DEFAULT clock_timestamp())",
    );
    const installed = (
      await client.query(
        "SELECT version, checksum FROM xeip_org.migrations ORDER BY version",
      )
    ).rows;
    if (
      installed.length > migrations.length ||
      installed.some(
        (row, i) =>
          row.version !== i + 1 || row.checksum !== migrations[i].checksum,
      )
    )
      throw new StoreUnavailable();
    for (let i = installed.length; i < migrations.length; i++) {
      await client.query(migrations[i].sql);
      await client.query(
        "INSERT INTO xeip_org.migrations(version,checksum) VALUES ($1,$2)",
        [i + 1, migrations[i].checksum],
      );
    }
  });
}
/** @param {Row} row @returns {Proposal} */
const proposalOf = (row) => ({
  action: JSON.parse(row.canonical),
  digest: row.digest,
});
/** @param {Row} row */
const resultOf = (row) => ({
  proposal: proposalOf(row),
  state: row.state,
  claimId: row.claim_id,
  result: row.result_canonical ? JSON.parse(row.result_canonical) : null,
});
/** @param {Principal} principal */
const actorOf = (principal) => ({
  subject: principal.subject,
  entity: principal.entity,
  kid: principal.kid,
});
/** @param {Client} client @param {Row} row @param {string} event @param {object} actor */
async function audit(client, row, event, actor) {
  await client.query(
    "INSERT INTO xeip_org.audit(session_id,request_id,digest,event,actor) VALUES ($1,$2,$3,$4,$5)",
    [row.session_id, row.request_id, row.digest, event, actor],
  );
}

/** @typedef {import('./contracts.js').ActionLedger} ActionLedger */
/** @implements {ActionLedger} */
export class ActionStore {
  #pool;
  #policy;
  #authorize;
  #control;
  /** @param {Pool} pool @param {import('./actions.mjs').ActionPolicy} policy @param {Authorizer} authorize @param {import('./contracts.js').ActionControlFence} [control] */
  constructor(pool, policy, authorize, control) {
    boundedPool(pool);
    if (typeof authorize !== "function")
      throw new TypeError("live authorizer required");
    this.#pool = pool;
    this.#policy = policy;
    if (
      control !== undefined &&
      (typeof control.current !== "function" ||
        typeof control.lock !== "function")
    )
      throw new TypeError("invalid control fence");
    this.#authorize = authorize;
    this.#control = control;
  }
  /** @param {Principal} principal @param {AuthorizationContext} context */
  async #allowed(principal, context) {
    if (!Object.isFrozen(principal) || !Object.isFrozen(principal.roles))
      throw new PolicyDenied();
    let timer;
    try {
      const result = await Promise.race([
        this.#authorize(principal, context),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new StoreUnavailable()), 10000);
          timer.unref();
        }),
      ]);
      if (result !== true) throw new PolicyDenied();
    } finally {
      clearTimeout(timer);
    }
  }
  /** Guard client operations after all mutation/audit waits, before initiating COMMIT.
   * Internal finish intentionally uses transaction() directly: an attempted effect must
   * still be recorded after the caller disconnects or its authorization expires.
   * @template {{proposal:Proposal,approver?:Principal|null}} T
   * @param {Principal} principal @param {string} phase @param {(client:Client)=>Promise<T>} work
   */
  async #authorizedTransaction(principal, phase, work) {
    const control = this.#control;
    if (control && !control.current()) throw new StoreUnavailable();
    return transaction(
      this.#pool,
      async (client) => {
        // All authorizing operations use control-head -> action-row lock order.
        if (control) await control.lock(client);
        return work(client);
      },
      async (result) => {
        await this.#allowed(principal, {
          phase,
          proposal: result.proposal,
          ...(result.approver ? { approver: result.approver } : {}),
        });
        if (control && !control.current()) throw new StoreUnavailable();
        const eligible =
          phase === "inspect"
            ? this.#policy.canInspect(principal, result.proposal)
            : phase === "propose"
              ? this.#policy.canExecute(principal, result.proposal)
              : this.#eligible(principal, result.proposal, phase);
        if (
          !eligible ||
          (phase === "claim" &&
            (!result.approver ||
              !this.#policy.canApprove(result.approver, result.proposal)))
        )
          throw new PolicyDenied();
      },
    );
  }
  /** @param {Client} client @param {string} session @param {string} id @param {string | undefined} digest @param {boolean} [lock] @returns {Promise<Row>} */
  async #lock(client, session, id, digest, lock = true) {
    if (
      typeof session !== "string" ||
      session.length > 128 ||
      typeof id !== "string" ||
      id.length > 128 ||
      (digest !== undefined &&
        (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)))
    )
      throw new StoreConflict();
    const row = (
      await client.query(
        "SELECT * FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2" +
          (lock ? " FOR UPDATE" : ""),
        [session, id],
      )
    ).rows[0];
    if (!row || (digest !== undefined && row.digest !== digest))
      throw new StoreConflict();
    return row;
  }
  /** @param {Principal} principal @param {Proposal} proposal @param {string} phase */
  #eligible(principal, proposal, phase) {
    return phase === "decide"
      ? this.#policy.canApprove(principal, proposal)
      : phase === "claim"
        ? this.#policy.canExecute(principal, proposal)
        : this.#policy.canExecute(principal, proposal) ||
          this.#policy.canApprove(principal, proposal);
  }
  /** @param {Client} client @param {Principal} principal @param {string} session @param {string} id @param {string} digest @param {string} phase */
  async #prepare(client, principal, session, id, digest, phase) {
    if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest))
      throw new StoreConflict();
    const candidate = await this.#lock(client, session, id, digest, false);
    if (!this.#eligible(principal, proposalOf(candidate), phase))
      throw new PolicyDenied();
    const row = await this.#lock(client, session, id, digest);
    if (!this.#eligible(principal, proposalOf(row), phase))
      throw new PolicyDenied();
    return row;
  }
  /** Authorized read-only resolution of ambiguous commits; never returns an execution capability.
   * @param {Principal} principal @param {string} session @param {string} id
   */
  async inspect(principal, session, id) {
    return this.#authorizedTransaction(principal, "inspect", async (client) => {
      const candidate = await this.#lock(client, session, id, undefined, false);
      if (!this.#policy.canInspect(principal, proposalOf(candidate)))
        throw new PolicyDenied();
      await this.#allowed(principal, {
        phase: "inspect",
        proposal: proposalOf(candidate),
      });
      const row = await this.#lock(client, session, id, undefined, false);
      if (!this.#policy.canInspect(principal, proposalOf(row)))
        throw new PolicyDenied();
      return {
        proposal: proposalOf(row),
        state: row.state,
        result: row.result_canonical ? JSON.parse(row.result_canonical) : null,
      };
    });
  }
  /** @param {Principal} principal @param {import('./actions.mjs').ActionRequest} request */
  async propose(principal, request) {
    const proposal = this.#policy.propose(principal, request);
    return this.#authorizedTransaction(principal, "propose", async (client) => {
      await this.#allowed(principal, { phase: "propose", proposal });
      if (!this.#policy.canExecute(principal, proposal))
        throw new PolicyDenied();
      const a = proposal.action;
      const inserted = (
        await client.query(
          "INSERT INTO xeip_org.actions(session_id,request_id,digest,canonical,expires_at,state) VALUES ($1,$2,$3,$4,$5,'pending') ON CONFLICT DO NOTHING RETURNING *",
          [a.session, a.id, proposal.digest, canonicalize(a), a.expiresAt],
        )
      ).rows[0];
      const row =
        inserted ??
        (await this.#lock(client, a.session, a.id, proposal.digest));
      if (inserted) await audit(client, row, "proposed", actorOf(principal));
      return resultOf(row);
    });
  }
  /** @param {Principal} principal @param {string} session @param {string} id @param {string} digest @param {'approve'|'reject'} decision */
  async decide(principal, session, id, digest, decision) {
    if (!["approve", "reject"].includes(decision)) throw new StoreConflict();
    return this.#authorizedTransaction(principal, "decide", async (client) => {
      const row = await this.#prepare(
          client,
          principal,
          session,
          id,
          digest,
          "decide",
        ),
        proposal = proposalOf(row);
      await this.#allowed(principal, { phase: "decide", proposal });
      if (!this.#policy.canApprove(principal, proposal))
        throw new PolicyDenied();
      const state = decision === "approve" ? "approved" : "rejected";
      if (row.state !== "pending") throw new StoreConflict();
      const approver = {
        ...actorOf(principal),
        clientId: principal.clientId,
        roles: ["approver"],
        expiresAt: Math.min(principal.expiresAt, proposal.action.expiresAt),
      };
      const updated = (
        await client.query(
          "UPDATE xeip_org.actions SET state=$3,approver=$4,approval_expires_at=$5,updated_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2 AND expires_at > floor(extract(epoch from clock_timestamp())) RETURNING *",
          [session, id, state, approver, approver.expiresAt],
        )
      ).rows[0];
      if (!updated) throw new PolicyDenied();
      await audit(client, updated, state, actorOf(principal));
      return resultOf(updated);
    });
  }
  /** @param {Principal} principal @param {string} session @param {string} id @param {string} digest */
  async revoke(principal, session, id, digest) {
    return this.#authorizedTransaction(principal, "revoke", async (client) => {
      const row = await this.#prepare(
          client,
          principal,
          session,
          id,
          digest,
          "revoke",
        ),
        proposal = proposalOf(row);
      await this.#allowed(principal, { phase: "revoke", proposal });
      if (
        !this.#policy.canExecute(principal, proposal) &&
        !this.#policy.canApprove(principal, proposal)
      )
        throw new PolicyDenied();
      if (!["pending", "approved"].includes(row.state))
        throw new StoreConflict();
      const updated = (
        await client.query(
          "UPDATE xeip_org.actions SET state='revoked',updated_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2 RETURNING *",
          [session, id],
        )
      ).rows[0];
      await audit(client, updated, "revoked", actorOf(principal));
      return resultOf(updated);
    });
  }
  /** Caller must recheck identity/trust immediately before upstream I/O after claiming.
   * @param {Principal} principal @param {string} session @param {string} id @param {string} digest
   */
  async claim(principal, session, id, digest) {
    return this.#authorizedTransaction(principal, "claim", async (client) => {
      const row = await this.#prepare(
          client,
          principal,
          session,
          id,
          digest,
          "claim",
        ),
        proposal = proposalOf(row);
      await this.#allowed(principal, {
        phase: "claim",
        proposal,
        ...(row.approver ? { approver: row.approver } : {}),
      });
      if (!this.#policy.canExecute(principal, proposal))
        throw new PolicyDenied();
      if (row.state !== "approved") throw new StoreConflict();
      if (!row.approver || !this.#policy.canApprove(row.approver, proposal))
        throw new PolicyDenied();
      const updated = (
        await client.query(
          "UPDATE xeip_org.actions SET state='executing',claim_id=$3,updated_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2 AND expires_at > floor(extract(epoch from clock_timestamp())) AND approval_expires_at > floor(extract(epoch from clock_timestamp())) RETURNING *",
          [session, id, randomUUID()],
        )
      ).rows[0];
      if (!updated) throw new PolicyDenied();
      await audit(client, updated, "claimed", actorOf(principal));
      return { ...resultOf(updated), approver: row.approver };
    });
  }
  /** Internal worker capability; never expose claim IDs as authority to a public endpoint.
   * @param {string} session @param {string} id @param {string} claimId @param {'succeeded'|'failed'|'indeterminate'} outcome @param {import('./types.js').Json} [result]
   */
  async finish(session, id, claimId, outcome, result = null) {
    if (
      !["succeeded", "failed", "indeterminate"].includes(outcome) ||
      typeof claimId !== "string" ||
      !/^[0-9a-f-]{36}$/.test(claimId)
    )
      throw new StoreConflict();
    let encoded;
    try {
      encoded = result === null ? null : canonicalize(snapshot(result, 131072));
      if (outcome === "indeterminate" && encoded !== null) throw new Error();
    } catch {
      throw new StoreConflict();
    }
    return transaction(this.#pool, async (client) => {
      const row = (
        await client.query(
          "SELECT * FROM xeip_org.actions WHERE session_id=$1 AND request_id=$2 FOR UPDATE",
          [session, id],
        )
      ).rows[0];
      if (!row || row.claim_id !== claimId) throw new StoreConflict();
      if (row.state === outcome) {
        if (row.result_canonical !== encoded) throw new StoreConflict();
        return resultOf(row);
      }
      if (row.state !== "executing") throw new StoreConflict();
      const updated = (
        await client.query(
          "UPDATE xeip_org.actions SET state=$3,result_canonical=$4,updated_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2 RETURNING *",
          [session, id, outcome, encoded],
        )
      ).rows[0];
      await audit(client, updated, outcome, { worker: "execution", claimId });
      return resultOf(updated);
    });
  }
}
