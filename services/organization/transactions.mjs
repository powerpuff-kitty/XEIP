/** Shared synchronous durability boundary for organization state. */
import { PolicyDenied } from "./actions.mjs";
import { StoreConflict, StoreUnavailable } from "./errors.mjs";
/** @typedef {{options:import('pg').PoolConfig,connect:()=>Promise<import('pg').PoolClient>}} TransactionPool */
/** @typedef {TransactionPool} Pool */
/** @typedef {import('pg').PoolClient} Client */
/** @param {Pool} pool */
export function boundedPool(pool) {
  for (const value of [
    pool?.options?.connectionTimeoutMillis,
    pool?.options?.query_timeout,
  ]) {
    if (
      !Number.isInteger(value) ||
      value === undefined ||
      value < 100 ||
      value > 10000
    )
      throw new TypeError(
        "bounded database acquisition and query timeouts required (100–10000ms)",
      );
  }
}

/** @template T @param {Pool} pool @param {(client: Client) => Promise<T>} work @param {(result:T)=>Promise<void>} [beforeCommit] @returns {Promise<T>} */
export async function transaction(pool, work, beforeCommit) {
  boundedPool(pool);
  /** @type {Client | undefined} */
  let client;
  let broken = false;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    await client.query(
      "SET LOCAL synchronous_commit = on; SET LOCAL client_min_messages = warning; SET LOCAL statement_timeout = '10s'; SET LOCAL lock_timeout = '3s'; SET LOCAL idle_in_transaction_session_timeout = '30s'",
    );
    const result = await work(client);
    // Even read-only/idempotent results must cover previously observed local WAL.
    await client.query(
      "SELECT pg_catalog.pg_logical_emit_message(true, 'xeip.durability', ''::text, false)",
    );
    if (beforeCommit) await beforeCommit(result);
    let warned = false;
    const notice = () => {
      warned = true;
    };
    client.on("notice", notice);
    try {
      await client.query("COMMIT");
      // A cancelled SyncRep wait can return COMMIT after only local durability.
      if (warned) throw new StoreUnavailable();
    } finally {
      client.removeListener("notice", notice);
    }
    return result;
  } catch (error) {
    const domainError =
      error instanceof PolicyDenied || error instanceof StoreConflict;
    if (client && domainError) {
      try {
        await client.query("ROLLBACK");
      } catch {
        broken = true;
      }
    }
    if (domainError) throw error;
    // A timed-out protocol stream must not be reused or wait on a queued rollback.
    // Destroying the connection aborts any still-open server transaction.
    broken = true;
    // Commit failure may be ambiguous. The caller must resolve it by request ID, never execute.
    throw new StoreUnavailable();
  } finally {
    client?.release(broken);
  }
}
