/** One runtime or owner-maintenance operation per database, on a dedicated session.
 * This does not fence a separately restored database or an unobserved partition. */
import pg from "pg";
class LeaseUnavailable extends Error {
  constructor() {
    super("organization control lease unavailable");
    this.name = "LeaseUnavailable";
  }
}
/** @param {import('pg').ClientConfig} configuration @param {{signal?:AbortSignal}} [options] */
export async function openControlLease(configuration, { signal } = {}) {
  return (await openSession(configuration, signal)).lease;
}
/** Owner transactions run on the connection holding the session lock.
 * @param {import('pg').ClientConfig} configuration @param {{signal?:AbortSignal}} [options] */
export async function openControlMaintenance(configuration, { signal } = {}) {
  const { lease, pool } = await openSession(configuration, signal);
  return Object.freeze({ ...lease, pool });
}
/** @param {import('pg').ClientConfig} configuration @param {AbortSignal} [signal] */
async function openSession(configuration, signal) {
  for (const value of [
    configuration?.connectionTimeoutMillis,
    configuration?.query_timeout,
  ])
    if (
      !Number.isInteger(value) ||
      value === undefined ||
      value < 100 ||
      value > 10000
    )
      throw new LeaseUnavailable();
  if (signal?.aborted) throw new LeaseUnavailable();
  const client = new pg.Client({
    ...configuration,
    password: configuration.password,
    keepAlive: true,
    keepAliveInitialDelayMillis: 1000,
    application_name: "xeip-control-lease",
  });
  const cancellation = new AbortController();
  let borrowed = false;
  /** @type {'opening'|'active'|'closed'|'failed'} */ let state = "opening";
  /** @type {NodeJS.Timeout|undefined} */ let heartbeat;
  /** @type {Promise<void>|undefined} */ let closing;
  /** @type {()=>void} */ let fail;
  const failed = new Promise((resolve) => {
    fail = () => resolve(undefined);
  });
  const disconnect = () => {
    closing ??= (async () => {
      /** @type {NodeJS.Timeout|undefined} */ let deadline;
      try {
        await Promise.race([
          Promise.resolve().then(() => client.end()),
          new Promise((_, reject) => {
            deadline = setTimeout(() => {
              reject(new LeaseUnavailable());
            }, 3000);
          }),
        ]);
      } catch {
        throw new LeaseUnavailable();
      } finally {
        clearTimeout(deadline);
      }
    })();
    // Error/end events cannot create unhandled rejections during asynchronous teardown.
    void closing.catch(() => {});
    return closing;
  };
  const invalidate = () => {
    if (state === "closed" || state === "failed") return;
    state = "failed";
    clearTimeout(heartbeat);
    cancellation.abort();
    signal?.removeEventListener("abort", invalidate);
    fail();
    void disconnect();
  };
  client.on("error", invalidate);
  client.on("end", invalidate);
  signal?.addEventListener("abort", invalidate, { once: true });
  const assertActive = () => {
    if (state !== "active" || cancellation.signal.aborted)
      throw new LeaseUnavailable();
  };
  const checkOpening = () => {
    if (state !== "opening" || signal?.aborted || cancellation.signal.aborted)
      throw new LeaseUnavailable();
  };
  const heartbeatOnce = async () => {
    if (state !== "active") return;
    if (borrowed) {
      schedule();
      return;
    }
    try {
      await client.query("SELECT 1 AS alive");
    } catch {
      invalidate();
    }
    if (state === "active") schedule();
  };
  const schedule = () => {
    heartbeat = setTimeout(() => {
      void heartbeatOnce();
    }, 1000);
    heartbeat.unref();
  };
  const close = () => {
    if (state !== "failed") state = "closed";
    clearTimeout(heartbeat);
    signal?.removeEventListener("abort", invalidate);
    cancellation.abort();
    return disconnect();
  };
  /** @type {import('./transactions.mjs').TransactionPool} */
  const pool = Object.freeze({
    options: Object.freeze({
      connectionTimeoutMillis: configuration.connectionTimeoutMillis,
      query_timeout: configuration.query_timeout,
    }),
    async connect() {
      assertActive();
      if (borrowed) throw new LeaseUnavailable();
      borrowed = true;
      let released = false;
      const check = () => {
        assertActive();
        if (released) throw new LeaseUnavailable();
      };
      /** @param {boolean|Error} [broken] */
      const release = (broken) => {
        if (released) throw new LeaseUnavailable();
        released = true;
        borrowed = false;
        if (broken) invalidate();
      };
      // Bind pg methods to the original Client so its protocol state stays on
      // that one backend. Each borrow has an independent release guard.
      const handle = /** @type {import('pg').PoolClient} */ (
        new Proxy(client, {
          get(target, property) {
            if (property === "release") return release;
            const value = Reflect.get(target, property, target);
            if (typeof value !== "function") return value;
            /** @param {unknown[]} args */
            return (...args) => {
              // Listener cleanup must remain possible after a connection failure.
              if (property !== "removeListener") check();
              const result = Reflect.apply(value, target, args);
              return result === target ? handle : result;
            };
          },
        })
      );
      return handle;
    },
  });
  try {
    // pg can leave connect() pending when end() interrupts authentication.
    // The explicit failure notification must settle acquisition independently.
    await Promise.race([client.connect(), failed]);
    checkOpening();
    const result = await Promise.race([
      client.query("SELECT pg_try_advisory_lock(1480935760,3) AS held"),
      failed,
    ]);
    checkOpening();
    if (!result || result.rows.length !== 1 || result.rows[0].held !== true)
      throw new LeaseUnavailable();
    state = "active";
    schedule();
    const lease = Object.freeze({
      signal: cancellation.signal,
      failed,
      assertActive,
      close,
    });
    return { lease, pool };
  } catch {
    invalidate();
    await disconnect().catch(() => {});
    throw new LeaseUnavailable();
  }
}
