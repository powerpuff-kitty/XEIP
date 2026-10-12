// Dedicated-session ownership against actual PostgreSQL; no operator resources.
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { withPostgres } from "./postgres.mjs";
import { grantRuntime } from "../services/organization/database.mjs";
import { openControlLease } from "../services/organization/control-lease.mjs";
import { openControlMaintenance } from "../services/organization/control-lease.mjs";
import { maintainDatabase } from "../services/organization/maintenance.mjs";
import { transaction } from "../services/organization/transactions.mjs";
const within = async (promise) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("fixture deadline")), 12000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};
await withPostgres(
  async ({ pool }) => {
    const role = "xeip_lease_" + randomBytes(6).toString("hex"),
      password = randomBytes(32).toString("hex");
    await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await grantRuntime(pool, role);
    const runtime = new pg.Pool({
      ...pool.options,
      user: role,
      password,
      max: 1,
    });
    runtime.on("error", () => {});
    let lease, owner;
    try {
      lease = await openControlLease(runtime.options);
      await assert.rejects(maintainDatabase(pool.options, role));
      await assert.rejects(openControlLease(pool.options));
      await assert.rejects(openControlLease(runtime.options));
      assert.equal(
        (await within(runtime.query("SELECT 1 AS n"))).rows[0].n,
        1,
        "lease must not consume the sole work-pool slot",
      );
      const rows = (
        await pool.query(
          "SELECT pid FROM pg_stat_activity WHERE application_name='xeip-control-lease' AND usename=$1",
          [role],
        )
      ).rows;
      assert.equal(rows.length, 1);
      await pool.query("SELECT pg_terminate_backend($1)", [rows[0].pid]);
      await within(lease.failed);
      assert.equal(lease.signal.aborted, true);
      assert.throws(() => lease.assertActive());
      await lease.close();
      owner = await openControlLease(pool.options);
      await assert.rejects(openControlLease(runtime.options));
      await owner.close();
      owner = undefined;
      const race = await Promise.allSettled([
        openControlLease(runtime.options),
        openControlLease(pool.options),
      ]);
      assert.equal(race.filter((r) => r.status === "fulfilled").length, 1);
      for (const r of race) if (r.status === "fulfilled") await r.value.close();
      lease = await openControlLease(runtime.options);
      await lease.close();
      await maintainDatabase(pool.options, role);
      owner = await openControlMaintenance(pool.options);
      const backend = await transaction(
        owner.pool,
        async (client) =>
          (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid,
      );
      assert.equal(
        (
          await pool.query(
            "SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1480935760 AND objid=3 AND granted",
          )
        ).rows[0].pid,
        backend,
        "maintenance transactions must use the ownership backend",
      );
      await assert.rejects(openControlLease(runtime.options));
      await pool.query("CREATE TABLE public.lease_mutation (value integer)");
      let entered;
      const started = new Promise((resolve) => {
        entered = resolve;
      });
      let continueTransaction;
      const paused = new Promise((resolve) => {
        continueTransaction = resolve;
      });
      const mutation = transaction(owner.pool, async (client) => {
        await client.query("INSERT INTO public.lease_mutation VALUES (1)");
        entered();
        await paused;
      });
      const refusedMutation = assert.rejects(mutation);
      try {
        await within(started);
        await pool.query("SELECT pg_terminate_backend($1)", [backend]);
        await within(owner.failed);
        lease = await openControlLease(runtime.options);
      } finally {
        continueTransaction();
        await refusedMutation;
      }
      assert.equal(
        (
          await pool.query(
            "SELECT count(*)::integer AS n FROM public.lease_mutation",
          )
        ).rows[0].n,
        0,
      );
      await assert.rejects(owner.pool.connect());
      await owner.close();
      owner = undefined;
      await lease.close();
      console.log(
        JSON.stringify({
          result: "pass",
          workPoolMax: 1,
          workQueryCompleted: true,
          competingOwnerAndRuntimeRefused: true,
          observedBackendLossInvalidates: true,
          simultaneousAcquisitionWinners: 1,
          maintenanceExcludesRuntime: true,
          mutationSharesLeaseBackend: true,
          terminatedOwnerMutationRolledBack: true,
          scope:
            "session coordination in owned PostgreSQL; external fencing and owner command integration remain open",
        }),
      );
    } finally {
      await lease?.close();
      await owner?.close();
      await runtime.end();
    }
  },
  { baselineChecks: false },
);
