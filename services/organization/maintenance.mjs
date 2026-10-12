#!/usr/bin/env node
/** Explicit owner-only maintenance on an operator-selected DEDICATED database. */
import { pathToFileURL } from "node:url";
import { openControlMaintenance } from "./control-lease.mjs";
import { loadOwnerConfiguration } from "./configuration.mjs";
import { migrate } from "./store.mjs";
import { grantRuntime } from "./database.mjs";

/** @param {string[]} args */
export async function prepareDatabase(args) {
  if (
    args.length !== 4 ||
    args[0] !== "--config" ||
    args[2] !== "--runtime-role" ||
    !/^[a-z][a-z0-9_]{0,62}$/.test(args[3]) ||
    args[3].startsWith("pg_") ||
    args[3] === "public" ||
    process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"
  )
    throw new Error("maintenance_failed");
  const configuration = loadOwnerConfiguration(args[1]);
  await maintainDatabase(configuration, args[3]);
}

/** Programmatic maintenance; callers supply validated owner connection settings.
 * @param {import('pg').ClientConfig} configuration @param {string} role */
export async function maintainDatabase(configuration, role) {
  if (
    typeof role !== "string" ||
    !/^[a-z][a-z0-9_]{0,62}$/.test(role) ||
    role.startsWith("pg_") ||
    role === "public"
  )
    throw new Error("maintenance_failed");
  const owner = await openControlMaintenance(configuration);
  try {
    await migrate(owner.pool);
    await grantRuntime(owner.pool, role);
    owner.assertActive();
  } finally {
    await owner.close();
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const failed = () => {
    process.stderr.write('{"event":"maintenance_failed"}\n');
    process.exit(1);
  };
  const timer = setTimeout(failed, 30000);
  timer.unref();
  process.once("uncaughtException", failed);
  process.once("unhandledRejection", failed);
  try {
    await prepareDatabase(process.argv.slice(2));
    process.stdout.write('{"event":"database_prepared"}\n');
  } catch {
    failed();
  } finally {
    clearTimeout(timer);
  }
}
