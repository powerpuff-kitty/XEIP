#!/usr/bin/env node
/** Dedicated executable; never imported by the demonstration relay. */
import { pathToFileURL } from "node:url";
import pg from "pg";
import { loadConfiguration, readProvisioning } from "./configuration.mjs";
import { KeycloakAuthenticator } from "./auth.mjs";
import { ActionPolicy } from "./actions.mjs";
import { ActionStore } from "./store.mjs";
import { verifyDatabase } from "./database.mjs";
import { openControlLease } from "./control-lease.mjs";
import { ControlStore } from "./control-store.mjs";
import { publicAuthority } from "./control-state.mjs";
import { openPostgresTrust } from "./postgres-trust.mjs";
import { OrganizationController } from "./controller.mjs";
import { McpConnector } from "./mcp.mjs";
import { createActionExecutor } from "./execution.mjs";
import { serveOrganization } from "./runtime.mjs";
import { Telemetry } from "./telemetry.mjs";
import { createConsole, loadConsoleAssets } from "./console-server.mjs";
let loggingFailed = false;
process.stderr.on("error", () => {
  loggingFailed = true;
});
const telemetry = new Telemetry((line) => {
  if (loggingFailed || process.stderr.writableLength > 65536)
    throw new Error("logging unavailable");
  return process.stderr.write(line);
});

/** Only fixed event codes reach stderr; never stringify errors or configuration.
 * @param {string} event
 */
function report(event) {
  telemetry.event(event);
}

/** The executable owns process termination, including fatal listener failures.
 * @param {Awaited<ReturnType<typeof serveOrganization>>} runtime
 * @param {(event:string)=>void} reportEvent
 * @param {(code:number)=>unknown} exit
 */
export function supervise(runtime, reportEvent, exit) {
  let fatal = false;
  /** @type {Promise<void>|undefined} */ let stopping;
  const stop = () => {
    stopping ??= (async () => {
      reportEvent("draining");
      try {
        const result = await runtime.stop();
        reportEvent(result.forced ? "shutdown_forced" : "shutdown_complete");
        exit(fatal || result.forced ? 1 : 0);
      } catch {
        reportEvent("shutdown_forced");
        exit(1);
      }
    })();
    return stopping;
  };
  void runtime.failed.then((reason) => {
    fatal = true;
    reportEvent(
      reason === "control_lease_lost"
        ? "control_lease_lost"
        : "listener_failed",
    );
    void stop();
  });
  return stop;
}

/** Compose the actual launcher from validated configuration and a bounded runtime pool.
 * Pool ownership passes to the runtime on success; the caller closes failed startup.
 * @param {ReturnType<typeof loadConfiguration>} configuration
 * @param {import('pg').Pool} pool
 */
export async function startOrganization(configuration, pool) {
  const authentication = new KeycloakAuthenticator(
    configuration.authentication,
  );
  const policy = new ActionPolicy(configuration.policy);
  const connector = new McpConnector(configuration.targets);
  /** @type {Awaited<ReturnType<typeof openPostgresTrust>>|undefined} */ let trust;
  /** @type {Awaited<ReturnType<typeof openControlLease>>|undefined} */ let lease;
  /** @type {Awaited<ReturnType<typeof serveOrganization>>|undefined} */ let runtime;
  try {
    lease = await openControlLease(pool.options);
    const activeLease = lease;
    lease.signal.addEventListener(
      "abort",
      () => {
        // Invalidate synchronous admission/dispatch before scheduling any drain.
        trust?.close();
        runtime?.invalidateHealth();
        if (runtime) void runtime.stop().catch(() => {});
      },
      { once: true },
    );
    await verifyDatabase(pool);
    trust = await openPostgresTrust({
      store: new ControlStore(pool),
      authority: publicAuthority(configuration),
      provisioning: configuration.provisioning,
      signal: lease.signal,
    });
    const activeTrust = trust;
    const controller = new OrganizationController({
      authentication,
      trust,
      gateway: configuration.gateway,
      createStore: (authorize) =>
        new ActionStore(pool, policy, authorize, activeTrust.controlFence()),
      execute: createActionExecutor(policy, connector, () =>
        activeTrust.controlFence(),
      ),
    });
    runtime = await serveOrganization(configuration, {
      controller,
      authentication,
      trust,
      telemetry,
      console: configuration.console
        ? createConsole({
            configuration: {
              issuer: configuration.authentication.issuer,
              clientId: configuration.console.clientId,
              gateway: configuration.gateway,
              audience: configuration.authentication.audience,
            },
            authentication,
            assets: loadConsoleAssets(),
          })
        : undefined,
      checkDatabase: async () => {
        activeLease.assertActive();
        await verifyDatabase(pool);
        activeLease.assertActive();
      },
      closeDatabase: async () => {
        await pool.end();
        await activeLease.close();
      },
      provisioning: () =>
        readProvisioning(configuration.trust.provisioningFile),
    });
    activeLease.assertActive();
    return {
      ...runtime,
      failed: Promise.race([
        runtime.failed,
        activeLease.failed.then(() => "control_lease_lost"),
      ]),
    };
  } catch {
    trust?.close();
    if (runtime) await runtime.stop().catch(() => {});
    await lease?.close().catch(() => {});
    throw new Error("startup_failed");
  }
}

/** @param {string[]} args */
export async function run(args) {
  if (
    args.length !== 3 ||
    !["serve", "check"].includes(args[0]) ||
    args[1] !== "--config" ||
    process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"
  )
    throw new Error("startup_failed");
  const configuration = loadConfiguration(args[2]);
  if (args[0] === "check") {
    report("configuration_valid");
    return;
  }
  const startupDeadline = setTimeout(() => {
    report("startup_failed");
    process.exit(1);
  }, 30000);
  startupDeadline.unref();
  const pool = new pg.Pool({
    ...configuration.database,
    ssl: { ...configuration.database.ssl },
  });
  /** @type {Awaited<ReturnType<typeof serveOrganization>>|undefined} */ let runtime;
  pool.on("error", () => {
    runtime?.invalidateHealth();
    report("database_unavailable");
  });
  try {
    runtime = await startOrganization(configuration, pool);
  } catch {
    if (!pool.ended) await pool.end();
    throw new Error("startup_failed");
  } finally {
    clearTimeout(startupDeadline);
  }
  const stop = supervise(runtime, report, (code) => process.exit(code));
  process.on("SIGTERM", () => {
    void stop();
  });
  process.on("SIGINT", () => {
    void stop();
  });
  process.on("SIGHUP", () => {
    void runtime
      .reloadTrust()
      .then((accepted) =>
        report(accepted ? "trust_reloaded" : "trust_reload_rejected"),
      );
  });
  report("started");
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const fatal = () => {
    report("startup_failed");
    process.exit(1);
  };
  process.once("uncaughtException", fatal);
  process.once("unhandledRejection", fatal);
  try {
    await run(process.argv.slice(2));
  } catch {
    fatal();
  }
}
