/** Direct-TLS listener composition. Call only after protected configuration/trust construction. */
import { createOrganizationServer } from "./http.mjs";
import { RuntimeLifecycle } from "./lifecycle.mjs";
import { createManagementServer } from "./management.mjs";
import { Telemetry } from "./telemetry.mjs";
/** @typedef {{origin:string,tls:{key:string|Buffer,cert:string|Buffer},bind:{host:string,port:number},shutdownMs:number,management?:{host:string,port:number,token:string}}} Configuration */
/** @typedef {Omit<import('./lifecycle.mjs').Dependencies,'closeListeners'|'forceCloseListeners'|'shutdownMs'>&{telemetry?:Telemetry,console?:ReturnType<typeof import('./console-server.mjs').createConsole>}} Dependencies */
/** @param {Configuration} configuration @param {Dependencies} dependencies */
export async function serveOrganization(configuration, dependencies) {
  /** @type {ReturnType<typeof createOrganizationServer>} */ let server;
  /** @type {ReturnType<typeof createOrganizationServer>[]} */ const listeners =
    [];
  /** @type {NodeJS.Timeout|undefined} */ let healthTimer;
  /** @type {()=>void} */ let fail;
  const failed = new Promise((resolve) => {
    fail = () => resolve(undefined);
  });
  const telemetry = dependencies.telemetry ?? new Telemetry(() => {});
  const console = dependencies.console;
  const lifecycle = new RuntimeLifecycle({
    ...dependencies,
    shutdownMs: configuration.shutdownMs,
    closeListeners: async () => {
      clearInterval(healthTimer);
      await Promise.all(
        listeners.map(
          (listener) =>
            new Promise((resolve) => {
              listener.close(() => resolve(undefined));
              listener.closeIdleConnections();
            }),
        ),
      );
    },
    forceCloseListeners: () =>
      listeners.forEach((listener) => listener.closeAllConnections()),
  });
  server = createOrganizationServer({
    origin: configuration.origin,
    tls: configuration.tls,
    controller: lifecycle,
    ready: () => lifecycle.ready(),
    onRequest: (observation) => telemetry.request(observation),
    console: console
      ? {
          asset: console.asset,
          profile: (authorization, options) =>
            lifecycle.run(
              (signal) => console.profile(authorization, { signal }),
              options,
            ),
        }
      : undefined,
  });
  listeners.push(server);
  const metrics = () => {
    const { ready, active } = lifecycle.status();
    telemetry.health(ready, active);
    return telemetry.metrics();
  };
  const management = configuration.management
    ? createManagementServer({
        ...configuration.management,
        tls: configuration.tls,
        origin: configuration.origin,
        metrics,
      })
    : undefined;
  if (management) listeners.push(management);
  /** @param {ReturnType<typeof createOrganizationServer>} listener @param {{host:string,port:number}} bind */
  const listen = (listener, bind) =>
    new Promise((resolve, reject) => {
      listener.once("error", reject);
      listener.listen(bind.port, bind.host, () => {
        listener.removeListener("error", reject);
        resolve(undefined);
      });
    });
  try {
    await lifecycle.start();
    if (management && configuration.management)
      await listen(management, configuration.management);
    await listen(server, configuration.bind);
    listeners.forEach((listener) =>
      listener.on("error", () => {
        lifecycle.invalidateHealth();
        fail();
        void lifecycle.stop();
      }),
    );
    healthTimer = setInterval(() => {
      void lifecycle.ready();
    }, 5000);
    healthTimer.unref();
    return {
      failed,
      address: () => server.address(),
      ready: () => lifecycle.ready(),
      reloadTrust: () => lifecycle.reloadTrust(),
      stop: () => lifecycle.stop(),
      invalidateHealth: () => lifecycle.invalidateHealth(),
      metrics,
    };
  } catch {
    await lifecycle.stop();
    throw new Error("organization startup unavailable");
  }
}
