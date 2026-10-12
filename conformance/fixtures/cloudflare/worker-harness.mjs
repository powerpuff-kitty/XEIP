/** TEST ONLY: production bundle with a separate private caller and persistent SQLite. */
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, Log, LogLevel } from "miniflare";
export async function harness(bindings, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "xeip-worker-"));
  const scriptPath = join(directory, "worker.mjs");
  let mf;
  const caller = `export default {async fetch(r,env){const i=await r.json(); if(i.kind==='cost-probe') return Response.json(await env.COST_PROBE.run(i.value)); if(i.kind==='refresh-http')return env.REFRESH.fetch(new Request('https://private.invalid/')); if(i.kind==='unlabelled-refresh'){try{await env.REFRESH_UNLABELLED.refresh();return Response.json({invoked:true});}catch{return Response.json({error:'forbidden'},{status:403});}} if(i.kind==='default-scheduled'||i.kind==='default-refresh') {try {await env.PUBLIC[i.kind==='default-scheduled'?'scheduled':'refresh']({cron:'* * * * *',scheduledTime:Date.now()});return Response.json({invoked:true});} catch{return Response.json({error:'rpc_unavailable'},{status:502});}} if(i.kind==='public') return env.PUBLIC.fetch(new Request(i.url??'https://xeip.example/live',{method:i.method??'GET',headers:i.headers,...(i.body===undefined?{}:{body:i.body})})); if(i.kind==='owner-http') return env.OWNER.fetch(new Request('https://owner.invalid/initialize',{method:'POST',body:i.raw})); try {const result=await env[i.kind==='default-rpc'?'PUBLIC':i.kind==='missing-operator'?'UNLABELLED':'OWNER'].manage(i.raw);return new Response(result,{headers:{'content-type':'application/json'}});}catch{return Response.json({error:'rpc_unavailable'},{status:502});}}};`;
  const start = async () => {
    mf = new Miniflare({
      host: "127.0.0.1",
      port: 0,
      ...(options.inspector
        ? { inspectorHost: "127.0.0.1", inspectorPort: 0 }
        : {}),
      unsafeTriggerHandlers: true,
      log: new Log(LogLevel.NONE),
      durableObjectsPersist: join(directory, "storage"),
      workers: [
        {
          name: "scheduler",
          modules: true,
          script: await readFile(
            new URL(
              "../../../services/organization/cloudflare/scheduler.mjs",
              import.meta.url,
            ),
            "utf8",
          ),
          compatibilityDate: "2026-07-30",
          routes: ["schedule.fixture/*"],
          serviceBindings: {
            REFRESH: {
              name: "xeip",
              entrypoint: "RefreshEntrypoint",
              props: { purpose: "trust-refresh" },
            },
          },
        },
        {
          name: "caller",
          routes: ["localhost/*"],
          modules: true,
          script: caller,
          compatibilityDate: "2026-07-30",
          serviceBindings: {
            ...(options.costProbe
              ? {
                  COST_PROBE: {
                    name: "xeip",
                    entrypoint: "CostProbeEntrypoint",
                  },
                }
              : {}),
            PUBLIC: "xeip",
            OWNER: {
              name: "xeip",
              entrypoint: "OwnerEntrypoint",
              props: { operator: "fixture:operator" },
            },
            REFRESH_UNLABELLED: {
              name: "xeip",
              entrypoint: "RefreshEntrypoint",
            },
            REFRESH: {
              name: "xeip",
              entrypoint: "RefreshEntrypoint",
              props: { purpose: "trust-refresh" },
            },
            UNLABELLED: { name: "xeip", entrypoint: "OwnerEntrypoint" },
          },
        },
        {
          name: "xeip",
          modules: true,
          scriptPath,
          modulesRoot: directory,
          compatibilityDate: "2026-07-30",
          compatibilityFlags: ["nodejs_compat"],
          bindings,
          durableObjects: {
            ORGANIZATION: { className: "OrganizationObject", useSQLite: true },
          },
          ...(options.outboundService
            ? { outboundService: options.outboundService }
            : {}),
        },
      ],
    });
    await mf.ready;
  };
  try {
    if (options.artifactPath)
      await writeFile(scriptPath, await readFile(options.artifactPath));
    else
      await build({
        entryPoints: [
          options.entryPoint ??
            new URL(
              "../../../services/organization/cloudflare/worker.mjs",
              import.meta.url,
            ).pathname,
        ],
        outfile: scriptPath,
        bundle: true,
        format: "esm",
        platform: "neutral",
        conditions: ["browser"],
        external: ["cloudflare:workers", "node:*"],
        logLevel: "silent",
      });
    await start();
  } catch (e) {
    await mf?.dispose();
    await rm(directory, { recursive: true, force: true });
    throw e;
  }
  return {
    async inspectorSource() {
      if (!options.inspector) throw Error("fixture inspector is disabled");
      return readFile(scriptPath, "utf8");
    },
    async inspectorURL() {
      if (!options.inspector) throw Error("fixture inspector is disabled");
      return mf.getInspectorURL();
    },
    async send(input) {
      if (input.kind === "scheduled") {
        const r = await mf.dispatchFetch(
          "https://schedule.fixture/cdn-cgi/handler/scheduled?cron=*%20*%20*%20*%20*&format=json",
        );
        return { status: r.status, body: await r.json() };
      }
      const r = await mf.dispatchFetch("http://localhost/", {
        method: "POST",
        body: JSON.stringify(input),
      });
      return { status: r.status, body: await r.json() };
    },
    async restart(next = bindings) {
      bindings = next;
      await mf.dispose();
      await start();
    },
    async close() {
      await mf?.dispose();
      await rm(directory, { recursive: true, force: true });
    },
  };
}
