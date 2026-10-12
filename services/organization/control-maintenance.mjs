#!/usr/bin/env node
/** Explicit owner control operations. No listener is opened by this module. */
import { pathToFileURL } from "node:url";
import { loadConfiguration, loadOwnerConfiguration } from "./configuration.mjs";
import { openControlMaintenance } from "./control-lease.mjs";
import { openLegacyCheckpoint } from "./legacy-checkpoint.mjs";
import { ControlStore } from "./control-store.mjs";
import { publicAuthority } from "./control-state.mjs";
import { snapshot } from "./actions.mjs";
import { prepareEntityTrustInWorker } from "../../packages/identity/trust-preparation.mjs";
/** @typedef {import('./control-store.mjs').Token} Token */
/** @typedef {ReturnType<typeof loadConfiguration>} Configuration */
/** @typedef {{operation:'inspect'}|{operation:'enroll',configuration:Configuration}|{operation:'change',configuration:Configuration,expected:Token}} Request */
/** @typedef {{ownerPath:string}&({operation:'inspect'}|{operation:'enroll',runtimePath:string}|{operation:'change',runtimePath:string,expected:Token})} Arguments */
class MaintenanceFailed extends Error {
  constructor() {
    super("control_maintenance_failed");
  }
}
/** @param {unknown} revision @param {unknown} digest @returns {Token} */
function expectedHead(revision, digest) {
  if (
    !Number.isSafeInteger(revision) ||
    Number(revision) < 1 ||
    typeof digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(digest)
  )
    throw new MaintenanceFailed();
  return Object.freeze({ revision: Number(revision), digest });
}
/** @param {string[]} args @returns {Arguments} */
export function parseControlArguments(args) {
  if (args[1] !== "--owner-config" || !args[2]) throw new MaintenanceFailed();
  const ownerPath = args[2];
  if (args[0] === "inspect" && args.length === 3)
    return { operation: "inspect", ownerPath };
  if (args[3] !== "--runtime-config" || !args[4]) throw new MaintenanceFailed();
  const runtimePath = args[4];
  if (args[0] === "enroll" && args.length === 6 && args[5] === "--expect-empty")
    return { operation: "enroll", ownerPath, runtimePath };
  if (
    args[0] === "change" &&
    args.length === 9 &&
    args[5] === "--expected-revision" &&
    args[7] === "--expected-digest" &&
    /^[1-9][0-9]{0,15}$/.test(args[6])
  )
    return {
      operation: "change",
      ownerPath,
      runtimePath,
      expected: expectedHead(Number(args[6]), args[8]),
    };
  throw new MaintenanceFailed();
}
/** Programmatic owner boundary; CLI obtains these inputs from protected files.
 * @param {import('pg').ClientConfig} ownerConfiguration @param {Request} request
 * @param {{signal?:AbortSignal}} [options] */
export async function maintainControl(
  ownerConfiguration,
  request,
  { signal } = {},
) {
  const cancellation = AbortSignal.any([
    AbortSignal.timeout(30000),
    ...(signal ? [signal] : []),
  ]);
  /** @type {Awaited<ReturnType<typeof openControlMaintenance>>|undefined} */ let owner;
  /** @type {ReturnType<typeof openLegacyCheckpoint>|undefined} */ let checkpoint;
  try {
    cancellation.throwIfAborted();
    if (!["inspect", "enroll", "change"].includes(request.operation))
      throw new MaintenanceFailed();
    let input, expected;
    if (request.operation !== "inspect") {
      const configuration = request.configuration;
      for (const key of /** @type {const} */ (["host", "port", "database"]))
        if (
          configuration.database[key] !== ownerConfiguration[key] ||
          ownerConfiguration[key] === undefined
        )
          throw new MaintenanceFailed();
      if (configuration.database.user === ownerConfiguration.user)
        throw new MaintenanceFailed();
      if (request.operation === "change")
        expected = expectedHead(
          request.expected.revision,
          request.expected.digest,
        );
      const authority = publicAuthority(configuration);
      const copy = snapshot(
        configuration.provisioning,
        8 * 1024 * 1024,
        262144,
      );
      if (
        !copy ||
        typeof copy !== "object" ||
        Array.isArray(copy) ||
        Object.keys(copy).sort().join(",") !== "keyDocuments,statusDocuments" ||
        !("keyDocuments" in copy) ||
        !("statusDocuments" in copy) ||
        !Array.isArray(copy.keyDocuments) ||
        !Array.isArray(copy.statusDocuments)
      )
        throw new MaintenanceFailed();
      const provisioning =
        /** @type {import('./control-state.mjs').Provisioning} */ (copy);
      const started = Math.floor(Date.now() / 1000);
      const prepared = await prepareEntityTrustInWorker(
        authority.value.trust,
        provisioning,
        started,
        cancellation,
      );
      const now = Math.floor(Date.now() / 1000);
      if (
        now < started ||
        [...prepared.bundles.values()].some(
          (bundle) => now > bundle.issuedSeconds + bundle.maxAgeSeconds,
        )
      )
        throw new MaintenanceFailed();
      input = { authority, provisioning, acceptedAt: now };
      if (request.operation === "enroll")
        checkpoint = openLegacyCheckpoint(configuration.trust.directory);
    }
    let response;
    try {
      owner = await openControlMaintenance(ownerConfiguration, {
        signal: cancellation,
      });
      const active = AbortSignal.any([cancellation, owner.signal]);
      const store = new ControlStore(owner.pool);
      checkpoint?.assertOwned();
      const current =
        request.operation === "inspect"
          ? await store.inspect({ signal: active })
          : request.operation === "enroll" && input && checkpoint
            ? await store.enroll(
                { ...input, retainedRecords: checkpoint.records },
                { signal: active },
              )
            : input && expected
              ? await store.changeAuthority(expected, input, { signal: active })
              : undefined;
      if (current === undefined) throw new MaintenanceFailed();
      active.throwIfAborted();
      owner.assertActive();
      checkpoint?.assertOwned();
      response = current
        ? Object.freeze({
            event:
              request.operation === "inspect"
                ? "control_head"
                : request.operation === "enroll"
                  ? "control_enrolled"
                  : "control_changed",
            revision: current.revision,
            digest: current.digest,
          })
        : Object.freeze({ event: "control_empty" });
    } finally {
      try {
        await owner?.close();
      } finally {
        checkpoint?.close();
      }
    }
    cancellation.throwIfAborted();
    return response;
  } catch {
    throw new MaintenanceFailed();
  }
}
/** @param {string[]} args @param {{signal?:AbortSignal}} [options] */
export async function runControlCommand(args, options = {}) {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0")
    throw new MaintenanceFailed();
  const parsed = parseControlArguments(args);
  const owner = loadOwnerConfiguration(parsed.ownerPath);
  const request =
    parsed.operation === "inspect"
      ? parsed
      : { ...parsed, configuration: loadConfiguration(parsed.runtimePath) };
  return maintainControl(owner, request, options);
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const cancellation = new AbortController();
  const failed = () => {
    process.stderr.write('{"event":"control_maintenance_failed"}\n');
    process.exit(1);
  };
  /** @type {NodeJS.Timeout|undefined} */ let forced;
  const cancel = () => {
    cancellation.abort();
    forced ??= setTimeout(failed, 3000);
    forced.unref();
  };
  const deadline = setTimeout(cancel, 30000);
  deadline.unref();
  process.once("SIGTERM", cancel);
  process.once("SIGINT", cancel);
  process.once("uncaughtException", failed);
  process.once("unhandledRejection", failed);
  try {
    process.stdout.write(
      JSON.stringify(
        await runControlCommand(process.argv.slice(2), {
          signal: cancellation.signal,
        }),
      ) + "\n",
    );
  } catch {
    failed();
  } finally {
    clearTimeout(deadline);
    clearTimeout(forced);
  }
}
