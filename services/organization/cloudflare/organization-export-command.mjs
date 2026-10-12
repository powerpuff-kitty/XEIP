/** Node-only private organization bundle collection. Never activates or deploys a source. */
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  canonicalize,
  strictParse,
} from "../../../sdks/typescript/dist/identity.js";
import { withOwnerSession } from "./owner.mjs";
import { WireDeadline } from "./recovery-wire.mjs";
import { components, validators, hash } from "./organization-bundle-record.mjs";
import { validateOrganizationCheckpoint } from "./organization-checkpoint.mjs";
import {
  collectOrganizationBundle,
  verifyOrganizationBundle,
} from "./organization-bundle.mjs";
import {
  validateExportDescription,
  validateExportReceipt,
} from "./organization-export-wire.mjs";
/** @typedef {import('./organization-export-wire.mjs').ExportContext} ExportContext */
/** @typedef {{send:(raw:string,context?:ExportContext)=>Promise<Record<string,unknown>>}} Session */
/** @param {unknown} organization @returns {asserts organization is string} */
function scope(organization) {
  if (
    typeof organization !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization)
  )
    throw Error();
}
/** The supplied session must use the existing private owner receipt-validation boundary.
 * @param {{directory:string,organization:string,session:Session,timeoutMs?:number}} options */
export async function collectOwnerOrganizationBundle({
  directory,
  organization,
  session,
  timeoutMs = 30000,
}) {
  /** @type {import('./organization-export.mjs').Description|undefined} */ let description;
  /** @type {import('./organization-checkpoint.mjs').Checkpoint|undefined} */ let checkpoint;
  let active = true,
    sourceClosed = false;
  /** @param {string} operation @param {Record<string,unknown>} extra @param {ExportContext} [context] */
  const send = async (operation, extra, context) => {
    const result = await new WireDeadline().wait(
      Promise.resolve().then(() =>
        session.send(
          JSON.stringify({ operation, requestId: randomUUID(), ...extra }),
          context,
        ),
      ),
      timeoutMs,
    );
    if (result.ok !== true) throw Error();
    return result;
  };
  /** @param {string} operation @param {Record<string,unknown>} extra @param {ExportContext} [context] */
  const read = async (operation, extra, context) => {
    if (!active) throw Error();
    const result = await send(operation, extra, context);
    if (!active) throw Error();
    return result;
  };
  let bundle;
  try {
    scope(organization);
    if (
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 30000 ||
      typeof session?.send !== "function"
    )
      throw Error();
    bundle = await collectOrganizationBundle({
      directory,
      organization,
      timeoutMs,
      capture: async () => {
        const begin = await read(
          "organizationExportBegin",
          {},
          { organization },
        );
        description = validateExportDescription(begin.export, organization);
        /** @type {Record<string,unknown>} */ const bodies = {};
        for (const component of components) {
          const descriptor = description.components[component],
            bytes = Buffer.alloc(descriptor.bytes);
          let offset = 0;
          for (let index = 0; index < descriptor.parts; index++) {
            const expected = {
              operation: "organizationExportPart",
              exportId: description.exportId,
              component,
              index,
              exportContext: { description },
            };
            const receipt = await read(
              expected.operation,
              { exportId: description.exportId, component, index },
              { description },
            );
            const part = validateExportReceipt(receipt.part, expected);
            const chunk = Buffer.from(
              /** @type {{data:string}} */ (/** @type {unknown} */ (part)).data,
              "base64",
            );
            offset += chunk.copy(bytes, offset);
          }
          if (offset !== descriptor.bytes || hash(bytes) !== descriptor.sha256)
            throw Error();
          const raw = new TextDecoder("utf-8", {
            fatal: true,
            ignoreBOM: true,
          }).decode(bytes);
          const value = validators[component](strictParse(raw), organization);
          if (canonicalize(value) + "\n" !== raw) throw Error();
          bodies[component] = value;
        }
        checkpoint = validateOrganizationCheckpoint(
          { manifest: description.manifest, ...bodies },
          organization,
        );
        return checkpoint;
      },
      readPage: async (manifest, options) => {
        if (
          !description ||
          !checkpoint ||
          manifest.digest !== description.manifest.digest
        )
          throw Error();
        const request = { exportId: description.exportId, ...options },
          expected = {
            operation: "organizationExportPage",
            ...request,
            exportContext: { checkpoint },
          };
        const receipt = await read(expected.operation, request, { checkpoint });
        const value = validateExportReceipt(receipt.page, expected);
        const { exportId: _, ...page } = /** @type {Record<string,unknown>} */ (
          /** @type {unknown} */ (value)
        );
        return page;
      },
    });
  } catch {
    throw new Error("organization export failed");
  } finally {
    active = false;
    if (description) {
      try {
        const expected = {
          operation: "organizationExportClose",
          exportId: description.exportId,
        };
        const receipt = await send(expected.operation, {
          exportId: expected.exportId,
        });
        validateExportReceipt(receipt.closed, expected);
        sourceClosed = true;
      } catch {
        /* expiry releases unconfirmed remote cleanup; never discard a valid bundle */
      }
    }
  }
  return { bundle, sourceClosed };
}
/** @param {{configPath:string,directory:string,organization:string,remote:boolean}} options */
export async function exportOrganizationBundle({
  configPath,
  directory,
  organization,
  remote,
}) {
  try {
    scope(organization);
    let transportClosed = true;
    const result = await withOwnerSession(
      {
        configPath,
        remote,
        onCleanupFailure: () => {
          transportClosed = false;
        },
      },
      (session) =>
        collectOwnerOrganizationBundle({ directory, organization, session }),
    );
    return { ...result, transportClosed };
  } catch {
    throw new Error("organization export failed");
  }
}
/** @param {import('./organization-bundle-record.mjs').Bundle} bundle */
const summary = (bundle) => ({
  organization: bundle.checkpoint.organization,
  checkpointDigest: bundle.checkpoint.digest,
  bundleChecksum: bundle.checksum,
  actions: bundle.checkpoint.actions.actions,
  cut: bundle.checkpoint.actions.cut,
});
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [operation, ...args] = process.argv.slice(2);
    if (operation === "collect") {
      const [configPath, organization, directory, mode, ...extra] = args;
      if (
        !configPath ||
        !directory ||
        !["--local", "--remote"].includes(mode) ||
        extra.length
      )
        throw Error();
      const result = await exportOrganizationBundle({
        configPath,
        organization,
        directory,
        remote: mode === "--remote",
      });
      console.log(
        JSON.stringify({
          ...summary(result.bundle),
          sourceClosed: result.sourceClosed,
          transportClosed: result.transportClosed,
        }),
      );
    } else if (operation === "verify") {
      const [directory, organization, expectedDigest, ...extra] = args;
      scope(organization);
      if (!directory || extra.length) throw Error();
      const bundle = await verifyOrganizationBundle(directory, {
        organization,
        ...(expectedDigest === undefined ? {} : { expectedDigest }),
      });
      console.log(JSON.stringify(summary(bundle)));
    } else throw Error();
  } catch {
    console.error(
      "Organization export failed. Usage: node organization-export-command.mjs collect OPERATOR_CONFIG.json ORGANIZATION NEW_DIRECTORY --local|--remote; or verify DIRECTORY ORGANIZATION [CHECKPOINT_DIGEST]",
    );
    process.exitCode = 1;
  }
}
