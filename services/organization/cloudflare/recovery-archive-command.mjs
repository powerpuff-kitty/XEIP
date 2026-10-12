/** Protected-file operator interface; no credential arguments or implicit environment configuration. */
import * as fs from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { strictParse } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { transportConfiguration } from "./recovery-wire.mjs";
import { createRecoveryClient } from "./recovery-client.mjs";
import {
  collectRecoveryArchive,
  verifyRecoveryArchive,
} from "./recovery-archive.mjs";
import { verifyRecoveryActions } from "./recovery-action-archive.mjs";
/** @param {string} path */
async function configurationFile(path) {
  const h = await fs.open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await h.stat();
    if (!stat.isFile() || stat.size > 8192 || (stat.mode & 0o077) !== 0)
      throw Error();
    const data = Buffer.alloc(8193);
    let count = 0;
    while (count < data.length) {
      const r = await h.read(data, count, data.length - count, null);
      if (!r.bytesRead) break;
      count += r.bytesRead;
    }
    if (count > 8192) throw Error();
    return transportConfiguration(
      snapshot(
        strictParse(
          new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
            data.subarray(0, count),
          ),
        ),
        8192,
      ),
    );
  } finally {
    await h.close();
  }
}
/** @param {{configPath:string,directory:string,previous?:string,request?:typeof fetch}} settings */
export async function collectConfiguredRecovery({
  configPath,
  directory,
  previous,
  request = fetch,
}) {
  try {
    const configuration = await configurationFile(configPath),
      { token, ...source } = configuration;
    return await collectRecoveryArchive({
      directory,
      source,
      previous,
      client: createRecoveryClient(configuration, request),
    });
  } catch {
    throw Error("recovery archive collection failed");
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [operation, ...args] = process.argv.slice(2);
    if (operation === "actions" && (args.length === 1 || args.length === 2)) {
      console.log(
        JSON.stringify({
          ok: true,
          operation,
          ...(await verifyRecoveryActions(args[0], { previous: args[1] })),
        }),
      );
    } else {
      let manifest;
      if (operation === "verify" && (args.length === 1 || args.length === 2))
        manifest = await verifyRecoveryArchive(args[0], { previous: args[1] });
      else if (
        operation === "collect" &&
        (args.length === 2 || args.length === 3)
      )
        manifest = await collectConfiguredRecovery({
          configPath: args[0],
          directory: args[1],
          previous: args[2],
        });
      else throw Error();
      console.log(
        JSON.stringify({
          ok: true,
          operation,
          head: manifest.head,
          manifestChecksum: manifest.manifestChecksum,
          totalBytes: manifest.totalBytes,
        }),
      );
    }
  } catch {
    console.error(
      "Recovery archive failed. Usage: node recovery-archive-command.mjs collect CONFIG NEW_DIRECTORY [PREVIOUS_ARCHIVE] | verify DIRECTORY [PREVIOUS_ARCHIVE] | actions DIRECTORY [PREVIOUS_ARCHIVE]",
    );
    process.exitCode = 1;
  }
}
