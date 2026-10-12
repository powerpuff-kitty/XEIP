import { ActionArchiveVerifier } from "./action-archive-record.mjs";
export { ActionArchiveVerifier } from "./action-archive-record.mjs";
/** Manual private action archive. Never restores, prunes or authorizes replay. */
import * as fs from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import {
  sourceCopy,
  readJson,
  writeDurable,
  syncDirectory,
} from "./archive.mjs";
import { withOwnerSession } from "./owner.mjs";
import {
  ACTION_PAGE_BYTES,
  validateActionSnapshot,
  validateActionPage,
} from "./action-export.mjs";
/** @typedef {import('./action-export.mjs').ActionSnapshot} Snapshot */
/** @typedef {{cut:number,actions:number,digest:string,manifestChecksum:string}} Witness */
/** @typedef {{schema:string,source:import('./owner.mjs').OperatorConfiguration,snapshot:Snapshot,pages:number,filesChecksum:string,previous:Witness|null,manifestChecksum:string}} Manifest */
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
/** @param {unknown} value */
const digest = (value) =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
/** @param {string|Uint8Array} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {Omit<Manifest,'manifestChecksum'>} value */
const seal = (value) => hash("XEIP action archive v1\n" + canonicalize(value));
/** @param {number} index */
const filename = (index) => String(index).padStart(6, "0") + ".json";
const filesHasher = () =>
  createHash("sha256").update("XEIP action archive files v1\n");
/** @param {unknown} value @returns {Manifest} */
function manifestValue(value) {
  if (
    !exact(value, [
      "schema",
      "source",
      "snapshot",
      "pages",
      "filesChecksum",
      "previous",
      "manifestChecksum",
    ]) ||
    value.schema !== "xeip.action-archive/1" ||
    !digest(value.filesChecksum) ||
    !digest(value.manifestChecksum)
  )
    throw Error();
  const snapshot = validateActionSnapshot(value.snapshot);
  sourceCopy(value.source);
  if (value.pages !== snapshot.actions) throw Error();
  if (value.previous !== null) {
    const previous = value.previous;
    if (
      !exact(previous, ["cut", "actions", "digest", "manifestChecksum"]) ||
      !digest(previous.digest) ||
      !digest(previous.manifestChecksum)
    )
      throw Error();
    validateActionSnapshot({
      schema: snapshot.schema,
      organization: snapshot.organization,
      cut: previous.cut,
      actions: previous.actions,
      digest: previous.digest,
    });
    if (
      Number(previous.cut) > snapshot.cut ||
      Number(previous.actions) > snapshot.actions
    )
      throw Error();
  }
  const m = /** @type {Manifest} */ (/** @type {unknown} */ (value)),
    { manifestChecksum, ...data } = m;
  if (seal(data) !== manifestChecksum) throw Error();
  return m;
}
/** Content consistency only; not independent authenticity or historic flush certification.
 * @param {string} directory @returns {Promise<Manifest>} */
export async function verifyActionArchive(directory) {
  try {
    const path = resolve(directory),
      stat = await fs.lstat(path);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.mode & 0o077) !== 0
    )
      throw Error();
    const manifest = manifestValue(
      (await readJson(join(path, "manifest.json"), 16384, fs)).value,
    );
    const allowed = new Set([
      "manifest.json",
      ...Array.from({ length: manifest.pages }, (_, i) => filename(i + 1)),
    ]);
    const dir = await fs.opendir(path);
    let count = 0;
    for await (const entry of dir) {
      if (
        ++count > manifest.pages + 1 ||
        !entry.isFile() ||
        !allowed.delete(entry.name)
      )
        throw Error();
    }
    if (allowed.size) throw Error();
    const check = new ActionArchiveVerifier(
        manifest.snapshot,
        manifest.previous,
      ),
      files = filesHasher();
    for (let i = 1; i <= manifest.pages; i++) {
      const name = filename(i),
        { value, raw } = await readJson(
          join(path, name),
          ACTION_PAGE_BYTES,
          fs,
        );
      check.accept(value);
      files.update(canonicalize([name, hash(raw)]));
    }
    check.finish();
    if (files.digest("hex") !== manifest.filesChecksum) throw Error();
    return manifest;
  } catch {
    throw Error("invalid action archive");
  }
}
/** @param {{directory:string,source:unknown,capture:(cut?:number)=>Promise<unknown>,readPage:(options:{cut:number,after:number})=>Promise<unknown>,previous?:string,io?:typeof fs,timeoutMs?:number}} options @returns {Promise<Manifest>} */
export async function collectActionArchive({
  directory,
  source,
  capture,
  readPage,
  previous,
  io = fs,
  timeoutMs = 30000,
}) {
  try {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000)
      throw Error();
    /** @param {()=>Promise<unknown>} work */
    const request = async (work) => {
      let timer;
      try {
        return await Promise.race([
          Promise.resolve().then(work),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error()), timeoutMs);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
    const config = sourceCopy(source),
      prior =
        previous === undefined ? null : await verifyActionArchive(previous);
    if (prior && canonicalize(prior.source) !== canonicalize(config))
      throw Error();
    if (prior) {
      const old = validateActionSnapshot(
        await request(() => capture(prior.snapshot.cut)),
      );
      if (canonicalize(old) !== canonicalize(prior.snapshot)) throw Error();
    }
    const snapshot = Object.freeze({
      ...validateActionSnapshot(await request(() => capture())),
    });
    if (
      prior &&
      (snapshot.organization !== prior.snapshot.organization ||
        snapshot.cut < prior.snapshot.cut ||
        snapshot.actions < prior.snapshot.actions)
    )
      throw Error();
    const witness = prior
      ? {
          cut: prior.snapshot.cut,
          actions: prior.snapshot.actions,
          digest: prior.snapshot.digest,
          manifestChecksum: prior.manifestChecksum,
        }
      : null;
    const path = resolve(directory);
    await io.mkdir(path, { mode: 0o700 });
    await syncDirectory(dirname(path), io);
    const check = new ActionArchiveVerifier(snapshot, witness),
      files = filesHasher();
    for (let i = 1; i <= snapshot.actions; i++) {
      const options = { cut: snapshot.cut, after: check.after };
      const page = validateActionPage(
        await request(() => readPage(options)),
        options,
      );
      if (page.record === null) throw Error();
      check.accept(page.record);
      const name = filename(i),
        raw = canonicalize(page.record) + "\n";
      if (Buffer.byteLength(raw) > ACTION_PAGE_BYTES) throw Error();
      await writeDurable(join(path, name), raw, io);
      files.update(canonicalize([name, hash(raw)]));
    }
    const options = { cut: snapshot.cut, after: check.after };
    if (
      validateActionPage(await request(() => readPage(options)), options)
        .record !== null
    )
      throw Error();
    check.finish();
    await syncDirectory(path, io);
    const data = {
      schema: "xeip.action-archive/1",
      source: config,
      snapshot,
      pages: snapshot.actions,
      filesChecksum: files.digest("hex"),
      previous: witness,
    };
    const manifest = { ...data, manifestChecksum: seal(data) };
    await writeDurable(
      join(path, "manifest.json"),
      canonicalize(manifest) + "\n",
      io,
    );
    await syncDirectory(path, io);
    await syncDirectory(dirname(path), io);
    return manifest;
  } catch {
    throw Error("action archive collection failed");
  }
}
/** @param {{configPath:string,directory:string,remote?:boolean,previous?:string}} options */
export async function collectOwnerActions({
  configPath,
  directory,
  remote = false,
  previous,
}) {
  try {
    return await withOwnerSession(
      { configPath, remote },
      async ({ configuration, send }) => {
        /** @param {string} operation @param {Record<string,unknown>} extra @param {string} field */
        const call = async (operation, extra, field) => {
          const receipt = await send(
            JSON.stringify({ operation, requestId: randomUUID(), ...extra }),
          );
          if (receipt.ok !== true) throw Error();
          return receipt[field];
        };
        return collectActionArchive({
          directory,
          source: configuration,
          previous,
          capture: (cut) =>
            call(
              "actionSnapshot",
              cut === undefined ? {} : { cut },
              "snapshot",
            ),
          readPage: (options) => call("actionPage", options, "page"),
        });
      },
    );
  } catch {
    throw Error("action archive collection failed");
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [operation, ...args] = process.argv.slice(2);
    let manifest;
    if (operation === "verify" && args.length === 1)
      manifest = await verifyActionArchive(args[0]);
    else if (
      operation === "collect" &&
      (args.length === 3 || args.length === 4) &&
      ["--local", "--remote"].includes(args[2])
    )
      manifest = await collectOwnerActions({
        configPath: args[0],
        directory: args[1],
        remote: args[2] === "--remote",
        previous: args[3],
      });
    else throw Error();
    console.log(
      JSON.stringify({
        ok: true,
        operation,
        snapshot: manifest.snapshot,
        manifestChecksum: manifest.manifestChecksum,
        pages: manifest.pages,
      }),
    );
  } catch {
    console.error(
      "Action archive failed. Usage: node action-archive.mjs collect CONFIG NEW_DIRECTORY --local|--remote [PREVIOUS_ARCHIVE] | verify DIRECTORY",
    );
    process.exitCode = 1;
  }
}
