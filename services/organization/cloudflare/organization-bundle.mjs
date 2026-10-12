import {
  hash,
  seal,
  filesHasher,
  filename,
  components,
  limits,
  validators,
  counts,
  bundleValue,
  checks,
  finish,
} from "./organization-bundle-record.mjs";
/** Complete historical content only; never a durability receipt or restored execution authority. */
import * as fs from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { readJson, writeDurable, syncDirectory } from "./archive.mjs";
import { ACTION_PAGE_BYTES, validateActionPage } from "./action-export.mjs";
import { validateOrganizationCheckpoint } from "./organization-checkpoint.mjs";
import { WireDeadline } from "./recovery-wire.mjs";
/** @typedef {import('./organization-checkpoint.mjs').Checkpoint} Checkpoint */
/** @typedef {import('./organization-checkpoint.mjs').Manifest} CheckpointManifest */
/** @typedef {'actions'|'authority'|'administration'} Section */
/** @typedef {import('./organization-bundle-record.mjs').Bundle} Bundle */
/** @typedef {{organization:string,expectedDigest?:string}} Expected */
/** @typedef {{capture:()=>Promise<unknown>,readPage:(manifest:CheckpointManifest,options:{section:Section,cursor:unknown})=>Promise<unknown>}} Reader */
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  !!value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((k) => Object.hasOwn(value, k));
/** @param {string} path */
async function privateDirectory(path) {
  const stat = await fs.lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
    throw Error();
}
/** Streaming exact inventory; no allocation proportional to an untrusted revision number.
 * @param {string} path @param {Checkpoint} checkpoint */
async function inventory(path, checkpoint) {
  const pages = counts(checkpoint),
    fixed = new Set(["manifest.json", ...components.map((k) => k + ".json")]);
  let seen = 0;
  const expected = 5 + pages.actions + pages.authority + pages.administration;
  const dir = await fs.opendir(path);
  for await (const entry of dir) {
    if (++seen > expected || !entry.isFile()) throw Error();
    if (fixed.delete(entry.name)) continue;
    const match = /^(actions|authority|administration)-([0-9]+)\.json$/.exec(
      entry.name,
    );
    if (!match) throw Error();
    const section = /** @type {Section} */ (match[1]),
      index = Number(match[2]);
    if (
      !Number.isSafeInteger(index) ||
      index < 1 ||
      index > pages[section] ||
      filename(section, index) !== entry.name
    )
      throw Error();
  }
  if (seen !== expected || fixed.size) throw Error();
}
/** Content consistency, optionally against an independently retained digest; never activation.
 * @param {string} directory @param {Expected} expected @returns {Promise<Bundle>} */
export async function verifyOrganizationBundle(directory, expected) {
  try {
    const path = resolve(directory);
    await privateDirectory(path);
    const manifest = bundleValue(
      (await readJson(join(path, "manifest.json"), 4096, fs)).value,
      expected,
    );
    /** @type {Record<string,unknown>} */ const bodies = {};
    const files = filesHasher();
    for (const key of components) {
      const name = key + ".json",
        { value, raw } = await readJson(
          join(path, name),
          limits[key] + 1,
          fs,
          (v) => validators[key](v, expected.organization),
        );
      bodies[key] = value;
      files.update(canonicalize([name, hash(raw)]));
    }
    const checkpoint = validateOrganizationCheckpoint(
      { manifest: manifest.checkpoint, ...bodies },
      expected.organization,
    );
    await inventory(path, checkpoint);
    const check = checks(checkpoint),
      pages = counts(checkpoint);
    for (const section of /** @type {const} */ ([
      "actions",
      "authority",
      "administration",
    ])) {
      for (let index = 1; index <= pages[section]; index++) {
        const name = filename(section, index),
          { value, raw } = await readJson(
            join(path, name),
            section === "actions"
              ? ACTION_PAGE_BYTES
              : section === "authority"
                ? 131073
                : 65537,
            fs,
          );
        check[section].accept(value);
        files.update(canonicalize([name, hash(raw)]));
      }
    }
    finish(check, checkpoint);
    if (files.digest("hex") !== manifest.filesChecksum) throw Error();
    return manifest;
  } catch {
    throw Error("invalid organization bundle");
  }
}
/** @param {{directory:string,organization:string,io?:typeof fs,timeoutMs?:number}&Reader} options @returns {Promise<Bundle>} */
export async function collectOrganizationBundle({
  directory,
  organization,
  capture,
  readPage,
  io = fs,
  timeoutMs = 30000,
}) {
  try {
    if (
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 30000 ||
      typeof capture !== "function" ||
      typeof readPage !== "function"
    )
      throw Error();
    /** @template T @param {()=>Promise<unknown>} work @param {(value:unknown)=>T} validate @returns {Promise<T>} */
    const request = (work, validate) =>
      new WireDeadline().wait(
        Promise.resolve().then(work).then(validate),
        timeoutMs,
      );
    const checkpoint = await request(capture, (v) =>
        validateOrganizationCheckpoint(v, organization),
      ),
      path = resolve(directory),
      files = filesHasher(),
      check = checks(checkpoint);
    await io.mkdir(path, { mode: 0o700 });
    await syncDirectory(dirname(path), io);
    /** @param {string} name @param {unknown} value @param {number} limit */
    const write = async (name, value, limit) => {
      const raw = canonicalize(value) + "\n";
      if (Buffer.byteLength(raw) > limit) throw Error();
      await writeDurable(join(path, name), raw, io);
      files.update(canonicalize([name, hash(raw)]));
    };
    for (const key of components)
      await write(key + ".json", checkpoint[key], limits[key] + 1);
    /** @template T @param {Section} section @param {unknown} cursor @param {(value:unknown)=>T} validate */
    const page = (section, cursor, validate) =>
      request(
        () => readPage(checkpoint.manifest, { section, cursor }),
        (value) => {
          const response = snapshot(
            value,
            (section === "actions"
              ? ACTION_PAGE_BYTES
              : section === "authority"
                ? 131072
                : 65536) + 1024,
          );
          if (
            !exact(response, ["checkpointDigest", "section", "page"]) ||
            response.checkpointDigest !== checkpoint.manifest.digest ||
            response.section !== section
          )
            throw Error();
          return validate(response.page);
        },
      );
    for (let index = 1; index <= checkpoint.manifest.actions.actions; index++) {
      const options = {
        cut: checkpoint.manifest.actions.cut,
        after: check.actions.after,
      };
      const record = await page("actions", options.after, (v) => {
        const p = validateActionPage(v, options);
        if (p.record === null) throw Error();
        check.actions.accept(p.record);
        return p.record;
      });
      await write(filename("actions", index), record, ACTION_PAGE_BYTES);
    }
    await page("actions", check.actions.after, (v) => {
      if (
        validateActionPage(v, {
          cut: checkpoint.manifest.actions.cut,
          after: check.actions.after,
        }).record !== null
      )
        throw Error();
    });
    for (const section of /** @type {const} */ ([
      "authority",
      "administration",
    ])) {
      let index = 0;
      while (!check[section].complete()) {
        const value = await page(section, check[section].cursor(), (v) => {
          check[section].accept(v);
          return v;
        });
        await write(
          filename(section, ++index),
          value,
          section === "authority" ? 131073 : 65537,
        );
      }
    }
    finish(check, checkpoint);
    await syncDirectory(path, io);
    const body = {
      schema: /** @type {const} */ ("xeip.organization-bundle/1"),
      checkpoint: checkpoint.manifest,
      filesChecksum: files.digest("hex"),
    };
    const manifest = bundleValue(
      { ...body, checksum: seal(body) },
      { organization },
    );
    await writeDurable(
      join(path, "manifest.json"),
      canonicalize(manifest) + "\n",
      io,
    );
    await syncDirectory(path, io);
    await syncDirectory(dirname(path), io);
    return manifest;
  } catch {
    throw Error("organization bundle collection failed");
  }
}
